use std::{
    ffi::CString,
    fs::File,
    os::fd::{FromRawFd, IntoRawFd},
    ptr::NonNull,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
};

use anyhow::{Context, Error, Result};

use crate::backend::dpdk::{ffi, mbuf::MbufBurst, mempool::Mempool, port::Port};

/// Upper bound on captured bytes per packet. Longer frames are truncated
/// in the capture file (the original length is still recorded).
const SNAPLEN: u32 = 2048;

/// Sizing of the capture mempool. It doubles as the backpressure buffer:
/// when the pcap worker falls behind, the pool runs dry and further
/// packets are dropped from the capture (never blocking the Rx path).
const CAPTURE_POOL_MBUFS: u32 = 8192;
const CAPTURE_POOL_CACHE: u32 = 256;

/// An mbuf holding a pcapng-formatted copy of a received frame.
/// Freed on drop.
pub struct CapturedMbuf {
    ptr: NonNull<ffi::dpdk_mbuf_t>,
}

// The mbuf is exclusively owned and DPDK mempools are safe to
// alloc/free from on different lcores.
unsafe impl Send for CapturedMbuf {}

impl Drop for CapturedMbuf {
    fn drop(&mut self) {
        unsafe {
            ffi::dpdk_mbuf_free(self.ptr.as_ptr());
        }
    }
}

/// A pcapng capture file backed by librte_pcapng.
pub struct Pcapng {
    ptr: NonNull<ffi::dpdk_pcapng_t>,
}

// Only used by one worker at a time (moved, never shared).
unsafe impl Send for Pcapng {}

impl Pcapng {
    /// Takes ownership of `file`; the fd is closed when `self` drops.
    fn create(file: File) -> Result<Self> {
        let appname = CString::new(concat!("pktflow ", env!("CARGO_PKG_VERSION"))).unwrap();
        let fd = file.into_raw_fd();
        let ptr = unsafe { ffi::dpdk_pcapng_fdopen(fd, appname.as_ptr()) };
        match NonNull::new(ptr) {
            Some(ptr) => Ok(Self { ptr }),
            None => {
                // Reclaim the fd so it is not leaked.
                drop(unsafe { File::from_raw_fd(fd) });
                Err(Error::msg("Failed to open pcapng stream"))
            }
        }
    }

    fn add_interface(&mut self, port_id: u16) -> Result<()> {
        // Returns the number of bytes written on success, negative on error.
        let ret = unsafe { ffi::dpdk_pcapng_add_interface(self.ptr.as_ptr(), port_id) };
        if ret < 0 {
            return Err(Error::msg(format!(
                "Failed to add port {port_id} to pcapng file"
            )));
        }
        Ok(())
    }

    /// Writes the packets to the file. Despite its doc comment,
    /// rte_pcapng_write_packets (as of DPDK 23.11) never frees the
    /// mbufs; the caller must, or the capture pool drains for good.
    /// Here `pkts` keeps ownership and drops them after the write.
    pub fn write_packets(&mut self, pkts: Vec<CapturedMbuf>) -> Result<usize> {
        let mut raw: Vec<*mut ffi::dpdk_mbuf_t> = pkts.iter().map(|m| m.ptr.as_ptr()).collect();
        let nb_pkts = raw.len() as u16;
        let written =
            unsafe { ffi::dpdk_pcapng_write_packets(self.ptr.as_ptr(), raw.as_mut_ptr(), nb_pkts) };
        // Return the mbufs to the capture pool on both paths.
        drop(pkts);
        if written < 0 {
            return Err(Error::msg("Failed to write packets to pcapng file"));
        }
        Ok(written as usize)
    }

    /// Writes an interface statistics block. Should be called once,
    /// after the last packet and before closing.
    pub fn write_stats(&mut self, port_id: u16, ifrecv: u64, ifdrop: u64) -> Result<()> {
        let written =
            unsafe { ffi::dpdk_pcapng_write_stats(self.ptr.as_ptr(), port_id, ifrecv, ifdrop) };
        if written < 0 {
            return Err(Error::msg("Failed to write stats to pcapng file"));
        }
        Ok(())
    }
}

impl Drop for Pcapng {
    fn drop(&mut self) {
        unsafe {
            ffi::dpdk_pcapng_close(self.ptr.as_ptr());
        }
    }
}

/// Rx-side half of a capture session, owned by the captured [`Port`]:
/// clones received mbufs into the capture mempool and queues them for
/// the pcap worker. Runs on the Rx lcore so timestamps are taken at
/// receive time, not at write time.
pub(super) struct Capture {
    port_id: u16,
    queue_id: u16,
    pool: Arc<Mutex<Mempool>>,
    tx: mpsc::Sender<CapturedMbuf>,
    dropped: Arc<AtomicU64>,
}

impl Capture {
    pub(super) fn capture_burst<const N: usize>(&self, burst: &MbufBurst<N>) {
        let pool = self.pool.lock().unwrap();
        for m in burst.iter() {
            let copy = unsafe {
                ffi::dpdk_pcapng_copy_rx(
                    self.port_id,
                    self.queue_id,
                    m.as_ptr(),
                    pool.ptr.as_ptr(),
                    SNAPLEN,
                )
            };
            // A failed copy means the capture pool is exhausted (the
            // writer is falling behind); a failed send means the writer
            // is gone. Either way the packet leaves the capture.
            let sent = NonNull::new(copy)
                .map(|ptr| self.tx.send(CapturedMbuf { ptr }).is_ok())
                .unwrap_or(false);
            if !sent {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Writer-side half of a capture session, consumed by a pcap worker.
pub struct CaptureSession {
    pub writer: Pcapng,
    pub packets: mpsc::Receiver<CapturedMbuf>,
    pub port_id: u16,
    /// Shared with [`Capture`]: packets that never reached the writer.
    pub dropped: Arc<AtomicU64>,
    // Keeps the capture mempool alive while cloned mbufs are in flight.
    _pool: Arc<Mutex<Mempool>>,
}

/// Attaches a pcapng capture to the port's Rx path and returns the
/// writer-side session. Must be called before the Rx worker starts.
pub(super) fn setup(port: &mut Port, file: File) -> Result<CaptureSession> {
    let port_id = port.id();
    let mbuf_size = unsafe { ffi::dpdk_pcapng_mbuf_size(SNAPLEN) };
    let mbuf_size = u16::try_from(mbuf_size).context("Capture mbuf size exceeds u16")?;
    // The name must be unique among live mempools; one capture per port
    // at a time is enforced by the callers, so the port id suffices.
    let pool = Mempool::new(
        &format!("capture-p{port_id}"),
        CAPTURE_POOL_MBUFS,
        CAPTURE_POOL_CACHE,
        mbuf_size,
    )?;

    let mut writer = Pcapng::create(file)?;
    writer.add_interface(port_id)?;

    let (tx, packets) = mpsc::channel();
    let dropped = Arc::new(AtomicU64::new(0));
    port.set_capture(Capture {
        port_id,
        // The Rx path only polls queue 0 for now.
        queue_id: 0,
        pool: pool.clone(),
        tx,
        dropped: dropped.clone(),
    });

    Ok(CaptureSession {
        writer,
        packets,
        port_id,
        dropped,
        _pool: pool,
    })
}
