use std::{
    ffi::CString,
    mem::MaybeUninit,
    ptr::NonNull,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Error, Result};

use crate::backend::{
    self,
    dpdk::{
        ffi,
        mbuf::MbufBurst,
        mempool::Mempool,
        pcapng::Capture,
        queue::{self, RxQueue, TxQueue},
    },
};

const BURST_SIZE: usize = 16;
/// Consecutive zero-progress tx polls tolerated while the tx ring drains
/// before the queue is considered stuck (link down, ...).
const TX_STALL_LIMIT: u32 = 10_000;

pub struct Port {
    ptr: NonNull<ffi::dpdk_port_t>,
    pool: Arc<Mutex<Mempool>>,

    rxqs: Vec<RxQueue<queue::Setup>>,
    txqs: Vec<TxQueue<queue::Setup>>,

    capture: Option<Capture>,
    detach_on_drop: bool,
}

impl Port {
    pub(super) fn id(&self) -> u16 {
        unsafe { ffi::dpdk_port_get_id(self.ptr.as_ptr()) }
    }

    pub(super) fn set_capture(&mut self, capture: Capture) {
        self.capture = Some(capture);
    }

    /// Detaches the capture from the Rx path. Dropping the sender lets
    /// the pcap worker drain the queued packets and finish the file.
    pub fn disable_capture(&mut self) {
        self.capture = None;
    }

    /// Makes the drop also remove the device from the EAL (not just stop
    /// and close it), so the same device can be attached again later.
    /// Used when a port is removed at runtime rather than at exit.
    pub(super) fn detach_on_drop(&mut self) {
        self.detach_on_drop = true;
    }

    fn send_burst<const N: usize>(&mut self, burst: &mut MbufBurst<N>) -> Result<()> {
        // A full tx ring makes tx_burst accept only part of the burst;
        // keep polling as long as the NIC drains it.
        let mut stalls = 0;
        while !burst.is_empty() {
            let before = burst.len();
            self.txqs[0].tx_burst(burst);
            if burst.len() < before {
                stalls = 0;
            } else {
                stalls += 1;
                if stalls >= TX_STALL_LIMIT {
                    return Err(Error::msg(format!(
                        "Tx queue stalled, {} pkts unsent",
                        burst.len()
                    )));
                }
            }
        }
        Ok(())
    }
}

impl backend::Port for Port {
    fn start(&mut self) -> Result<()> {
        let ret = unsafe { ffi::dpdk_port_start(self.ptr.as_ptr()) };
        if ret != 0 {
            return Err(Error::msg("Failed to start port"));
        }
        Ok(())
    }

    fn wait_linkup(&self) -> Result<()> {
        let ret = unsafe { ffi::dpdk_port_wait_linkup(self.ptr.as_ptr()) };
        if ret != 0 {
            return Err(Error::msg("Port link up timed out"));
        }
        Ok(())
    }

    fn link_up(&self) -> Result<bool> {
        let mut up = 0;
        let ret = unsafe { ffi::dpdk_port_get_link(self.ptr.as_ptr(), &mut up) };
        if ret < 0 {
            return Err(Error::msg(format!("Failed to read link status ({ret})")));
        }
        Ok(up != 0)
    }

    fn send_frames(&mut self, frames: &[&[u8]]) -> Result<()> {
        for chunk in frames.chunks(BURST_SIZE) {
            let mut burst = MbufBurst::<BURST_SIZE>::new();
            self.pool
                .lock()
                .unwrap()
                .alloc_bulk(&mut burst, chunk.len())?;
            for (frame, m) in chunk.iter().zip(burst.iter_mut()) {
                let buf = m
                    .append(frame.len())
                    .context("Frame does not fit in mbuf")?;
                buf.copy_from_slice(frame);
            }
            self.send_burst(&mut burst)?;
        }
        Ok(())
    }

    fn recv_frames(&mut self, on_frame: &mut dyn FnMut(&[u8])) -> Result<usize> {
        let mut burst = MbufBurst::<BURST_SIZE>::new();
        let nb_recv = self.rxqs[0].rx_burst(&mut burst) as usize;
        for i in 0..nb_recv {
            on_frame(burst[i].data());
        }
        if let Some(capture) = &self.capture {
            capture.capture_burst(&burst);
        }
        Ok(nb_recv)
    }

    fn stats(&self) -> Result<backend::PortStats> {
        let mut raw = MaybeUninit::<ffi::dpdk_port_stats>::uninit();
        let ret = unsafe { ffi::dpdk_port_get_stats(self.ptr.as_ptr(), raw.as_mut_ptr()) };
        if ret < 0 {
            return Err(Error::msg(format!("Failed to read port stats ({ret})")));
        }
        // Safety: dpdk_port_get_stats fills every field on success (ret == 0).
        let raw = unsafe { raw.assume_init() };
        Ok(backend::PortStats {
            rx_packets: raw.rx_packets,
            tx_packets: raw.tx_packets,
            rx_bytes: raw.rx_bytes,
            tx_bytes: raw.tx_bytes,
            rx_missed: raw.rx_missed,
            rx_errors: raw.rx_errors,
            tx_errors: raw.tx_errors,
            rx_nombuf: raw.rx_nombuf,
        })
    }
}

impl Drop for Port {
    fn drop(&mut self) {
        unsafe {
            if self.detach_on_drop {
                if ffi::dpdk_port_detach(self.ptr.as_ptr()) < 0 {
                    tracing::error!("Failed to detach port from the EAL");
                }
            } else {
                ffi::dpdk_port_destroy(self.ptr.as_ptr());
            }
        }
    }
}

// DPDK port objects are safe to share across lcores via Arc.
unsafe impl Send for Port {}
unsafe impl Sync for Port {}

pub(super) struct PortBuilder {
    pci_addr: String,
    nb_rxqs: u16,
    nb_txqs: u16,
    nb_rxd: u16,
}

impl PortBuilder {
    pub(super) fn new() -> Self {
        Self {
            pci_addr: String::new(),
            nb_rxqs: 0,
            nb_txqs: 0,
            nb_rxd: 0,
        }
    }

    pub(super) fn pci_addr(mut self, addr: &str) -> Self {
        self.pci_addr = addr.to_string();
        self
    }

    pub(super) fn rx_queues(mut self, n: u16) -> Self {
        self.nb_rxqs = n;
        self
    }

    /// Number of descriptors in each rx queue's ring.
    pub(super) fn rx_descs(mut self, n: u16) -> Self {
        self.nb_rxd = n;
        self
    }

    pub(super) fn tx_queues(mut self, n: u16) -> Self {
        self.nb_txqs = n;
        self
    }

    pub(super) unsafe fn build(self, pktmbuf_pool: Arc<Mutex<Mempool>>) -> Result<Port> {
        let pci_addr =
            CString::new(self.pci_addr.as_str()).context("PCI address contains null byte")?;
        let p = unsafe { ffi::dpdk_port_attach(pci_addr.as_ptr()) };
        let p = NonNull::new(p)
            .context("Failed to find or probe port (is it bound to a DPDK driver?)")?;
        let port_id = unsafe { ffi::dpdk_port_get_id(p.as_ptr()) };
        let mut rxqs = Vec::new();
        let mut txqs = Vec::new();
        unsafe {
            ffi::dpdk_port_configure(p.as_ptr(), self.nb_rxqs, self.nb_txqs);
            let mut pool = pktmbuf_pool.lock().unwrap();
            for i in 0..self.nb_rxqs {
                rxqs.push(RxQueue::new(port_id, i).setup(&mut pool, self.nb_rxd)?);
            }
            for i in 0..self.nb_txqs {
                txqs.push(TxQueue::new(port_id, i).setup());
            }
        }
        Ok(Port {
            ptr: p,
            pool: pktmbuf_pool,
            rxqs,
            txqs,
            capture: None,
            detach_on_drop: false,
        })
    }
}
