use std::sync::{Mutex, atomic::Ordering};

use tracing::{debug, error, info};

use crate::backend::{Worker, dpdk::pcapng::CaptureSession};

/// Upper bound on packets written to the file in one call.
const WRITE_BATCH: usize = 32;

/// Occupies one execution context (a DPDK lcore) and owns the pcapng
/// file I/O. The Rx path only clones received mbufs and queues them;
/// this worker is the single place where capture data hits the disk,
/// so file write latency never stalls the Rx poll loop.
///
/// It finishes when every sender is gone (the capture is detached from
/// the port), after draining the queue and writing the statistics block.
pub struct PcapWorker {
    // Worker::run takes &self, so the session (file writer) needs
    // interior mutability. The lock is uncontended: only this worker
    // touches it.
    session: Mutex<CaptureSession>,
}

impl PcapWorker {
    pub fn new(session: CaptureSession) -> Self {
        Self {
            session: Mutex::new(session),
        }
    }
}

impl Worker for PcapWorker {
    fn run(&self) {
        debug!("Pcap worker running.");
        let mut session = self.session.lock().unwrap();
        let mut written: u64 = 0;
        loop {
            // Block until a packet arrives, then greedily batch what is
            // already queued to amortize the write syscall.
            let Ok(first) = session.packets.recv() else {
                break;
            };
            let mut batch = vec![first];
            while batch.len() < WRITE_BATCH {
                let Ok(m) = session.packets.try_recv() else {
                    break;
                };
                batch.push(m);
            }
            let nb_pkts = batch.len() as u64;
            match session.writer.write_packets(batch) {
                Ok(_) => written += nb_pkts,
                Err(e) => error!("Error while writing capture: {e}"),
            }
        }
        let dropped = session.dropped.load(Ordering::Relaxed);
        let port_id = session.port_id;
        if let Err(e) = session
            .writer
            .write_stats(port_id, written + dropped, dropped)
        {
            error!("Error while writing capture stats: {e}");
        }
        info!("Capture completed! ({written} packets written, {dropped} dropped)");
    }
}
