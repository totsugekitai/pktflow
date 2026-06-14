use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;

/// Software-side traffic counters of one port, shared between the
/// workers that update them and the readers (stats API, end-of-run
/// summary). Updates are relaxed atomic adds so the hot path pays no
/// more than a plain increment; readers only need eventually-consistent
/// totals.
#[derive(Debug, Default)]
pub struct PortCounters {
    tx_frames: AtomicU64,
    tx_bytes: AtomicU64,
    rx_frames: AtomicU64,
    rx_bytes: AtomicU64,
}

impl PortCounters {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_tx(&self, frames: u64, bytes: u64) {
        self.tx_frames.fetch_add(frames, Ordering::Relaxed);
        self.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_rx(&self, frames: u64, bytes: u64) {
        self.rx_frames.fetch_add(frames, Ordering::Relaxed);
        self.rx_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            tx_frames: self.tx_frames.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            rx_frames: self.rx_frames.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
        }
    }
}

/// A point-in-time copy of [`PortCounters`].
#[derive(Debug, Clone, Copy, Serialize)]
pub struct CounterSnapshot {
    pub tx_frames: u64,
    pub tx_bytes: u64,
    pub rx_frames: u64,
    pub rx_bytes: u64,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn counters_accumulate_across_clones_of_the_arc() {
        let counters = Arc::new(PortCounters::new());
        let writer = counters.clone();
        writer.add_tx(16, 1024);
        writer.add_tx(4, 256);
        writer.add_rx(2, 128);
        let s = counters.snapshot();
        assert_eq!(s.tx_frames, 20);
        assert_eq!(s.tx_bytes, 1280);
        assert_eq!(s.rx_frames, 2);
        assert_eq!(s.rx_bytes, 128);
    }
}
