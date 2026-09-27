use std::{
    sync::{Arc, RwLock},
    time::Instant,
};

use tracing::{debug, error, info, trace, warn};

use crate::{
    backend::{Port, Worker},
    proto::stream::Rate,
    signal,
    worker::{StopFlag, stats::PortCounters},
};

const BURST_LEN: usize = 16;

/// Frames allowed beyond the `sent` total after `elapsed_secs` at
/// `rate_pps` frames per second (the credit accrued so far).
fn credit(elapsed_secs: f64, rate_pps: f64, sent: u64) -> u64 {
    ((elapsed_secs * rate_pps) as u64).saturating_sub(sent)
}

/// Credit-based pacer: frames become sendable as wall-clock time
/// accrues, so bursts never run ahead of the target rate.
struct Pacer {
    /// Target rate in frames per second; `None` disables pacing.
    rate_pps: Option<f64>,
    start: Instant,
    sent: u64,
}

impl Pacer {
    fn new(rate_pps: Option<f64>) -> Self {
        Self {
            rate_pps,
            start: Instant::now(),
            sent: 0,
        }
    }

    /// Returns how many of `want` frames may be sent now, counting them
    /// as sent; `0` means the caller should poll again later.
    fn grant(&mut self, want: u64) -> u64 {
        let granted = match self.rate_pps {
            Some(rate) => want.min(credit(self.start.elapsed().as_secs_f64(), rate, self.sent)),
            None => want,
        };
        self.sent += granted;
        granted
    }
}

/// How many frames a [`TxPattern`] sends before stopping on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxCount {
    Fixed(u64),
    /// Runs until the worker is stopped (SIGINT or its `StopFlag`).
    Continuous,
}

/// A precomputed cycle of on-wire frames sent at a target rate for a
/// fixed count or continuously. One `TxPattern` corresponds to one
/// `[[tx.streams]]` entry in one-shot mode, or one OTG `Flow` in
/// daemon mode; every frame in `frames` has the same length.
#[derive(Debug)]
pub struct TxPattern {
    frames: Vec<Vec<u8>>,
    count: TxCount,
    rate: Option<Rate>,
    /// Per-flow counters, kept alongside the port-wide counters the
    /// `TxWorker` already updates. Only used in daemon mode, where OTG
    /// flow metrics must be reported separately from port metrics.
    flow_counters: Option<Arc<PortCounters>>,
}

impl TxPattern {
    /// A pattern that always sends the same, single frame (the
    /// one-shot mode case: `StreamSpec::build_frame()` is called once
    /// per `[[tx.streams]]` entry).
    pub fn single(frame: Vec<u8>, count: TxCount, rate: Option<Rate>) -> Self {
        Self {
            frames: vec![frame],
            count,
            rate,
            flow_counters: None,
        }
    }

    /// A pattern that cycles through several precomputed frame
    /// variants (daemon mode: an OTG Flow whose header fields vary
    /// across packets). All `frames` must have the same length.
    pub fn cycle(
        frames: Vec<Vec<u8>>,
        count: TxCount,
        rate: Option<Rate>,
        flow_counters: Arc<PortCounters>,
    ) -> Self {
        Self {
            frames,
            count,
            rate,
            flow_counters: Some(flow_counters),
        }
    }

    #[cfg(test)]
    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }

    #[cfg(test)]
    pub fn frame_at(&self, i: usize) -> &[u8] {
        self.frames[i].as_slice()
    }
}

pub struct TxWorker<P: Port> {
    port: Arc<RwLock<P>>,
    patterns: Vec<TxPattern>,
    stop: StopFlag,
    counters: Arc<PortCounters>,
}

impl<P: Port> TxWorker<P> {
    pub fn new(
        port: Arc<RwLock<P>>,
        patterns: Vec<TxPattern>,
        stop: StopFlag,
        counters: Arc<PortCounters>,
    ) -> Self {
        Self {
            port,
            patterns,
            stop,
            counters,
        }
    }
}

impl<P: Port> Worker for TxWorker<P> {
    fn run(&self) {
        debug!("Tx worker running.");
        if self.patterns.is_empty() {
            warn!("No streams/flows configured, nothing to send.");
            return;
        }
        let mut total: u64 = 0;
        for (i, pattern) in self.patterns.iter().enumerate() {
            let frame_len = pattern.frames[0].len();
            let burst_frames: Vec<&[u8]> = pattern.frames.iter().map(Vec::as_slice).collect();
            let mut pacer = Pacer::new(pattern.rate.map(|r| r.to_pps(frame_len)));
            let mut remaining = match pattern.count {
                TxCount::Fixed(n) => Some(n),
                TxCount::Continuous => None,
            };
            trace!(
                "Tx pattern #{i}: {:?}, period {}.",
                pattern.count,
                burst_frames.len()
            );
            let mut sent_in_pattern: u64 = 0;
            loop {
                if remaining == Some(0) {
                    break;
                }
                if signal::sigint_received() || self.stop.is_signaled() {
                    info!("Tx interrupted, {total} frames sent.");
                    return;
                }
                let want = remaining
                    .map(|r| r.min(BURST_LEN as u64))
                    .unwrap_or(BURST_LEN as u64);
                let n = pacer.grant(want) as usize;
                if n == 0 {
                    std::hint::spin_loop();
                    continue;
                }
                let burst: Vec<&[u8]> = (0..n)
                    .map(|j| burst_frames[(sent_in_pattern as usize + j) % burst_frames.len()])
                    .collect();
                if let Err(e) = self.port.write().unwrap().send_frames(&burst) {
                    error!("Tx pattern #{i} failed after {total} frames total: {e:#}");
                    return;
                }
                sent_in_pattern += n as u64;
                total += n as u64;
                if let Some(r) = remaining.as_mut() {
                    *r -= n as u64;
                }
                let bytes = (n * frame_len) as u64;
                self.counters.add_tx(n as u64, bytes);
                if let Some(flow_counters) = &pattern.flow_counters {
                    flow_counters.add_tx(n as u64, bytes);
                }
            }
        }
        info!("Tx succeed, {total} frames sent.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credit_accrues_with_time() {
        assert_eq!(credit(0.0, 100.0, 0), 0);
        assert_eq!(credit(1.0, 100.0, 0), 100);
        assert_eq!(credit(0.5, 100.0, 40), 10);
    }

    #[test]
    fn credit_never_underflows_when_ahead_of_schedule() {
        assert_eq!(credit(0.1, 100.0, 50), 0);
    }

    #[test]
    fn credit_handles_fractional_pps() {
        assert_eq!(credit(1.0, 0.5, 0), 0);
        assert_eq!(credit(10.0, 0.5, 0), 5);
    }

    #[test]
    fn unpaced_grant_passes_want_through() {
        let mut pacer = Pacer::new(None);
        assert_eq!(pacer.grant(16), 16);
        assert_eq!(pacer.grant(16), 16);
    }
}
