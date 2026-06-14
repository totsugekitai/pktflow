use std::{
    sync::{Arc, RwLock},
    time::Instant,
};

use tracing::{debug, error, info, trace, warn};

use crate::{
    backend::{Port, Worker},
    proto::stream::StreamSpec,
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

pub struct TxWorker<P: Port> {
    port: Arc<RwLock<P>>,
    streams: Vec<StreamSpec>,
    stop: StopFlag,
    counters: Arc<PortCounters>,
}

impl<P: Port> TxWorker<P> {
    pub fn new(
        port: Arc<RwLock<P>>,
        streams: Vec<StreamSpec>,
        stop: StopFlag,
        counters: Arc<PortCounters>,
    ) -> Self {
        Self {
            port,
            streams,
            stop,
            counters,
        }
    }
}

impl<P: Port> Worker for TxWorker<P> {
    fn run(&self) {
        debug!("Tx worker running.");
        if self.streams.is_empty() {
            warn!("No [[tx.streams]] configured, nothing to send.");
            return;
        }
        let mut total: u64 = 0;
        for (i, stream) in self.streams.iter().enumerate() {
            let frame = stream.build_frame();
            let burst = vec![frame.as_slice(); BURST_LEN];
            let mut pacer = Pacer::new(stream.rate.map(|r| r.to_pps(frame.len())));
            trace!("Tx stream #{i}: {} frames.", stream.count);
            let mut remaining = stream.count;
            while remaining > 0 {
                if signal::sigint_received() || self.stop.is_signaled() {
                    info!("Tx interrupted, {total} frames sent.");
                    return;
                }
                let n = pacer.grant(remaining.min(BURST_LEN as u64)) as usize;
                if n == 0 {
                    std::hint::spin_loop();
                    continue;
                }
                if let Err(e) = self.port.write().unwrap().send_frames(&burst[..n]) {
                    error!("Tx stream #{i} failed after {total} frames total: {e:#}");
                    return;
                }
                remaining -= n as u64;
                total += n as u64;
                self.counters.add_tx(n as u64, (n * frame.len()) as u64);
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
