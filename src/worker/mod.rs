use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

pub mod log;
pub mod pcap;
pub mod rx;
pub mod stats;
pub mod tx;

/// Requests a graceful stop of one specific worker, in contrast to the
/// process-wide SIGINT flag. Workers poll it between bursts, so a stop
/// is observed within one iteration of their loop.
#[derive(Clone, Default)]
pub struct StopFlag(Arc<AtomicBool>);

impl StopFlag {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn signal(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub fn is_signaled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stop_flag_is_shared_between_clones() {
        let flag = StopFlag::new();
        let clone = flag.clone();
        assert!(!clone.is_signaled());
        flag.signal();
        assert!(clone.is_signaled());
    }
}
