use crate::{backend::dpdk::ffi, log::Timer};

pub struct Tsc {
    start_tsc: u64,
    hz: u64,
}

impl Tsc {
    pub fn new() -> Self {
        Self {
            start_tsc: unsafe { ffi::dpdk_rdtsc() },
            hz: unsafe { ffi::dpdk_tsc_get_hz() },
        }
    }

    pub fn current_tsc(&self) -> u64 {
        unsafe { ffi::dpdk_rdtsc() }
    }
}

impl Timer for Tsc {
    fn elapsed_ns(&self) -> u64 {
        // Widen to u128: cycles * 1e9 overflows u64 within seconds on GHz-class TSCs.
        let elapsed = u128::from(self.current_tsc() - self.start_tsc);
        (elapsed * 1_000_000_000 / u128::from(self.hz)) as u64
    }
}
