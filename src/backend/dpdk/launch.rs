use std::ffi::c_void;

use crate::backend::{
    Worker,
    dpdk::{ffi, lcore::Lcore},
};

unsafe extern "C" fn worker_trampoline<W>(arg: *mut c_void) -> i32
where
    W: Worker,
{
    let worker = unsafe { Box::from_raw(arg.cast::<W>()) };
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| worker.run())) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

pub(super) fn launch<W>(lcore: Lcore, worker: W)
where
    W: Worker + 'static,
{
    let ptr = Box::into_raw(Box::new(worker));
    unsafe {
        ffi::dpdk_lcore_launch(lcore.id(), Some(worker_trampoline::<W>), ptr.cast());
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use super::*;

    struct TestWorker {
        ran: Arc<AtomicBool>,
        dropped: Arc<AtomicBool>,
        should_panic: bool,
    }

    impl Worker for TestWorker {
        fn run(&self) {
            self.ran.store(true, Ordering::SeqCst);
            if self.should_panic {
                panic!("worker panicked intentionally");
            }
        }
    }

    impl Drop for TestWorker {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    fn spawn_trampoline(should_panic: bool) -> (i32, Arc<AtomicBool>, Arc<AtomicBool>) {
        let ran = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicBool::new(false));
        let worker = TestWorker {
            ran: ran.clone(),
            dropped: dropped.clone(),
            should_panic,
        };
        let ptr = Box::into_raw(Box::new(worker));
        let ret = unsafe { worker_trampoline::<TestWorker>(ptr.cast()) };
        (ret, ran, dropped)
    }

    #[test]
    fn trampoline_returns_zero_on_success() {
        let (ret, ran, dropped) = spawn_trampoline(false);
        assert_eq!(ret, 0);
        assert!(ran.load(Ordering::SeqCst));
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn trampoline_returns_minus_one_on_panic() {
        let (ret, ran, dropped) = spawn_trampoline(true);
        assert_eq!(ret, -1);
        assert!(ran.load(Ordering::SeqCst));
        assert!(dropped.load(Ordering::SeqCst));
    }
}
