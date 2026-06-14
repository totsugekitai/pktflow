use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Error, Result};

/// Set by the SIGINT handler; a plain atomic store is async-signal-safe.
static SIGINT_RECEIVED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_sigint(_signum: libc::c_int) {
    SIGINT_RECEIVED.store(true, Ordering::Release);
}

/// Installs a SIGINT handler so that Ctrl-C requests a graceful shutdown
/// (observed via [`sigint_received`]) instead of killing the process
/// before DPDK resources are released.
pub fn install_sigint_handler() -> Result<()> {
    let handler = on_sigint as *const () as libc::sighandler_t;
    let prev = unsafe { libc::signal(libc::SIGINT, handler) };
    if prev == libc::SIG_ERR {
        return Err(Error::msg("Failed to install SIGINT handler"));
    }
    Ok(())
}

/// Whether Ctrl-C has been pressed since the handler was installed.
pub fn sigint_received() -> bool {
    SIGINT_RECEIVED.load(Ordering::Acquire)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigint_sets_the_flag() {
        install_sigint_handler().unwrap();
        assert!(!sigint_received());
        // raise() delivers the signal synchronously to the calling
        // thread, so the handler has run by the time it returns.
        unsafe { libc::raise(libc::SIGINT) };
        assert!(sigint_received());
    }
}
