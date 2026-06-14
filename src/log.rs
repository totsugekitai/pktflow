use std::{
    fmt,
    io::{self, Write},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
};

use tracing_subscriber::{
    EnvFilter,
    fmt::{format::Writer, time::FormatTime, writer::MakeWriter},
};

/// A single formatted log record, ready to be written to the sink.
pub type LogRecord = Vec<u8>;

/// A monotonic time source used to timestamp log records.
pub trait Timer: Send + Sync {
    /// Returns nanoseconds elapsed since the timer was created.
    fn elapsed_ns(&self) -> u64;
}

/// Adapts a [`Timer`] to `tracing_subscriber`'s time formatting.
struct TimerFormat<T: Timer>(T);

impl<T: Timer> FormatTime for TimerFormat<T> {
    fn format_time(&self, w: &mut Writer<'_>) -> fmt::Result {
        let ns = self.0.elapsed_ns();
        write!(w, "[{}.{:09}]", ns / 1_000_000_000, ns % 1_000_000_000)
    }
}

/// Signals the log-draining worker that no more records will follow.
#[derive(Clone)]
pub struct LogShutdown(Arc<AtomicBool>);

impl LogShutdown {
    pub(crate) fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    pub fn signal(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub fn is_signaled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Buffers one formatted record and sends it over the channel when the
/// record is complete (on flush or drop). Emitting threads never touch
/// the actual sink.
struct RecordWriter {
    tx: mpsc::Sender<LogRecord>,
    buf: Vec<u8>,
}

impl RecordWriter {
    fn send_buf(&mut self) {
        if !self.buf.is_empty() {
            // The receiver being gone means logging is shut down; there is
            // nowhere left to report the loss, so drop the record.
            let _ = self.tx.send(std::mem::take(&mut self.buf));
        }
    }
}

impl Write for RecordWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.send_buf();
        Ok(())
    }
}

impl Drop for RecordWriter {
    fn drop(&mut self) {
        self.send_buf();
    }
}

/// A [`MakeWriter`] that forwards each formatted record to the logging
/// worker instead of writing to stdout on the emitting core.
struct ChannelMakeWriter {
    tx: mpsc::Sender<LogRecord>,
}

impl<'a> MakeWriter<'a> for ChannelMakeWriter {
    type Writer = RecordWriter;

    fn make_writer(&'a self) -> Self::Writer {
        RecordWriter {
            tx: self.tx.clone(),
            buf: Vec::new(),
        }
    }
}

/// Initializes the global subscriber in forwarding mode: every record is
/// formatted on the emitting thread and sent over a channel, so emitting
/// cores never block on the sink. The returned receiver must be drained by
/// a dedicated worker (see [`crate::worker::log::LogWorker`]), and the
/// returned [`LogShutdown`] tells that worker when to stop.
pub fn init_forwarding(timer: impl Timer + 'static) -> (mpsc::Receiver<LogRecord>, LogShutdown) {
    let (tx, rx) = mpsc::channel();
    tracing_subscriber::fmt()
        .with_timer(TimerFormat(timer))
        .with_thread_names(true)
        .with_line_number(true)
        .with_file(true)
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_writer(ChannelMakeWriter { tx })
        .init();
    (rx, LogShutdown::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_writer_sends_one_record_on_drop() {
        let (tx, rx) = mpsc::channel();
        {
            let mut w = RecordWriter {
                tx,
                buf: Vec::new(),
            };
            w.write_all(b"hello ").unwrap();
            w.write_all(b"world\n").unwrap();
        }
        assert_eq!(rx.recv().unwrap(), b"hello world\n");
        assert!(rx.recv().is_err());
    }

    #[test]
    fn record_writer_sends_nothing_when_empty() {
        let (tx, rx) = mpsc::channel();
        drop(RecordWriter {
            tx,
            buf: Vec::new(),
        });
        assert!(rx.recv().is_err());
    }

    #[test]
    fn record_writer_flush_clears_buffer() {
        let (tx, rx) = mpsc::channel();
        let mut w = RecordWriter {
            tx,
            buf: Vec::new(),
        };
        w.write_all(b"first").unwrap();
        w.flush().unwrap();
        drop(w);
        assert_eq!(rx.recv().unwrap(), b"first");
        assert!(rx.recv().is_err());
    }

    #[test]
    fn shutdown_flag_is_shared_between_clones() {
        let shutdown = LogShutdown::new();
        let clone = shutdown.clone();
        assert!(!clone.is_signaled());
        shutdown.signal();
        assert!(clone.is_signaled());
    }
}
