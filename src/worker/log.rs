use std::{
    io::{self, Write},
    sync::{Mutex, mpsc},
    time::Duration,
};

use crate::{
    backend::Worker,
    log::{LogRecord, LogShutdown},
};

/// How long the worker sleeps in `recv_timeout` before re-checking the
/// shutdown flag. Also bounds how long shutdown can take.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Occupies one execution context (a DPDK lcore) and owns the log sink.
/// All other workers only format records and send them over the channel;
/// this worker is the single place that performs sink I/O.
///
/// It must not emit `tracing` records itself: after shutdown is signaled
/// and the channel is drained, such records would be lost.
pub struct LogWorker<W: Write + Send> {
    rx: mpsc::Receiver<LogRecord>,
    shutdown: LogShutdown,
    // Worker::run takes &self, so the sink needs interior mutability.
    // The lock is uncontended: only this worker writes.
    sink: Mutex<W>,
}

impl LogWorker<io::Stdout> {
    pub fn new(rx: mpsc::Receiver<LogRecord>, shutdown: LogShutdown) -> Self {
        Self::with_sink(rx, shutdown, io::stdout())
    }
}

impl<W: Write + Send> LogWorker<W> {
    pub fn with_sink(rx: mpsc::Receiver<LogRecord>, shutdown: LogShutdown, sink: W) -> Self {
        Self {
            rx,
            shutdown,
            sink: Mutex::new(sink),
        }
    }
}

impl<W: Write + Send> Worker for LogWorker<W> {
    fn run(&self) {
        let mut sink = self.sink.lock().unwrap();
        loop {
            match self.rx.recv_timeout(POLL_INTERVAL) {
                Ok(record) => {
                    let _ = sink.write_all(&record);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if self.shutdown.is_signaled() {
                        break;
                    }
                    let _ = sink.flush();
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        // Records sent before the shutdown signal may still be queued.
        while let Ok(record) = self.rx.try_recv() {
            let _ = sink.write_all(&record);
        }
        let _ = sink.flush();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, mpsc};

    use super::*;

    /// A `Write` sink whose contents stay observable after the worker
    /// (and thus the sink value) has been moved away.
    #[derive(Clone, Default)]
    struct SharedSink(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn drains_all_records_then_stops_on_shutdown() {
        let (tx, rx) = mpsc::channel();
        let shutdown = LogShutdown::new();
        let sink = SharedSink::default();
        let worker = LogWorker::with_sink(rx, shutdown.clone(), sink.clone());

        tx.send(b"one\n".to_vec()).unwrap();
        tx.send(b"two\n".to_vec()).unwrap();
        shutdown.signal();

        let handle = std::thread::spawn(move || worker.run());
        handle.join().unwrap();

        assert_eq!(*sink.0.lock().unwrap(), b"one\ntwo\n");
    }

    #[test]
    fn stops_when_all_senders_are_gone() {
        let (tx, rx) = mpsc::channel::<LogRecord>();
        let shutdown = LogShutdown::new();
        let sink = SharedSink::default();
        let worker = LogWorker::with_sink(rx, shutdown, sink.clone());

        tx.send(b"last\n".to_vec()).unwrap();
        drop(tx);

        let handle = std::thread::spawn(move || worker.run());
        handle.join().unwrap();

        assert_eq!(*sink.0.lock().unwrap(), b"last\n");
    }
}
