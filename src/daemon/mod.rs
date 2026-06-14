//! Daemon mode: the process starts idle and is driven entirely through a
//! REST API (see [`api`]). HTTP threads translate requests into
//! [`Command`]s sent over a channel; this module executes them serially
//! on the main lcore, which keeps every DPDK control-path call on one
//! thread and the worker lifecycle in one place.

mod api;

use std::{
    collections::HashMap,
    fs::{self, File},
    path::PathBuf,
    sync::{Arc, RwLock, mpsc},
    time::Duration,
};

use anyhow::{Context as aContext, Result, ensure};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::{
    backend::{
        Backend, Port as _, PortStats, Worker,
        dpdk::{DpdkBackend, Lcore},
    },
    config::{Config, PortConfig},
    proto::stream::StreamSpec,
    signal,
    worker::{
        StopFlag,
        pcap::PcapWorker,
        rx::RxWorker,
        stats::{CounterSnapshot, PortCounters},
        tx::TxWorker,
    },
};

type DpdkPort = <DpdkBackend as Backend>::Port;

/// How long the daemon loop sleeps in `recv_timeout` before re-checking
/// the SIGINT flag. Also bounds how long shutdown can take.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Which functions a port is allowed to run. Fields absent in a request
/// body mean "disabled".
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PortMode {
    #[serde(default)]
    pub tx: bool,
    #[serde(default)]
    pub rx: bool,
    #[serde(default)]
    pub pcap: bool,
}

impl PortMode {
    /// Default for ports added without an explicit mode.
    const ALL: Self = Self {
        tx: true,
        rx: true,
        pcap: true,
    };
}

/// A request from the API layer; the outcome is sent back over `reply`.
struct Request {
    cmd: Command,
    reply: mpsc::Sender<CmdResult>,
}

enum Command {
    ListPorts,
    AddPort {
        pci: String,
        rxq: u16,
        txq: u16,
        rxd: u16,
        mode: PortMode,
    },
    RemovePort {
        pci: String,
    },
    SetMode {
        pci: String,
        mode: PortMode,
    },
    StartTx {
        pci: String,
        streams: Vec<StreamSpec>,
    },
    StopTx {
        pci: String,
    },
    StartRx {
        pci: String,
    },
    StopRx {
        pci: String,
    },
    StartPcap {
        pci: String,
    },
    StopPcap {
        pci: String,
    },
    GetPcap {
        pci: String,
    },
    GetStats {
        pci: String,
    },
}

enum Reply {
    Empty,
    Ports(Vec<PortStatus>),
    Pcap(Vec<u8>),
    Stats(PortStatsReport),
}

/// The body of a stats response: hardware counters read from the NIC
/// and software counters accumulated by the workers.
#[derive(Debug, Serialize)]
struct PortStatsReport {
    pci: String,
    hw: PortStats,
    sw: CounterSnapshot,
}

/// Errors cross the channel as strings so the daemon loop never hands
/// `anyhow::Error` internals to another thread.
type CmdResult = std::result::Result<Reply, String>;

#[derive(Debug, Serialize)]
struct PortStatus {
    pci: String,
    /// Physical link status; `None` (JSON `null`) when it could not be
    /// read from the NIC.
    link_up: Option<bool>,
    mode: PortMode,
    running: RunningStatus,
    /// Whether a finished capture is available for download.
    pcap_ready: bool,
}

#[derive(Debug, Serialize)]
struct RunningStatus {
    tx: bool,
    rx: bool,
    pcap: bool,
}

/// Wraps a worker so its completion is observable without blocking on
/// the lcore: `done` is signaled by the worker itself when it returns.
struct Tracked<W> {
    inner: W,
    done: StopFlag,
}

impl<W: Worker> Worker for Tracked<W> {
    fn run(&self) {
        self.inner.run();
        self.done.signal();
    }
}

/// A worker occupying one lcore until reaped.
struct Task {
    handle: Lcore,
    stop: StopFlag,
    done: StopFlag,
}

struct PcapTask {
    handle: Lcore,
    done: StopFlag,
    path: PathBuf,
}

struct PortEntry {
    port: Arc<RwLock<DpdkPort>>,
    mode: PortMode,
    tx: Option<Task>,
    rx: Option<Task>,
    pcap: Option<PcapTask>,
    /// Software counters shared with every worker spawned on this port.
    /// They live as long as the entry, so totals survive start/stop
    /// cycles of the workers.
    counters: Arc<PortCounters>,
    /// File of the most recent finished capture, served by `GetPcap`.
    last_pcap: Option<PathBuf>,
    /// Distinguishes capture files across start/stop cycles.
    pcap_seq: u32,
}

impl PortEntry {
    fn new(port: Arc<RwLock<DpdkPort>>, mode: PortMode) -> Self {
        Self {
            port,
            mode,
            tx: None,
            rx: None,
            pcap: None,
            counters: Arc::new(PortCounters::new()),
            last_pcap: None,
            pcap_seq: 0,
        }
    }

    /// Reclaims lcores of tasks that finished on their own (a Tx worker
    /// that sent all frames, a worker that hit SIGINT, ...).
    fn reap_finished(&mut self, backend: &mut DpdkBackend) {
        if self.tx.as_ref().is_some_and(|t| t.done.is_signaled()) {
            let t = self.tx.take().unwrap();
            backend.reap(t.handle);
        }
        if self.rx.as_ref().is_some_and(|t| t.done.is_signaled()) {
            let t = self.rx.take().unwrap();
            backend.reap(t.handle);
        }
        if self.pcap.as_ref().is_some_and(|t| t.done.is_signaled()) {
            let t = self.pcap.take().unwrap();
            backend.reap(t.handle);
            self.last_pcap = Some(t.path);
        }
    }

    fn is_idle(&self) -> bool {
        self.tx.is_none() && self.rx.is_none() && self.pcap.is_none()
    }
}

/// Runs the daemon until SIGINT. Ports and workers only come into being
/// through API commands; at startup nothing but the API server runs.
pub fn run(backend: &mut DpdkBackend, config: &Config) -> Result<()> {
    let (cmd_tx, cmd_rx) = mpsc::channel::<Request>();
    let http_stop = StopFlag::new();
    let server = api::spawn(&config.daemon.listen, cmd_tx, http_stop.clone())?;
    info!("Daemon listening on {}.", config.daemon.listen);

    let mut daemon = Daemon {
        ports: HashMap::new(),
        pcap_dir: config.daemon.pcap_dir.clone(),
    };
    while !signal::sigint_received() {
        match cmd_rx.recv_timeout(POLL_INTERVAL) {
            Ok(req) => {
                let result = daemon
                    .execute(backend, req.cmd)
                    .map_err(|e| format!("{e:#}"));
                // The client may have hung up already; nothing to do then.
                let _ = req.reply.send(result);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            // The API server is gone, so no command can ever arrive again.
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    info!("Shutting down daemon.");
    http_stop.signal();
    // Dropping the receiver fails any request the API thread is still
    // waiting on (it answers 503); otherwise join below could hang.
    drop(cmd_rx);
    // Every lcore worker must be reaped before the backend drops,
    // otherwise rte_eal_cleanup() spins forever.
    daemon.shutdown(backend);
    if server.join().is_err() {
        error!("API server thread panicked.");
    }
    Ok(())
}

struct Daemon {
    ports: HashMap<String, PortEntry>,
    pcap_dir: PathBuf,
}

impl Daemon {
    fn execute(&mut self, backend: &mut DpdkBackend, cmd: Command) -> Result<Reply> {
        match cmd {
            Command::ListPorts => Ok(Reply::Ports(self.list())),
            Command::AddPort {
                pci,
                rxq,
                txq,
                rxd,
                mode,
            } => self.add_port(backend, pci, rxq, txq, rxd, mode),
            Command::RemovePort { pci } => self.remove_port(backend, &pci),
            Command::SetMode { pci, mode } => self.set_mode(backend, &pci, mode),
            Command::StartTx { pci, streams } => self.start_tx(backend, &pci, streams),
            Command::StopTx { pci } => self.stop_tx(backend, &pci),
            Command::StartRx { pci } => self.start_rx(backend, &pci),
            Command::StopRx { pci } => self.stop_rx(backend, &pci),
            Command::StartPcap { pci } => self.start_pcap(backend, &pci),
            Command::StopPcap { pci } => self.stop_pcap(backend, &pci),
            Command::GetPcap { pci } => self.get_pcap(backend, &pci),
            Command::GetStats { pci } => self.get_stats(&pci),
        }
    }

    fn entry_mut(&mut self, pci: &str) -> Result<&mut PortEntry> {
        self.ports
            .get_mut(pci)
            .with_context(|| format!("No port {pci}"))
    }

    fn list(&self) -> Vec<PortStatus> {
        let mut v: Vec<_> = self
            .ports
            .iter()
            .map(|(pci, e)| PortStatus {
                pci: pci.clone(),
                link_up: e
                    .port
                    .read()
                    .unwrap()
                    .link_up()
                    .map_err(|err| warn!("Failed to read link status of {pci}: {err:#}"))
                    .ok(),
                mode: e.mode,
                running: RunningStatus {
                    tx: e.tx.as_ref().is_some_and(|t| !t.done.is_signaled()),
                    rx: e.rx.as_ref().is_some_and(|t| !t.done.is_signaled()),
                    pcap: e.pcap.as_ref().is_some_and(|t| !t.done.is_signaled()),
                },
                pcap_ready: e.last_pcap.is_some(),
            })
            .collect();
        v.sort_by(|a, b| a.pci.cmp(&b.pci));
        v
    }

    fn add_port(
        &mut self,
        backend: &mut DpdkBackend,
        pci: String,
        rxq: u16,
        txq: u16,
        rxd: u16,
        mode: PortMode,
    ) -> Result<Reply> {
        ensure!(!self.ports.contains_key(&pci), "Port {pci} already added");
        let cfg = PortConfig {
            pci: pci.clone(),
            nb_rxq: rxq,
            nb_txq: txq,
            nb_rxd: rxd,
        };
        let port = backend.add_port(&cfg)?;
        // Bring the link up right away so start requests don't have to
        // wait for (or worry about) link negotiation.
        let up = port.write().unwrap().start();
        if let Err(e) = up {
            drop(port);
            let _ = backend.remove_port(&pci);
            return Err(e.context(format!("Failed to bring up port {pci}")));
        }
        info!("Port {pci} added.");
        self.ports.insert(pci, PortEntry::new(port, mode));
        Ok(Reply::Empty)
    }

    fn remove_port(&mut self, backend: &mut DpdkBackend, pci: &str) -> Result<Reply> {
        let entry = self.entry_mut(pci)?;
        entry.reap_finished(backend);
        ensure!(
            entry.is_idle(),
            "Port {pci} still has running tasks; stop them first"
        );
        // Drop our Arc before the backend releases its own so the DPDK
        // device is really detached (and can be added again later).
        self.ports.remove(pci);
        backend.remove_port(pci)?;
        info!("Port {pci} removed.");
        Ok(Reply::Empty)
    }

    fn set_mode(&mut self, backend: &mut DpdkBackend, pci: &str, mode: PortMode) -> Result<Reply> {
        let entry = self.entry_mut(pci)?;
        entry.reap_finished(backend);
        ensure!(
            entry.is_idle(),
            "Port {pci} still has running tasks; stop them before changing the mode"
        );
        entry.mode = mode;
        Ok(Reply::Empty)
    }

    fn start_tx(
        &mut self,
        backend: &mut DpdkBackend,
        pci: &str,
        streams: Vec<StreamSpec>,
    ) -> Result<Reply> {
        ensure!(!streams.is_empty(), "streams must not be empty");
        let entry = self.entry_mut(pci)?;
        ensure!(entry.mode.tx, "Port {pci} is not in tx mode");
        entry.reap_finished(backend);
        ensure!(entry.tx.is_none(), "Tx is already running on {pci}");
        let stop = StopFlag::new();
        let done = StopFlag::new();
        let worker = Tracked {
            inner: TxWorker::new(
                entry.port.clone(),
                streams,
                stop.clone(),
                entry.counters.clone(),
            ),
            done: done.clone(),
        };
        let handle = backend.spawn(worker)?;
        entry.tx = Some(Task { handle, stop, done });
        info!("Tx started on {pci}.");
        Ok(Reply::Empty)
    }

    fn stop_tx(&mut self, backend: &mut DpdkBackend, pci: &str) -> Result<Reply> {
        let entry = self.entry_mut(pci)?;
        let task = entry
            .tx
            .take()
            .with_context(|| format!("Tx is not running on {pci}"))?;
        task.stop.signal();
        // Blocks only until the worker observes the flag (one burst).
        backend.reap(task.handle);
        info!("Tx stopped on {pci}.");
        Ok(Reply::Empty)
    }

    fn start_rx(&mut self, backend: &mut DpdkBackend, pci: &str) -> Result<Reply> {
        let entry = self.entry_mut(pci)?;
        ensure!(entry.mode.rx, "Port {pci} is not in rx mode");
        entry.reap_finished(backend);
        ensure!(entry.rx.is_none(), "Rx is already running on {pci}");
        let stop = StopFlag::new();
        let done = StopFlag::new();
        let worker = Tracked {
            inner: RxWorker::new(entry.port.clone(), stop.clone(), entry.counters.clone()),
            done: done.clone(),
        };
        let handle = backend.spawn(worker)?;
        entry.rx = Some(Task { handle, stop, done });
        info!("Rx started on {pci}.");
        Ok(Reply::Empty)
    }

    fn stop_rx(&mut self, backend: &mut DpdkBackend, pci: &str) -> Result<Reply> {
        let entry = self.entry_mut(pci)?;
        let task = entry
            .rx
            .take()
            .with_context(|| format!("Rx is not running on {pci}"))?;
        task.stop.signal();
        backend.reap(task.handle);
        info!("Rx stopped on {pci}.");
        Ok(Reply::Empty)
    }

    fn start_pcap(&mut self, backend: &mut DpdkBackend, pci: &str) -> Result<Reply> {
        let dir = self.pcap_dir.clone();
        let entry = self.entry_mut(pci)?;
        ensure!(entry.mode.pcap, "Port {pci} is not in pcap mode");
        entry.reap_finished(backend);
        ensure!(entry.pcap.is_none(), "Pcap is already running on {pci}");
        let path = dir.join(format!(
            "pktflow-{}-{}.pcapng",
            pci.replace([':', '.'], "-"),
            entry.pcap_seq
        ));
        entry.pcap_seq += 1;
        let file = File::create(&path)
            .with_context(|| format!("Failed to create capture file {}", path.display()))?;
        // On any failure below, remove the created file so an aborted
        // start does not leave an empty capture behind.
        let session = match backend.setup_capture(pci, file) {
            Ok(s) => s,
            Err(e) => {
                let _ = fs::remove_file(&path);
                return Err(e);
            }
        };
        let done = StopFlag::new();
        let worker = Tracked {
            inner: PcapWorker::new(session),
            done: done.clone(),
        };
        let handle = match backend.spawn(worker) {
            Ok(h) => h,
            Err(e) => {
                // Nothing will drain the capture queue, so detach it.
                entry.port.write().unwrap().disable_capture();
                let _ = fs::remove_file(&path);
                return Err(e);
            }
        };
        if entry.rx.is_none() {
            warn!("Capture on {pci} records nothing until rx is started.");
        }
        info!("Capture started on {pci} to {}.", path.display());
        entry.pcap = Some(PcapTask { handle, done, path });
        Ok(Reply::Empty)
    }

    fn stop_pcap(&mut self, backend: &mut DpdkBackend, pci: &str) -> Result<Reply> {
        let entry = self.entry_mut(pci)?;
        let task = entry
            .pcap
            .take()
            .with_context(|| format!("Pcap is not running on {pci}"))?;
        // Detaching the capture drops the sender side, letting the pcap
        // worker drain the queue and finish the file.
        entry.port.write().unwrap().disable_capture();
        backend.reap(task.handle);
        entry.last_pcap = Some(task.path);
        info!("Capture stopped on {pci}.");
        Ok(Reply::Empty)
    }

    fn get_pcap(&mut self, backend: &mut DpdkBackend, pci: &str) -> Result<Reply> {
        let entry = self.entry_mut(pci)?;
        entry.reap_finished(backend);
        ensure!(
            entry.pcap.is_none(),
            "Capture on {pci} is still running; stop it first"
        );
        let path = entry
            .last_pcap
            .as_ref()
            .with_context(|| format!("No finished capture for {pci}"))?;
        let data = fs::read(path)
            .with_context(|| format!("Failed to read capture file {}", path.display()))?;
        Ok(Reply::Pcap(data))
    }

    fn get_stats(&mut self, pci: &str) -> Result<Reply> {
        let entry = self.entry_mut(pci)?;
        let hw = entry
            .port
            .read()
            .unwrap()
            .stats()
            .with_context(|| format!("Failed to read hardware stats of {pci}"))?;
        let sw = entry.counters.snapshot();
        Ok(Reply::Stats(PortStatsReport {
            pci: pci.to_string(),
            hw,
            sw,
        }))
    }

    /// Stops and reaps everything so the backend can drop safely.
    fn shutdown(&mut self, backend: &mut DpdkBackend) {
        for (pci, entry) in self.ports.iter_mut() {
            if let Some(t) = entry.tx.take() {
                t.stop.signal();
                backend.reap(t.handle);
            }
            if let Some(t) = entry.rx.take() {
                t.stop.signal();
                backend.reap(t.handle);
            }
            if let Some(t) = entry.pcap.take() {
                entry.port.write().unwrap().disable_capture();
                backend.reap(t.handle);
                info!("Capture on {pci} finished at {}.", t.path.display());
            }
        }
        self.ports.clear();
    }
}
