//! Daemon mode: the process starts idle and is driven entirely through
//! an Open Traffic Generator (OTG) REST API (see [`api`] and
//! [`otg`]). HTTP threads translate requests into [`Command`]s sent
//! over a channel; this module executes them serially on the main
//! lcore, which keeps every DPDK control-path call on one thread and
//! the worker lifecycle in one place.
//!
//! Ports are configured declaratively (`POST /config`): once added, a
//! port immediately starts its link and an Rx worker that runs for as
//! long as the port exists (needed for capture and future Rx metrics;
//! see `TODO.md`). Only Tx (`traffic.flow_transmit`) and capture
//! (`port.capture`) are separately start/stoppable, matching the OTG
//! control model.

mod api;
mod otg;

use std::{
    collections::HashMap,
    fs::{self, File},
    path::PathBuf,
    sync::{Arc, RwLock, mpsc},
    time::{Duration, Instant},
};

use anyhow::{Context as aContext, Result, ensure};
use tracing::{error, info};

use crate::{
    backend::{
        Backend, Port as _, Worker,
        dpdk::{DpdkBackend, Lcore},
    },
    config::Config,
    daemon::otg::{flow::FlowConfig, model},
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

/// A request from the API layer; the outcome is sent back over `reply`.
struct Request {
    cmd: Command,
    reply: mpsc::Sender<CmdResult>,
}

enum Command {
    SetConfig(model::Config),
    GetConfig,
    SetControlState(model::ControlAction),
    GetMetrics(model::MetricsSelector),
    GetCapture(model::CaptureRequest),
    GetVersion,
}

enum Reply {
    Empty,
    Config(model::Config),
    Metrics(model::MetricsResponse),
    Pcap(Vec<u8>),
    Version(model::Version),
}

/// Errors cross the channel as strings so the daemon loop never hands
/// `anyhow::Error` internals to another thread.
type CmdResult = std::result::Result<Reply, String>;

/// A worker occupying one lcore until reaped.
struct Task {
    handle: Lcore,
    stop: StopFlag,
    done: StopFlag,
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

struct PcapTask {
    handle: Lcore,
    done: StopFlag,
    path: PathBuf,
}

struct PortEntry {
    port: Arc<RwLock<DpdkPort>>,
    location: model::PortLocation,
    /// Always running from the moment the port is added until it is
    /// removed from the config.
    rx: Task,
    tx: Option<Task>,
    /// Names of the flows currently included in `tx`'s combined
    /// stream, so a later `flow_transmit` start/stop can tell which
    /// of a port's flows are already running.
    tx_flow_names: Vec<String>,
    pcap: Option<PcapTask>,
    /// Port-wide software counters (aggregate across every flow that
    /// has ever transmitted on this port, plus every received frame).
    counters: Arc<PortCounters>,
    /// File of the most recent finished capture, served by `GetCapture`.
    last_pcap: Option<PathBuf>,
    /// Distinguishes capture files across start/stop cycles.
    pcap_seq: u32,
}

impl PortEntry {
    /// Reclaims lcores of tasks that finished on their own (a Tx worker
    /// that sent all its frames, for instance).
    fn reap_finished(&mut self, backend: &mut DpdkBackend) {
        if self.tx.as_ref().is_some_and(|t| t.done.is_signaled()) {
            let t = self.tx.take().unwrap();
            backend.reap(t.handle);
            self.tx_flow_names.clear();
        }
        if self.pcap.as_ref().is_some_and(|t| t.done.is_signaled()) {
            let t = self.pcap.take().unwrap();
            backend.reap(t.handle);
            self.last_pcap = Some(t.path);
        }
    }
}

/// Tracks the last snapshot of a set of monotonically increasing
/// counters so `GetMetrics` can report a current rate (delta over
/// elapsed time) instead of just the running totals.
#[derive(Default)]
struct RateHistory(HashMap<String, (Instant, [u64; 4])>);

impl RateHistory {
    fn rates(&mut self, key: &str, values: [u64; 4]) -> [f64; 4] {
        let now = Instant::now();
        let rates = match self.0.get(key) {
            Some((prev_t, prev_v)) => {
                let dt = now.duration_since(*prev_t).as_secs_f64();
                if dt <= 0.0 {
                    [0.0; 4]
                } else {
                    let mut r = [0.0; 4];
                    for i in 0..4 {
                        r[i] = values[i].saturating_sub(prev_v[i]) as f64 / dt;
                    }
                    r
                }
            }
            None => [0.0; 4],
        };
        self.0.insert(key.to_string(), (now, values));
        rates
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
        flows: HashMap::new(),
        captures: HashMap::new(),
        flow_counters: HashMap::new(),
        port_rates: RateHistory::default(),
        flow_rates: RateHistory::default(),
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
    /// Stored verbatim so `GetConfig` echoes exactly what was
    /// configured; re-parsed into a [`FlowConfig`] wherever a flow is
    /// actually started or its metrics computed.
    flows: HashMap<String, model::Flow>,
    captures: HashMap<String, model::Capture>,
    /// Per-flow Tx counters, keyed by flow name. Persist across
    /// start/stop cycles like port counters do, except a `start`
    /// resets the counters of the flows it (re)starts.
    flow_counters: HashMap<String, Arc<PortCounters>>,
    port_rates: RateHistory,
    flow_rates: RateHistory,
    pcap_dir: PathBuf,
}

impl Daemon {
    fn execute(&mut self, backend: &mut DpdkBackend, cmd: Command) -> Result<Reply> {
        match cmd {
            Command::SetConfig(config) => self.set_config(backend, config),
            Command::GetConfig => Ok(self.get_config()),
            Command::SetControlState(action) => self.set_control_state(backend, action),
            Command::GetMetrics(selector) => self.get_metrics(selector),
            Command::GetCapture(req) => self.get_capture(backend, req),
            Command::GetVersion => Ok(Reply::Version(model::Version {
                api_spec_version: "1.61.0".into(),
                sdk_version: env!("CARGO_PKG_VERSION").into(),
                app_version: env!("CARGO_PKG_VERSION").into(),
            })),
        }
    }

    fn get_config(&self) -> Reply {
        let mut ports: Vec<model::Port> = self
            .ports
            .iter()
            .map(|(name, e)| model::Port {
                name: name.clone(),
                location: e.location.to_location_string(),
            })
            .collect();
        ports.sort_by(|a, b| a.name.cmp(&b.name));
        Reply::Config(model::Config {
            ports,
            captures: self.captures.values().cloned().collect(),
            flows: self.flows.values().cloned().collect(),
        })
    }

    // -------------------------------------------------------------
    // POST /config
    // -------------------------------------------------------------

    fn set_config(&mut self, backend: &mut DpdkBackend, config: model::Config) -> Result<Reply> {
        let mut new_ports: HashMap<String, model::PortLocation> = HashMap::new();
        for p in &config.ports {
            ensure!(
                new_ports
                    .insert(p.name.clone(), p.parsed_location()?)
                    .is_none(),
                "duplicate port name {:?}",
                p.name
            );
        }

        let mut new_flows: HashMap<String, model::Flow> = HashMap::new();
        for f in &config.flows {
            let parsed =
                FlowConfig::try_from(f.clone()).with_context(|| format!("flow {:?}", f.name))?;
            ensure!(
                new_ports.contains_key(&parsed.tx_name),
                "flow {:?}: tx_name {:?} is not a configured port",
                f.name,
                parsed.tx_name
            );
            for rx in &parsed.rx_names {
                ensure!(
                    new_ports.contains_key(rx),
                    "flow {:?}: rx_names includes unknown port {:?}",
                    f.name,
                    rx
                );
            }
            ensure!(
                new_flows.insert(f.name.clone(), f.clone()).is_none(),
                "duplicate flow name {:?}",
                f.name
            );
        }

        let mut new_captures: HashMap<String, model::Capture> = HashMap::new();
        for c in &config.captures {
            c.validate()?;
            for pn in &c.port_names {
                ensure!(
                    new_ports.contains_key(pn),
                    "capture {:?}: references unknown port {:?}",
                    c.name,
                    pn
                );
            }
            ensure!(
                new_captures.insert(c.name.clone(), c.clone()).is_none(),
                "duplicate capture name {:?}",
                c.name
            );
        }

        // Ports removed from the config.
        let removed: Vec<String> = self
            .ports
            .keys()
            .filter(|n| !new_ports.contains_key(*n))
            .cloned()
            .collect();
        for name in &removed {
            let entry = self.ports.get_mut(name).unwrap();
            entry.reap_finished(backend);
            ensure!(
                entry.tx.is_none() && entry.pcap.is_none(),
                "port {name:?} still has a running tx/capture task; stop it before removing the port from the config"
            );
            entry.rx.stop.signal();
            backend.reap(entry.rx.handle);
            let pci = entry.location.pci.clone();
            self.ports.remove(name);
            backend.remove_port(&pci)?;
            info!("Port {name:?} ({pci}) removed.");
        }

        // Ports that already exist must keep the same location (queue
        // counts are only applied at device configure time).
        for (name, loc) in &new_ports {
            if let Some(existing) = self.ports.get(name) {
                ensure!(
                    existing.location == *loc,
                    "port {name:?}: changing its location/rxq/txq/rxd requires removing and re-adding it"
                );
            }
        }

        // Ports added by this config.
        for (name, loc) in &new_ports {
            if self.ports.contains_key(name) {
                continue;
            }
            let cfg = crate::config::PortConfig {
                pci: loc.pci.clone(),
                nb_rxq: loc.rxq,
                nb_txq: loc.txq,
                nb_rxd: loc.rxd,
            };
            let port = backend.add_port(&cfg)?;
            let up = port.write().unwrap().start();
            if let Err(e) = up {
                drop(port);
                let _ = backend.remove_port(&loc.pci);
                return Err(e.context(format!("failed to bring up port {name:?} ({})", loc.pci)));
            }
            let counters = Arc::new(PortCounters::new());
            let stop = StopFlag::new();
            let worker = RxWorker::new(port.clone(), stop.clone(), counters.clone());
            let handle = match backend.spawn(worker) {
                Ok(h) => h,
                Err(e) => {
                    drop(port);
                    let _ = backend.remove_port(&loc.pci);
                    return Err(
                        e.context(format!("failed to start the Rx worker for port {name:?}"))
                    );
                }
            };
            info!("Port {name:?} ({}) added.", loc.pci);
            self.ports.insert(
                name.clone(),
                PortEntry {
                    port,
                    location: loc.clone(),
                    rx: Task {
                        handle,
                        stop,
                        done: StopFlag::new(),
                    },
                    tx: None,
                    tx_flow_names: Vec::new(),
                    pcap: None,
                    counters,
                    last_pcap: None,
                    pcap_seq: 0,
                },
            );
        }

        self.flows = new_flows;
        self.captures = new_captures;
        Ok(Reply::Empty)
    }

    // -------------------------------------------------------------
    // POST /control/state
    // -------------------------------------------------------------

    fn set_control_state(
        &mut self,
        backend: &mut DpdkBackend,
        action: model::ControlAction,
    ) -> Result<Reply> {
        match action {
            model::ControlAction::PortLink { port_names, up } => {
                for name in self.resolve_port_names(&port_names)? {
                    self.ports[&name].port.write().unwrap().set_link(up)?;
                }
                Ok(Reply::Empty)
            }
            model::ControlAction::PortCapture { port_names, start } => {
                for name in self.resolve_port_names(&port_names)? {
                    if start {
                        self.start_pcap(backend, &name)?;
                    } else {
                        self.stop_pcap(backend, &name)?;
                    }
                }
                Ok(Reply::Empty)
            }
            model::ControlAction::FlowTransmit { flow_names, state } => {
                let target = self.resolve_flow_names(&flow_names)?;
                match state {
                    model::TransmitState::Start => self.start_flows(backend, &target),
                    model::TransmitState::Stop => self.stop_flows(backend, &target),
                    model::TransmitState::Pause | model::TransmitState::Resume => {
                        anyhow::bail!(
                            "transmit state \"pause\"/\"resume\" is not supported yet (see TODO.md)"
                        )
                    }
                }
            }
        }
    }

    fn resolve_port_names(&self, names: &[String]) -> Result<Vec<String>> {
        if names.is_empty() {
            return Ok(self.ports.keys().cloned().collect());
        }
        for n in names {
            ensure!(self.ports.contains_key(n), "no such port {n:?}");
        }
        Ok(names.to_vec())
    }

    fn resolve_flow_names(&self, names: &[String]) -> Result<Vec<String>> {
        if names.is_empty() {
            return Ok(self.flows.keys().cloned().collect());
        }
        for n in names {
            ensure!(self.flows.contains_key(n), "no such flow {n:?}");
        }
        Ok(names.to_vec())
    }

    fn start_pcap(&mut self, backend: &mut DpdkBackend, name: &str) -> Result<()> {
        let dir = self.pcap_dir.clone();
        let pci = self.ports[name].location.pci.clone();
        ensure!(
            self.captures
                .values()
                .any(|c| c.port_names.iter().any(|p| p == name)),
            "no capture is configured for port {name:?}"
        );
        let entry = self.ports.get_mut(name).unwrap();
        entry.reap_finished(backend);
        ensure!(
            entry.pcap.is_none(),
            "capture is already running on port {name:?}"
        );
        let path = dir.join(format!(
            "pktflow-{}-{}.pcapng",
            name.replace(['/', ' '], "_"),
            entry.pcap_seq
        ));
        entry.pcap_seq += 1;
        let file = File::create(&path)
            .with_context(|| format!("failed to create capture file {}", path.display()))?;
        let session = match backend.setup_capture(&pci, file) {
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
                entry.port.write().unwrap().disable_capture();
                let _ = fs::remove_file(&path);
                return Err(e);
            }
        };
        info!("Capture started on port {name:?} to {}.", path.display());
        entry.pcap = Some(PcapTask { handle, done, path });
        Ok(())
    }

    fn stop_pcap(&mut self, backend: &mut DpdkBackend, name: &str) -> Result<()> {
        let entry = self
            .ports
            .get_mut(name)
            .with_context(|| format!("no port {name:?}"))?;
        entry.reap_finished(backend);
        let Some(task) = entry.pcap.take() else {
            // Stopping a capture that is not running is a no-op, matching
            // idempotent OTG state transitions.
            return Ok(());
        };
        entry.port.write().unwrap().disable_capture();
        backend.reap(task.handle);
        entry.last_pcap = Some(task.path);
        info!("Capture stopped on port {name:?}.");
        Ok(())
    }

    fn start_flows(&mut self, backend: &mut DpdkBackend, target: &[String]) -> Result<Reply> {
        let mut by_port: HashMap<String, Vec<String>> = HashMap::new();
        for name in target {
            let parsed = FlowConfig::try_from(self.flows[name].clone())?;
            by_port
                .entry(parsed.tx_name)
                .or_default()
                .push(name.clone());
        }
        for (port_name, new_flow_names) in by_port {
            let entry = self
                .ports
                .get_mut(&port_name)
                .with_context(|| format!("no port {port_name:?}"))?;
            entry.reap_finished(backend);
            let mut combined: Vec<String> = entry
                .tx_flow_names
                .iter()
                .filter(|n| !new_flow_names.contains(n))
                .cloned()
                .collect();
            combined.extend(new_flow_names.iter().cloned());
            if let Some(t) = entry.tx.take() {
                t.stop.signal();
                backend.reap(t.handle);
            }
            for n in &new_flow_names {
                self.flow_counters
                    .insert(n.clone(), Arc::new(PortCounters::new()));
            }
            let mut patterns = Vec::new();
            for n in &combined {
                let parsed = FlowConfig::try_from(self.flows[n].clone())?;
                let counters = self
                    .flow_counters
                    .entry(n.clone())
                    .or_insert_with(|| Arc::new(PortCounters::new()))
                    .clone();
                patterns.push(
                    parsed
                        .expand(counters)
                        .with_context(|| format!("flow {n:?}"))?,
                );
            }
            let entry = self.ports.get_mut(&port_name).unwrap();
            let stop = StopFlag::new();
            let done = StopFlag::new();
            let worker = Tracked {
                inner: TxWorker::new(
                    entry.port.clone(),
                    patterns,
                    stop.clone(),
                    entry.counters.clone(),
                ),
                done: done.clone(),
            };
            let handle = backend.spawn(worker)?;
            entry.tx = Some(Task { handle, stop, done });
            entry.tx_flow_names = combined;
            info!(
                "Tx started on port {port_name:?} ({} flows).",
                entry.tx_flow_names.len()
            );
        }
        Ok(Reply::Empty)
    }

    fn stop_flows(&mut self, backend: &mut DpdkBackend, target: &[String]) -> Result<Reply> {
        let mut by_port: HashMap<String, Vec<String>> = HashMap::new();
        for name in target {
            let parsed = FlowConfig::try_from(self.flows[name].clone())?;
            by_port
                .entry(parsed.tx_name)
                .or_default()
                .push(name.clone());
        }
        for (port_name, stop_names) in by_port {
            let entry = self
                .ports
                .get_mut(&port_name)
                .with_context(|| format!("no port {port_name:?}"))?;
            entry.reap_finished(backend);
            if entry.tx.is_none() {
                continue;
            }
            let remaining: Vec<String> = entry
                .tx_flow_names
                .iter()
                .filter(|n| !stop_names.contains(n))
                .cloned()
                .collect();
            if remaining.len() == entry.tx_flow_names.len() {
                // None of the requested flows were running on this port.
                continue;
            }
            ensure!(
                remaining.is_empty(),
                "port {port_name:?}: stopping only some of its running flows ({stop_names:?} of {:?}) \
                 is not supported; stop them all together (see TODO.md)",
                entry.tx_flow_names
            );
            let t = entry.tx.take().unwrap();
            t.stop.signal();
            backend.reap(t.handle);
            entry.tx_flow_names.clear();
            info!("Tx stopped on port {port_name:?}.");
        }
        Ok(Reply::Empty)
    }

    // -------------------------------------------------------------
    // POST /monitor/metrics
    // -------------------------------------------------------------

    fn get_metrics(&mut self, selector: model::MetricsSelector) -> Result<Reply> {
        match selector {
            model::MetricsSelector::Port(names) => {
                let names = self.resolve_port_names(&names)?;
                let mut metrics = Vec::with_capacity(names.len());
                for name in names {
                    let entry = &self.ports[&name];
                    let snap = entry.counters.snapshot();
                    let link = entry.port.read().unwrap().link_up().unwrap_or(false);
                    let r = self.port_rates.rates(
                        &name,
                        [snap.tx_frames, snap.rx_frames, snap.tx_bytes, snap.rx_bytes],
                    );
                    metrics.push(model::PortMetric {
                        name: name.clone(),
                        location: entry.location.to_location_string(),
                        link: if link { "up" } else { "down" },
                        capture: if entry.pcap.is_some() {
                            "started"
                        } else {
                            "stopped"
                        },
                        transmit: if entry.tx.is_some() {
                            "started"
                        } else {
                            "stopped"
                        },
                        frames_tx: snap.tx_frames,
                        frames_rx: snap.rx_frames,
                        bytes_tx: snap.tx_bytes,
                        bytes_rx: snap.rx_bytes,
                        frames_tx_rate: r[0],
                        frames_rx_rate: r[1],
                        bytes_tx_rate: r[2],
                        bytes_rx_rate: r[3],
                    });
                }
                metrics.sort_by(|a, b| a.name.cmp(&b.name));
                Ok(Reply::Metrics(model::MetricsResponse {
                    choice: "port_metrics",
                    port_metrics: Some(metrics),
                    flow_metrics: None,
                }))
            }
            model::MetricsSelector::Flow(names) => {
                let names = self.resolve_flow_names(&names)?;
                let mut metrics = Vec::with_capacity(names.len());
                for name in names {
                    let parsed = FlowConfig::try_from(self.flows[&name].clone())?;
                    let snap = self
                        .flow_counters
                        .get(&name)
                        .map(|c| c.snapshot())
                        .unwrap_or(CounterSnapshot {
                            tx_frames: 0,
                            tx_bytes: 0,
                            rx_frames: 0,
                            rx_bytes: 0,
                        });
                    let r = self
                        .flow_rates
                        .rates(&name, [snap.tx_frames, snap.tx_bytes, 0, 0]);
                    let running = self
                        .ports
                        .get(&parsed.tx_name)
                        .is_some_and(|e| e.tx_flow_names.contains(&name));
                    metrics.push(model::FlowMetric {
                        name: name.clone(),
                        port_tx: parsed.tx_name,
                        port_rx: parsed.rx_names.first().cloned().unwrap_or_default(),
                        transmit: if running { "started" } else { "stopped" },
                        // Rx-side flow classification is not implemented; see TODO.md.
                        frames_tx: snap.tx_frames,
                        frames_rx: 0,
                        bytes_tx: snap.tx_bytes,
                        bytes_rx: 0,
                        frames_tx_rate: r[0],
                        frames_rx_rate: 0.0,
                        loss: 0.0,
                    });
                }
                metrics.sort_by(|a, b| a.name.cmp(&b.name));
                Ok(Reply::Metrics(model::MetricsResponse {
                    choice: "flow_metrics",
                    port_metrics: None,
                    flow_metrics: Some(metrics),
                }))
            }
        }
    }

    // -------------------------------------------------------------
    // POST /monitor/capture
    // -------------------------------------------------------------

    fn get_capture(
        &mut self,
        backend: &mut DpdkBackend,
        req: model::CaptureRequest,
    ) -> Result<Reply> {
        req.validate()?;
        self.stop_pcap(backend, &req.port_name)?;
        let entry = self
            .ports
            .get(&req.port_name)
            .with_context(|| format!("no port {:?}", req.port_name))?;
        let path = entry
            .last_pcap
            .as_ref()
            .with_context(|| format!("no finished capture for port {:?}", req.port_name))?;
        let data = fs::read(path)
            .with_context(|| format!("failed to read capture file {}", path.display()))?;
        Ok(Reply::Pcap(data))
    }

    /// Stops and reaps everything so the backend can drop safely.
    fn shutdown(&mut self, backend: &mut DpdkBackend) {
        for (name, entry) in self.ports.iter_mut() {
            if let Some(t) = entry.tx.take() {
                t.stop.signal();
                backend.reap(t.handle);
            }
            if let Some(t) = entry.pcap.take() {
                entry.port.write().unwrap().disable_capture();
                backend.reap(t.handle);
                info!("Capture on port {name:?} finished at {}.", t.path.display());
            }
            entry.rx.stop.signal();
            backend.reap(entry.rx.handle);
        }
        self.ports.clear();
    }
}
