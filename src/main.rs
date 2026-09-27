use std::{
    env,
    fs::File,
    process::exit,
    sync::{Arc, RwLock},
};

use anyhow::{Context, Result, ensure};
use tracing::{error, info, warn};

use crate::{
    backend::{
        Backend, Port,
        dpdk::{DpdkBackend, tsc::Tsc},
    },
    config::Config,
    worker::{
        StopFlag,
        log::LogWorker,
        pcap::PcapWorker,
        rx::RxWorker,
        stats::PortCounters,
        tx::{TxCount, TxPattern, TxWorker},
    },
};

mod backend;
mod config;
mod daemon;
mod log;
mod proto;
mod signal;
mod worker;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    // `pktflow <config>` runs the one-shot mode; `pktflow daemon <config>`
    // starts idle and is driven through the REST API.
    let (daemon_mode, tomlpath) = match args.get(1).map(String::as_str) {
        Some("daemon") => (true, args.get(2)),
        Some(_) => (false, args.get(1)),
        None => (false, None),
    };
    let Some(tomlpath) = tomlpath else {
        eprintln!("Usage: pktflow [daemon] <config.toml>");
        exit(1);
    };
    let config = Config::parse(tomlpath)?;

    // The TSC timer used by the logger requires an initialized EAL.
    let builder = DpdkBackend::builder(&config.eal_args)?;

    // Records are only formatted and queued on the emitting cores; a
    // dedicated worker spawned below drains them onto stdout.
    let (log_rx, log_shutdown) = log::init_forwarding(Tsc::new());

    // Ctrl-C must request a graceful stop: the Rx worker polls until the
    // flag is set, and the default handler would kill the process without
    // releasing DPDK resources.
    signal::install_sigint_handler()?;

    // The daemon does nothing at startup: its ports come from the API.
    let port_configs = if daemon_mode {
        &[]
    } else {
        config.port_configs.as_slice()
    };
    // No lcore is running yet, so an early return here cannot leave
    // rte_eal_cleanup() waiting on a worker (the hazard noted below).
    let mut backend = builder.build(&config.lcores, port_configs)?;
    info!("Init backend.");
    let log_handle = backend.spawn(LogWorker::new(log_rx, log_shutdown.clone()))?;

    // Errors must not return before the shutdown sequence below: dropping
    // the backend while the log worker still occupies its lcore leaves
    // rte_eal_cleanup() spinning forever (and the error never shown).
    let result = if daemon_mode {
        daemon::run(&mut backend, &config)
    } else {
        run(&mut backend, &config)
    };
    match &result {
        Ok(()) => info!("Exit."),
        Err(e) => error!("Fatal: {e:#}"),
    }

    // The log worker drains queued records (including the one above)
    // before it stops, so signal only after the last log statement.
    log_shutdown.signal();
    backend.wait(log_handle);

    result
}

fn run(backend: &mut DpdkBackend, config: &Config) -> Result<()> {
    ensure!(
        config.port_configs.len() >= 2,
        "one-shot mode requires two [[dpdk.ports]] entries (tx and rx)"
    );
    let tx_port = backend.port(&config.port_configs[0].pci).unwrap();
    let rx_port = backend.port(&config.port_configs[1].pci).unwrap();

    info!("Init Tx/Rx port.");
    tx_port.write().unwrap().start()?;
    rx_port.write().unwrap().start()?;

    tx_port.read().unwrap().wait_linkup()?;
    rx_port.read().unwrap().wait_linkup()?;

    info!("All interface are linkup.");
    // The capture must be attached before the Rx worker starts
    // polling so that no received frame is missed.
    let pcap_handle = match &config.capture_file {
        Some(path) => {
            let file = File::create(path)
                .with_context(|| format!("Failed to create capture file {path}"))?;
            let session = backend.setup_capture(&config.port_configs[1].pci, file)?;
            info!("Capture to {path}.");
            Some(backend.spawn(PcapWorker::new(session))?)
        }
        None => None,
    };
    // One-shot workers stop on SIGINT only, so the per-task flags stay
    // unsignaled for the whole run.
    let tx_counters = Arc::new(PortCounters::new());
    let rx_counters = Arc::new(PortCounters::new());
    let tx_patterns = config
        .tx_streams
        .iter()
        .map(|s| TxPattern::single(s.build_frame(), TxCount::Fixed(s.count), s.rate))
        .collect();
    let tx_handle = backend.spawn(TxWorker::new(
        tx_port.clone(),
        tx_patterns,
        StopFlag::new(),
        tx_counters.clone(),
    ))?;
    let rx_handle = backend.spawn(RxWorker::new(
        rx_port.clone(),
        StopFlag::new(),
        rx_counters.clone(),
    ))?;
    info!("Launched.");

    backend.wait(tx_handle);
    backend.wait(rx_handle);
    if let Some(pcap_handle) = pcap_handle {
        // Detaching the capture drops the sender side, letting the
        // pcap worker drain the queue and finish the file.
        rx_port.write().unwrap().disable_capture();
        backend.wait(pcap_handle);
    }
    let tx = tx_counters.snapshot();
    let rx = rx_counters.snapshot();
    info!(
        "Stats: tx {} frames ({} bytes), rx {} frames ({} bytes).",
        tx.tx_frames, tx.tx_bytes, rx.rx_frames, rx.rx_bytes
    );
    log_hw_stats("tx", &tx_port);
    log_hw_stats("rx", &rx_port);
    info!("All workers are completed!");
    Ok(())
}

fn log_hw_stats<P: Port>(label: &str, port: &Arc<RwLock<P>>) {
    match port.read().unwrap().stats() {
        Ok(s) => info!(
            "HW stats ({label}): rx {} pkts / {} bytes (missed {}, errors {}, nombuf {}), \
             tx {} pkts / {} bytes (errors {}).",
            s.rx_packets,
            s.rx_bytes,
            s.rx_missed,
            s.rx_errors,
            s.rx_nombuf,
            s.tx_packets,
            s.tx_bytes,
            s.tx_errors
        ),
        Err(e) => warn!("Failed to read {label} port stats: {e:#}"),
    }
}
