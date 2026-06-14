use std::{
    fs::File,
    sync::{Arc, RwLock},
};

use anyhow::{Context as aContext, Result};
use tracing::trace;

use crate::{
    backend::{Backend, Worker},
    config::PortConfig,
};

mod context;
mod launch;
mod lcore;
mod mbuf;
mod mempool;
pub mod pcapng;
mod port;
mod queue;
mod runtime;
pub mod tsc;

mod ffi {
    #![allow(non_camel_case_types)]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use context::{AllInited, Context};
pub use lcore::Lcore;
use runtime::Runtime;

pub struct DpdkBackend {
    ctx: Context<AllInited>,
}

impl DpdkBackend {
    /// Initializes the DPDK EAL. TSC-based utilities (e.g. [`tsc::Tsc`])
    /// only work after this call.
    pub fn builder(eal_args: &[String]) -> Result<DpdkBackendBuilder> {
        let rt = Runtime::new(eal_args)?;
        Ok(DpdkBackendBuilder { rt })
    }
}

impl DpdkBackend {
    /// Attaches a pcapng capture to the Rx path of the port identified
    /// by `pci`. Must be called before the Rx worker starts polling.
    /// The returned session is meant to be consumed by a pcap worker.
    pub fn setup_capture(&self, pci: &str, file: File) -> Result<pcapng::CaptureSession> {
        let port = self
            .ctx
            .port_by_pci(pci)
            .with_context(|| format!("No port {pci} to capture"))?;
        pcapng::setup(&mut port.write().unwrap(), file)
    }

    /// Configures and registers a device at runtime. The device must have
    /// been bound to a DPDK driver before the EAL was initialized.
    pub fn add_port(&mut self, cfg: &PortConfig) -> Result<Arc<RwLock<port::Port>>> {
        self.ctx.add_port(cfg)
    }

    /// Unregisters a port added with [`DpdkBackend::add_port`]. No worker
    /// may still hold the port when this is called.
    pub fn remove_port(&mut self, pci: &str) -> Result<()> {
        self.ctx.remove_port(pci)
    }

    /// Waits for the worker on `handle` and returns its lcore to the pool
    /// so a later spawn can reuse it. One-shot mode uses [`Backend::wait`]
    /// instead because it never respawns.
    pub fn reap(&mut self, handle: Lcore) {
        self.wait(handle);
        self.ctx.lcore_manager.release(handle);
    }
}

pub struct DpdkBackendBuilder {
    rt: Arc<Runtime>,
}

impl DpdkBackendBuilder {
    pub fn build(self, lcores: &[u32], port_configs: &[PortConfig]) -> Result<DpdkBackend> {
        let ctx = Context::new(self.rt, lcores)
            .init_mempools()?
            .init_ports(port_configs)?;
        Ok(DpdkBackend { ctx })
    }
}

impl Backend for DpdkBackend {
    type Port = port::Port;
    type Handle = Lcore;

    fn port(&self, name: &str) -> Option<Arc<RwLock<Self::Port>>> {
        self.ctx.port_by_pci(name).cloned()
    }

    fn spawn<W: Worker + 'static>(&mut self, worker: W) -> Result<Self::Handle> {
        let lcore = self
            .ctx
            .lcore_manager
            .distribute()
            .context("No available lcore")?;
        launch::launch(lcore, worker);
        Ok(lcore)
    }

    fn wait(&self, handle: Self::Handle) {
        trace!("start waiting [{}]", handle.id());
        unsafe {
            ffi::dpdk_lcore_wait(handle.id());
        }
        trace!("finish waiting [{}]", handle.id());
    }
}
