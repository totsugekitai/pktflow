use std::{
    collections::HashMap,
    marker::PhantomData,
    sync::{Arc, Mutex, RwLock},
};

use anyhow::{Context as aContext, Result, ensure};

use crate::{
    backend::dpdk::{
        lcore::LcoreManager,
        mempool::Mempool,
        port::{Port, PortBuilder},
        runtime::Runtime,
    },
    config::PortConfig,
};

pub(super) struct Uninited;
pub(super) struct PartInited;
pub(super) struct AllInited;

pub(super) struct Context<S> {
    state: PhantomData<S>,

    ports: HashMap<String, Arc<RwLock<Port>>>,
    mempools: Vec<Arc<Mutex<Mempool>>>,

    pub(super) lcore_manager: LcoreManager,

    // Dropped last: rte_eal_cleanup() must run after all DPDK objects are freed.
    _rt: Arc<Runtime>,
}

impl Context<Uninited> {
    pub(super) fn new(_rt: Arc<Runtime>, lcores: &[u32]) -> Self {
        Self {
            state: PhantomData,
            _rt,
            ports: HashMap::new(),
            mempools: Vec::new(),
            lcore_manager: LcoreManager::new(lcores),
        }
    }

    pub(super) fn init_mempools(mut self) -> Result<Context<PartInited>> {
        self.mempools
            .push(Mempool::new("mempool[0]", 8192, 256, 2048)?);
        Ok(Context {
            state: PhantomData,
            _rt: self._rt,
            ports: self.ports,
            mempools: self.mempools,
            lcore_manager: self.lcore_manager,
        })
    }
}

impl Context<PartInited> {
    pub(super) fn init_ports(mut self, port_configs: &[PortConfig]) -> Result<Context<AllInited>> {
        for cfg in port_configs {
            let port = unsafe {
                PortBuilder::new()
                    .pci_addr(&cfg.pci)
                    .rx_queues(cfg.nb_rxq)
                    .rx_descs(cfg.nb_rxd)
                    .tx_queues(cfg.nb_txq)
                    .build(self.mempools[0].clone())
                    .with_context(|| format!("Failed to init port {}", cfg.pci))?
            };
            self.ports
                .insert(cfg.pci.clone(), Arc::new(RwLock::new(port)));
        }
        Ok(Context {
            state: PhantomData,
            _rt: self._rt,
            ports: self.ports,
            mempools: self.mempools,
            lcore_manager: self.lcore_manager,
        })
    }
}

impl Context<AllInited> {
    pub(super) fn port_by_pci(&self, pci_addr: &str) -> Option<&Arc<RwLock<Port>>> {
        self.ports.get(pci_addr)
    }

    /// Configures a device that was probed at EAL init and registers it.
    /// Unlike [`Context::init_ports`], failures are reported to the caller
    /// (the device may not exist or may not be bound to a DPDK driver).
    pub(super) fn add_port(&mut self, cfg: &PortConfig) -> Result<Arc<RwLock<Port>>> {
        ensure!(
            !self.ports.contains_key(&cfg.pci),
            "Port {} already added",
            cfg.pci
        );
        let port = unsafe {
            PortBuilder::new()
                .pci_addr(&cfg.pci)
                .rx_queues(cfg.nb_rxq)
                .rx_descs(cfg.nb_rxd)
                .tx_queues(cfg.nb_txq)
                .build(self.mempools[0].clone())?
        };
        let port = Arc::new(RwLock::new(port));
        self.ports.insert(cfg.pci.clone(), port.clone());
        Ok(port)
    }

    /// Unregisters a port. The device is detached from the EAL when the
    /// last `Arc` drops (so it can be attached again later); the caller
    /// must ensure no worker still holds one.
    pub(super) fn remove_port(&mut self, pci_addr: &str) -> Result<()> {
        let port = self
            .ports
            .remove(pci_addr)
            .with_context(|| format!("No port {pci_addr}"))?;
        port.write().unwrap().detach_on_drop();
        Ok(())
    }
}
