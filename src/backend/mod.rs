use std::sync::{Arc, RwLock};

use anyhow::Result;
use serde::Serialize;

pub mod dpdk;

/// Hardware-level counters of one port as reported by the backend
/// (`rte_eth_stats` for DPDK). Values are cumulative since port start.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct PortStats {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// Frames dropped by the NIC because the rx queues were full.
    pub rx_missed: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    /// Rx failures caused by mbuf allocation (mempool exhausted).
    pub rx_nombuf: u64,
}

/// A network port abstracted at the frame level. All backend-specific
/// buffer management (mempool, mbuf, burst) stays inside the implementation.
pub trait Port: Send + Sync {
    fn start(&mut self) -> Result<()>;
    fn wait_linkup(&self) -> Result<()>;
    /// Reads the current link status without waiting for negotiation.
    /// Safe to call from any thread while workers are polling the port.
    fn link_up(&self) -> Result<bool>;
    /// Forces the link administratively up or down. Not every PHY/driver
    /// supports this.
    fn set_link(&mut self, up: bool) -> Result<()>;
    /// Sends the given frames onto the wire.
    fn send_frames(&mut self, frames: &[&[u8]]) -> Result<()>;
    /// Polls once for received frames and invokes `on_frame` for each.
    /// Returns the number of frames received.
    fn recv_frames(&mut self, on_frame: &mut dyn FnMut(&[u8])) -> Result<usize>;
    /// Reads the hardware counters. Safe to call from any thread while
    /// workers are polling the port.
    fn stats(&self) -> Result<PortStats>;
}

/// A unit of work executed on a backend-provided execution context
/// (a DPDK lcore, an OS thread, ...).
pub trait Worker: Send {
    fn run(&self);
}

/// A packet I/O backend. `name` identifies a port in backend-specific
/// notation (a PCI address for DPDK).
pub trait Backend {
    type Port: Port + 'static;
    /// Identifies a spawned worker so it can be waited on individually
    /// (an lcore for DPDK, a join handle for OS threads, ...).
    type Handle: Copy;

    fn port(&self, name: &str) -> Option<Arc<RwLock<Self::Port>>>;
    fn spawn<W: Worker + 'static>(&mut self, worker: W) -> Result<Self::Handle>;
    /// Blocks until the worker identified by `handle` has finished.
    fn wait(&self, handle: Self::Handle);
}
