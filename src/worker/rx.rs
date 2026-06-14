use std::sync::{Arc, RwLock};

use tracing::{debug, error, info, trace};

use crate::{
    backend::{Port, Worker},
    proto::dump,
    signal,
    worker::{StopFlag, stats::PortCounters},
};

pub struct RxWorker<P: Port> {
    port: Arc<RwLock<P>>,
    stop: StopFlag,
    counters: Arc<PortCounters>,
}

impl<P: Port> RxWorker<P> {
    pub fn new(port: Arc<RwLock<P>>, stop: StopFlag, counters: Arc<PortCounters>) -> Self {
        Self {
            port,
            stop,
            counters,
        }
    }
}

impl<P: Port> Worker for RxWorker<P> {
    fn run(&self) {
        debug!("Rx worker running.");
        let mut total_recv = 0;
        let mut f = true;
        // Receive until Ctrl-C or the owning task requests a shutdown.
        while !signal::sigint_received() && !self.stop.is_signaled() {
            let mut bytes: u64 = 0;
            let nb_recv = self.port.write().unwrap().recv_frames(&mut |frame| {
                bytes += frame.len() as u64;
                // Formatting and forwarding every frame is expensive, so the
                // dump is gated behind its own target: when the filter leaves
                // it disabled, format_frame is never evaluated and nothing is
                // sent to the log worker. Enable with
                // RUST_LOG=info,pktflow::packet=trace.
                trace!(
                    target: "pktflow::packet",
                    "Received\n{}",
                    dump::format_frame(frame)
                );
            });
            match nb_recv {
                Ok(0) => {
                    if f {
                        trace!("Recv 0 frames.");
                        f = false;
                    }
                }
                Ok(nb_recv) => {
                    f = true;
                    trace!("Recv {nb_recv} frames.");
                    total_recv += nb_recv;
                    self.counters.add_rx(nb_recv as u64, bytes);
                }
                Err(e) => {
                    error!("Error while Rx {e:x?}");
                }
            }
        }
        info!("Rx completed! ({total_recv} frames received)");
    }
}
