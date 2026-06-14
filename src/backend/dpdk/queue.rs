use std::{marker::PhantomData, ptr::NonNull};

use anyhow::{Error, Result};

use crate::backend::dpdk::{ffi, mbuf::MbufBurst, mempool::Mempool};

pub(super) struct UnSetup;
pub(super) struct Setup;

pub struct RxQueue<S> {
    pub(super) ptr: NonNull<ffi::dpdk_rx_queue_t>,
    state: PhantomData<S>,
    setup: bool,
}

pub struct TxQueue<S> {
    pub(super) ptr: NonNull<ffi::dpdk_tx_queue_t>,
    state: PhantomData<S>,
    setup: bool,
}

impl RxQueue<UnSetup> {
    pub unsafe fn new(port_id: u16, queue_id: u16) -> Self {
        let q = unsafe { ffi::dpdk_rx_queue_create(port_id, queue_id) };
        Self {
            ptr: NonNull::new(q).unwrap(),
            state: PhantomData,
            setup: false,
        }
    }

    pub unsafe fn setup(
        self,
        pktmbuf_pool: &mut Mempool,
        nb_rx_desc: u16,
    ) -> Result<RxQueue<Setup>> {
        let mp = pktmbuf_pool.ptr.as_ptr();
        let ret = unsafe { ffi::dpdk_rx_queue_setup(self.ptr.as_ptr(), mp, nb_rx_desc) };
        if ret != 0 {
            return Err(Error::msg(format!(
                "Failed to setup rx queue with {nb_rx_desc} descriptors ({ret})"
            )));
        }
        Ok(RxQueue {
            ptr: self.ptr,
            state: PhantomData,
            setup: true,
        })
    }
}

impl RxQueue<Setup> {
    pub fn rx_burst<const N: usize>(&mut self, burst: &mut MbufBurst<N>) -> u16 {
        let q = self.ptr.as_ptr();
        let nb_recv = unsafe { ffi::dpdk_rx_queue_burst(q, burst.as_mut_ptr(), N as u16) };
        burst.set_len(nb_recv as usize);
        nb_recv
    }
}

impl<S> Drop for RxQueue<S> {
    fn drop(&mut self) {
        if self.setup {
            unsafe {
                ffi::dpdk_rx_queue_destroy(self.ptr.as_ptr());
            }
        }
    }
}

impl TxQueue<UnSetup> {
    pub unsafe fn new(port_id: u16, queue_id: u16) -> Self {
        let q = unsafe { ffi::dpdk_tx_queue_create(port_id, queue_id) };
        Self {
            ptr: NonNull::new(q).unwrap(),
            state: PhantomData,
            setup: false,
        }
    }

    pub unsafe fn setup(self) -> TxQueue<Setup> {
        unsafe {
            ffi::dpdk_tx_queue_setup(self.ptr.as_ptr());
        }
        TxQueue {
            ptr: self.ptr,
            state: PhantomData,
            setup: true,
        }
    }
}

impl TxQueue<Setup> {
    pub fn tx_burst<const N: usize>(&mut self, burst: &mut MbufBurst<N>) {
        let q = self.ptr.as_ptr();
        let nb_sent =
            unsafe { ffi::dpdk_tx_queue_burst(q, burst.as_mut_ptr(), burst.len() as u16) };
        burst.consume(nb_sent as usize);
    }
}
impl<S> Drop for TxQueue<S> {
    fn drop(&mut self) {
        if self.setup {
            unsafe {
                ffi::dpdk_tx_queue_destroy(self.ptr.as_ptr());
            }
        }
    }
}
