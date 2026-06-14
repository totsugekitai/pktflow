use std::{
    ffi::CString,
    ptr::NonNull,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Error, Result};

use crate::backend::dpdk::{ffi, mbuf::MbufBurst};

pub struct Mempool {
    pub(super) ptr: NonNull<ffi::dpdk_mempool_t>,
}

impl Mempool {
    pub(super) fn new(
        name: &str,
        nb_mbufs: u32,
        cache_size: u32,
        data_room_size: u16,
    ) -> Result<Arc<Mutex<Self>>> {
        let cname = CString::new(name).context("Mempool name contains null byte")?;
        let ptr = unsafe {
            ffi::dpdk_mempool_create(cname.as_ptr(), nb_mbufs, cache_size, data_room_size)
        };
        let ptr = NonNull::new(ptr).ok_or_else(|| {
            // A duplicate name yields EEXIST, exhausted hugepages ENOMEM.
            let errno = unsafe { ffi::dpdk_rte_errno() };
            Error::msg(format!(
                "Failed to create mempool {name} ({nb_mbufs} mbufs of {data_room_size} bytes): {}",
                std::io::Error::from_raw_os_error(errno)
            ))
        })?;
        Ok(Arc::new(Mutex::new(Mempool { ptr })))
    }

    pub(super) fn alloc_bulk<const N: usize>(
        &mut self,
        burst: &mut MbufBurst<N>,
        count: usize,
    ) -> Result<()> {
        assert!(count <= N);
        let st = unsafe {
            ffi::dpdk_mempool_alloc_bulk(self.ptr.as_ptr(), burst.as_mut_ptr(), count as u32)
        };
        if st != 0 {
            Err(Error::msg("Failed to allocate pktmbuf bulk."))
        } else {
            burst.set_len(count);
            Ok(())
        }
    }
}

impl Drop for Mempool {
    fn drop(&mut self) {
        unsafe {
            ffi::dpdk_mempool_free(self.ptr.as_ptr());
        }
    }
}

// DPDK mempool objects are safe to share across lcores via Arc.
unsafe impl Send for Mempool {}
unsafe impl Sync for Mempool {}
