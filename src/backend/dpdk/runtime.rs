use std::{
    ffi::{CString, c_char},
    ptr::NonNull,
    sync::Arc,
};

use anyhow::{Context as aContext, Result};

use crate::backend::dpdk::ffi;

#[derive(Debug)]
pub struct Runtime {
    ptr: NonNull<ffi::dpdk_runtime_t>,
}

impl Runtime {
    pub fn new(eal_args: &[String]) -> Result<Arc<Self>> {
        let c_strings: Vec<CString> = eal_args
            .iter()
            .map(|s| CString::new(s.as_str()).unwrap())
            .collect();
        let mut c_ptrs: Vec<*mut c_char> = c_strings
            .iter()
            .map(|cs| cs.as_ptr() as *mut c_char)
            .collect();
        c_ptrs.push(std::ptr::null_mut());
        let argv = c_ptrs.as_mut_ptr();
        let rt = unsafe { ffi::dpdk_runtime_create(eal_args.len() as i32, argv) };
        let p = NonNull::new(rt).context("DPDK runtime null pointer")?;

        Ok(Arc::new(Self { ptr: p }))
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        unsafe {
            ffi::dpdk_runtime_destroy(self.ptr.as_ptr());
        }
    }
}

// DPDK runtime is initialized once and safe to reference across lcores via Arc.
unsafe impl Send for Runtime {}
unsafe impl Sync for Runtime {}
