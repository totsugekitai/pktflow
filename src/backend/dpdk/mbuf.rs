use std::{
    marker::PhantomData,
    mem::MaybeUninit,
    ops::{Index, IndexMut},
    slice::{from_raw_parts, from_raw_parts_mut},
};

use crate::backend::dpdk::ffi;

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mbuf {
    ptr: *mut ffi::dpdk_mbuf_t,
}

impl Mbuf {
    pub(super) fn as_ptr(&self) -> *mut ffi::dpdk_mbuf_t {
        self.ptr
    }

    pub fn len(&self) -> usize {
        unsafe { ffi::dpdk_mbuf_data_len(self.ptr) as usize }
    }

    pub fn data(&self) -> &[u8] {
        unsafe {
            let ptr = ffi::dpdk_mbuf_data(self.ptr) as *const u8;
            from_raw_parts(ptr, self.len())
        }
    }

    #[allow(unused)]
    pub fn data_mut(&mut self) -> &mut [u8] {
        unsafe {
            let ptr = ffi::dpdk_mbuf_data(self.ptr) as *mut u8;
            from_raw_parts_mut(ptr, self.len())
        }
    }

    pub fn append(&mut self, len: usize) -> Option<&mut [u8]> {
        unsafe {
            let ptr = ffi::dpdk_mbuf_append(self.ptr, len as u16);
            if ptr.is_null() {
                None
            } else {
                Some(from_raw_parts_mut(ptr as *mut u8, len))
            }
        }
    }
}

#[derive(Debug)]
pub struct MbufBurst<const N: usize> {
    pub(super) ptrs: [MaybeUninit<Mbuf>; N],
    start: usize,
    len: usize,
}

impl<const N: usize> MbufBurst<N> {
    pub fn new() -> Self {
        Self {
            ptrs: [MaybeUninit::uninit(); N],
            start: 0,
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(super) fn as_mut_ptr(&mut self) -> *mut *mut ffi::dpdk_mbuf_t {
        unsafe { self.ptrs.as_mut_ptr().add(self.start).cast() }
    }

    pub(super) fn set_len(&mut self, n: usize) {
        self.len = n;
    }

    /// Marks the first `n` mbufs as consumed by DPDK (they must not be freed on Drop).
    pub(super) fn consume(&mut self, n: usize) {
        self.start += n;
        self.len -= n;
    }

    #[allow(unused)]
    pub fn iter(&self) -> Iter<'_, N> {
        Iter {
            burst: self,
            index: 0,
        }
    }

    pub fn iter_mut(&mut self) -> IterMut<'_> {
        let ptr = unsafe { self.ptrs.as_mut_ptr().add(self.start).cast::<Mbuf>() };
        IterMut {
            current: ptr,
            end: unsafe { ptr.add(self.len) },
            _marker: PhantomData,
        }
    }
}

impl<const N: usize> Drop for MbufBurst<N> {
    fn drop(&mut self) {
        for i in 0..self.len {
            let idx = self.start + i;
            unsafe {
                let ptr = self.ptrs[idx].assume_init_ref();
                ffi::dpdk_mbuf_free(ptr.ptr);
            }
        }
    }
}

impl<const N: usize> Index<usize> for MbufBurst<N> {
    type Output = Mbuf;

    fn index(&self, index: usize) -> &Self::Output {
        assert!(index < self.len);
        let idx = self.start + index;
        unsafe { self.ptrs[idx].assume_init_ref() }
    }
}

impl<const N: usize> IndexMut<usize> for MbufBurst<N> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        assert!(index < self.len);
        let idx = self.start + index;
        unsafe { self.ptrs[idx].assume_init_mut() }
    }
}

#[allow(unused)]
pub struct Iter<'a, const N: usize> {
    burst: &'a MbufBurst<N>,
    index: usize,
}

impl<'a, const N: usize> Iterator for Iter<'a, N> {
    type Item = &'a Mbuf;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.burst.len {
            return None;
        }
        let ptr = &self.burst[self.index];
        self.index += 1;
        Some(ptr)
    }
}

pub struct IterMut<'a> {
    current: *mut Mbuf,
    end: *mut Mbuf,
    _marker: PhantomData<&'a mut Mbuf>,
}

impl<'a> Iterator for IterMut<'a> {
    type Item = &'a mut Mbuf;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current == self.end {
            return None;
        }
        let ptr = self.current;
        self.current = unsafe { self.current.add(1) };
        Some(unsafe { &mut *ptr })
    }
}
