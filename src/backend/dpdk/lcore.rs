use tracing::debug;

use crate::backend::dpdk::ffi;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Lcore {
    id: u32,
}

impl Lcore {
    pub fn new(id: u32) -> Self {
        Self { id }
    }

    pub fn id(&self) -> u32 {
        self.id
    }
}

pub struct LcoreManager {
    #[allow(unused)]
    main_id: Lcore,
    availables: Vec<Lcore>,
}

impl LcoreManager {
    pub fn new(lcores: &[u32]) -> Self {
        let main_id = Lcore::new(unsafe { ffi::dpdk_lcore_main_id() });
        let availables = lcores
            .iter()
            .copied()
            .map(Lcore::new)
            .filter(|x| *x != main_id)
            .collect();
        debug!("available lcores: {availables:?}");
        Self {
            main_id,
            availables,
        }
    }

    pub fn distribute(&mut self) -> Option<Lcore> {
        self.availables.pop()
    }

    /// Returns a distributed lcore to the pool. Only call after the
    /// worker on it has been waited on, so the lcore is idle again.
    pub fn release(&mut self, lcore: Lcore) {
        debug_assert!(!self.availables.contains(&lcore));
        self.availables.push(lcore);
    }
}
