#include "lcore.h"

#include <stdint.h>

#include <rte_launch.h>
#include <rte_lcore.h>

unsigned int dpdk_lcore_main_id(void) { return rte_get_main_lcore(); }

unsigned int dpdk_lcore_id(void) { return rte_lcore_id(); }

uint32_t dpdk_lcore_next(uint32_t current) {
        return rte_get_next_lcore(current, 1, 0);
}
int dpdk_lcore_launch(unsigned int lcore_id, dpdk_lcore_fn_t fn, void *arg) {
        return rte_eal_remote_launch(fn, arg, lcore_id);
}

int dpdk_lcore_wait(unsigned int lcore_id) {
        return rte_eal_wait_lcore(lcore_id);
}
