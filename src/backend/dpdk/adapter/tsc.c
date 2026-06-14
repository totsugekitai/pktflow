#include <stdint.h>

#include <generic/rte_cycles.h>
#include <rte_cycles.h>

uint64_t dpdk_rdtsc(void) { return rte_rdtsc(); }

uint64_t dpdk_tsc_get_hz(void) { return rte_get_tsc_hz(); }
