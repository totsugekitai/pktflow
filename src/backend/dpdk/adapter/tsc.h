#ifndef PKTFLOW_TSC_H
#define PKTFLOW_TSC_H

#include <stdint.h>

uint64_t dpdk_rdtsc(void);
uint64_t dpdk_tsc_get_hz(void);

#endif
