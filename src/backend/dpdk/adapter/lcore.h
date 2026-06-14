#ifndef PKTFLOW_LCORE_H
#define PKTFLOW_LCORE_H

#include <stdint.h>

typedef int (*dpdk_lcore_fn_t)(void *);

unsigned int dpdk_lcore_main_id(void);
unsigned int dpdk_lcore_id(void);
uint32_t dpdk_lcore_next(uint32_t current);
int dpdk_lcore_launch(unsigned int lcore_id, dpdk_lcore_fn_t fn, void *arg);
int dpdk_lcore_wait(unsigned int lcore_id);

#endif
