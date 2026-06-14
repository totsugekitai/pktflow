#ifndef PKTFLOW_MBUF_H
#define PKTFLOW_MBUF_H

#include <stdint.h>

#include <rte_mbuf_core.h>

typedef struct dpdk_mbuf {
        struct rte_mbuf m;
} dpdk_mbuf_t;

uint32_t dpdk_mbuf_pkt_len(dpdk_mbuf_t *m);
void *dpdk_mbuf_data(dpdk_mbuf_t *m);
uint16_t dpdk_mbuf_data_len(dpdk_mbuf_t *m);
char *dpdk_mbuf_append(dpdk_mbuf_t *m, uint16_t len);
dpdk_mbuf_t *dpdk_mbuf_next(dpdk_mbuf_t *m);
void dpdk_mbuf_free(dpdk_mbuf_t *m);

#endif
