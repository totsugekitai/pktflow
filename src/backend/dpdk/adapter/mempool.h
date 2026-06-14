#ifndef PKTFLOW_MEMPOOL_H
#define PKTFLOW_MEMPOOL_H

#include <sys/types.h>

#include <rte_mempool.h>

#include "mbuf.h"

typedef struct dpdk_mempool {
        struct rte_mempool *mp;
} dpdk_mempool_t;

dpdk_mempool_t *dpdk_mempool_create(
        const char *name,
        const uint32_t num_mbufs,
        const uint32_t cache_size,
        const uint16_t data_room_size);
void dpdk_mempool_free(dpdk_mempool_t *pool);
int dpdk_mempool_alloc_bulk(
        dpdk_mempool_t *pool,
        dpdk_mbuf_t **mbufs,
        unsigned int count);

#endif
