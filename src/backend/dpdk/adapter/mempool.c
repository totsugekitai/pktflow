#include "mempool.h"

#include <stdint.h>
#include <stdlib.h>

#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mbuf_core.h>
#include <rte_mempool.h>

#include "mbuf.h"

dpdk_mempool_t *dpdk_mempool_create(
        const char *name,
        uint32_t num_mbufs,
        uint32_t cache_size,
        uint16_t data_room_size) {
        struct dpdk_mempool *pool = calloc(1, sizeof(*pool));
        if (!pool) {
                return nullptr;
        }

        pool->mp = rte_pktmbuf_pool_create(
                name, num_mbufs, cache_size, 0, data_room_size,
                (int)rte_socket_id());
        if (!pool->mp) {
                free(pool);
                return nullptr;
        }

        return pool;
}

void dpdk_mempool_free(dpdk_mempool_t *pool) {
        if (!pool) {
                return;
        }
        if (pool->mp) {
                rte_mempool_free(pool->mp);
        }
        free(pool);
}

int dpdk_mempool_alloc_bulk(
        dpdk_mempool_t *pool,
        dpdk_mbuf_t **mbufs,
        unsigned int count) {
        return rte_pktmbuf_alloc_bulk(
                pool->mp, (struct rte_mbuf **)mbufs, count);
}
