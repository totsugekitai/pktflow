#include "rx_queue.h"

#include <stdint.h>
#include <stdlib.h>

#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf_core.h>

#include "mbuf.h"
#include "mempool.h"

dpdk_rx_queue_t *dpdk_rx_queue_create(
        const uint16_t port_id,
        const uint16_t queue_id) {
        dpdk_rx_queue_t *q = calloc(1, sizeof(*q));
        if (!q) {
                return nullptr;
        }
        q->port_id = port_id;
        q->queue_id = queue_id;
        return q;
}

int dpdk_rx_queue_setup(
        dpdk_rx_queue_t *q,
        dpdk_mempool_t *pool,
        const uint16_t nb_rx_desc) {
        return rte_eth_rx_queue_setup(
                q->port_id, q->queue_id, nb_rx_desc, rte_socket_id(), nullptr,
                pool->mp);
}

void dpdk_rx_queue_destroy(dpdk_rx_queue_t *q) {
        if (!q) {
                return;
        }
        free(q);
}

uint16_t dpdk_rx_queue_burst(
        dpdk_rx_queue_t *q,
        dpdk_mbuf_t **pkts,
        const uint16_t nb_pkts) {
        return rte_eth_rx_burst(
                q->port_id, q->queue_id, (struct rte_mbuf **)pkts, nb_pkts);
}

uint16_t dpdk_rx_queue_id(const dpdk_rx_queue_t *q) { return q->queue_id; }
