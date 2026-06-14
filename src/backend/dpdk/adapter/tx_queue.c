#include "tx_queue.h"

#include <stdint.h>
#include <stdlib.h>

#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf_core.h>

#include "mbuf.h"

dpdk_tx_queue_t *dpdk_tx_queue_create(
        const uint16_t port_id,
        const uint16_t queue_id) {
        dpdk_tx_queue_t *q = calloc(1, sizeof(*q));
        if (!q) {
                return nullptr;
        }
        q->port_id = port_id;
        q->queue_id = queue_id;
        return q;
}

int dpdk_tx_queue_setup(dpdk_tx_queue_t *q) {
        return rte_eth_tx_queue_setup(
                q->port_id, q->queue_id, 1024, rte_socket_id(), nullptr);
}

void dpdk_tx_queue_destroy(dpdk_tx_queue_t *q) {
        if (!q) {
                return;
        }
        free(q);
}

uint16_t dpdk_tx_queue_burst(
        dpdk_tx_queue_t *q,
        dpdk_mbuf_t **pkts,
        const uint16_t nb_pkts) {
        return rte_eth_tx_burst(
                q->port_id, q->queue_id, (struct rte_mbuf **)pkts, nb_pkts);
}

uint16_t dpdk_tx_queue_id(const dpdk_tx_queue_t *q) { return q->queue_id; }
