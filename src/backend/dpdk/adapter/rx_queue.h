#ifndef PKTFLOW_RX_QUEUE_H
#define PKTFLOW_RX_QUEUE_H

#include <stdint.h>

#include "mbuf.h"
#include "mempool.h"

typedef struct dpdk_rx_queue {
        uint16_t port_id;
        uint16_t queue_id;
} dpdk_rx_queue_t;

dpdk_rx_queue_t *dpdk_rx_queue_create(
        const uint16_t port_id,
        const uint16_t queue_id);
int dpdk_rx_queue_setup(
        dpdk_rx_queue_t *q,
        dpdk_mempool_t *pool,
        const uint16_t nb_rx_desc);
void dpdk_rx_queue_destroy(dpdk_rx_queue_t *q);
uint16_t dpdk_rx_queue_burst(
        dpdk_rx_queue_t *q,
        dpdk_mbuf_t **pkts,
        const uint16_t nb_pkts);
uint16_t dpdk_rx_queue_id(const dpdk_rx_queue_t *q);

#endif
