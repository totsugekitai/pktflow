#ifndef PKTFLOW_TX_QUEUE_H
#define PKTFLOW_TX_QUEUE_H

#include <stdint.h>

#include "mbuf.h"

typedef struct dpdk_tx_queue {
        uint16_t port_id;
        uint16_t queue_id;
} dpdk_tx_queue_t;

dpdk_tx_queue_t *dpdk_tx_queue_create(
        const uint16_t port_id,
        const uint16_t queue_id);
int dpdk_tx_queue_setup(dpdk_tx_queue_t *q);
void dpdk_tx_queue_destroy(dpdk_tx_queue_t *q);
uint16_t dpdk_tx_queue_burst(
        dpdk_tx_queue_t *q,
        dpdk_mbuf_t **pkts,
        const uint16_t nb_pkts);
uint16_t dpdk_tx_queue_id(const dpdk_tx_queue_t *q);

#endif
