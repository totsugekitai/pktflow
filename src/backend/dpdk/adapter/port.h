#ifndef PKTFLOW_PORT_H
#define PKTFLOW_PORT_H

#include <stdint.h>

#include <rte_config.h>

typedef struct dpdk_port {
        uint16_t port_id;
} dpdk_port_t;

// Hardware-level counters of one port, cumulative since port start.
typedef struct dpdk_port_stats {
        uint64_t rx_packets;
        uint64_t tx_packets;
        uint64_t rx_bytes;
        uint64_t tx_bytes;
        uint64_t rx_missed;
        uint64_t rx_errors;
        uint64_t tx_errors;
        uint64_t rx_nombuf;
} dpdk_port_stats_t;

dpdk_port_t *dpdk_port_create_by_name(const char *name);
dpdk_port_t *dpdk_port_attach(const char *devargs);
int dpdk_port_detach(dpdk_port_t *p);
void dpdk_port_destroy(dpdk_port_t *p);
int dpdk_port_get_name(const dpdk_port_t *p, char *name);
uint16_t dpdk_port_get_id(const dpdk_port_t *p);
int dpdk_port_configure(
        dpdk_port_t *p,
        const uint16_t nb_rxq,
        const uint16_t nb_txq);
int dpdk_port_start(dpdk_port_t *p);
int dpdk_port_get_link(const dpdk_port_t *p, int *link_up);
int dpdk_port_wait_linkup(dpdk_port_t *p);
int dpdk_port_get_stats(const dpdk_port_t *p, dpdk_port_stats_t *stats);

#endif
