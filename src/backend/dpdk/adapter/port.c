#include "port.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <generic/rte_cycles.h>
#include <rte_dev.h>
#include <rte_ethdev.h>

static dpdk_port_t *dpdk_port_create(uint16_t port_id) {
        dpdk_port_t *p = calloc(1, sizeof(*p));
        if (!p) {
                return nullptr;
        }
        p->port_id = port_id;
        return p;
}

dpdk_port_t *dpdk_port_create_by_name(const char *name) {
        uint16_t port_id;
        if (rte_eth_dev_get_port_by_name(name, &port_id) != 0) {
                return nullptr;
        }
        return dpdk_port_create(port_id);
}

dpdk_port_t *dpdk_port_attach(const char *devargs) {
        uint16_t port_id;
        // Devices bound before EAL init are already probed; a device
        // detached earlier (dpdk_port_detach) must be probed again.
        if (rte_eth_dev_get_port_by_name(devargs, &port_id) == 0) {
                return dpdk_port_create(port_id);
        }
        if (rte_dev_probe(devargs) < 0) {
                return nullptr;
        }
        if (rte_eth_dev_get_port_by_name(devargs, &port_id) != 0) {
                return nullptr;
        }
        return dpdk_port_create(port_id);
}

int dpdk_port_detach(dpdk_port_t *p) {
        if (!p) {
                return -1;
        }
        // The device handle must be taken before close releases the
        // ethdev; it is needed to remove the device from the EAL so a
        // later dpdk_port_attach can probe it again.
        struct rte_eth_dev_info info;
        int ret = rte_eth_dev_info_get(p->port_id, &info);
        if (ret < 0) {
                free(p);
                return ret;
        }
        rte_eth_dev_stop(p->port_id);
        rte_eth_dev_close(p->port_id);
        ret = rte_dev_remove(info.device);
        free(p);
        return ret < 0 ? ret : 0;
}

void dpdk_port_destroy(dpdk_port_t *p) {
        if (!p) {
                return;
        }
        rte_eth_dev_stop(p->port_id);
        rte_eth_dev_close(p->port_id);
        free(p);
}

int dpdk_port_get_name(const dpdk_port_t *p, char *name) {
        return rte_eth_dev_get_name_by_port(p->port_id, name);
}

uint16_t dpdk_port_get_id(const dpdk_port_t *p) { return p->port_id; }

int dpdk_port_configure(
        dpdk_port_t *p,
        const uint16_t nb_rxq,
        const uint16_t nb_txq) {
        int ret;
        // TODO: Use NIC offload.
        const struct rte_eth_conf port_conf = {0};
        ret = rte_eth_dev_configure(p->port_id, nb_rxq, nb_txq, &port_conf);
        if (ret != 0) {
                return ret;
        }
        return 0;
}

int dpdk_port_start(dpdk_port_t *p) {
        int ret;

        ret = rte_eth_dev_start(p->port_id);
        if (ret != 0) {
                return ret;
        }
        ret = rte_eth_promiscuous_enable(p->port_id);
        if (ret != 0) {
                return ret;
        }

        return 0;
}

int dpdk_port_get_stats(const dpdk_port_t *p, dpdk_port_stats_t *out) {
        struct rte_eth_stats stats;
        const int ret = rte_eth_stats_get(p->port_id, &stats);
        if (ret < 0) {
                return ret;
        }
        out->rx_packets = stats.ipackets;
        out->tx_packets = stats.opackets;
        out->rx_bytes = stats.ibytes;
        out->tx_bytes = stats.obytes;
        out->rx_missed = stats.imissed;
        out->rx_errors = stats.ierrors;
        out->tx_errors = stats.oerrors;
        out->rx_nombuf = stats.rx_nombuf;
        return 0;
}

int dpdk_port_get_link(const dpdk_port_t *p, int *link_up) {
        struct rte_eth_link link;
        const int ret = rte_eth_link_get_nowait(p->port_id, &link);
        if (ret < 0) {
                return ret;
        }
        *link_up = link.link_status == RTE_ETH_LINK_UP;
        return 0;
}

int dpdk_port_wait_linkup(dpdk_port_t *p) {
        int ret;
        struct rte_eth_dev_info info;
        struct rte_eth_link link;

        for (int i = 0; i < 1000; i++) {
                ret = rte_eth_dev_info_get(p->port_id, &info);
                if (ret) return ret;
                ret = rte_eth_link_get(p->port_id, &link);
                if (ret) return ret;
                if (info.device != nullptr &&
                    link.link_status == RTE_ETH_LINK_UP) {
                        return 0;
                }
                rte_delay_ms(10);
        }
        return -1;
}
