#include "pcapng.h"

#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

#include <rte_pcapng.h>

#include "mbuf.h"
#include "mempool.h"

dpdk_pcapng_t *dpdk_pcapng_fdopen(int fd, const char *appname) {
        struct dpdk_pcapng *p = calloc(1, sizeof(*p));
        if (!p) {
                return nullptr;
        }

        p->pcapng = rte_pcapng_fdopen(fd, nullptr, nullptr, appname, nullptr);
        if (!p->pcapng) {
                free(p);
                return nullptr;
        }

        return p;
}

void dpdk_pcapng_close(dpdk_pcapng_t *p) {
        if (!p) {
                return;
        }
        if (p->pcapng) {
                rte_pcapng_close(p->pcapng);
        }
        free(p);
}

int dpdk_pcapng_add_interface(dpdk_pcapng_t *p, uint16_t port_id) {
        return rte_pcapng_add_interface(
                p->pcapng, port_id, DLT_EN10MB, nullptr, nullptr, nullptr);
}

uint32_t dpdk_pcapng_mbuf_size(uint32_t length) {
        return rte_pcapng_mbuf_size(length);
}

dpdk_mbuf_t *dpdk_pcapng_copy_rx(
        uint16_t port_id,
        uint16_t queue_id,
        const dpdk_mbuf_t *m,
        dpdk_mempool_t *pool,
        uint32_t snaplen) {
        return (dpdk_mbuf_t *)rte_pcapng_copy(
                port_id, queue_id, &m->m, pool->mp, snaplen,
                RTE_PCAPNG_DIRECTION_IN, nullptr);
}

ssize_t dpdk_pcapng_write_packets(
        dpdk_pcapng_t *p,
        dpdk_mbuf_t **pkts,
        uint16_t nb_pkts) {
        return rte_pcapng_write_packets(
                p->pcapng, (struct rte_mbuf **)pkts, nb_pkts);
}

ssize_t dpdk_pcapng_write_stats(
        dpdk_pcapng_t *p,
        uint16_t port_id,
        uint64_t ifrecv,
        uint64_t ifdrop) {
        return rte_pcapng_write_stats(
                p->pcapng, port_id, ifrecv, ifdrop, nullptr);
}
