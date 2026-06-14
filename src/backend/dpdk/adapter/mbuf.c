#include "mbuf.h"

#include <stdint.h>

#include <rte_mbuf.h>
#include <rte_mbuf_core.h>

static inline struct rte_mbuf *to_rte_mbuf(dpdk_mbuf_t *m) {
        return (struct rte_mbuf *)m;
}

static inline dpdk_mbuf_t *from_rte_mbuf(struct rte_mbuf *r) {
        return (dpdk_mbuf_t *)r;
}

uint32_t dpdk_mbuf_pkt_len(dpdk_mbuf_t *m) {
        return rte_pktmbuf_pkt_len(to_rte_mbuf(m));
}

void *dpdk_mbuf_data(dpdk_mbuf_t *m) {
        return rte_pktmbuf_mtod(to_rte_mbuf(m), void *);
}

uint16_t dpdk_mbuf_data_len(dpdk_mbuf_t *m) {
        return rte_pktmbuf_data_len(to_rte_mbuf(m));
}

char *dpdk_mbuf_append(dpdk_mbuf_t *m, uint16_t len) {
        return rte_pktmbuf_append(to_rte_mbuf(m), len);
}

dpdk_mbuf_t *dpdk_mbuf_next(dpdk_mbuf_t *m) {
        if (!m) {
                return nullptr;
        }
        return from_rte_mbuf(to_rte_mbuf(m)->next);
}

void dpdk_mbuf_free(dpdk_mbuf_t *m) {
        if (!m) {
                return;
        }
        rte_pktmbuf_free(to_rte_mbuf(m));
}
