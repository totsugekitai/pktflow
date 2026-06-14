#ifndef PKTFLOW_PCAPNG_H
#define PKTFLOW_PCAPNG_H

#include <stdint.h>
#include <sys/types.h>

#include <rte_pcapng.h>

#include "mbuf.h"
#include "mempool.h"

typedef struct dpdk_pcapng {
        rte_pcapng_t *pcapng;
} dpdk_pcapng_t;

dpdk_pcapng_t *dpdk_pcapng_fdopen(int fd, const char *appname);
void dpdk_pcapng_close(dpdk_pcapng_t *p);
int dpdk_pcapng_add_interface(dpdk_pcapng_t *p, uint16_t port_id);
uint32_t dpdk_pcapng_mbuf_size(uint32_t length);
dpdk_mbuf_t *dpdk_pcapng_copy_rx(
        uint16_t port_id,
        uint16_t queue_id,
        const dpdk_mbuf_t *m,
        dpdk_mempool_t *pool,
        uint32_t snaplen);
ssize_t dpdk_pcapng_write_packets(
        dpdk_pcapng_t *p,
        dpdk_mbuf_t **pkts,
        uint16_t nb_pkts);
ssize_t dpdk_pcapng_write_stats(
        dpdk_pcapng_t *p,
        uint16_t port_id,
        uint64_t ifrecv,
        uint64_t ifdrop);

#endif
