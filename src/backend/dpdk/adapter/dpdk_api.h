#ifndef PKTFLOW_DPDK_API_H
#define PKTFLOW_DPDK_API_H

#include <stdint.h>
#include <sys/types.h>

typedef int (*dpdk_lcore_fn_t)(void *);
typedef struct dpdk_mempool dpdk_mempool_t;
typedef struct dpdk_port dpdk_port_t;
typedef struct dpdk_runtime dpdk_runtime_t;
typedef struct dpdk_rx_queue dpdk_rx_queue_t;
typedef struct dpdk_tx_queue dpdk_tx_queue_t;
typedef struct dpdk_mbuf dpdk_mbuf_t;
typedef struct dpdk_pcapng dpdk_pcapng_t;

// Hardware-level counters of one port, cumulative since port start.
// Unlike the opaque handles above, the layout is public so that callers
// can read the fields directly.
typedef struct dpdk_port_stats {
        uint64_t rx_packets;
        uint64_t tx_packets;
        uint64_t rx_bytes;
        uint64_t tx_bytes;
        // Frames dropped by the NIC because the rx queues were full.
        uint64_t rx_missed;
        uint64_t rx_errors;
        uint64_t tx_errors;
        // Rx failures caused by mbuf allocation (mempool exhausted).
        uint64_t rx_nombuf;
} dpdk_port_stats_t;

// DPDK lcore
unsigned int dpdk_lcore_main_id(void);
int dpdk_lcore_launch(unsigned int lcore_id, dpdk_lcore_fn_t fn, void *arg);
int dpdk_lcore_wait(unsigned int lcore_id);

// Mempool
dpdk_mempool_t *dpdk_mempool_create(
        const char *name,
        const uint32_t num_mbufs,
        const uint32_t cache_size,
        const uint16_t data_room_size);
void dpdk_mempool_free(dpdk_mempool_t *pool);
int dpdk_mempool_alloc_bulk(
        dpdk_mempool_t *pool,
        dpdk_mbuf_t **mbufs,
        unsigned int count);

// Port
// dpdk_port_t *dpdk_port_create_by_name(const char *name);
dpdk_port_t *dpdk_port_attach(const char *devargs);
int dpdk_port_detach(dpdk_port_t *p);
void dpdk_port_destroy(dpdk_port_t *p);
uint16_t dpdk_port_get_id(const dpdk_port_t *p);
int dpdk_port_configure(
        dpdk_port_t *p,
        const uint16_t nb_rxq,
        const uint16_t nb_txq);
int dpdk_port_start(dpdk_port_t *p);
// Reads the link status without waiting for negotiation; *link_up is
// set to 1 when the link is up, 0 otherwise.
int dpdk_port_get_link(const dpdk_port_t *p, int *link_up);
// Forces the link administratively up or down (up != 0 means up).
// Not every PHY/driver supports this; unsupported returns a negative
// DPDK errno.
int dpdk_port_set_link(dpdk_port_t *p, int up);
int dpdk_port_wait_linkup(dpdk_port_t *p);
int dpdk_port_get_stats(const dpdk_port_t *p, dpdk_port_stats_t *stats);

// Runtime
dpdk_runtime_t *dpdk_runtime_create(int argc, char **argv);
void dpdk_runtime_destroy(dpdk_runtime_t *rt);
// The per-lcore rte_errno left by the last failed DPDK call.
int dpdk_rte_errno(void);

// Rx Queue
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

// Tx Queue
dpdk_tx_queue_t *dpdk_tx_queue_create(
        const uint16_t port_id,
        const uint16_t queue_id);
int dpdk_tx_queue_setup(dpdk_tx_queue_t *q);
void dpdk_tx_queue_destroy(dpdk_tx_queue_t *q);
uint16_t dpdk_tx_queue_burst(
        dpdk_tx_queue_t *q,
        dpdk_mbuf_t **pkts,
        const uint16_t nb_pkts);

// DPDK mbuf
// uint32_t dpdk_mbuf_pkt_len(dpdk_mbuf_t *m);
void *dpdk_mbuf_data(dpdk_mbuf_t *m);
uint16_t dpdk_mbuf_data_len(dpdk_mbuf_t *m);
char *dpdk_mbuf_append(dpdk_mbuf_t *m, uint16_t len);
void dpdk_mbuf_free(dpdk_mbuf_t *m);

// TSC
uint64_t dpdk_rdtsc(void);
uint64_t dpdk_tsc_get_hz(void);

// pcapng capture
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
