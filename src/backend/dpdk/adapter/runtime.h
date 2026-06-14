#ifndef PKTFLOW_RUNTIME_H
#define PKTFLOW_RUNTIME_H

typedef struct dpdk_runtime {
        bool initialized;
} dpdk_runtime_t;

dpdk_runtime_t *dpdk_runtime_create(int argc, char **argv);
void dpdk_runtime_destroy(dpdk_runtime_t *rt);
int dpdk_rte_errno(void);

#endif
