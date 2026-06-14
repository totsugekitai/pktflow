#include "runtime.h"

#include <stdlib.h>

#include <rte_eal.h>
#include <rte_errno.h>

dpdk_runtime_t *dpdk_runtime_create(int argc, char **argv) {
        dpdk_runtime_t *rt = calloc(1, sizeof(*rt));
        if (!rt) {
                return nullptr;
        }
        int ret = rte_eal_init(argc, argv);
        if (ret < 0) {
                free(rt);
                return nullptr;
        }
        rt->initialized = true;

        return rt;
}

int dpdk_rte_errno(void) { return rte_errno; }

void dpdk_runtime_destroy(dpdk_runtime_t *rt) {
        if (!rt) {
                return;
        }
        if (rt->initialized) {
                rte_eal_cleanup();
        }
        free(rt);
}
