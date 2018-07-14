#ifndef LCORE_CONF__INCLUE
#define LCORE_CONF__INCLUE
#include <stdint.h>
#include <rte_common.h>
#include <rte_vect.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_string_fns.h>
#include <rte_cpuflags.h>
#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16
#define MAX_LCORE_PARAMS 1024

struct lcore_params {
	   uint8_t port_id;
	   uint8_t queue_id;
	   uint8_t lcore_id;
} __rte_cache_aligned;

struct port_queue{
	uint8_t rx_port_id;
	uint8_t rx_queue_id;
	uint8_t tx_port_id;
	uint8_t tx_queue_id;
} __rte_cache_aligned;

struct lcore_conf {
	uint16_t length;
	struct port_queue port_queue_list[MAX_RX_QUEUE_PER_LCORE];
    	
} __rte_cache_aligned;

static struct lcore_params lcore_params_array[MAX_LCORE_PARAMS];
static struct lcore_params lcore_params_array_default[] = {
	   {0, 0, 1},
	   {1, 0, 1},
	   {2, 0, 1},
       {3, 0, 1},
};

static struct lcore_params * lcore_params = lcore_params_array_default;
static uint16_t nb_lcore_params = sizeof(lcore_params_array_default) /sizeof(lcore_params_array_default[0]);
extern struct lcore_conf lcore_conf[RTE_MAX_LCORE];


int init_lcore_conf(struct lcore_conf *lcore_conf);
int parse_config(char *arg);
#endif
