/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdint.h>
#include <inttypes.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <getopt.h>
#include "cap_ipv4_ss.h"
#include "cap_ipv6_ss.h"
#include "dpdk_fwd.h"
#include <rte_malloc.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_log.h>
#include <rte_interrupts.h>
#include <rte_devargs.h>
#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_eth_ctrl.h>
#include <rte_dev_info.h>
#include "lcore_conf.h"
#include "redirect.h"

//for test
#define uint32_t_to_char(ip, a, b, c, d) do {\
	                *a = (unsigned char)(ip >> 24 & 0xff);\
	                *b = (unsigned char)(ip >> 16 & 0xff);\
	                *c = (unsigned char)(ip >> 8 & 0xff);\
	                *d = (unsigned char)(ip & 0xff);\
	        } while (0)
void showip(struct ipv4_hdr *ip);
#define PRINT_MAC(addr)         printf("%02"PRIx8":%02"PRIx8":%02"PRIx8 \
			                ":%02"PRIx8":%02"PRIx8":%02"PRIx8,      \
			                addr.addr_bytes[0], addr.addr_bytes[1], addr.addr_bytes[2], \
			                addr.addr_bytes[3], addr.addr_bytes[4], addr.addr_bytes[5])


#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100
#define TEST 0

static const struct rte_eth_conf port_conf_default = {
	.rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN }
};

static struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];

/* basicfwd.c: Basic DPDK skeleton forwarding example. */

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint8_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	int retval;
	uint16_t q;

	if (port >= rte_eth_dev_count())
		return -1;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for(q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct ether_addr addr;
	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			(unsigned)port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable(port);

	return 0;
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
//static __attribute__((noreturn)) void
static int lcore_main(void *p)
{
	const uint8_t nb_ports = rte_eth_dev_count();
	uint8_t index,port,coreid;
    uint64_t prev_tsc, diff_tsc, cur_tsc;
    struct rte_mbuf *bufs[BURST_SIZE];
	struct rte_mbuf *m=NULL;
    uint16_t nb_rx,nb_tx ;
	int i,rx_queueid;
	int sent;
	struct rte_eth_dev_tx_buffer *buffer;
    const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) /US_PER_S * BURST_TX_DRAIN_US;
	uint16_t ether_type;
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr * ipv4_hdr=NULL;
	struct ipv6_hdr * ipv6_hdr=NULL;
	unsigned long rv=0;
	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	for (port = 0; port < nb_ports; port++)
		if (rte_eth_dev_socket_id(port) > 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);
    coreid=rte_lcore_id();
	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
    			coreid);
    prev_tsc = 0;
	printf("lcore_conf[coreid].length=%d\n",lcore_conf[coreid].length);
#if 0
	if(coreid==2)
	    port=0;
	else if(coreid==4)
		port=1;
	else
	{
	    printf("number of lcore error\n");
		exit(-1);
	}
#endif
	/* Run until the application is quit or killed. */
	for (;;) {
        /*drain*/
         #if 0
		     
                cur_tsc = rte_rdtsc();
                diff_tsc = cur_tsc - prev_tsc;
                if (unlikely(diff_tsc > drain_tsc)) {
                    buffer = tx_buffer[port^1];  
					rte_eth_tx_buffer_flush(port^1, 0, buffer);
		            prev_tsc = cur_tsc;
		        }
         #endif
		/*
		 * Receive packets on a port and forward them on the paired
		 * port. The mapping is 0 -> 1, 1 -> 0, 2 -> 3, 3 -> 2, etc.
		 */
		for(index = 0; index < lcore_conf[coreid].length; index++) {

			/* Get burst of RX packets, from first port of pair. */
		        //struct rte_mbuf *bufs[BURST_SIZE];
		        //uint16_t nb_rx ;
			port=lcore_conf[coreid].port_queue_list[index].rx_port_id;
			rx_queueid=lcore_conf[coreid].port_queue_list[index].rx_queue_id;
	   #if 1
			             
			cur_tsc = rte_rdtsc();
		    diff_tsc = cur_tsc - prev_tsc;
		    if(unlikely(diff_tsc > drain_tsc)) {
				  buffer = tx_buffer[port^1];  
				  rte_eth_tx_buffer_flush(port^1, 0, buffer);
				  prev_tsc = cur_tsc;		
			}
       #endif
            nb_rx=0;
			memset(bufs,0,sizeof(bufs));
			nb_rx = rte_eth_rx_burst(port, rx_queueid,bufs, BURST_SIZE);
			if (unlikely(nb_rx == 0))
				continue;
            for(i=0;i<nb_rx;i++)
			{
			   //printf("\n<-------------------nb_rx=%d---------------->\n",nb_rx);
			#if 0
			   m = bufs[i];
			   rte_prefetch0(rte_pktmbuf_mtod(m, void *));
			   buffer=tx_buffer[port^1];
			   sent=rte_eth_tx_buffer(port^1, 0, buffer, m);
			   //printf("sent=%d\n",sent);
            #endif
			   eth_hdr = rte_pktmbuf_mtod(bufs[i], struct ether_hdr *);
			   //printf("mac_src:");PRINT_MAC(eth_hdr->s_addr);printf("\n");
			   //printf("mac_dst:");PRINT_MAC(eth_hdr->d_addr);printf("\n");
		       ether_type = eth_hdr->ether_type;
			   //printf("ether_type:%x\n",ether_type);
			   if (ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4)) {//ipv4
                   //printf("\n*************pkt len %d, data len %d******************\n",rte_pktmbuf_pkt_len(bufs[i]),bufs[i]->data_len);
				   //printf("pkt->nb_seg:%d\n",bufs[i]->nb_segs);
				   //printf("pkt->tso_segsz:%d\n",bufs[i]->tso_segsz);
                  #if TEST 
				   if(port==0){
				  #endif
					  ipv4_hdr = rte_pktmbuf_mtod_offset(bufs[i], struct ipv4_hdr *,sizeof(struct ether_hdr));
					  if(ipv4_hdr==IPPROTO_ICMP)
					  {
						   showip(ipv4_hdr);
					  }
						#if 0
					  //for test
					  showip(ipv4_hdr);
					  //printf("ip total_length:%d\n",rte_be_to_cpu_16(ipv4_hdr->total_length));
					  struct tcp_hdr *tcphdr;
					  tcphdr=(struct tcp_hdr *)((unsigned char *)ipv4_hdr + sizeof(struct ipv4_hdr));
					  //printf("src port:%d, dst port:%d\n",rte_be_to_cpu_16(tcphdr->src_port),rte_be_to_cpu_16(tcphdr->dst_port));
						#endif
				      rv=transfer_test_and_merge_flow4((struct iphdr*)ipv4_hdr);
					  if(rv)
					  {
						  //printf("~~~~~~~~~~~~~~auth pass~~~~~~~~~~~~~~~~~~~\n");
						   //nb_tx = rte_eth_tx_burst(port ^ 1, 0,&bufs[i], 1);
						   m = bufs[i];
					       rte_prefetch0(rte_pktmbuf_mtod(m, void *));
						   buffer=tx_buffer[port^1];
						   sent=rte_eth_tx_buffer(port^1, 0, buffer, m);
						   continue;
						   //if (unlikely(sent < 1)) {
							   //printf("rte_eth_tx_buffer ipv4 fail\n");
							   //rte_pktmbuf_free(bufs[i]);
						   //}
					  }
					#if 1 
					  if(get_ipv4_status((unsigned char *)&((struct iphdr*)ipv4_hdr)->saddr)==IPVI_UNAUTH)
					  {
						   //showip(ipv4_hdr);printf("redirect_enqueue,port:%d\n",port);
						   redirected_skb_enqueue(bufs[i],port,(struct rte_mempool *)p);

					  }else{
						   rte_pktmbuf_free(bufs[i]);
					  }
					#endif
		     #if TEST 
			      }else if(port==1){
					  m = bufs[i];
			          rte_prefetch0(rte_pktmbuf_mtod(m, void *));
					  buffer=tx_buffer[port^1];
					  sent=rte_eth_tx_buffer(port^1, 0, buffer, m);
				  }else{
					  printf("in ipv4 error port:%d\n",port);
					  exit(-1);
				  }
			 #endif
			   }else if(ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv6)){
				#if TEST
				   if(port==0){
				#endif
				     ipv6_hdr = rte_pktmbuf_mtod_offset(bufs[i], struct ipv6_hdr *,sizeof(struct ether_hdr));
                     if(transfer_test_and_merge_flow6((struct ip6_hdr *)ipv6_hdr))
					 {
				     	  //nb_tx = rte_eth_tx_burst(port ^ 1, 0,&bufs[i],1);
						   m = bufs[i];
						   rte_prefetch0(rte_pktmbuf_mtod(m, void *));
						   buffer=tx_buffer[port^1];
						   sent=rte_eth_tx_buffer(port^1, 0, buffer, m);
						   continue;
					      //if(unlikely(sent < 1)) {
							   //printf("rte_eth_tx_buffer ipv6 fail\n");
							   //rte_pktmbuf_free(bufs[i]);
						  //}
					 }
					#if 1
					 if(get_ipv6_status((unsigned char *)&((struct ip6_hdr *)ipv6_hdr)->ip6_src)==IPVI_UNAUTH)
					 {
						  //printf("call redirected_skb_enqueue\n");
						  redirected_skb_enqueue(bufs[i],port,(struct rte_mempool *)p);
						  //redirected(bufs[i],port,(struct rte_mempool *)p);
						  continue;
                          //rte_pktmbuf_free(bufs[i]);
					 }else{
						  rte_pktmbuf_free(bufs[i]);
					 }
					#endif
			  #if TEST
				   }else if(port==1){
					   m = bufs[i];
				       rte_prefetch0(rte_pktmbuf_mtod(m, void *));
					   buffer=tx_buffer[port^1];
					   sent=rte_eth_tx_buffer(port^1, 0, buffer, m);
				   }else{
					   printf("in ipv6 error port:%d\n",port);
					   exit(-1);
				   }
			  #endif
			   }else{//arp ...
				   //printf("port:%d\n,port^1:%d\n",port,port ^ 1);
				     nb_tx = rte_eth_tx_burst(port ^ 1, 0,&bufs[i],1);
					 /*
					 if (unlikely(nb_tx < 1)) {
						        rte_pktmbuf_free(bufs[i]);
					 }
					 */
			   }
			}
			/* Send burst of TX packets, to second port of pair. 
			nb_tx = rte_eth_tx_burst(port ^ 1, 0,bufs, nb_rx);

			if (unlikely(nb_tx < nb_rx)) {
				uint16_t buf;
				for (buf = nb_tx; buf < nb_rx; buf++)
					rte_pktmbuf_free(bufs[buf]);
			}
			*/

	    }
    }
	return 0;
}
static int ParseArgs(int argc,char **argv){
	int c;
    int lp_index;

	const struct option long_options[]={
		{"config",1,0,1},
		{0,0,0,0}
	};
	while((c=getopt_long(argc,argv,"",long_options,&lp_index))!=-1){
		printf("c=%d\n",c);
		 printf("optarg is %s\n",optarg);
		 switch(c){
			case 1:
				if(optarg){
                    if(parse_config(optarg)!=0)
					   return -1;
				}else{
					return -1;
				}
				break;
			default:
				printf("wrong option\n");
				return -1;
		 }
	}
	return 0;
}
/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int dpdk_forward(int argc,char *argv[])
//main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	struct rte_mempool *pool;
	unsigned nb_ports;
	uint8_t portid;
    //unsigned lcore_id;

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;
	printf("argc: %d,argv: %s\n ",argc,argv);
	if(ParseArgs(argc,argv)!=0)
	   return -1;
    init_lcore_conf(lcore_conf); 
	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count();
	if (nb_ports < 2 || (nb_ports & 1))
		rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS*nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	pool = rte_pktmbuf_pool_create("MBUFS_POOL", NUM_MBUFS*nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
	if (pool == NULL)
	    rte_exit(EXIT_FAILURE, "Cannot create pool\n");

	/* Initialize all ports. */
	for (portid = 0; portid < nb_ports; portid++)
	{
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n",
					portid);
		tx_buffer[portid] = rte_zmalloc_socket("tx_buffer",RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,\
					                          rte_eth_dev_socket_id(portid));
		if (tx_buffer[portid] == NULL)
	       rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",(unsigned) portid);
		rte_eth_tx_buffer_init(tx_buffer[portid], MAX_PKT_BURST);
    }
    /*launch*/
	if(rte_eal_mp_remote_launch(lcore_main, (void *)pool,CALL_MASTER)!=0){
		printf("rte_eal_mp_remote_launch fail\n");
		return -1;
	}

	return 0;
}

#if 1
void showip(struct ipv4_hdr *ip)
{
	    unsigned char a, b, c, d,m,n,p,q;
	    uint32_t_to_char(rte_bswap32(ip->src_addr), &a, &b, &c, &d);
        printf("Packet Src:%hhu.%hhu.%hhu.%hhu ", a, b, c, d);
	    uint32_t_to_char(rte_bswap32(ip->dst_addr), &m, &n, &p, &q);
	    printf("Packet Dst:%hhu.%hhu.%hhu.%hhu ", m, n, p, q);
	    printf("\n");
}
#endif
