#include <linux/tcp.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <stdint.h>
#include <pthread.h>
#include <linux/if_ether.h>
#include <stdlib.h>

#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_string_fns.h>
#include <rte_acl.h>

#include "redirect.h"
#include "list.h"
#include "poison.h"



int redirect_timeout=10;//超时的秒数
unsigned char redirect_url[128];

unsigned char redirect_buff[256];
int redirect_buff_len;
static struct rte_mempool *mbuf_pool;

#define MAXIMUM_SKBLENTH 256
#define MAXIMUM_CONNECTIONS 65535
#define TCP_LISTEN 0
#define TCP_SYN_RECV 1
#define TCP_ESTABLISHED 2
#define TCP_FIN_WAIT1 3
#define TCP_FIN_WAIT2 4
#define TCP_CLOSE 5
struct connection_state_item conn_stat_table={&conn_stat_table,&conn_stat_table};
struct connection_state_item free_conn_table={&free_conn_table,&free_conn_table};

static pthread_mutex_t conn_stat_mutex;
static pthread_mutex_t free_stat_mutex;
static pthread_mutex_t redirect_paras_mutex;

//void redirected_skb_enqueue(struct rte_mbuf*bufs,uint8_t port);
static void dpdk_forward(struct rte_mbuf* bufs,uint8_t port);
static void showip(struct ipv4_hdr *ip);
static void showip6(struct ipv6_hdr *ipv6_hdr);
//static unsigned short checksum(unsigned short *buf, int buf_len);

#define uint32_t_to_char(ip, a, b, c, d) do {\
                *a = (unsigned char)(ip >> 24 & 0xff);\
                *b = (unsigned char)(ip >> 16 & 0xff);\
                *c = (unsigned char)(ip >> 8 & 0xff);\
                *d = (unsigned char)(ip & 0xff);\
        } while (0)

static void conn_table_exit(void)
{//无需加锁
	struct connection_state_item * first=NULL;
	
	pthread_mutex_lock(&conn_stat_mutex);
	//spin_lock_irqsave(&g_conn_stat_lock,flags);
	while( !list_empty((struct list_head*)&conn_stat_table) )
	{
		first=conn_stat_table.next;
		list_del((struct list_head*)first);
		if(first->buf_send){
			rte_pktmbuf_free(first->buf_send);
			first->buf_send=NULL;
		}
		free(first);
	}
	pthread_mutex_unlock(&conn_stat_mutex);
	
	pthread_mutex_lock(&free_stat_mutex);
	while( !list_empty((struct list_head*)&free_conn_table) )
	{
		first=free_conn_table.next;
		list_del((struct list_head*)first);
		if(first->buf_send){
			rte_pktmbuf_free(first->buf_send);
			first->buf_send=NULL;
		}
		free(first);
	}
	pthread_mutex_unlock(&free_stat_mutex);

}

int conn_table_init(void)
{//无需加锁
	int i;
	
	for(i=0;i<MAXIMUM_CONNECTIONS;i++){
		//struct connection_state_item * item=malloc(sizeof(struct connection_state_item),GFP_ATOMIC);	
		struct connection_state_item * item = (struct connection_state_item*)malloc(sizeof(struct connection_state_item));
		if(item){
			memset(item,0,sizeof(struct connection_state_item));
			pthread_mutex_lock(&free_stat_mutex);
			list_add_tail((struct list_head*)item,(struct list_head*)&free_conn_table);
			pthread_mutex_unlock(&free_stat_mutex);
		}else{
			goto errorreturn;
		}
	}

	return 0;

errorreturn:
	conn_table_exit();
	return -ENOMEM;
}	

static struct connection_state_item * conn_item_alloc(void)
{
	struct connection_state_item * free_item=NULL;
	
	pthread_mutex_lock(&free_stat_mutex);
	if(!list_empty((struct list_head*)&free_conn_table)){
		free_item=free_conn_table.next;
		list_del((struct list_head*)free_item);
	}
	pthread_mutex_unlock(&free_stat_mutex);

	if(free_item){
		memset(free_item,0,sizeof(struct connection_state_item));
		free_item->stat=TCP_LISTEN;
		free_item->buf_send=NULL;
	}
	
	return free_item;

}

static void conn_item_free(struct connection_state_item *free_item)
{
	if(free_item){
		if(free_item->buf_send){
			rte_pktmbuf_free(free_item->buf_send);
			free_item->buf_send=NULL;
		}
		
		pthread_mutex_lock(&free_stat_mutex);
		list_add_tail((struct list_head*)free_item,(struct list_head*)&free_conn_table);
		pthread_mutex_unlock(&free_stat_mutex);
	}
	return;
}

static void conn_insert(struct connection_state_item*  item)
{
	pthread_mutex_lock(&conn_stat_mutex);
	list_add_tail((struct list_head*)item,(struct list_head*)&conn_stat_table);
	pthread_mutex_unlock(&conn_stat_mutex);
	return;
}

static struct connection_state_item* conn_find_v4(uint32_t s_ipv4, uint32_t d_ipv4, uint16_t s_port, uint16_t d_port)
{
	struct connection_state_item*finding=NULL;
	struct connection_state_item*pcurrent=NULL;

	pthread_mutex_lock(&conn_stat_mutex);
	
	pcurrent=conn_stat_table.next;
	for(;pcurrent!=&conn_stat_table;pcurrent=pcurrent->next) {
		if(	pcurrent->s_ipv4 == s_ipv4 && 
			pcurrent->d_ipv4 == d_ipv4 && 
			pcurrent->s_port == s_port && 	
			pcurrent->d_port == d_port) {
				finding=pcurrent;
				list_del((struct list_head*)finding);
				break;	
		}
	}
	
	pthread_mutex_unlock(&conn_stat_mutex);
	
	return finding;
}

static struct connection_state_item* conn_find_v6(uint8_t *s_ipv6, uint8_t * d_ipv6, uint16_t s_port, uint16_t d_port)
{
	struct connection_state_item*finding=NULL;
	struct connection_state_item*pcurrent=NULL;


	pthread_mutex_lock(&conn_stat_mutex);
	
	pcurrent=conn_stat_table.next;
	for(;pcurrent!=&conn_stat_table;pcurrent=pcurrent->next) {
		if(	memcmp(&pcurrent->s_ipv6 ,s_ipv6,IPV6_ADDR_LEN) == 0 && 
			memcmp(&pcurrent->d_ipv6 ,d_ipv6,IPV6_ADDR_LEN) == 0 && 
			pcurrent->s_port == s_port && 	
			pcurrent->d_port == d_port) {
				finding=pcurrent;
				list_del((struct list_head*)finding);
				break;	
		}
	}
	
	pthread_mutex_unlock(&conn_stat_mutex);
	
	return finding;
}

int get_redirect_timeout(void)
{
	return redirect_timeout;
}

void set_redirect_timeout(int timeout)
{
	redirect_timeout=timeout;
	return;
}

void get_redirect_url(char * url_buffer)
{
	pthread_mutex_lock(&redirect_paras_mutex);
	strcpy(url_buffer,(char*)redirect_url);
	pthread_mutex_unlock(&redirect_paras_mutex);
}

static char *fmt="HTTP/1.1 302 Moved Temporatily\r\nLocation: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n ";//without the last space,firefox will be fault.

void set_redirect_url(char *url)
{
	if(strlen(url) > 128)
		return;

	pthread_mutex_lock(&redirect_paras_mutex);

	strcpy(redirect_url,url);
	snprintf(redirect_buff,256,fmt,redirect_url);
	redirect_buff_len=strlen(redirect_buff);
	printf("redirect_buff_len:%d\n",redirect_buff_len);

	pthread_mutex_unlock(&redirect_paras_mutex);
	return;	
}

static void dpdk_forward(struct rte_mbuf* bufs,uint8_t port)
{
	const uint16_t nb_tx = rte_eth_tx_burst(port, 0,
                                        &bufs, 1);
	if(nb_tx>0)
	{
		printf("send success:nb_tx=%d\n",nb_tx);	
	}
	return;
}

static struct tcp_hdr* gettcphdr(struct rte_mbuf*bufs,uint16_t ether_type)
{
	struct ether_hdr* eth_hdr;
	struct ipv4_hdr* iphdr;
	struct ipv6_hdr* ip6hdr;
	struct tcp_hdr*tcp;
	uint16_t type = ether_type;
	
	eth_hdr = rte_pktmbuf_mtod(bufs, struct ether_hdr*);
	if(type == ETH_P_IP)
	{
		iphdr = (struct ipv4_hdr *)(eth_hdr + 1);
		if(iphdr->next_proto_id == IPPROTO_TCP)
                {
			tcp = (struct tcp_hdr *)((unsigned char *)iphdr + sizeof(struct ipv4_hdr));
		}
		else
			return NULL;
	}
	else if(type == ETH_P_IPV6)
	{
		ip6hdr = (struct ipv6_hdr *)(eth_hdr + 1);
		if(ip6hdr->proto == IPPROTO_TCP)
                {
			tcp = (struct tcp_hdr *)((unsigned char *)ip6hdr + sizeof(struct ipv4_hdr));
		}
		else
			return NULL;
	}	
	else
		return NULL;

	return tcp;
}

static int gethdrinfo(struct rte_mbuf*bufs,uint16_t *ether_type,struct ether_hdr** ethhdr,struct ipv4_hdr**iphdr,struct ipv6_hdr**ip6hdr,struct tcp_hdr **tcphdr)
{
	struct ether_hdr *eth=NULL;
	struct ipv4_hdr *ip=NULL;
	struct ipv6_hdr *ip6=NULL;
	struct tcp_hdr *tcp=NULL;
	uint16_t type;

	eth = rte_pktmbuf_mtod(bufs, struct ether_hdr*);
	type = rte_be_to_cpu_16(eth->ether_type);
	printf("type:%x\n",type);

	if(type == ETH_P_IP)
	{
		ip = (struct ipv4_hdr *)(eth + 1);
		if(ip->next_proto_id == IPPROTO_TCP)
		{
			tcp = (struct tcp_hdr *)((unsigned char *)ip + sizeof(struct ipv4_hdr));
			*tcphdr = tcp;
		}
		*iphdr=ip;
	}
	else if(type == ETH_P_IPV6)
	{
		ip6 = (struct ipv6_hdr *)(eth + 1);
		if(ip6->proto == IPPROTO_TCP)
		{
			tcp = (struct tcp_hdr *)((unsigned char *)ip6 + sizeof(struct ipv6_hdr));
			*tcphdr = tcp;
		}
		*ip6hdr = ip6;
	}
	*ether_type = type;
	*ethhdr = eth;
	return 1;	
}

static int gethdr(struct rte_mbuf*bufs,uint16_t type,struct ether_hdr** ethhdr,struct ipv4_hdr**iphdr,struct ipv6_hdr**ip6hdr,struct tcp_hdr **tcphdr)
{
        struct ether_hdr *eth=NULL;
        struct ipv4_hdr *ip=NULL;
        struct ipv6_hdr *ip6=NULL;
        struct tcp_hdr *tcp=NULL;

        eth = rte_pktmbuf_mtod(bufs, struct ether_hdr*);
	if(eth==NULL)
		printf("eth is null\n");

        if(type == ETH_P_IP)
        {
                ip = (struct ipv4_hdr *)(eth + 1);
		*iphdr=ip;
                tcp = (struct tcp_hdr *)((unsigned char *)ip + sizeof(struct ipv4_hdr));
                *tcphdr = tcp;
        }
        else if(type == ETH_P_IPV6)
        {
                ip6 = (struct ipv6_hdr *)(eth + 1);
		*ip6hdr = ip6;
                tcp = (struct tcp_hdr *)((unsigned char *)ip6 + sizeof(struct ipv6_hdr));
                *tcphdr = tcp;
        }
        *ethhdr = eth;

        return 1;
}

static void showip(struct ipv4_hdr *ip)
{
	unsigned char a, b, c, d,m,n,p,q;
	uint32_t_to_char(rte_bswap32(ip->src_addr), &a, &b, &c, &d);
        printf("Packet Src:%hhu.%hhu.%hhu.%hhu ", a, b, c, d);
	uint32_t_to_char(rte_bswap32(ip->dst_addr), &m, &n, &p, &q);
	printf("Packet Dst:%hhu.%hhu.%hhu.%hhu ", m, n, p, q);
	printf("\n");
}

static void showip6(struct ipv6_hdr *ipv6_hdr)
{
	unsigned i;
	printf("Packet Src");
        for (i = 0; i < RTE_DIM(ipv6_hdr->src_addr); i += sizeof(uint16_t))
                printf(":%.2x%.2x",
                        ipv6_hdr->src_addr[i], ipv6_hdr->src_addr[i + 1]);
        printf("\nDst");
        for (i = 0; i < RTE_DIM(ipv6_hdr->dst_addr); i += sizeof(uint16_t))
                printf(":%.2x%.2x",
                        ipv6_hdr->dst_addr[i], ipv6_hdr->dst_addr[i + 1]);
	printf("\n");
}

//监听接收连接请求，ack=1,syn=1
static int my_tcp_listen_2_syn_recv(struct connection_state_item*conn_item,struct rte_mbuf *bufs,uint8_t port)
{
 
	printf("my_tcp_listen_2_syn_recv\n");
	struct rte_mbuf *buf_send=NULL;
	struct ether_hdr *ethhdr=NULL,*eth_send=NULL;
	struct ipv4_hdr *iphdr=NULL,*ip_send=NULL;
	struct ipv6_hdr *ip6hdr=NULL,*ip6_send=NULL;
	struct tcp_hdr *tcphdr=NULL,*tcp_send=NULL;
	uint16_t ether_type;
	
	int res = gethdrinfo(bufs,&ether_type,&ethhdr,&iphdr,&ip6hdr,&tcphdr);
	if(res!=1)
	{	
		printf("get head info failed\n");
		goto discard_packet;
	}

	if( (ether_type != ETH_P_IP) && (ether_type != ETH_P_IPV6) )
		goto discard_packet;
	if(tcphdr==NULL)
		goto discard_packet;
	conn_item->last_recv_seq=rte_be_to_cpu_32(tcphdr->sent_seq);//tcphdr->sent_seq
	conn_item->last_recv_ack_seq=rte_be_to_cpu_32(tcphdr->recv_ack);//test tcphdr->recv_ack ntohl
	conn_item->last_send_seq=0;
	if(conn_item->buf_send){
		rte_pktmbuf_free(conn_item->buf_send);
		conn_item->buf_send=NULL;
	}
	
	conn_item->buf_send = rte_pktmbuf_alloc(mbuf_pool);
	buf_send = conn_item->buf_send;
	if(buf_send==NULL)
		printf("buf_send is null\n");

	int res2 = gethdr(buf_send,ether_type,&eth_send,&ip_send,&ip6_send,&tcp_send);
	if(res2!=1)
		goto discard_packet;

	//fill tcp header
	//rte_memcpy(tcp_send,tcphdr,sizeof(struct tcp_hdr));
	tcp_send->src_port = tcphdr->dst_port; 
	tcp_send->dst_port = tcphdr->src_port;
	tcp_send->sent_seq = rte_cpu_to_be_32(conn_item->last_send_seq);
	tcp_send->recv_ack = rte_cpu_to_be_32(conn_item->last_recv_seq+1);
	tcp_send->data_off =0x50;  //not add option
	//tcp_send->data_off = tcphdr->data_off;  //add option
	tcp_send->tcp_flags |= TCP_SYN_FLAG;//syn=1
	tcp_send->tcp_flags |= TCP_ACK_FLAG; //ack=1
	tcp_send->tcp_urp = 0;
	tcp_send->rx_win=rte_cpu_to_be_16(65535);


	//add tcp options
	/*TCP_OPT tcp_opt;
        TCP_OPT *popt=NULL;
	tcp_opt.opt1=htonl(0x020405b4);
	tcp_opt.opt2=htonl(0x01010402);
	tcp_opt.opt3=htonl(0x01030309);
	tcp_opt.opt1=htonl(0x020405a0);
        tcp_opt.opt2=htonl(0x01010402);
        tcp_opt.opt3=htonl(0x01030307);
        popt=(TCP_OPT *)(rte_pktmbuf_mtod(buf_send, char *) +sizeof(struct ether_hdr)+sizeof(struct ipv4_hdr)+sizeof(struct tcp_hdr));
        *popt=tcp_opt;
	rte_memcpy(popt,&tcp_opt,sizeof(TCP_OPT));*/

	//fill ip，ip6 header
	if(ether_type == ETH_P_IP)
        {
		memcpy(ip_send,iphdr,sizeof(struct ipv4_hdr));
		ip_send->time_to_live = 128;
		ip_send->total_length = htons(sizeof(struct ipv4_hdr)+sizeof(struct tcp_hdr)); //add option
		//ip_send->total_length = rte_cpu_to_be_16(sizeof(struct ipv4_hdr)+sizeof(struct tcp_hdr)); //not add option
		ip_send->version_ihl = 0x45;
		ip_send->next_proto_id = IPPROTO_TCP;
		ip_send->src_addr = iphdr->dst_addr; //test iphdr->dst_addr
		ip_send->dst_addr = iphdr->src_addr;
		ip_send->hdr_checksum = 0;
		ip_send->hdr_checksum = rte_ipv4_cksum(ip_send);
		tcp_send->cksum = 0;
                tcp_send->cksum = rte_ipv4_udptcp_cksum(ip_send,tcp_send);
		conn_item->buf_send->data_len = sizeof(struct ether_hdr)+sizeof(struct ipv4_hdr)+sizeof(struct tcp_hdr);
		conn_item->buf_send->pkt_len = sizeof(struct ether_hdr)+sizeof(struct ipv4_hdr)+sizeof(struct tcp_hdr);
		printf("buf->data_len:%d\n",buf_send->data_len);

		//tcp校验和
		/*unsigned short check_Buff[65500]; //校验和缓存区      
	        PSD_HEADER psd_header={0};         //TCP伪首部结构
        	psd_header.saddr=ip_send->src_addr;    //源地址  test ip_send->src_addr 
	        psd_header.daddr=ip_send->dst_addr;    //源地址   ip_send
        	psd_header.mbz=0;
	        psd_header.ptcl=ip_send->next_proto_id;
		psd_header.tcpl=htons(sizeof(struct tcp_hdr));*/
		/*memset(check_Buff,0,65500);
        	memcpy(check_Buff,&psd_header,sizeof(PSD_HEADER));
	        memcpy(check_Buff+sizeof(PSD_HEADER),tcp_send,sizeof(struct tcp_hdr));
		memcpy(check_Buff+sizeof(PSD_HEADER)+sizeof(struct tcp_hdr),&tcp_opt,sizeof(TCP_OPT));*/
        	//tcp_send->cksum = checksum(check_Buff,sizeof(PSD_HEADER)+sizeof(struct tcp_hdr)+sizeof(TCP_OPT));
	}
	else if(ether_type == ETH_P_IPV6)
        {
		
		rte_memcpy(ip6_send,ip6hdr,sizeof(struct ipv6_hdr));
		ip6_send->hop_limits=128;
		ip6_send->payload_len=rte_cpu_to_be_16(sizeof(struct ipv6_hdr)+sizeof(struct tcp_hdr));
		ip6_send->proto=IPPROTO_TCP;
		
		rte_memcpy(ip6_send->src_addr,ip6hdr->dst_addr,IPV6_ADDR_LEN);
		rte_memcpy(ip6_send->dst_addr,ip6hdr->src_addr,IPV6_ADDR_LEN);
		
		tcp_send->cksum = 0;
		tcp_send->cksum = rte_ipv6_udptcp_cksum(ip6_send,tcp_send);

		conn_item->buf_send->data_len = sizeof(struct ether_hdr)+sizeof(struct ipv6_hdr)+sizeof(struct tcp_hdr);
	}

	//mac
	ether_addr_copy(&ethhdr->d_addr,&eth_send->s_addr);
	ether_addr_copy(&ethhdr->s_addr,&eth_send->d_addr);
	eth_send->ether_type = ethhdr->ether_type;
	
	time(&conn_item->time);
	conn_item->stat=TCP_SYN_RECV;
	conn_item->last_send_seq+=1;
	conn_item->last_send_ack_seq=conn_item->last_recv_seq+1;
	//conn_item->buf_send->data_len = 54;//not add option
	//conn_item->buf_send->data_len = bufs->data_len;  //add option
	dpdk_forward(conn_item->buf_send,port);

	return 1;
	
discard_packet:
	return 0;
}

static int my_tcp_syn_recv_2_establish(struct connection_state_item*conn_item,struct rte_mbuf *bufs,uint16_t type)
{
	printf("my_tcp_syn_recv_2_establish\n");
	struct tcp_hdr *tcp=NULL;
	tcp=gettcphdr(bufs,type);
	
	conn_item->last_recv_seq=rte_be_to_cpu_32(tcp->sent_seq);
	conn_item->last_recv_ack_seq=rte_be_to_cpu_32(tcp->recv_ack);
	printf("conn_item->last_recv_seq:%x,conn_item->last_recv_ack_seq:%x\n",conn_item->last_recv_seq,conn_item->last_recv_ack_seq);
	time(&conn_item->time);
	conn_item->stat=TCP_ESTABLISHED;
	
	return 0;
}

//建立成功 syn=0,ack=1
static int my_tcp_establish_http_reply(struct connection_state_item*conn_item,struct rte_mbuf *bufs,uint8_t port)
{
	struct rte_mbuf *buf_send=NULL;
        struct ether_hdr *ethhdr=NULL,*eth_send=NULL;
        struct ipv4_hdr *iphdr=NULL,*ip_send=NULL;
        struct ipv6_hdr *ip6hdr=NULL,*ip6_send=NULL;
        struct tcp_hdr *tcphdr=NULL,*tcp_send=NULL;
        uint16_t ether_type;
	
	int res = gethdrinfo(bufs,&ether_type,&ethhdr,&iphdr,&ip6hdr,&tcphdr);
	if(res!=1)
        {
                printf("get head info failed\n");
                goto discard_packet;
        }
	if((ether_type != ETH_P_IP) && (ether_type != ETH_P_IPV6) )
                goto discard_packet;
	if(tcphdr==NULL)
		goto discard_packet;

	conn_item->last_recv_seq=rte_be_to_cpu_32(tcphdr->sent_seq);
        conn_item->last_recv_ack_seq=rte_be_to_cpu_32(tcphdr->recv_ack);

	if(conn_item->buf_send){
                rte_pktmbuf_free(conn_item->buf_send);
                conn_item->buf_send=NULL;
        }

	conn_item->buf_send = rte_pktmbuf_alloc(mbuf_pool);
	buf_send = conn_item->buf_send;

	int res2 = gethdr(buf_send,ether_type,&eth_send,&ip_send,&ip6_send,&tcp_send);
	if(res2!=1)
		goto discard_packet;

	//fill the tcp header
	memset(tcp_send,0,sizeof(struct tcp_hdr));
	tcp_send->src_port = tcphdr->dst_port;
        tcp_send->dst_port = tcphdr->src_port;
        tcp_send->sent_seq = rte_cpu_to_be_32(conn_item->last_send_seq);
	//tcp_send->data_off = tcphdr->data_off;  //add option
        tcp_send->data_off = 0x50;  //not add option
        tcp_send->tcp_flags &= ~TCP_SYN_FLAG;//syn=0
        tcp_send->tcp_flags |= TCP_ACK_FLAG; //ack=1
	tcp_send->rx_win=rte_cpu_to_be_16(65535);
	tcp_send->tcp_urp = 0;

	//add tcp options
	/*TCP_OPT tcp_opt;
        TCP_OPT *popt=NULL;
        tcp_opt.opt1=htonl(0x020405b4);
        tcp_opt.opt2=htonl(0x01010402);
        tcp_opt.opt3=htonl(0x01030309);
        tcp_opt.opt1=htonl(0x020405a0);
        tcp_opt.opt2=htonl(0x01010402);
        tcp_opt.opt3=htonl(0x01030307);
	
	popt=(TCP_OPT *)(rte_pktmbuf_mtod(buf_send, char *) +sizeof(struct ether_hdr)+sizeof(struct ipv4_hdr)+sizeof(struct tcp_hdr));
        *popt=tcp_opt;
        rte_memcpy(popt,&tcp_opt,sizeof(TCP_OPT));*/

	//fill ip header
	if(ether_type == ETH_P_IP)
        {
		uint32_t hdrlen=sizeof(struct ether_hdr)+sizeof(struct ipv4_hdr)+sizeof(struct tcp_hdr);
		uint32_t len=bufs->pkt_len-hdrlen;
		tcp_send->recv_ack = rte_cpu_to_be_32(conn_item->last_recv_seq+len);
		//add redirect_buff
	        char *pbuf=(char*)(rte_pktmbuf_mtod(buf_send, char *) +hdrlen);
        	rte_memcpy(pbuf,redirect_buff,redirect_buff_len);

                rte_memcpy(ip_send,iphdr,sizeof(struct ipv4_hdr));
                ip_send->time_to_live = 128;
		//ip_send->total_length = rte_cpu_to_be_16(sizeof(struct ipv4_hdr)+sizeof(struct tcp_hdr)+redirect_buff_len+12);//add option
                ip_send->total_length = rte_cpu_to_be_16(sizeof(struct ipv4_hdr)+sizeof(struct tcp_hdr)+redirect_buff_len);  //add redirect_buff
                ip_send->version_ihl = 0x45;
                ip_send->next_proto_id = IPPROTO_TCP;
                ip_send->src_addr = iphdr->dst_addr;
                ip_send->dst_addr = iphdr->src_addr;

		//checksum of ip
                ip_send->hdr_checksum = 0;	
		ip_send->hdr_checksum = rte_ipv4_cksum(ip_send);
		//checksum of tcphdr
		tcp_send->cksum = 0;
                tcp_send->cksum = rte_ipv4_udptcp_cksum(ip_send,tcp_send);

		//buf_send length
		buf_send->data_len = hdrlen+redirect_buff_len;

		conn_item->last_send_ack_seq=conn_item->last_recv_seq+hdrlen;

		//ip_send->hdr_checksum = checksum((unsigned short *)ip_send,sizeof(*ip_send));
 		//memcpy(buf_send+sizeof(struct ether_hdr)+sizeof(struct ipv4_hdr)+sizeof(struct tcp_hdr),redirect_buff,redirect_buff_len);
		/*unsigned short check_Buff[65500]; //校验和缓存区  
		PSD_HEADER psd_header={0};         //TCP伪首部结构
                psd_header.saddr=ip_send->src_addr;    //源地址  test ip_send->src_addr 
                psd_header.daddr=ip_send->dst_addr;    //源地址   ip_send
                psd_header.mbz=0;
                psd_header.ptcl=ip_send->next_proto_id;
                psd_header.tcpl=htons(sizeof(struct tcp_hdr)+redirect_buff_len);

                tcp_send->cksum = 0;
                memset(check_Buff,0,65500);
                memcpy(check_Buff,&psd_header,sizeof(PSD_HEADER));
                memcpy(check_Buff+sizeof(PSD_HEADER),tcp_send,sizeof(struct tcp_hdr));
		memcpy(check_Buff+sizeof(PSD_HEADER)+sizeof(struct tcp_hdr),redirect_buff,redirect_buff_len);

                tcp_send->cksum = checksum(check_Buff,sizeof(PSD_HEADER)+sizeof(struct tcp_hdr)+redirect_buff_len);*/

        }
	else if(ether_type == ETH_P_IPV6)
        {
		uint32_t hdrlen=sizeof(struct ether_hdr)+sizeof(struct ipv6_hdr)+sizeof(struct tcp_hdr);
                uint32_t len=bufs->pkt_len-hdrlen;
                tcp_send->recv_ack = rte_cpu_to_be_32(conn_item->last_recv_seq+len);

		//add redirect_buff
                char *pbuf=(char*)(rte_pktmbuf_mtod(buf_send, char *) +hdrlen);
                rte_memcpy(pbuf,redirect_buff,redirect_buff_len);

                rte_memcpy(ip6_send,ip6hdr,sizeof(struct ipv6_hdr));
                ip6_send->hop_limits=128;
                ip6_send->payload_len=rte_cpu_to_be_16(sizeof(struct ipv6_hdr)+sizeof(struct tcp_hdr)+redirect_buff_len);
                ip6_send->proto=IPPROTO_TCP;

                rte_memcpy(ip6_send->src_addr,ip6hdr->dst_addr,IPV6_ADDR_LEN);
                rte_memcpy(ip6_send->dst_addr,ip6hdr->src_addr,IPV6_ADDR_LEN);
		
		tcp_send->cksum = 0;
                tcp_send->cksum = rte_ipv6_udptcp_cksum(ip6_send,tcp_send); 

		buf_send->data_len = hdrlen+redirect_buff_len;

		conn_item->last_send_ack_seq=conn_item->last_recv_seq+hdrlen;
        }
	else
                goto discard_packet;
	//mac
        ether_addr_copy(&ethhdr->d_addr,&eth_send->s_addr);
        ether_addr_copy(&ethhdr->s_addr,&eth_send->d_addr);
	eth_send->ether_type = ethhdr->ether_type;

	conn_item->last_send_seq+=redirect_buff_len;
	//conn_item->last_send_ack_seq=conn_item->last_recv_seq;
	//conn_item->last_send_ack_seq=conn_item->last_recv_seq+bufs->pkt_len;//add redirect_buff	
	time(&conn_item->time);
	dpdk_forward(conn_item->buf_send,port);
	return 1;

discard_packet:

        return 0;
}

//分手第三步 ack=1;fin=1
static int my_tcp_establish_2_fin_ack(struct connection_state_item*conn_item,uint8_t port)
{
        struct ether_hdr *eth_send=NULL;
        struct ipv4_hdr *ip_send=NULL;
        struct ipv6_hdr *ip6_send=NULL;
        struct tcp_hdr *tcp_send=NULL;
        uint16_t ether_type;

	int res = gethdrinfo(conn_item->buf_send,&ether_type,&eth_send,&ip_send,&ip6_send,&tcp_send);
        if(res!=1)
        {       
                printf("get head info failed\n");
                goto discard_packet;
        }

	tcp_send->tcp_flags |= TCP_FIN_FLAG;//syn=1
        tcp_send->tcp_flags |= TCP_ACK_FLAG; //ack=1
	
	if(ether_type == ETH_P_IP)
        {
		tcp_send->cksum = 0;
                tcp_send->cksum = rte_ipv4_udptcp_cksum(ip_send,tcp_send);
	}
	else if(ether_type == ETH_P_IPV6)
        {
		tcp_send->cksum = 0;
                tcp_send->cksum = rte_ipv6_udptcp_cksum(ip6_send,tcp_send);
	}

	conn_item->stat=TCP_CLOSE;

	dpdk_forward(conn_item->buf_send,port);

discard_packet:

        return 0;
}

//断开连接进入TCP_FIN_WAIT1状态
static int my_tcp_establish_2_fin_wait1(struct connection_state_item*conn_item,struct rte_mbuf *bufs,uint8_t port)
{
	printf("my_tcp_establish_2_fin_wait1\n");
	struct rte_mbuf *buf_send=NULL;
        struct ether_hdr *ethhdr=NULL,*eth_send=NULL;
        struct ipv4_hdr *iphdr=NULL,*ip_send=NULL;
        struct ipv6_hdr *ip6hdr=NULL,*ip6_send=NULL;
        struct tcp_hdr *tcphdr=NULL,*tcp_send=NULL;
        uint16_t ether_type;

        int res = gethdrinfo(bufs,&ether_type,&ethhdr,&iphdr,&ip6hdr,&tcphdr);
        if(res!=1)
        {
                printf("get head info failed\n");
                goto discard_packet;
        }
	if((ether_type != ETH_P_IP) && (ether_type != ETH_P_IPV6) )
        {
		printf("bufs is not ip or ip6\n");
		goto discard_packet;
	}

	if(tcphdr==NULL)
	{
		printf("tcphdr is null\n");
		goto discard_packet;
	}

	conn_item->last_recv_seq=rte_be_to_cpu_32(tcphdr->sent_seq);
        conn_item->last_recv_ack_seq=rte_be_to_cpu_32(tcphdr->recv_ack);
	
	if(conn_item->buf_send){
                rte_pktmbuf_free(conn_item->buf_send);
                conn_item->buf_send=NULL;
        }

        conn_item->buf_send = rte_pktmbuf_alloc(mbuf_pool);
        if(conn_item->buf_send==NULL)
	{
		printf("conn_item->buf_send is null\n");
                goto discard_packet;
	}
	buf_send = conn_item->buf_send;

	int res2 = gethdr(buf_send,ether_type,&eth_send,&ip_send,&ip6_send,&tcp_send);
	if(res2!=1)
	{
		printf("res2 !=1\n");
		goto discard_packet;
	}
	
	/*eth_send = rte_pktmbuf_mtod(buf_send, struct ether_hdr*);
        if(ether_type == ETH_P_IP)
        {
                ip_send = (struct ipv4_hdr *)(ethhdr + 1);
                tcp_send = (struct tcp_hdr *)((unsigned char *)iphdr +sizeof(struct ipv4_hdr));
        }
        else if(ether_type == ETH_P_IPV6)
        {
                ip6_send = (struct ipv6_hdr *)(ethhdr + 1);
                tcp_send = (struct tcp_hdr *)((unsigned char *)ip6hdr +sizeof(struct ipv4_hdr));
        }*/

	memset(tcp_send,0,sizeof(struct tcp_hdr));
	tcp_send->src_port = tcphdr->dst_port;
        tcp_send->dst_port = tcphdr->src_port;
        tcp_send->sent_seq = rte_cpu_to_be_32(conn_item->last_send_seq);
        tcp_send->recv_ack = rte_cpu_to_be_32(conn_item->last_recv_seq+1);
        tcp_send->data_off = 0x50;
        tcp_send->tcp_flags &= ~TCP_FIN_FLAG;//syn=0
        tcp_send->tcp_flags |= TCP_ACK_FLAG; //ack=1
	//tcp_send->tcp_urp = 0;
        tcp_send->rx_win=rte_cpu_to_be_16(65535);

	if(ether_type == ETH_P_IP)
        {
		rte_memcpy(ip_send,iphdr,sizeof(struct ipv4_hdr));
                ip_send->time_to_live = 128;
                ip_send->total_length = rte_cpu_to_be_16(sizeof(struct ipv4_hdr)+sizeof(struct tcp_hdr));
                ip_send->version_ihl = 0x45;
                ip_send->next_proto_id = IPPROTO_TCP;
                ip_send->src_addr = iphdr->dst_addr;
                ip_send->dst_addr = iphdr->src_addr;
                ip_send->hdr_checksum = 0;
		ip_send->hdr_checksum = rte_ipv4_cksum(ip_send);

		tcp_send->cksum = 0;
                tcp_send->cksum = rte_ipv4_udptcp_cksum(ip_send,tcp_send);
		
		conn_item->buf_send->data_len = sizeof(struct ether_hdr)+sizeof(struct ipv4_hdr)+sizeof(struct tcp_hdr);
                conn_item->buf_send->pkt_len = sizeof(struct ether_hdr)+sizeof(struct ipv4_hdr)+sizeof(struct tcp_hdr);
	}
	else if(ether_type == ETH_P_IPV6)
        {
                rte_memcpy(ip6_send,ip6hdr,sizeof(struct ipv6_hdr));
                ip6_send->hop_limits=128;
                ip6_send->payload_len=rte_cpu_to_be_16(sizeof(struct ipv6_hdr)+sizeof(struct tcp_hdr));
                ip6_send->proto=IPPROTO_TCP;

                rte_memcpy(ip6_send->src_addr,ip6hdr->dst_addr,IPV6_ADDR_LEN);
                rte_memcpy(ip6_send->dst_addr,ip6hdr->src_addr,IPV6_ADDR_LEN);
		
		tcp_send->cksum = 0;
                tcp_send->cksum = rte_ipv6_udptcp_cksum(ip6_send,tcp_send);

		conn_item->buf_send->data_len = sizeof(struct ether_hdr)+sizeof(struct ipv6_hdr)+sizeof(struct tcp_hdr);
                conn_item->buf_send->pkt_len = sizeof(struct ether_hdr)+sizeof(struct ipv6_hdr)+sizeof(struct tcp_hdr);
        }
        else
                goto discard_packet;
	
        //mac
	ether_addr_copy(&ethhdr->d_addr,&eth_send->s_addr);
        ether_addr_copy(&ethhdr->s_addr,&eth_send->d_addr);
        eth_send->ether_type = ethhdr->ether_type;

	//conn_item->last_send_seq+=1;
	conn_item->last_send_ack_seq+=1;
	time(&conn_item->time);
	//conn_item->stat=TCP_FIN_WAIT1;

	//分手第二步 ack=1
	dpdk_forward(conn_item->buf_send,port);
	sleep(1);
	//分手第三步 fin=1,ack=1
	my_tcp_establish_2_fin_ack(conn_item,port);

	return 1;

discard_packet:

        return 0;

}

//FIN_WAIT2 状态
static int my_tcp_fin_wait1_2_fin_wait2(struct connection_state_item*conn_item,struct rte_mbuf *bufs,uint16_t type)
{
	struct tcp_hdr *tcp=NULL;
        tcp=gettcphdr(bufs,type);
	if(tcp==NULL)
		return 0;
	conn_item->last_recv_seq=rte_be_to_cpu_32(tcp->sent_seq);
        conn_item->last_recv_ack_seq=rte_be_to_cpu_32(tcp->recv_ack);

	time(&conn_item->time);
	conn_item->stat=TCP_FIN_WAIT2;

	return 0;
}

// TIME_WAIT 状态。
static int my_tcp_fin_wait1_2_time_wait(struct connection_state_item*conn_item,struct rte_mbuf*bufs,uint8_t port)
{
	printf("my_tcp_fin_wait1_2_time_wait\n");
	struct rte_mbuf *buf_send=NULL;
        struct ether_hdr *ethhdr=NULL,*eth_send=NULL;
        struct ipv4_hdr *iphdr=NULL,*ip_send=NULL;
        struct ipv6_hdr *ip6hdr=NULL,*ip6_send=NULL;
        struct tcp_hdr *tcphdr=NULL,*tcp_send=NULL;
        uint16_t ether_type;

        int res = gethdrinfo(bufs,&ether_type,&ethhdr,&iphdr,&ip6hdr,&tcphdr);
        if(res!=1)
        {
                printf("get head info failed\n");
                goto discard_packet;
        }
	if((ether_type != ETH_P_IP) && (ether_type != ETH_P_IPV6) )
                goto discard_packet;
	if(tcphdr==NULL)
		goto discard_packet;

	conn_item->last_recv_seq=rte_be_to_cpu_32(tcphdr->sent_seq);
        conn_item->last_recv_ack_seq=rte_be_to_cpu_32(tcphdr->recv_ack);
	if(conn_item->buf_send){
                rte_pktmbuf_free(conn_item->buf_send);
                conn_item->buf_send=NULL;
        }

        conn_item->buf_send = rte_pktmbuf_alloc(mbuf_pool);
        buf_send = conn_item->buf_send;
	int res2 = gethdr(buf_send,ether_type,&eth_send,&ip_send,&ip6_send,&tcp_send);
	if(res2!=1)
		goto discard_packet;

	/*eth_send = rte_pktmbuf_mtod(buf_send, struct ether_hdr*);
        if(ether_type == ETH_P_IP)
        {
                ip_send = (struct ipv4_hdr *)(ethhdr + 1);
                tcp_send = (struct tcp_hdr *)((unsigned char *)iphdr +sizeof(struct ipv4_hdr));
        }
        else if(ether_type == ETH_P_IPV6)
        {
                ip6_send = (struct ipv6_hdr *)(ethhdr + 1);
                tcp_send = (struct tcp_hdr *)((unsigned char *)ip6hdr +sizeof(struct ipv4_hdr));
        }*/

	memset(tcp_send,0,sizeof(struct tcp_hdr));
	tcp_send->src_port = tcphdr->dst_port;
        tcp_send->dst_port = tcphdr->src_port;
        tcp_send->sent_seq = rte_cpu_to_be_32(conn_item->last_send_seq);
        tcp_send->recv_ack = rte_cpu_to_be_32(conn_item->last_recv_seq+1);
        tcp_send->data_off = 0x50;
        tcp_send->tcp_flags &= ~TCP_FIN_FLAG;//fin=0
        tcp_send->tcp_flags |= TCP_ACK_FLAG; //ack=1

	//补充ip，ip6报头
        if(ether_type == ETH_P_IP)
        {
		rte_memcpy(ip_send,iphdr,sizeof(struct ipv4_hdr));
                ip_send->time_to_live = 128;
                ip_send->total_length = rte_cpu_to_be_16(sizeof(struct ipv4_hdr)+sizeof(struct tcp_hdr));
                ip_send->version_ihl = 0x45;
                ip_send->next_proto_id = IPPROTO_TCP;
                ip_send->src_addr = iphdr->dst_addr;
                ip_send->dst_addr = iphdr->src_addr;
                ip_send->hdr_checksum = 0;
		ip_send->hdr_checksum = rte_ipv4_cksum(ip_send);

		tcp_send->cksum = 0;
                tcp_send->cksum = rte_ipv4_udptcp_cksum(ip_send,tcp_send);
	}
	else if(ether_type == ETH_P_IPV6)
        {
                rte_memcpy(ip6_send,ip6hdr,sizeof(struct ipv6_hdr));
                ip6_send->hop_limits=128;
                ip6_send->payload_len=rte_cpu_to_be_16(sizeof(struct ipv6_hdr)+sizeof(struct tcp_hdr));
                ip6_send->proto=IPPROTO_TCP;

                rte_memcpy(ip6_send->src_addr,ip6hdr->dst_addr,IPV6_ADDR_LEN);
                rte_memcpy(ip6_send->dst_addr,ip6hdr->src_addr,IPV6_ADDR_LEN);

		tcp_send->cksum = 0;
                tcp_send->cksum = rte_ipv6_udptcp_cksum(ip6_send,tcp_send);
        }
        else
                goto discard_packet;

	//mac
        ether_addr_copy(&eth_send->s_addr, &ethhdr->d_addr);
        ether_addr_copy(&eth_send->d_addr, &ethhdr->s_addr);
        eth_send->ether_type = ethhdr->ether_type;

	conn_item->last_send_ack_seq=conn_item->last_recv_seq+1;
	time(&conn_item->time);
	conn_item->stat=TCP_CLOSE;
	
	dpdk_forward(conn_item->buf_send,port);

	return 1;

discard_packet:
	
	return 0;
}

static int my_tcp_fin_wait2_2_timewait(struct connection_state_item*conn_item,struct rte_mbuf*bufs,uint8_t port)
{
	printf("my_tcp_fin_wait2_2_timewait\n");
	struct rte_mbuf *buf_send=NULL;
        struct ether_hdr *ethhdr=NULL,*eth_send=NULL;
        struct ipv4_hdr *iphdr=NULL,*ip_send=NULL;
        struct ipv6_hdr *ip6hdr=NULL,*ip6_send=NULL;
        struct tcp_hdr *tcphdr=NULL,*tcp_send=NULL;
        uint16_t ether_type;

	int res = gethdrinfo(bufs,&ether_type,&ethhdr,&iphdr,&ip6hdr,&tcphdr);
        if(res!=1)
        {
                printf("get head info failed\n");
                goto discard_packet;
        }

	if( (ether_type != ETH_P_IP) && (ether_type != ETH_P_IPV6) )
                goto discard_packet;
        if(tcphdr==NULL)
                goto discard_packet;

	conn_item->last_recv_seq=rte_be_to_cpu_32(tcphdr->sent_seq);
        conn_item->last_recv_ack_seq=rte_be_to_cpu_32(tcphdr->recv_ack);
	
	if(conn_item->buf_send){
                rte_pktmbuf_free(conn_item->buf_send);
                conn_item->buf_send=NULL;
        }

        conn_item->buf_send = rte_pktmbuf_alloc(mbuf_pool);
        buf_send = conn_item->buf_send;

	int res2 = gethdr(buf_send,ether_type,&eth_send,&ip_send,&ip6_send,&tcp_send);
	if(res2!=1)
                goto discard_packet;
	/*eth_send = rte_pktmbuf_mtod(buf_send, struct ether_hdr*);
        if(ether_type == ETH_P_IP)
        {
                ip_send = (struct ipv4_hdr *)(ethhdr + 1);
                tcp_send = (struct tcp_hdr *)((unsigned char *)iphdr +sizeof(struct ipv4_hdr));
        }
        else if(ether_type == ETH_P_IPV6)
        {
                ip6_send = (struct ipv6_hdr *)(ethhdr + 1);
                tcp_send = (struct tcp_hdr *)((unsigned char *)ip6hdr +sizeof(struct ipv4_hdr));
        }*/
	
	//补充tcp报头
	memset(tcphdr,0,sizeof(struct tcp_hdr));
	tcp_send->src_port = tcphdr->dst_port;
        tcp_send->dst_port = tcphdr->src_port;
        tcp_send->sent_seq = rte_be_to_cpu_32(tcphdr->sent_seq);
        tcp_send->recv_ack = rte_be_to_cpu_32(tcphdr->recv_ack+1);
        tcp_send->data_off = 0x50;
        tcp_send->tcp_flags &= ~TCP_RST_FLAG;//rst=0
        tcp_send->tcp_flags |= TCP_ACK_FLAG; //ack=1
	tcp_send->tcp_urp = 0;
        tcp_send->rx_win=rte_cpu_to_be_16(65535);

        //补充ip，ip6报头
        if(ether_type == ETH_P_IP)
        {
                rte_memcpy(ip_send,iphdr,sizeof(struct ipv4_hdr));
		ip_send->time_to_live = 128;
                ip_send->total_length = rte_cpu_to_be_16(sizeof(struct ipv4_hdr)+sizeof(struct tcp_hdr));
                ip_send->version_ihl = 0x45;
                ip_send->next_proto_id = IPPROTO_TCP;
                ip_send->src_addr = iphdr->dst_addr;
                ip_send->dst_addr = iphdr->src_addr;
                ip_send->hdr_checksum = 0;
		ip_send->hdr_checksum = rte_ipv4_cksum(ip_send);

		tcp_send->cksum = 0;
                tcp_send->cksum = rte_ipv4_udptcp_cksum(ip_send,tcp_send);
	}
	else if(ether_type == ETH_P_IPV6)
        {
                rte_memcpy(ip6_send,ip6hdr,sizeof(struct ipv6_hdr));
                ip6_send->hop_limits=128;
                ip6_send->payload_len=htons(sizeof(struct ipv6_hdr)+sizeof(struct tcp_hdr));
                ip6_send->proto=IPPROTO_TCP;

                rte_memcpy(ip6_send->src_addr,ip6hdr->dst_addr,IPV6_ADDR_LEN);
                rte_memcpy(ip6_send->dst_addr,ip6hdr->src_addr,IPV6_ADDR_LEN);

		tcp_send->cksum = 0;
                tcp_send->cksum = rte_ipv6_udptcp_cksum(ip6_send,tcp_send);
        }
	else
                goto discard_packet;
	
	//mac
	ether_addr_copy(&ethhdr->d_addr,&eth_send->s_addr);
        ether_addr_copy(&ethhdr->s_addr,&eth_send->d_addr);
        eth_send->ether_type = ethhdr->ether_type;

	conn_item->last_send_ack_seq=conn_item->last_recv_seq+1;
	time(&conn_item->time);
	conn_item->stat=TCP_CLOSE;

	dpdk_forward(conn_item->buf_send,port);

	return 1;

discard_packet:

        return 0;
}

static void redirect_packet(struct rte_mbuf*bufs,uint8_t port)
{
	struct connection_state_item * conn_item=NULL;

	uint16_t type;
	struct ether_hdr *ethhdr=NULL;
	struct ipv4_hdr *iphdr=NULL;
	struct ipv6_hdr *ip6hdr=NULL;
	struct tcp_hdr *tcphdr=NULL;
	uint32_t s_ipv4,d_ipv4;
	uint8_t s_ipv6[IPV6_ADDR_LEN],d_ipv6[IPV6_ADDR_LEN];
	uint16_t  s_port,d_port;
	uint32_t recv_seq,recv_ack_seq;

	uint32_t hdrlen=0;
	uint32_t buflen=0;

	if(bufs==NULL)
		goto discard_packet;

	int res = gethdrinfo(bufs,&type,&ethhdr,&iphdr,&ip6hdr,&tcphdr);
	if(res!=1)
		goto discard_packet;

	if(type==ETH_P_IP)
	{
		s_ipv4=iphdr->src_addr;
		d_ipv4=iphdr->dst_addr;
	}
	else if(type==ETH_P_IPV6)
	{
		memcpy(s_ipv6,ip6hdr->src_addr,IPV6_ADDR_LEN);
		memcpy(d_ipv6,ip6hdr->dst_addr,IPV6_ADDR_LEN);
	}
	else
	{
		printf("not ip or ip6\n");
		goto discard_packet;
	}

	s_port = rte_be_to_cpu_16(tcphdr->src_port);
	d_port = rte_be_to_cpu_16(tcphdr->dst_port);
	recv_seq=rte_be_to_cpu_32(tcphdr->sent_seq);
	printf("recv_seq:%x",recv_seq);
	recv_ack_seq=rte_be_to_cpu_32(tcphdr->recv_ack);	
	
	if(type == ETH_P_IP){
		conn_item=conn_find_v4(s_ipv4, d_ipv4, s_port, d_port);
	}else if(type == ETH_P_IPV6){
		conn_item=conn_find_v6(s_ipv6, d_ipv6, s_port, d_port);
	}
	
	//没有找到就分配一个
	if(conn_item==NULL){// syn
		conn_item=conn_item_alloc();
	}
	if(conn_item==NULL){//
		printf("conn_item is null\n");
		goto discard_packet;
	}

	if(tcphdr->tcp_flags&TCP_RST_FLAG)//如果你得到的数据段设置了rst位，那说明你这一端有了问题。所以关闭该端
	{
		printf("rst was set\n");
		conn_item->stat=TCP_CLOSE;
		goto discard_packet;
	}

	printf("bufs->pkt_len:%d,bufs->data_len:%d\n",bufs->pkt_len,bufs->data_len);
	switch(conn_item->stat)//policy:重发，状态迁移，忽略
	{
		case TCP_LISTEN:
			printf("!!!!!!!!!!!!!!!!!!!TCP_LISTEN!!!!!!!!!!!!!!!\n");
			if((tcphdr->tcp_flags&TCP_SYN_FLAG)&&(!(tcphdr->tcp_flags&TCP_ACK_FLAG)))
			{
				conn_item->type=type;

				if(type == ETH_P_IP){
					conn_item->d_ipv4=d_ipv4;
					conn_item->s_ipv4=s_ipv4;
				}else if(type == ETH_P_IPV6){
					memcpy(&conn_item->s_ipv6,s_ipv6,IPV6_ADDR_LEN);
					memcpy(&conn_item->d_ipv6,d_ipv6,IPV6_ADDR_LEN);
				}
				
				conn_item->s_port=s_port;
				conn_item->d_port=d_port;
				printf("tcp srcport:%d, dstport:%d\n",s_port,d_port);			
				my_tcp_listen_2_syn_recv(conn_item,bufs,port); //监听到连接请求
			}
			break;
		case TCP_SYN_RECV: 
			printf("!!!!!!!!!!!!!!!!!!!TCP_SYN_RECV!!!!!!!!!!!!!!\n");
			if(recv_seq==conn_item->last_send_ack_seq && recv_ack_seq==conn_item->last_send_seq && ((tcphdr->tcp_flags)&TCP_ACK_FLAG)){
				printf("握手啦\n");
				my_tcp_syn_recv_2_establish(conn_item,bufs,type);
				break;
			}
			//发送失败，重新发送
			if(recv_seq==conn_item->last_recv_seq && recv_ack_seq ==conn_item->last_recv_ack_seq){
				printf("重新发送\n\n");
				dpdk_forward(conn_item->buf_send,port);
				break;
			}

			break;
		case TCP_ESTABLISHED:   
			if(type==ETHER_TYPE_IPv4)
				hdrlen=sizeof(struct ether_hdr)+sizeof(struct ipv4_hdr)+sizeof(struct tcp_hdr);
			else if(type==ETHER_TYPE_IPv6)
				hdrlen=sizeof(struct ether_hdr)+sizeof(struct ipv6_hdr)+sizeof(struct tcp_hdr);
			buflen=bufs->pkt_len - hdrlen - 6;//为什么多出来4个
			printf("!!!!!!!!!!!!!!!!!!!!TCP_ESTABLISHED!!!!!!!!!!!!!!\n");
			printf("recv_seq:%x,conn_item->last_send_ack_seq:%x\n",recv_seq,conn_item->last_send_ack_seq);
			printf("recv_ack_seq:%x, conn_item->last_send_seq:%x\n",recv_ack_seq,conn_item->last_send_seq);
			printf("hdrlen:%d,buflen:%d,datalen:%d\n",hdrlen,buflen,bufs->data_len);
			if(recv_seq==conn_item->last_send_ack_seq && recv_ack_seq==conn_item->last_send_seq  && (tcphdr->tcp_flags&TCP_ACK_FLAG)){
				printf("will enter tcp_established\n");
				if(  (tcphdr->tcp_flags&TCP_PSH_FLAG) && (buflen>0)  ){
					my_tcp_establish_http_reply(conn_item,bufs,port);
					break;
				}
				
				if(  (!(tcphdr->tcp_flags&TCP_PSH_FLAG)) &&  (buflen==0)  ){
					my_tcp_establish_2_fin_wait1(conn_item,bufs,port);
					break;
				}
				
				break;
			}
			
			else if(recv_seq==conn_item->last_recv_seq && recv_ack_seq ==conn_item->last_recv_ack_seq){
				printf("重传\n");
				dpdk_forward(conn_item->buf_send,port^1);
				break;
			}

			break;
		case TCP_FIN_WAIT1:
			printf("!!!!!!!!!!!!!!!!!!!!TCP_FIN_WAIT1!!!!!!!!!!!!!!!!!\n");
			printf("recv_seq:%x,conn_item->last_send_ack_seq:%x\n",recv_seq,conn_item->last_send_ack_seq);
			printf("recv_ack_seq:%x,conn_item->last_send_seq:%x\n",recv_ack_seq,conn_item->last_send_seq);
		
			if(recv_seq==conn_item->last_send_ack_seq && recv_ack_seq==conn_item->last_send_seq  && (tcphdr->tcp_flags&TCP_ACK_FLAG)){
				if((tcphdr->tcp_flags&TCP_FIN_FLAG)){//fin=1,ack=1
					my_tcp_fin_wait1_2_time_wait(conn_item,bufs,port);//TCP_CLOSE fin=0,ack=1
				}else{
					my_tcp_fin_wait1_2_fin_wait2(conn_item,bufs,type);//TCP_FIN_WAIT2
				}
				break;
			}

			break;
		case TCP_FIN_WAIT2:
			printf("!!!!!!!!!!!!!!!!!!!!TCP_FIN_WAIT2!!!!!!!!!!!!!!!!!\n");
			printf("recv_seq:%x,conn_item->last_send_ack_seq:%x\n",recv_seq,conn_item->last_send_ack_seq);
			printf("recv_ack_seq:%x,conn_item->last_send_seq:%x\n",recv_ack_seq,conn_item->last_send_seq);

			if(recv_seq==conn_item->last_send_ack_seq && recv_ack_seq==conn_item->last_send_seq  && (tcphdr->tcp_flags&TCP_ACK_FLAG)){
				printf("before enter TCP_FIN_FLAG\n");
				if(tcphdr->tcp_flags&TCP_FIN_FLAG)
					my_tcp_fin_wait2_2_timewait(conn_item,bufs,port); //TCP_CLOSE
			}

			break;
		default:
			break;
	}
	
discard_packet:
	printf("redirect_packet discard_packet\n");
	if(bufs)
		rte_pktmbuf_free(bufs);
	if(conn_item){
		if(conn_item->stat==TCP_LISTEN || conn_item->stat==TCP_CLOSE){
			conn_item_free(conn_item);
		}else{
			conn_insert(conn_item);
		}
	}
}

static void conn_table_check_timeout(uint16_t sig)
{
	if(SIGALRM == sig)
	{
		struct connection_state_item * pcurrent = NULL;
		struct connection_state_item * pchecking= NULL;

		time_t current_time;
		time(&current_time);

		pthread_mutex_lock(&conn_stat_mutex);

		pcurrent=conn_stat_table.next;
		while(pcurrent != &conn_stat_table)
		{
			pchecking=pcurrent;
			pcurrent=pcurrent->next;
	
			if(pchecking->time+redirect_timeout< current_time){ //超时了
				list_del((struct list_head*)pchecking);
				conn_item_free(pchecking);
			}
		}
	
		pthread_mutex_unlock(&conn_stat_mutex);
		
		alarm(redirect_timeout);
	}
	return;
}


int  init_cap_redirect(void)
{
	signal(SIGALRM, conn_table_check_timeout);//relate the signal and function  

	alarm(redirect_timeout);//trigger the timer  

	pthread_mutex_init(&conn_stat_mutex,NULL);
	pthread_mutex_init(&free_stat_mutex,NULL);
	pthread_mutex_init(&redirect_paras_mutex,NULL);

	int result=conn_table_init();

	if(result)
		return result;
	set_redirect_url("http://www.edu.cn");
	
	return 0;
}

void  exit_cap_redirect(void)
{
	conn_table_exit();

	pthread_mutex_destroy(&conn_stat_mutex);
	pthread_mutex_destroy(&free_stat_mutex);
	pthread_mutex_destroy(&redirect_paras_mutex);

	return ;
}

/*static unsigned short checksum(unsigned short *buf, int buf_len)
{
    unsigned long checksum = 0;

    while (buf_len > 1)
    {
        checksum += *buf++;
        buf_len -= sizeof(unsigned short);
    }

    if (buf_len)
    {
        checksum += *(unsigned char *)buf;
    }

    checksum = (checksum >> 16) + (checksum & 0xffff);
    checksum += (checksum >> 16);

    return (unsigned short)(~checksum);
}

static void checksumtest(struct rte_mbuf*bufs,uint8_t port,struct rte_mempool *pool)
{
	printf("checksumtest\n");
	struct ether_hdr *ethhdr=NULL;
        struct ipv4_hdr *iphdr=NULL;
        struct ipv6_hdr *ip6hdr=NULL;
        struct tcp_hdr *tcphdr=NULL;
        uint16_t ether_type;

	int res = gethdrinfo(bufs,&ether_type,&ethhdr,&iphdr,&ip6hdr,&tcphdr);
	printf("ether_type:%x\n",ether_type);
	
	unsigned short check_Buff[65500]; //校验和缓存区
	
        if(res!=1)
        {
                printf("get head info failed\n");
                goto discard_packet;
        }
        if((ether_type!=ETH_P_IP)&&(ether_type!=ETH_P_IPV6))
	{
		printf("not ip or ip6\n");
                goto discard_packet;
	}
	if(ether_type==ETH_P_IP)
        {
		printf("ip->hdr_checksum:%x\n",iphdr->hdr_checksum);
		int hdr_len = (iphdr->version_ihl & IPV4_HDR_IHL_MASK) * IPV4_IHL_MULTIPLIER;
		printf("sizeof(struct ipv4_hdr):%d,hdr_len:%d,sizeof(*iphdr):%d\n",sizeof(struct ipv4_hdr),hdr_len,sizeof(*iphdr));
		iphdr->dst_addr = iphdr->src_addr;
		iphdr->src_addr = 0;
		
		iphdr->hdr_checksum = 0;
		unsigned short checksumres = checksum((unsigned short *)iphdr,hdr_len);
		printf("checksumres:%x\n",checksumres);
        }
        else if(ether_type==ETH_P_IPV6)
        {
		return;
        }
	if(tcphdr==NULL)
	{
		printf("!!!!!tcphdr is null\n");
                goto discard_packet;
	}
	
	//tcp校验和	
	//unsigned short check_Buff[65500]; //校验和缓存区	
	PSD_HEADER psd_header={0};         //TCP伪首部结构
	psd_header.saddr=iphdr->src_addr;    //源地址	
	psd_header.daddr=iphdr->dst_addr;    //源地址   
	psd_header.mbz=0;
	psd_header.ptcl=iphdr->next_proto_id;
	psd_header.tcpl=htons(sizeof(struct tcphdr));
	//tcp->dataoff - ip->length
	printf("!!!!!!!!!!!!!!!!!!!tcp->cksum:%x, ",tcphdr->cksum);
	tcphdr->cksum = 0;
	memset(check_Buff,0,65500);
	memcpy(check_Buff,&psd_header,sizeof(PSD_HEADER));
	memcpy(check_Buff+sizeof(PSD_HEADER),tcphdr,sizeof(*tcphdr));
	tcphdr->cksum = checksum(check_Buff,sizeof(PSD_HEADER)+sizeof(*tcphdr));
	printf("tcp->cksum later2:%x!!!!!!!!!!!!!\n",tcphdr->cksum);
	//mac
	struct ether_hdr *eth = (struct ether_hdr*)malloc(sizeof(struct ether_hdr));
	ether_addr_copy(&eth->d_addr, &ethhdr->d_addr);
        ether_addr_copy(&eth->s_addr, &ethhdr->s_addr);

        ether_addr_copy(&ethhdr->d_addr, &eth->s_addr);
	ether_addr_copy(&ethhdr->s_addr, &eth->d_addr);
	
	dpdk_forward(bufs,port^1);
	
discard_packet:
	printf("discard_packet\n");
	printf("\n\n");
	return;	
}*/

unsigned short redirect_ports[8]={80,81,88,8080,8081,8088,};
int                   redirect_ports_count=6;


void redirected_skb_enqueue(struct rte_mbuf*bufs,uint8_t port,struct rte_mempool *pool)
{
	//just for test
	
	//set_redirect_url("http://www.edu.cn");
	//set_redirect_url("http://192.168.0.43");

	printf("\n@@@@@@@@@@@@@@enqueue@@@@@@@@@@@@@@@@@@@@@\n");
	printf("bufs->pktlen:%d\n",bufs->pkt_len);
	mbuf_pool = pool;

	int i;
	int matched=0;
	
	struct ether_hdr *ethhdr=NULL;
	struct ipv4_hdr *iphdr=NULL;
	struct ipv6_hdr *ip6hdr=NULL;
	struct tcp_hdr *tcphdr=NULL;
	uint16_t ether_type;
	
	int res = gethdrinfo(bufs,&ether_type,&ethhdr,&iphdr,&ip6hdr,&tcphdr);
	
        if(res!=1)
        {
                printf("get head info failed\n");
                goto discard_packet;
        }
	if((ether_type!=ETH_P_IP)&&(ether_type!=ETH_P_IPV6))
		goto discard_packet;

	if(ether_type==ETH_P_IP)
	{
		showip(iphdr);
	}
	else if(ether_type==ETH_P_IPV6)
	{
		showip6(ip6hdr);
	}
	if(tcphdr==NULL)
                goto discard_packet;
	printf("\n\n=========================\ntcphdr srcport:%d,dstport:%d\n", rte_be_to_cpu_16(tcphdr->src_port),rte_be_to_cpu_16(tcphdr->dst_port));
	printf("tcphdr->sent_seq:%d\n",ntohl(tcphdr->sent_seq));
	/*if(ether_type==ETH_P_IP)
	{
		if(bufs->pkt_len<sizeof(struct ipv4_hdr))
			goto discard_packet;
	}
	pkt_len*/
	for(i=0;i<redirect_ports_count;i++){
		if( redirect_ports[i] == ntohs(tcphdr->dst_port) ){  //提取目的端口号
			matched=1;
			break;
		}
	}
	if( ! matched )
		goto discard_packet;

	//checksumtest(bufs,port,pool);
	//printf("\n\n");
        //return ;	
	redirect_packet(bufs,port);
	printf("\n\n");
	return;

discard_packet:
	printf("dpdk_forward\n");
	dpdk_forward(bufs,port^1);
	return ;
}
