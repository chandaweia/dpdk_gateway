#ifndef REDIRECT_H_
#define REDIRECT_H_

#define IPV6_ADDR_LEN 16

//struct connection_state_item;
struct connection_state_item{
	struct connection_state_item * next;	
	struct connection_state_item * prev;

	unsigned short stat;
	uint16_t type;  //协议类型
	time_t time; //单位秒

	union{	
		uint32_t s_ipv4;	
		uint8_t s_ipv6[IPV6_ADDR_LEN];
	};

	union{
		uint32_t d_ipv4;
		uint8_t d_ipv6[IPV6_ADDR_LEN];
	};
	
	uint16_t  s_port;
	uint16_t  d_port;


	uint32_t last_recv_seq;
	uint32_t last_recv_ack_seq;

	uint32_t last_send_seq;
	uint32_t last_send_ack_seq;
	
	struct rte_mbuf *buf_send;
};

typedef struct _psdhdr
{
	uint32_t saddr;           //源地址 4字节
	uint32_t daddr;           //目的地址 4字节
	uint8_t mbz;             //没用 1字节
	uint8_t ptcl;              //协议类型 1字节
	uint16_t tcpl;             //TCP长度 2字节
}PSD_HEADER;

typedef struct _tcpopt
{
	uint32_t opt1;
	uint32_t opt2;
	uint32_t opt3;
	
}TCP_OPT;

void redirected_skb_enqueue(struct rte_mbuf *bufs,uint8_t port,struct rte_mempool *mbuf_pool);
int conn_table_init(void);
int get_redirect_timeout(void);
void set_redirect_timeout(int timeout);
void get_redirect_url(char * url_buffer);
void set_redirect_url(char *url);
int  init_cap_redirect(void);
void  exit_cap_redirect(void);

#endif
