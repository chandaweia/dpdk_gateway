#ifndef IPV6_SS_MAIN_H
#define IPV6_SS_MAIN_H 
//#include <linux/ipv6.h>
#include <netinet/ip6.h>

int  cap_ipv6_ss_init(void);
unsigned long 	get_ipv6_status(unsigned char*ip);
void get_ipv6_all(struct trans_ioctl_ipv6 *attr);
int  set_ipv6_status(unsigned char * netprefix,unsigned long prefixlen,unsigned long status);
unsigned long transfer_test_and_merge_flow6(struct ip6_hdr *ipv6h);
int print_ipv6_memory_info(void);
void  cap_ipv6_ss_exit(void);
#endif
