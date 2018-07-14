#ifndef IPV4_SS_MAIN_H
#define IPV4_SS_MAIN_H 
#include <netinet/ip.h>
#include "cap_trans.h"
int cap_ipv4_ss_init(void);

void cap_ipv4_ss_exit(void);

unsigned long get_ipv4_status(unsigned char*ip);

void get_ipv4_all(struct trans_ioctl_ipv4 *attr);

int set_ipv4_status(unsigned char * netprefix,unsigned long prefixlen,unsigned long status);

unsigned long transfer_test_and_merge_flow4(struct iphdr*ipv4h);

int print_ipv4_memory_info(void);

#endif
