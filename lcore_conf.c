#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "lcore_conf.h"
struct lcore_conf lcore_conf[RTE_MAX_LCORE];
     
int init_lcore_conf(struct lcore_conf *lcore_conf){
	 uint16_t i, length;
	 uint8_t lcore_id;
   
	 if(lcore_conf==NULL){
		 printf("parameter:lcore_conf is null\n");
		 return -1;
	 }
     for(i = 0; i < nb_lcore_params; i++) {
		  lcore_id=lcore_params[i].lcore_id;
		  length=lcore_conf[lcore_id].length;
		  if(length >= MAX_RX_QUEUE_PER_LCORE){
			     printf("error: too many queues for lcore: %u\n",(unsigned)lcore_id);
				 return -1;
		  }else{
				 lcore_conf[lcore_id].port_queue_list[length].rx_port_id=lcore_params[i].port_id;
				 lcore_conf[lcore_id].port_queue_list[length].rx_queue_id=lcore_params[i].queue_id;
                 lcore_conf[lcore_id].port_queue_list[length].tx_port_id=lcore_params[i].port_id^1;
				 lcore_conf[lcore_id].port_queue_list[length].tx_queue_id=0;
				 lcore_conf[lcore_id].length++;
		  }
	 }    
     return 0;  	
}

int parse_config(char *arg)
{
     char *p,*str,*q,*psub;
     int i=0,j,m=0;
	 char substr[16][64]={0};
     char *ptr[16]={NULL};

	 str=arg;
	 while((p=strchr(str,'('))!=NULL){
		 if((q=strchr(p,')'))!=NULL){
             strncpy(substr[i],p+1,q-p-1);
			 i++;
			 str=q;
		 }else{
			 printf("miss )\n");
			 return -1;
		 }
	 }
	 if((unsigned)(str-arg+1)!=strlen(arg)){
		 printf("format of param is wrong\n");
		 return -1;
	 }
     nb_lcore_params=i;
	 for(j=0;j<i;j++){
		 printf("substr[%d]:%s\n",j,substr[j]);
		 psub=substr[j];
		 if(psub==NULL)
		     return -1;
		 m=0;
		 while((ptr[m]=strtok(psub,","))!=NULL){
			 switch(m){
				 case 0:
					 lcore_params_array[j].port_id=atoi(ptr[m]);
					 printf("port:%d\n",atoi(ptr[m]));break;
				 case 1:
					 lcore_params_array[j].queue_id=atoi(ptr[m]);
					 printf("queue:%d\n",atoi(ptr[m]));break;
				 case 2:
					 lcore_params_array[j].lcore_id=atoi(ptr[m]);
					 printf("lcore:%d\n",atoi(ptr[m]));break;
				 default:
					 printf("wrong m value\n");
					 return -1;
			 }
			 m++;
			 psub=NULL;
		 }
	 }
	 lcore_params=lcore_params_array;
	 return 0;
}

