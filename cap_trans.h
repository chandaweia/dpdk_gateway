#ifndef AF_TRANS_H
#define AF_TRANS_H
#include <stdint.h>
//#include <linux/ioctl.h>

#include <linux/types.h>

#define AF_TRANS	28
#define PF_TRANS	AF_TRANS

#define CAP_TRANS_IOCTL					         113

#define CAP_TRANS_IOCTL_UP					        _IOW(CAP_TRANS_IOCTL,0x01,int)
#define CAP_TRANS_IOCTL_DOWN				        _IOW(CAP_TRANS_IOCTL,0x02,int)
#define CAP_TRANS_IOCTL_SET_DEVICE			        _IOW(CAP_TRANS_IOCTL,0x03,int)
#define CAP_TRANS_IOCTL_GET_DEVICE                  _IOW(CAP_TRANS_IOCTL,0x04,int)

#define CAP_TRANS_IOCTL_IPV4_SET			        _IOW(CAP_TRANS_IOCTL,0x41,int)
#define CAP_TRANS_IOCTL_IPV4_GET			        _IOW(CAP_TRANS_IOCTL,0x42,int)
#define CAP_TRANS_IOCTL_IPV4_GET_ALL		        _IOW(CAP_TRANS_IOCTL,0x43,int)
#define CAP_TRANS_IOCTL_IPV4_PRINT                  _IOW(CAP_TRANS_IOCTL,0x44,int)

#define CAP_TRANS_IOCTL_IPV6_SET			        _IOW(CAP_TRANS_IOCTL,0x61,int)
#define CAP_TRANS_IOCTL_IPV6_GET			        _IOW(CAP_TRANS_IOCTL,0x62,int)
#define CAP_TRANS_IOCTL_IPV6_GET_ALL		        _IOW(CAP_TRANS_IOCTL,0x63,int)
#define CAP_TRANS_IOCTL_IPV6_PRINT                  _IOW(CAP_TRANS_IOCTL,0x64,int)

#define CAP_TRANS_IOCTL_SET_REDIRECT        		_IOW(CAP_TRANS_IOCTL,0x91,int)
#define CAP_TRANS_IOCTL_GET_REDIRECT        		_IOW(CAP_TRANS_IOCTL,0x92,int)




#define  TF_SCOPE_MASK  		 0x80000000 //������־
#define  TF_ADDRESS_MASK         0x00000001 //��ַ��־��������ָ�뻹��IPvx��ַ�����ԣ�
#define  IPVI_NO_LOGIN	         0x00000010 //��ר���û���־


#define  IPVI_BLOCK              0x80000001
#define  IPVI_UNAUTH             0x80000101
#define  IPVI_NATIVE             0x80000201 //������У԰����
#define  IPVI_PINER              0x80000401 //�����ڣ���ѵ�ַ�б�����е�ַ�Σ�
#define  IPVI_PRESTRICT          0x80000801 //�����ʣ���ѵ�ַ�б�֮������е�ַ�Σ�
#define  IPVI_INTER              0x80000601 //�����ڣ�����
#define  IPVI_ALL_AI             0x80000A01 //�����ʣ�����
#define  IPVI_ALL_CN             0x80000C01 //�����ʣ�������(���е�ַ�Σ�����)
#define  IPVI_ALL                0x80000E01 //�����ʣ������ڣ����������е�ַ�Σ�

#define  IPVO_BLOCK              0x00000001
#define  IPVO_NATIVE             0x00000201
#define  IPVO_INTER              0x00000401
#define  IPVO_RESTRICT           0x00000801
#define  IPVO_FREE               0x00FFFF01



#define  TF_ALL_FLAG_MASK	     0x00FFFF00 //���б�־λ
#define  TF_MAIN_FLAG_MASK	     0x0000FF00 //����־λ
#define  TF_OTHER_FLAG_MASK      0x00FF0000 //������־λ

#define  TF_GET_ALL_ATTR(x)      (x&TF_ALL_FLAG_MASK)    	//ȡ��16����־λ
#define  TF_GET_MAIN_ATTR(x)     (x&TF_MAIN_FLAG_MASK)   	//ȡ��8������־λ
#define  TF_GET_OTHER_ATTR(x)    (x&TF_OTHER_FLAG_MASK)   	//ȡ��8��������־λ



#define IPVI_DEFAULT			IPVI_UNAUTH   
#define IPVO_DEFAULT			IPVO_RESTRICT

//#define  __u32  uint32_t
//#define  __u64  uint64_t



struct trans_ioctl_transfer	{
	unsigned long trans_up;
	char	inner[32];
	char	outer[32];
};




struct trans_ioctl_redirect	{
	int      timeout;
	char     url[256];
};



#define NETKEYLENGTHIPV6     16
#define NETKEYLENGTHIPV4     4

struct trans_ioctl_ipv6 {
	unsigned char net[NETKEYLENGTHIPV6];
	unsigned long prefixlength;
	unsigned long status;

  	__u32 lasttime_in;   //����������������ݰ���ʱ��
  	__u32 lasttime_out;  
  	__u64 bytes_in;      //�ƷѵĽ�������
  	__u64 bytes_out;
  	__u64 bytesN_in;     //������ѵ�ַ��������
  	__u64 bytesN_out;
  	__u32 pkts_in;        //���������������ݰ�����
  	__u32 pkts_out;	
};

struct trans_ioctl_ipv4 {
	unsigned char net[NETKEYLENGTHIPV4];
	unsigned long prefixlength;
	unsigned long status;

  	__u32 lasttime_in;   //����������������ݰ���ʱ��
  	__u32 lasttime_out;  
  	__u64 bytes_in;      //�ƷѵĽ�������
  	__u64 bytes_out;
  	__u64 bytesN_in;     //������ѵ�ַ��������
  	__u64 bytesN_out;
  	__u32 pkts_in;        //���������������ݰ�����
  	__u32 pkts_out;	
};



static inline unsigned long transfer_test_with_status(unsigned long scntl ,unsigned long dcntl)
{
	if(  (scntl ^ dcntl) & TF_SCOPE_MASK ) {// inner and outer
		return (scntl & dcntl & TF_ALL_FLAG_MASK);
	}
	else if( scntl & dcntl & TF_SCOPE_MASK ){//s and d are both inter
		return 1;// without checking priviledge,mayby 
	}
	else {// both outer
		return 0;
	}
}	


static inline int is_address_valid(unsigned long status)
{
	if(  (status & TF_ADDRESS_MASK) != TF_ADDRESS_MASK)//�ǵ�ַ����ָ��
		return 0;
	
	if(  (status & TF_SCOPE_MASK)   != TF_SCOPE_MASK  )//����
		return 0;
	
	if(  (status & IPVI_NO_LOGIN)   == IPVI_NO_LOGIN  )//ר��
		return 0;

	return 1;
}

static inline int can_address_login_now(unsigned long status)
{
	if(is_address_valid(status) == 0)
		return 0;

	if(  (status & IPVI_UNAUTH )    !=  IPVI_UNAUTH   )//�Ѿ���¼
		return 0;

	return 1;
}



static inline int has_address_logined_now(unsigned long status)
{
	if(is_address_valid(status) == 0)
		return 0;

	if(  (status & IPVI_UNAUTH )    ==  IPVI_UNAUTH   )//û�е�¼
		return 0;

	return 1;
}


#endif
