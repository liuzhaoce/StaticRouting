#ifndef __ARPCACHE_H__
#define __ARPCACHE_H__

#include "base.h"
#include "types.h"
#include "list.h"

#include <pthread.h>

#define MAX_ARP_SIZE 32
#define ARP_ENTRY_TIMEOUT 15
#define ARP_REQUEST_MAX_RETRIES	5

struct cached_pkt {  //缓存数据包结构体
	struct list_head list; //串联不同数据包的链表节点
	char *packet;          //数据包指针
	int len;               //长度
};

struct arp_req {  //arp请求
	struct list_head list;    //用于串联不同arp_seq的链表节点
	iface_info_t *iface;      //转发数据包的端口
	u32 ip4;       //请求对应的ip地址
	time_t sent;   //arp数据包发送之后经历的时间
	int retries;   //arp数据包的发送次数
	struct list_head cached_packets; //目的地址为该ip地址的数据包列表
};

struct arp_cache_entry { //arp缓存条目
	u32 ip4; 	// stored in host byte order
	u8 mac[ETH_ALEN];//缓存对应的mac地址
	time_t added;   //在条目中存在的时间
	int valid;      //是否有效
};

typedef struct {
	struct arp_cache_entry entries[MAX_ARP_SIZE];//ARP缓存条目，总共有32条
	struct list_head req_list;                   //等待ARP回复的IP列表，指向arp_req
	pthread_mutex_t lock;                        //ARP查询、更新操作锁
	pthread_t thread;                            //老化操作对应的线程
} arpcache_t;

void arpcache_init();
void arpcache_destroy();
void *arpcache_sweep(void *);

int arpcache_lookup(u32 ip4, u8 mac[]);
void arpcache_insert(u32 ip4, u8 mac[]);
void arpcache_append_packet(iface_info_t *iface, u32 ip4, char *packet, int len);

#endif
