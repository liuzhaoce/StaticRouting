#include "packet.h"
#include "types.h"
#include "ether.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <errno.h>

extern ustack_t *instance;

void iface_send_packet(iface_info_t *iface, char *packet, int len)
{
	struct sockaddr_ll addr;//数据链路层的头信息结构体，并初始化相关信息
	memset(&addr, 0, sizeof(struct sockaddr_ll));
	addr.sll_family = AF_PACKET;            //通常设置
	addr.sll_ifindex = iface->index;        //结构index索引
	addr.sll_halen = ETH_ALEN;              //mac地址的长度
	addr.sll_protocol = htons(ETH_P_ARP);  //将实际内存中的整数存放方式调整为网络字节顺序

  struct ether_header *eh = (struct ether_header *)packet;
	memcpy(addr.sll_addr, eh->ether_dhost, ETH_ALEN);

	if (sendto(iface->fd, packet, len, 0, (const struct sockaddr *)&addr,
				sizeof(struct sockaddr_ll)) < 0) {
		printf("errno is %d\n",errno);
 		perror("Send raw packet failed");
	}

	free(packet);
}
