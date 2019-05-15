#include "ip.h"
#include "icmp.h"
#include "rtable.h"
#include "arp.h"
#include "arpcache.h"

#include <stdio.h>
#include <stdlib.h>

// forward the IP packet from the interface specified by longest_prefix_match,
// when forwarding the packet, you should check the TTL, update the checksum,
// determine the next hop to forward the packet, then send the packet by
// iface_send_packet_by_arp

void ip_forward_packet(u32 ip_dst, char *packet, int len)
{
	struct iphdr* ip = packet_to_ip_hdr(packet);

	ip->ttl -= 1;
	if(ip->ttl <= 0){//check the TTL
		icmp_send_packet(packet, len, ICMP_TIME_EXCEEDED , ICMP_NET_UNREACH);
		free(packet);
		return;
	}

	u32 daddr = ip_dst;
	rt_entry_t* my_entry = longest_prefix_match(daddr);//longest prefix match

	if(!my_entry){
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH , ICMP_NET_UNREACH);
		free(packet);
		return;
	}

	ip->checksum = ip_checksum(ip);//update the checksum

	u32 next_hop = my_entry->gw;
	if (!next_hop)
		next_hop = ntohl(ip->daddr);//determine the next hop

	iface_send_packet_by_arp(my_entry->iface, next_hop, packet, len);
}

// handle ip packet
//
// If the packet is ICMP echo request and the destination IP address is equal to
// the IP address of the iface, send ICMP echo reply; otherwise, forward the
// packet.
void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr* ip = packet_to_ip_hdr(packet);
	u32 daddr = ntohl(ip->daddr);

	if(daddr == iface->ip){//if dst IP equal to add of iface
	  icmp_send_packet(packet, len, ICMP_ECHOREPLY, ICMP_NET_UNREACH);
		free(packet);
		return;
	}
	else{
		ip_forward_packet(daddr,packet,len);//forward the packet
	}
}
