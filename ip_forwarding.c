#include "ip.h"
#include "ip_forwarding.h"
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
	struct iphdr* my_iph = packet_to_ip_hdr(packet);
	rt_entry_t* my_entry = longest_prefix_match(ip_dst);

	//failed in looking up
	if(!my_entry){
		u32 dst = ntohl(my_iph->saddr);
       	rt_entry_t* my_entry = longest_prefix_match(dst);
		u32 sip = my_entry->iface->ip;
		icmp_send_packet(packet, len, 3, 0, sip);
		free(packet);
		return;
	}

	//TTL - 1 <= 0
	my_iph->ttl -= 1;
	if(my_iph->ttl <= 0){
        u32 dst = ntohl(my_iph->saddr);
        rt_entry_t* my_entry = longest_prefix_match(dst);
        u32 sip = my_entry->iface->ip;
		icmp_send_packet(packet, len, 11, 0,sip);
		free(packet);
		return;
	}

	my_iph->checksum = ip_checksum(my_iph);//update checksum

	u32 next_hop = my_entry->gw;
	if (!next_hop)
		next_hop = ntohl(my_iph->daddr);//determine the next hop

	iface_send_packet_by_arp(my_entry->iface, next_hop, packet, len);
}


// handle ip packet
//
// If the packet is ICMP echo request and the destination IP address is equal to
// the IP address of the iface, send ICMP echo reply; otherwise, forward the
// packet.
void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ip = packet_to_ip_hdr(packet);
	u32 daddr = ntohl(ip->daddr);
	if (daddr == iface->ip) {
		u32 dst = ntohl(ip->saddr);
    rt_entry_t* my_entry = longest_prefix_match(dst);
    u32 sip = my_entry->iface->ip;

		icmp_send_packet(packet, len, 0, 0, sip);
		free(packet);
	}
	else {
		ip_forward_packet(daddr, packet, len);
	}
}
