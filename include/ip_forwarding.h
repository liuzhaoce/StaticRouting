#ifndef __IP_FORWARDING_H__
#define __IP_FORWARDING_H__

#include <endian.h>

#include "base.h"
#include "types.h"
#include "checksum.h"
#include "ether.h"

void ip_forward_packet(u32 ip_dst, char *packet, int len);
void handle_ip_packet(iface_info_t *iface, char *packet, int len);

#endif
