#ifndef _NF_NAT64_SEND_PACKET_H
#define _NF_NAT64_SEND_PACKET_H

/**
 * @file
 * Functions to artificially send homemade packets through the interfaces. Basically, you initialize
 * sk_buffs and this worries about putting them on the network.
 *
 * We need this because the kernel assumes that when a packet enters a module, a packet featuring
 * the same layer-3 protocol exits the module. So we can't just morph IPv4 packets into IPv6 ones
 * and vice-versa; we need to ask the kernel to drop the original packets and send new ones on our
 * own.
 */

//#include <linux/types.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include "types.h"
//#include "packet.h"


/**
 * One-liner for filling up a 'flowi' and then calling the kernel's IPv4 routing function.
 *
 * Routes the skb described by the arguments. Returns the 'destination entry' the kernel needs
 * to know which interface the skb should be forwarded through.
 */
struct dst_entry *route_ipv4(struct iphdr *hdr_ip, void *l4_hdr, l4_protocol l4_proto, __u32 mark);

/**
 * Same as route_ipv4(), except for IPv6.
 */
struct dst_entry *route_ipv6(struct ipv6hdr *hdr_ip, void *l4_hdr, l4_protocol l4_proto, __u32 mark);




#endif /* _NF_NAT64_SEND_PACKET_H */
