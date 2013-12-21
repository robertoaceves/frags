/*
 * packet.h
 *
 *  Created on: Nov 26, 2013
 *      Author: user
 */

#ifndef PACKET_H_
#define PACKET_H_

#include "types.h"

/** Returns a hack-free version of the 'Traffic class' field from the "hdr" IPv6 header. */
static inline __u8 get_traffic_class(struct ipv6hdr *hdr)
{
	__u8 upper_bits = hdr->priority;
	__u8 lower_bits = hdr->flow_lbl[0] >> 4;
	return (upper_bits << 4) | lower_bits;
}

/**
 * Returns a big endian (but otherwise hack-free) version of the 'Flow label' field from the "hdr"
 * IPv6 header.
 */
static inline __be32 get_flow_label(struct ipv6hdr *hdr)
{
	return (*(__be32 *) hdr) & IPV6_FLOWLABEL_MASK;
}

#endif /* PACKET_H_ */
