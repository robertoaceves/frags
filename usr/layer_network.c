/*
 * layer_network.c
 *
 *  Created on: Nov 25, 2013
 *      Author: user
 */

#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include "layer_network.h"
#include "layer_transport.h"
#include "parameters.h"
#include "network_utils.h"


/*
 *
 * @param[in]	offset. Fragment offset field, measured in units of eight-byte blocks.
 * @param[in]	flags. IP_DF: don't fragment, IP_MF: more fragments.
 * return  RES_SUCCESS, if all is fine;  RES_FAILURE, otherwise.
 */
result_t l3_hdr_init(struct configuration *config, void *hdr) {
	struct ip *ip4hdr;
	struct ip6_hdr *ip6hdr;
	struct ip6_frag *frag;
	result_t res = RES_SUCCESS;

	l3_protocol l3proto = config->l3proto;
	void *src_addr;
	void *dst_addr;
	u_int16_t flags;
	bool fragmented = config->has_frag_hdr;
	u_int32_t offset = config->frag_offset;
	u_int32_t fragment_id = config->frag_id;
	l4_protocol l4proto = config->l4proto;
	u_int16_t length = get_l3_payload_size(config);

log_debug("l3proto:%u, length:%u", l3proto, length);

	switch (l3proto) {
	case L3PROTO_IPV6:
		src_addr = &config->ipv6_src;
		dst_addr = &config->ipv6_dst;
		flags = (config->frag_more_frags_set) ? IPV6_FLAG_MORE_FRAGS : 0;
		ip6hdr = (struct ip6_hdr *) hdr;
		memset(ip6hdr, 0, sizeof(*ip6hdr));
		/* 4 bits version, 8 bits TC, 20 bits flow-ID */
		ip6hdr->ip6_flow = htonl(0x60000000);
		/* The size of the payload in octets, including any extension headers */
		ip6hdr->ip6_plen = htons(length);
		ip6hdr->ip6_hops = (64);
		ip6hdr->ip6_src = (*(struct in6_addr *)src_addr);
		ip6hdr->ip6_dst = (*(struct in6_addr *)dst_addr);

		if (fragmented) {
			ip6hdr->ip6_nxt = (44); /* 44: Fragment header */

			frag = (struct ip6_frag *) ((struct ip6_hdr *)hdr + 1);
			frag->ip6f_nxt = (l4proto);
			frag->ip6f_reserved = 0; /* reserved field */
			frag->ip6f_offlg = htons(((offset & IPV6_FRAG_OFFSET) )
									| (flags & IPV6_FLAG_MORE_FRAGS)); /* offset, reserved, and flag */
			frag->ip6f_ident = htonl(fragment_id); /* identification */
		} else {
			ip6hdr->ip6_nxt = l4proto;
		}
		break;

	case L3PROTO_IPV4:
		src_addr = &config->ipv4_src;
		dst_addr = &config->ipv4_dst;
		flags = (config->frag_more_frags_set) ? IPV4_FLAG_MORE_FRAGS : 0;
		ip4hdr = (struct ip *) hdr;
		memset(ip4hdr, 0, sizeof(*ip4hdr));
		ip4hdr->ip_hl = 5;
		ip4hdr->ip_v = 4;
		/* entire packet (fragment) size, including header and data, in bytes */
		ip4hdr->ip_len = htons(length);
		ip4hdr->ip_id = htons((u_int16_t)fragment_id);
		ip4hdr->ip_off = htons(flags | (offset >> 3));
		ip4hdr->ip_ttl = 32;
		ip4hdr->ip_p = l4proto;
		/* Compute the IP checksum as the standard says (RFC 791) */
		ip4hdr->ip_sum = 0;
		ip4hdr->ip_sum = htons(in_cksum(0, (unsigned short *) ip4hdr, sizeof(*ip4hdr)));
		ip4hdr->ip_src = (*(struct in_addr *)src_addr);
		ip4hdr->ip_dst = (*(struct in_addr *)dst_addr);
		break;

	default:
		log_err(ERR_L3PROTO, "Invalid network protocol: %u\n", l3proto);
		return RES_FAILURE;
	}

	return res;
}

/*
 * Size does not includes fragment header. */
inline unsigned int net_hdr_size(struct configuration *config) {
	switch (config->l3proto) {
	case L3PROTO_IPV6:
		return sizeof(struct ip6_hdr);

	case L3PROTO_IPV4:
		return sizeof(struct ip);

	default:
		log_err(ERR_L3PROTO, "Invalid l3proto: %u", config->l3proto);
		return -1;
	}
}
