/*
 * network_utils.c
 *
 *  Created on: Nov 25, 2013
 *      Author: user
 */

#include "network_utils.h"
#include "layer_network.h"
#include "layer_transport.h"
#include <netinet/ip6.h>

unsigned short in_cksum(u_int16_t prev, u_int16_t *addr, int len) {
	register u_int32_t sum = 0;
	u_int16_t answer = 0;
	register u_int16_t *w = addr;
	register u_int32_t nleft = len;

	sum = prev;

	/*
	 * Our algorithm is simple, using a 32-bit accumulator (sum),
	 * we add sequential 16-bit words to it, and at the end, fold back
	 * all the carry bits from the top 16 bits into the lower 16 bits .
	 */
	while (nleft > 1) {
		sum += (u_int32_t)(*w++);
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(u_char *) (&answer) = *(u_char *) w;
		sum += answer;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
	sum += (sum >> 16); /* add carry */
	answer = ~sum; /* truncate to 16 bits */

	return (answer);
}

unsigned short csum(unsigned short *buf, int nwords) {
	unsigned long sum;
	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

unsigned int get_packet_size(struct configuration *config) {
	return net_hdr_size(config) /* Network header */
			+ ((config->has_frag_hdr && config->l3proto == L3PROTO_IPV6) ? sizeof(struct ip6_frag) : 0) /* Fragment header */
			+ ((config->frag_offset == 0) ? trans_hdr_size(config) : 0) /* Transport header */
			+ config->payload_len; /* Payload */
}

unsigned int get_l3_payload_size(struct configuration *config) {
	return ((config->has_frag_hdr && config->l3proto == L3PROTO_IPV6) ? sizeof(struct ip6_frag) : 0) /* Fragment header */
			+ ((config->frag_offset == 0) ? trans_hdr_size(config) : 0) /* Transport header */
			+ config->payload_len; /* Payload */
}

unsigned int get_headers_size(struct configuration *config) {
	return net_hdr_size(config) /* Network header */
			+ ((config->has_frag_hdr && config->l3proto == L3PROTO_IPV6) ? sizeof(struct ip6_frag) : 0) /* Fragment header */
			+ ((config->frag_offset == 0) ? trans_hdr_size(config) : 0); /* Transport header */
}

unsigned int get_payload_capacity(struct configuration *config) {
	return config->mtu - get_headers_size(config);
}


