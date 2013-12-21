/*
 * layer_transport.h
 *
 *  Created on: Nov 25, 2013
 *      Author: user
 */

#ifndef LAYER_TRANSPORT_H_
#define LAYER_TRANSPORT_H_

#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include "configuration.h"


typedef enum {
	TCP_NONE = 0,
	TCP_FIN = 1 << 0,
	TCP_SYN = 1 << 1,
	TCP_RST = 1 << 2,
	TCP_PSH = 1 << 3,
	TCP_ACK = 1 << 4,
	TCP_URG = 1 << 5
} tcp_hdr_flags;


/** IPv6 Pseudo-header used to compute TCP and UDP checksum. */
typedef struct pseudoheader6 {
	struct in6_addr src_addr;
	struct in6_addr dst_addr;
	u_int32_t len;
	u_int32_t zero;
	u_int16_t protocol;

} l3_phdr_ipv6;

/** IPv4 Pseudo-header used to compute TCP and UDP checksum. */
typedef struct pseudoheader4 {
	struct in_addr src_addr;
	struct in_addr dst_addr;
	u_int16_t zero;
	u_int16_t protocol;
	u_int16_t len;

} l3_phdr_ipv4;

inline u_int32_t trans_hdr_size(struct configuration *config);

u_int16_t trans_hdr_chksum(struct configuration *config, void * l3hdr,
		void *l4hdr, void *payload_ptr);

result_t l4_hdr_update_cksum_and_len(struct configuration *config, void *l3hdr,
		void *l4hdr, void *payload_ptr, u_int16_t curr_payload_cap);

result_t l4_hdr_init(struct configuration *config, void *l4hdr);


#endif /* LAYER_TRANSPORT_H_ */
