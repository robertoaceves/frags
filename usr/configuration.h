/*
 * configuration.h
 *
 *  Created on: Nov 23, 2013
 *      Author: user
 */

#ifndef CONFIGURATION_H_
#define CONFIGURATION_H_

#include <stdbool.h>
#include "types.h"

#define DEFAULT_CHKSUM_VALUE 0x0001

enum config_mode {
	MODE_NONE = 0,
	MODE_IPV6 = 1,
	MODE_IPV4 = 2,
};

enum config_operation {
	OP_NONE = 0,
	OP_IPV6_EXTHDR_FRAG = 1,
	OP_TCP = 2,
	OP_UDP = 3,
	OP_ICMP = 4,
};

typedef enum {
	INPUT_MODE_NONE = 0,
	INPUT_MODE_FILE = 1,
	INPUT_MODE_STDIN= 2,
} config_input_mode;

struct configuration {
	/* Operation */
	config_input_mode input_mode;
	int input_fd;
	bool send_from_kernel_module;

	/* Network */
	u_int16_t mtu;
	u_int16_t frag_offset;
	u_int16_t frag_id;
	bool frag_more_frags_set;
	bool has_frag_hdr;

	/* IPv6 */
	l3_protocol l3proto;
	struct in6_addr ipv6_src;
	struct in6_addr ipv6_dst;
//	u_int16_t ipv6_frag_off;
//	u_int16_t ipv6_frag_flags;
//	u_int32_t ipv6_frag_id;
	u_int8_t ipv6_next_hdr;

	/* IPv4 */
	struct in_addr ipv4_src;
	struct in_addr ipv4_dst;
//	u_int16_t ipv4_frag_id;
//	u_int16_t ipv4_frag_off;
//	u_int16_t ipv4_flags; // TODO: Handle DF flag
	u_int16_t ipv4_ttl;
	/* u_int16_t ipv4_chksum; TODO: Implement me! */

	/* Transport protocol */
	l4_protocol l4proto;
	u_int16_t port_src;
	u_int16_t port_dst;
	u_int16_t port_id;

	/* TCP */
	u_int16_t tcp_flags;
	u_int32_t tcp_seq_num;
	u_int32_t tcp_ack_num;
	u_int16_t tcp_chksum;

	/* UDP */
	u_int16_t udp_chksum;
	u_int16_t udp_len;

	/* ICMP */
	u_int8_t icmp_type;
	u_int8_t icmp_code;
	u_int16_t icmp_chksum;
	u_int32_t icmp_hdr_rest; /* TODO: Implement me! */

	/* Payload */
	u_int16_t payload_len;
};

void init_config(struct configuration *config);

#endif /* CONFIGURATION_H_ */
