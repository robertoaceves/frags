/*
 * parameters.h
 *
 *  Created on: Nov 23, 2013
 *      Author: user
 */

#ifndef PARAMETERS_H_
#define PARAMETERS_H_

#include <stdbool.h>
#include "configuration.h"

#define IPV6_FRAG_OFFSET 		0xffF8
#define IPV6_FLAG_MORE_FRAGS 	0x0001
#define IPV4_FLAG_DONT_FRAG		IP_DF
#define IPV4_FLAG_MORE_FRAGS 	IP_MF


#define NUM_FORMAT "NUM"
#define PREFIX_FORMAT "ADDR6/NUM"
#define IPV6_TRANSPORT_FORMAT "ADDR6#NUM"
#define IPV4_TRANSPORT_FORMAT "ADDR4#NUM"
#define IPV4_ADDR_FORMAT "ADDR4"
#define BOOL_FORMAT "BOOL"
#define NUM_ARR_FORMAT "NUM[,NUM]*"

/**
 * The parameters received from the user, formatted and ready to be read in any order.
 */
struct arguments {
	/* Header */
	unsigned short mode;
	unsigned int operation;

	/* Operation */
	config_input_mode input_mode; // none, file, stdin
	bool input_mode_set;
	char *input_file;
	int input_fd;
	bool input_file_set;
	bool send_from_kernel_module;

	/* Network */
	u_int16_t mtu;
	bool mtu_set;
	u_int16_t frag_offset;
	u_int16_t frag_id;
	bool mtu_set;
	bool frag_offset_set;
	bool frag_id_set;
	bool frag_more_frags_set;
	bool has_frag_hdr;

	/* IPv6 */
	struct in6_addr ipv6_src;
	struct in6_addr ipv6_dst;
//	u_int16_t ipv6_frag_off;
//	u_int32_t ipv6_frag_id;
//	u_int16_t ipv6_flags;
	u_int8_t ipv6_next_hdr;
	bool ipv6;
	bool ipv6_src_set;
	bool ipv6_dst_set;
//	bool ipv6_frag_off_set;
//	bool ipv6_frag_id_set;
//	bool ipv6_flags_set;
	bool ipv6_next_hdr_set;

	/* IPv4 */
	struct in_addr ipv4_src;
	struct in_addr ipv4_dst;
//	u_int16_t ipv4_frag_off;
	u_int16_t ipv4_flags;
	u_int16_t ipv4_ttl;
	bool ipv4;
	bool ipv4_src_set;
	bool ipv4_dst_set;
//	bool ipv4_frag_off_set;
	bool ipv4_flags_set;
	bool ipv4_ttl_set;

	/* Transport protocol */
	u_int16_t port_src;
	u_int16_t port_dst;
	u_int16_t port_id;
	bool port_src_set;
	bool port_dst_set;
	bool port_id_set;

	/* TCP */
	u_int32_t tcp_seq_num;
	u_int32_t tcp_ack_num;
	u_int16_t tcp_flags;
	u_int16_t tcp_chksum;
	bool tcp_seq_num_set;
	bool tcp_ack_num_set;
	bool tcp_flags_set;
	bool tcp_chksum_set;
	bool tcp;

	/* UDP */
	unsigned short udp_len; /* The sum of all the fragment's payloads */
	u_int16_t udp_chksum;
	bool udp_len_set;
	bool udp_chksum_set;
	bool udp;

	/* ICMP */
	u_int8_t icmp_type;
	u_int8_t icmp_code;
	u_int32_t icmp_rest;
	u_int32_t icmp_chksum;
	bool icmp_type_set;
	bool icmp_code_set;
	bool icmp_rest_set;
	bool icmp_chksum_set;
	bool icmp;

	/* Payload */
	u_int16_t payload_len;
	bool payload_len_set;
};

/**
 * The flags the user can write as program parameters.
 */
enum argp_flags {
	/* Operation */
	ARGP_INPUT_MODE_NONE = 900,
	ARGP_INPUT_MODE_FILE = 'f',
	ARGP_INPUT_MODE_STDIN = 's',
	ARGP_SEND_FROM_MODULE = 'k',
	ARGP_MTU = 901,
	ARGP_FRAG_OFF = 'o',
	ARGP_FRAG_ID = 902,
	ARGP_FRAG_MORE_FRAGS = 'M',
	ARGP_HAS_FRAG_HDR = 903,

	/* Modes */
	ARGP_IPV6 = '6',
	ARGP_IPV4 = '4',

	/* Addresses */
	ARGP_IPV6_SRC_ADDR = 1000,
	ARGP_IPV6_DST_ADDR = 1001,
	ARGP_IPV4_SRC_ADDR = 1002,
	ARGP_IPV4_DST_ADDR = 1003,

	/* Network header flags */
	ARGP_IPV6_NEXT_HDR = 1100,
//	ARGP_IPV6_MORE_FRAG = 'M',
//	ARGP_IPV6_FRAG_OFF = 'O',
//	ARGP_IPV6_FRAG_ID = 1110,

	ARGP_IPV4_DONT_FRAG = 'F',
//	ARGP_IPV4_MORE_FRAG = 'm',
//	ARGP_IPV4_FRAG_OFF = 'o',
//	ARGP_ID_NUM = 'y', /* TODO: Should we include this value? */
	ARGP_IPV4_TTL = 1500,

	/* Transport protocol */
	ARGP_TCP = 't',
	ARGP_UDP = 'u',
	ARGP_ICMP = 'i',

	/* Ports */
	ARGP_SRC_PORT = 2000,
	ARGP_DST_PORT = 2001,
	ARGP_ICMP_ID = 2002,

	/* TCP fields */
	ARGP_TCP_FLAG_URG = 3001,
	ARGP_TCP_FLAG_ACK = 3002,
	ARGP_TCP_FLAG_RST = 3003,
	ARGP_TCP_FLAG_SYN = 3004,
	ARGP_TCP_FLAG_FIN = 3005,
	ARGP_TCP_SEQ = 3006,
	ARGP_TCP_ACK = 3007,
	ARGP_TCP_CHKSUM = 3008,

	/* UDP fields */
	ARGP_UDP_LEN = 4000,
	ARGP_UDP_CHKSUM = 4001,

	/* ICMP fields */
	ARGP_ICMP_TYPE = 5000,
	ARGP_ICMP_CODE = 5001,
	ARGP_ICMP_REST = 5002,
	ARGP_ICMP_CHKSUM = 5003,

	/* Payload size */
	ARGP_PAYLOAD_LEN = 'p',
};


int parse_args(int argc, char **argv, struct arguments *result);




#endif /* PARAMETERS_H_ */
