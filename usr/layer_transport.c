/*
 * layer_transport.c
 *
 *  Created on: Nov 25, 2013
 *      Author: user
 */

#include <stdlib.h>
#include <time.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include "types.h"
#include "layer_transport.h"
#include "network_utils.h"

inline unsigned int trans_hdr_size(struct configuration *config) {
	switch (config->l4proto) {
	case L4PROTO_TCP:
		return sizeof(struct tcphdr);

	case L4PROTO_UDP:
		return sizeof(struct udphdr);

	case L4PROTO_ICMP:
		return sizeof(struct icmphdr);

	case L4PROTO_ICMP6:
		return sizeof(struct icmp6_hdr);

	default:
		log_err(ERR_L4PROTO, "Invalid l4proto: %u", config->l4proto);
		return -1;
	}
}

/*
 * return  RES_SUCCESS, if all is fine;  RES_FAILURE, otherwise.
 */
result_t l4_hdr_init(struct configuration *config, void *l4hdr) {
	struct udphdr *udp;
	struct tcphdr *tcp;
	struct icmphdr *icmp;

	l4_protocol l4proto = config->l4proto;
	u_int16_t src_port = config->port_src;
	u_int16_t dst_port = config->port_dst;
	u_int8_t icmp_type= config->icmp_type;
	u_int8_t icmp_code = config->icmp_code;
	u_int32_t seq_num = config->tcp_seq_num;
	u_int32_t ack_num = config->tcp_ack_num;
	tcp_hdr_flags flags = config->tcp_flags;
	u_int16_t l4_pay_len = trans_hdr_size(config) + config->payload_len;
	u_int16_t udp_len= config->udp_len;

	srand(time(NULL)); /* Initialize seed for randomizer. */

	switch (l4proto) {
	case L4PROTO_UDP:
		udp = (struct udphdr *) l4hdr;
		udp->source = htons(src_port);
		udp->dest = htons(dst_port);
		if (config->has_frag_hdr)
			udp->len = htons(udp_len); /* Sum of all fragments size in bytes, including UDP header. */
		else
			udp->len = htons(l4_pay_len); /* Size of payload in bytes of the UDP header and UDP data. */
		udp->check = config->udp_chksum;
		break;

	case L4PROTO_TCP:
		tcp = (struct tcphdr *) l4hdr;
		tcp->source = htons(src_port);
		tcp->dest = htons(dst_port);
		tcp->seq = seq_num;// htonl(rand()); // TODO: Fixme, maybe using config struct instead of parameter list
		tcp->ack_seq = ack_num;
		tcp->res1 = 0;
		tcp->doff = 5;
		tcp->fin = (flags & TCP_FIN) > 0;
		tcp->syn = (flags & TCP_SYN) > 0;
		tcp->rst = (flags & TCP_RST) > 0;
		tcp->psh = (flags & TCP_PSH) > 0;
		tcp->ack = (flags & TCP_ACK) > 0;
		tcp->urg = (flags & TCP_URG) > 0;
		tcp->res2 = 0;
		tcp->window = htons(65535);
		tcp->check = config->tcp_chksum;
		tcp->urg_ptr = 0;
		break;

	case L4PROTO_ICMP:
	case L4PROTO_ICMP6:
		icmp = (struct icmphdr *) l4hdr;
		icmp->type = icmp_type; /* message type */
		icmp->code = icmp_code; /* type sub-code */
		icmp->un.echo.id = htons(1); // TODO: set through config
		icmp->un.echo.sequence = 0; // TODO: set through config
		icmp->checksum = config->icmp_chksum;
		break;

	default:
		log_err(ERR_L4PROTO, "Invalid transport protocol: %u\n", l4proto);
		return RES_FAILURE;
	}

	return RES_SUCCESS;
}



result_t l4_hdr_update_cksum_and_len(struct configuration *config, void *l3hdr, void *l4hdr, void *payload_ptr, u_int16_t curr_payload_cap) {
	struct udphdr *udp;
	struct tcphdr *tcp;
	struct icmphdr *icmp;

	l4_protocol l4proto = config->l4proto;
	u_int16_t l4_pay_len = trans_hdr_size(config) + config->payload_len;

	switch (l4proto) {
	case L4PROTO_UDP:
		udp = (struct udphdr *) l4hdr;
		udp->len = htons(l4_pay_len); /* l4_pay_len in bytes of the UDP header and UDP data */
		udp->check = (trans_hdr_chksum(config, l3hdr, l4hdr, payload_ptr));
		break;

	case L4PROTO_TCP:
		tcp = (struct tcphdr *) l4hdr;
		tcp->check = (trans_hdr_chksum(config, l3hdr, l4hdr, payload_ptr));
		break;

	case L4PROTO_ICMP:
	case L4PROTO_ICMP6:
		icmp = (struct icmphdr *) l4hdr;
		icmp->checksum = (trans_hdr_chksum(config, l3hdr, l4hdr, payload_ptr));
		break;

	default:
		log_err(ERR_L4PROTO, "Invalid transport protocol: %u\n", l4proto);
		return RES_FAILURE;
	}

	return RES_SUCCESS;
}


/*
 * Computes checksum from pseudo-header and transport header + data.
 * It is assumed that checksum of transport header already has a value of 0.
 *
 */
u_int16_t trans_hdr_chksum(struct configuration *config, void * l3hdr,
		void *l4hdr, void *payload_ptr) {
	l3_phdr_ipv6 pseudohdr6; /* TPC/UDP Pseudoheader (used in checksum)    */
	l3_phdr_ipv4 pseudohdr4; /* TPC/UDP Pseudoheader (used in checksum)    */
	u_int16_t checksum[3] = {0};
	u_int16_t l4_hdr_size = trans_hdr_size(config);
	l3_protocol l3proto = config->l3proto;
	l4_protocol l4proto = config->l4proto;
	u_int16_t payload_len = config->payload_len;

	/* Fill the pseudoheader so we can compute the TCP/UDP checksum*/
	switch (l3proto) {
	case L3PROTO_IPV6:
		memset(&pseudohdr6, 0, sizeof(pseudohdr6));
		pseudohdr6.src_addr = ((struct ip6_hdr *) l3hdr)->ip6_src;
		pseudohdr6.dst_addr = ((struct ip6_hdr *) l3hdr)->ip6_dst;
		pseudohdr6.zero = 0;
		pseudohdr6.protocol = htons(l4proto); // ((struct ip *)l3hdr)->ip_p;
		pseudohdr6.len = htonl(l4_hdr_size + payload_len);
		checksum[0] = ~in_cksum(0, (u_int16_t *)(&pseudohdr6), sizeof(pseudohdr6));
		break;

	case L3PROTO_IPV4:
		memset(&pseudohdr4, 0, sizeof(pseudohdr4));
		pseudohdr4.src_addr = ((struct ip *) l3hdr)->ip_src;
		pseudohdr4.dst_addr = ((struct ip *) l3hdr)->ip_dst;
		pseudohdr4.zero = 0;
		pseudohdr4.protocol = htons(l4proto); // ((struct ip *)l3hdr)->ip_p;
		pseudohdr4.len = htons(l4_hdr_size + payload_len);
		checksum[0] = ~in_cksum(0, (u_int16_t *)(&pseudohdr4), sizeof(pseudohdr4));
		break;

	default:
		log_err(ERR_L3PROTO, "Invalid network protocol: %u", l3proto);
		return -1;
	}

	/* Copy header and pseudoheader to a buffer to compute the checksum */
	switch (l4proto) {
	case L4PROTO_TCP:
		checksum[1] = ~in_cksum(checksum[0], (u_int16_t *)(l4hdr), l4_hdr_size);
		break;

	case L4PROTO_UDP:
		checksum[1] = ~in_cksum(checksum[0], (u_int16_t *)(l4hdr), l4_hdr_size);
		break;

	case L4PROTO_ICMP:
		checksum[1] = ~in_cksum(0, (u_int16_t *)(l4hdr), l4_hdr_size);
		break;

	case L4PROTO_ICMP6:
		checksum[1] = ~in_cksum(checksum[0], (u_int16_t *)(l4hdr), l4_hdr_size);
		break;

	default:
		log_err(ERR_L4PROTO, "Invalid transport protocol: %u", l4proto);
		return -1;
	}

	/* Get payload checksum. */
	checksum[2] = in_cksum(checksum[1], (u_int16_t *)(payload_ptr), payload_len);

	return checksum[2];
}

