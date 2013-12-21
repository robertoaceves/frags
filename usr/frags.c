/*
 * frags.c
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include "configuration.h"
#include "str_utils.h"
#include "communication.h"
#include "parameters.h"
#include "network_utils.h"
#include "layer_network.h"
#include "layer_transport.h"
#include "layer_payload.h"


/**
 * Size does not includes fragment header.
 *
 * TODO: This seems similar to get_packet_size() at network_utils.h
 */
unsigned int total_packet_size(struct configuration *config) {
	return	  net_hdr_size(config)
			+ trans_hdr_size(config)
			+ config->payload_len;
}

static int args_to_config(struct arguments *args, struct configuration *config) {
	/* Operation */
	if (args->input_mode_set)
		config->input_mode = args->input_mode;
	if (args->input_file_set)
		config->input_fd = args->input_fd;

	if (args->mtu_set)
		config->mtu= args->mtu;
	if (args->frag_offset_set)
		config->frag_offset = args->frag_offset;
	if (args->frag_id_set)
		config->frag_id = args->frag_id;
	if (args->frag_more_frags_set)
		config->frag_more_frags_set = args->frag_more_frags_set;
	if (args->has_frag_hdr)
		config->has_frag_hdr = args->has_frag_hdr;
	if (args->send_from_kernel_module)
		config->send_from_kernel_module = args->send_from_kernel_module;

	/* Network protocol */
	switch (args->mode) {
	case MODE_IPV6:
		config->l3proto = L3PROTO_IPV6;
		if (args->ipv6_src_set)
			config->ipv6_src = args->ipv6_src;
		if (args->ipv6_dst_set)
			config->ipv6_dst = args->ipv6_dst;
//		if (args->ipv6_frag_off_set)
//			config->ipv6_frag_off = args->ipv6_frag_off;
//		if (args->ipv6_frag_id_set)
//			config->ipv6_frag_id = args->ipv6_frag_id;
//		if (args->ipv6_flags_set)
//			config->ipv6_frag_flags = args->ipv6_flags;
		if (args->ipv6_next_hdr_set)
			config->l4proto = args->ipv6_next_hdr;
		break;

	case MODE_IPV4:
		config->l3proto = L3PROTO_IPV4;
		if (args->ipv4_src_set)
			config->ipv4_src = args->ipv4_src;
		if (args->ipv4_dst_set)
			config->ipv4_dst = args->ipv4_dst;
//		if (args->ipv4_frag_off_set)
//			config->ipv4_frag_off = args->ipv4_frag_off;
//		if (args->ipv4_flags_set)
//			config->ipv4_flags = args->ipv4_flags;
		break;

	default:
		log_err(ERR_L3PROTO, "(args_to_config) Invalid network protocol: %u", args->mode);
		return -EINVAL;
	}

	/* Transport protocol */
	switch (args->operation) {
	case OP_TCP:
		config->l4proto = L4PROTO_TCP;
		if (args->port_src_set)
			config->port_src = args->port_src;
		if (args->port_dst_set)
			config->port_dst = args->port_dst;
		if (args->tcp_seq_num_set)
			config->tcp_seq_num = args->tcp_seq_num;
		if (args->tcp_ack_num_set)
			config->tcp_ack_num = args->tcp_ack_num;
		if (args->tcp_flags_set)
			config->tcp_flags = args->tcp_flags;
		if (args->tcp_chksum_set)
			config->tcp_chksum = args->tcp_chksum;
		break;

	case OP_UDP:
		config->l4proto = L4PROTO_UDP;
		if (args->port_src_set)
			config->port_src = args->port_src;
		if (args->port_dst_set)
			config->port_dst = args->port_dst;
		if (args->udp_chksum_set)
			config->udp_chksum = args->udp_chksum;
		if (args->udp_len_set)
			config->udp_len = args->udp_len;
		break;

	case OP_ICMP:
		if (config->l3proto == L3PROTO_IPV4) {
			config->l4proto = L4PROTO_ICMP;
			config->icmp_type = ICMP_ECHO;
		} else {
			config->l4proto = L4PROTO_ICMP6;
			config->icmp_type = ICMP6_ECHO_REQUEST;
		}
		if (args->port_id_set)
			config->port_id = args->port_id;
		if (args->icmp_type_set)
			config->icmp_type = args->icmp_type;
		if (args->icmp_code_set)
			config->icmp_code = args->icmp_code;
		if (args->icmp_rest_set)
			config->icmp_hdr_rest = args->icmp_rest;
		if (args->icmp_chksum_set)
			config->icmp_chksum = args->icmp_chksum;
		break;

	default:
		log_err(ERR_L4PROTO, "(args_to_config) Invalid transport protocol: %u", args->operation);
		return -EINVAL;
	}

	/* Payload */
	if (args->payload_len_set)
		config->payload_len = args->payload_len;

	return EXIT_SUCCESS;
}


static int send_packet(struct configuration *config, void *pkt, u_int32_t pkt_len ) {
	struct sockaddr_in6 sin6 = { 0 };
	struct sockaddr_in sin4 = { 0 };
	struct ip *ip_hdr4;
	struct ip6_hdr *ip_hdr6;
	int raw_socket;
	int send_res;
	int sm=1;
	const int *val= NULL;

	val=&sm;

	/* Create socket */
	raw_socket = socket(config->l3proto, SOCK_RAW, IPPROTO_RAW);
	if (raw_socket == -1) {
		log_err(ERR_SOCKET_FAILED, "Cannot create socket. You should try using sudo.");
		return EXIT_FAILURE;
	}

	/* Set socket's routing info & Send the packet. */
	switch (config->l3proto) {
	case L3PROTO_IPV6:
		ip_hdr6 = (struct ip6_hdr *)pkt;
		/* sin6 is used in sendto() to determine the packet's path */
		sin6.sin6_family = L3PROTO_IPV6;
		memcpy(&sin6.sin6_addr.s6_addr, &ip_hdr6->ip6_dst, sizeof(sin6.sin6_addr.s6_addr));
		sin6.sin6_port = 0; /* WTF! This had to be Zero! */

		send_res = sendto(raw_socket, pkt, pkt_len, 0,
				(struct sockaddr *) &sin6, sizeof(sin6));
		if (send_res < 0) {
			log_err(ERR_SEND_FAILED, "Could not send the packet, error code: %d.", send_res);
			perror("IPv6 sendto");
			return EXIT_FAILURE;
		}
		break;

	case L3PROTO_IPV4:
		ip_hdr4 = (struct ip*)pkt;

		/* Spoofing header requires this socket configuration.
		 * For IPv6, there is no need for a socket option similar to the
		 * IPv4 IP_HDRINCL socket option.*/
		setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof(sm));

		/* sin4 is used in sendto() to determine the packet's path */
		sin4.sin_family = L3PROTO_IPV4;
		sin4.sin_port = htons(config->port_dst);
		sin4.sin_addr = ip_hdr4->ip_dst;

		send_res = sendto(raw_socket, pkt, pkt_len, 0,
				(struct sockaddr *) &sin4, sizeof(sin4));
		if (send_res < 0) {
			log_err(ERR_SEND_FAILED, "Could not send the packet, error code: %d.", send_res);
			perror("IPv4 sendto");
			return EXIT_FAILURE;
		}
		break;

	default:
		log_err(ERR_SEND_FAILED, "Invalid network protocol: %u", config->l3proto);
		return EXIT_FAILURE;
	}

	close(raw_socket);

	return EXIT_SUCCESS;
}


static int create_packets(struct configuration *config) {
	unsigned char packet[config->mtu];
	unsigned int curr_pkt_len;
	unsigned int curr_l3_hdr_len;
	unsigned int curr_l3_frag_len;
	unsigned int curr_l4_hdr_len;
	unsigned int curr_payload_len;
	unsigned char is_fragmenting = 0;
	unsigned char is_first = 0;
	void *transport_hdr;
	void *payload_buf;
	void *payload_pkt_ptr;
	size_t bytes_copied;
	int error = EXIT_SUCCESS;

	if (payload_create(config, &payload_buf, &bytes_copied)	!= RES_SUCCESS)
		return RES_FAILURE;

	transport_hdr = NULL;
	curr_l3_hdr_len = 0; /* Network header */
	curr_l3_frag_len = 0; /* Fragment header */
	curr_l4_hdr_len = 0; /* Transport header */

	is_fragmenting = config->has_frag_hdr;
	is_first = config->frag_offset == 0 ? 1 : 0;
	curr_l3_hdr_len = net_hdr_size(config); /* Network header */
	curr_l3_frag_len += is_fragmenting && config->l3proto == L3PROTO_IPV6 ? sizeof(struct ip6_frag) : 0; /* Fragment header */
	curr_l4_hdr_len += is_first ? trans_hdr_size(config) : 0; /* Transport header */
	curr_payload_len = config->payload_len;
	curr_pkt_len = get_packet_size(config);

	memset(packet, 0, config->mtu); /* Reset packet content. */

	/*
	 * Set network headers
	 */
	if (l3_hdr_init(config, packet) != RES_SUCCESS) {
		log_err(ERR_L3HDR_INIT_ERROR, "Trying to set network headers");
		return EXIT_FAILURE;
	}

	/*
	 * Set transport header, only the first packet should include one.
	 */
	if (is_first) {
		transport_hdr = packet + curr_l3_hdr_len + curr_l3_frag_len;
log_debug("curr_l3_hdr_len + curr_l3_frag_len: %u", curr_l3_hdr_len + curr_l3_frag_len);
		if (l4_hdr_init(config, transport_hdr) != RES_SUCCESS) {
			log_err(ERR_L4HDR_INIT_ERROR, "Can not initialize transport protocol.");
			return EXIT_FAILURE;
		}
	}

	/*
	 * Set the payload.
	 *
	 * Copy the corresponding payload portion to the actual packet.
	 */
	payload_pkt_ptr = packet + get_headers_size(config);
	memcpy(payload_pkt_ptr, payload_buf, curr_payload_len);

	/*
	 * Send any packet.
	 */
	if (config->send_from_kernel_module)
		error = send_packets_from_kernel_module(config, packet, curr_pkt_len);
	else
		error = send_packet(config, packet, curr_pkt_len);
	if (error) {
		log_err(ERR_SEND_FAILED, "Could not send the packet.");
		return error;
	}

	payload_destroy(&payload_buf, config);

	return error;
}


int main(int argc, char *argv[]) {
	struct configuration config;
	struct arguments args;
	int error;

	log_info("Hello world!\n");

	init_config(&config);

	error = parse_args(argc, argv, &args);
	if (error)
	{
		log_err(ERR_PARSE_ARGS, "Unable to parse arguments");
		return error;
	}

	error = args_to_config(&args, &config);
	if (error)
	{
		log_err(ERR_PARSE_ARGS, "Error  args_to_config");
		return error;
	}

	return create_packets(&config);
}
