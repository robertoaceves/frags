/*
 * configuration.c
 *
 *  Created on: Nov 23, 2013
 *      Author: user
 */

#include <stdlib.h>
#include <time.h>
#include <netinet/icmp6.h>

#include "str_utils.h"
#include "configuration.h"

/*
 * Set default packet values, creating a single fragment IPv6 & ICMP packet.
 *
 *	IPv4 values are set just in case.
 *
 * param[in] config		Default values to be used ahead.
 */
void init_config(struct configuration *config) {
	int error = EXIT_SUCCESS;

	/*
	 * Operation
	 */
	srand(time(NULL )); /* Initialize seed for randomizer. */

	config->input_mode = INPUT_MODE_NONE;
	config->input_fd = -1;
	config->send_from_kernel_module = false;

	/*
	 * Network
	 */

	/* MTU */
	config->mtu = 1280;
	config->frag_offset = 0;
	config->frag_id = 0;
	config->frag_more_frags_set = false;
	config->has_frag_hdr = true;
	config->ipv6_next_hdr = L4PROTO_UDP;

	/* Network protocol */
	config->l3proto = L3PROTO_IPV6;

	/* IPv6 */
	error = str_to_addr6("c0ca:db8:2001:2::2", &config->ipv6_src); // TODO: Get this value from our NIC.
	error |= str_to_addr6("c0ca:db8:2001:2::1", &config->ipv6_dst);
//	config->ipv6_frag_off = 0;
//	config->ipv6_frag_flags = 0;
//	config->ipv6_frag_id = rand();

	/* IPv4 */
	error = str_to_addr4("192.168.1.2", &config->ipv4_src); // TODO: Get this value from our NIC.
	error = str_to_addr4("192.168.1.1", &config->ipv4_dst);
//	config->ipv4_frag_id = rand();
//	config->ipv4_flags = 0;
//	config->ipv4_frag_off = 0;
	config->ipv4_ttl = 64;

	/*
	 * Transport protocol
	 */
	config->l4proto = L4PROTO_ICMP6;
	config->port_src = 50000;
	config->port_dst = 50000;
	config->port_id = 50000;

	/* TCP */
	config->tcp_flags = 0;
	config->tcp_seq_num = 0;
	config->tcp_ack_num = 0;
	config->tcp_chksum = DEFAULT_CHKSUM_VALUE;

	/* UDP */
	config->udp_chksum = DEFAULT_CHKSUM_VALUE;
	config->udp_len = 1000;

	/* ICMP */
	config->icmp_type = ICMP6_ECHO_REQUEST;
	config->icmp_code = 0;
	/* u_int32_t icmp_hdr_rest; TODO: Implement me! */
	config->icmp_chksum = DEFAULT_CHKSUM_VALUE;

	/*
	 * Payload
	 */
	config->payload_len = 5; //100;

	if (error)
		log_err(ERR_INIT_FAIL, "Invalid initial configuration value detected.");
}

