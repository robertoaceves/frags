/*
 * communication.c
 *
 *  Created on: Nov 23, 2013
 *      Author: user
 */

#include <errno.h>
#include "configuration.h"
#include "communication.h"
#include "str_utils.h"
#include "netlink.h"


#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(struct configuration)


static int handle_send_pkt_response(struct nl_msg *msg, void *arg)
{
	log_debug("Packet sent successfully.");
	return 0;
}
int send_packets_from_kernel_module(struct configuration *config, void *pkt, u_int32_t pkt_len) {
	unsigned char request[HDR_LEN + pkt_len];
	struct request_hdr *hdr = (struct request_hdr *) request;
	void *payload = (request + HDR_LEN);

	log_debug("Sending packets from kernel module.");
	hdr->mode = config->l3proto;
	hdr->operation = config->l4proto;
	hdr->length = sizeof(request);
	memcpy(payload, pkt, pkt_len);

	return netlink_request(request, hdr->length, handle_send_pkt_response, NULL);
}

