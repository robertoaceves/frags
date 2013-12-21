/*
 * communication.h
 *
 *  Created on: Nov 23, 2013
 *      Author: user
 */

#ifndef COMMUNICATION_H_
#define COMMUNICATION_H_

#include "configuration.h"


#define FRAGMENTATION_TIMEOUT_OPT 	"toFrag"


struct request_hdr {
	__u32 length;
	__u16 mode;
	__u32 operation;
};


int send_packets_from_kernel_module(struct configuration *config, void *pkt, u_int32_t pkt_len);


#endif /* COMMUNICATION_H_ */
