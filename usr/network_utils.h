/*
 * network_utils.h
 *
 *  Created on: Nov 25, 2013
 *      Author: user
 */

#ifndef NETWORK_UTILS_H_
#define NETWORK_UTILS_H_

#include <sys/types.h>
#include "configuration.h"

/**	This piece of code has been used many times in a lot of differents tools.
 * 	I haven't been able to determine the author of the code but it looks like
 * 	this is a public domain implementation of the checksum algorithm
 *
 * param[in] prev 	Should be one's complemented already.
 */
unsigned short in_cksum(u_int16_t prev, u_int16_t *addr, int len);

/** this function generates header checksums */
unsigned short csum(unsigned short *buf, int nwords);

unsigned int get_packet_size(struct configuration *config);

/** Returns the size of the network payload.
 * 	This accounts from network (IPv6) extension headers to payload size
 */
unsigned int get_l3_payload_size(struct configuration *config);

/**
 * Returns the total length of network and transport headers.
 */
unsigned int get_headers_size(struct configuration *config);

/**
 * Returns the packet's payload capacity.
 */
unsigned int get_payload_capacity(struct configuration *config);


#endif /* NETWORK_UTILS_H_ */
