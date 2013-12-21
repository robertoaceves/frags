/*
 * layer_network.h
 *
 *  Created on: Nov 25, 2013
 *      Author: user
 */

#ifndef LAYER_NETWORK_H_
#define LAYER_NETWORK_H_

#include "configuration.h"

/**
 *
 * @param[in]	offset. Fragment offset field, measured in units of eight-byte blocks.
 * @param[in]	flags. IP_DF: don't fragment, IP_MF: more fragments.
 * return  RES_SUCCESS, if all is fine;  RES_FAILURE, otherwise.
 */
result_t l3_hdr_init(struct configuration *config, void *hdr);

/**
 * Size does not includes fragment header. */
inline unsigned int net_hdr_size(struct configuration *config);


#endif /* LAYER_NETWORK_H_ */
