/*
 * layer_payload.h
 *
 *  Created on: Nov 25, 2013
 *      Author: user
 */

#ifndef LAYER_PAYLOAD_H_
#define LAYER_PAYLOAD_H_

#include "types.h"
#include "configuration.h"

result_t payload_create(struct configuration *config, void **ptr, size_t *bytes_copied);
void payload_destroy(void **ptr, struct configuration *config);

#endif /* LAYER_PAYLOAD_H_ */
