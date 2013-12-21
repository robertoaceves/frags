/*
 * layer_payload.c
 *
 *  Created on: Nov 25, 2013
 *      Author: user
 */

#include <stdlib.h>
#include <stdio.h>
#include <sys/select.h>
#include <unistd.h>
#include "layer_payload.h"



int is_ready(int fd) {
    fd_set fdset;
    struct timeval timeout;

    FD_ZERO(&fdset);
    FD_SET(fd, &fdset);
    timeout.tv_sec = 0;
    timeout.tv_usec = 1;
    //int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
    return select(fd+1, &fdset, NULL, NULL, &timeout) == 1 ? 1 : 0;
}
size_t empty_fd(int fd, void *buffer, int size) {
	size_t bytes_copied = 0;
	while (is_ready(fd)) {
    	bytes_copied += read(fd, buffer, size);
    }

	return bytes_copied;
}


/*
 * return  RES_SUCCESS, if all is fine;  RES_FAILURE, otherwise.
 */
static result_t payload_alloc(u_int16_t length, void **ptr) {
	log_debug("	allocating memory for payload, %u bytes", length);
	*ptr = malloc(length);
	if (!*ptr) {
		log_err(ERR_PAYLOAD_INIT_ERROR, "Can not create payload buffer.");
		return RES_FAILURE;
	}

	return RES_SUCCESS;
}
void payload_destroy(void **ptr, struct configuration *config) {
	if (config->input_mode == INPUT_MODE_FILE)
		close(config->input_fd);
	free(*ptr);

}

/*
 * return  RES_SUCCESS, if all is fine;  RES_FAILURE, otherwise.
 */
//static result_t payload_set(config_input_mode input_mode, int fd, u_int16_t length, void *hdr, u_int16_t *checksum) {
static result_t payload_set(config_input_mode input_mode, int fd, size_t length, void *hdr, size_t *bytes_copied) {
	u_int16_t ii;
	u_int8_t *ptr = hdr;
	int fd_stdin;

	*bytes_copied = 0;

	/* Randomly generated data */
	switch (input_mode) {
	case INPUT_MODE_NONE:
		for (ii = 1; ii <= length; ++ii)
			ptr[ii-1] =  ii ;
		*bytes_copied = ii;
		break;
	case INPUT_MODE_FILE:
		fd_stdin = fd;
		*bytes_copied = read(fd_stdin, ptr, length); // TODO: Validate the returned value
		/* Dump stuff on the packet after read data. */
		break;
	case INPUT_MODE_STDIN:
		fd_stdin = fileno(stdin);
		if (is_ready(fd_stdin)) {
			/* read stuff from stdin will not block */
			*bytes_copied = empty_fd(fd_stdin, ptr, length);
			/* Dump stuff on the packet after read data. */
		}
		break;
	default:
		log_err(ERR_PAYLOAD_INIT_ERROR, "Invalid input mode: %u", input_mode);
		return RES_FAILURE;
	}

//	*checksum = in_cksum(*checksum, ptr, length);

	log_debug("	set payload, %u bytes", length);
	return RES_SUCCESS;
}
result_t payload_create(struct configuration *config, void **ptr, size_t *bytes_copied) {
	config_input_mode input_mode = config->input_mode;
	int fd = config->input_fd;
	u_int16_t length = config->payload_len;

	if (payload_alloc(length, ptr) != RES_SUCCESS)
		return RES_FAILURE;
	if (payload_set(input_mode, fd, length, *ptr, bytes_copied) != RES_SUCCESS)
		return RES_FAILURE;
	return RES_SUCCESS;
}
