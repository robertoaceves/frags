#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include "str_utils.h"

#define MAX_PORT 0xFFFF

int str_to_bool(const char *str, bool *bool_out)
{
	if (strcasecmp(str, "true") == 0 || strcasecmp(str, "1") == 0
			|| strcasecmp(str, "yes") == 0 || strcasecmp(str, "on") == 0) {
		*bool_out = true;
		return 0;
	}

	if (strcasecmp(str, "false") == 0 || strcasecmp(str, "0") == 0
			|| strcasecmp(str, "no") == 0 || strcasecmp(str, "off") == 0) {
		*bool_out = false;
		return 0;
	}

	log_err(ERR_PARSE_BOOL, "Cannot parse '%s' as a boolean (true|false|1|0|yes|no|on|off).", str);
	return -EINVAL;
}

int str_to_u8(const char *str, __u8 *u8_out, __u8 min, __u8 max)
{
	__u16 result;
	int error;

	error = str_to_u16(str, &result, min, max);
	if (error)
		return error; /* Error msg already printed. */

	*u8_out = result;
	return 0;
}

int str_to_u16(const char *str, __u16 *u16_out, __u16 min, __u16 max)
{
	long result;
	char *endptr;

	errno = 0;
	result = strtol(str, &endptr, 10);
	if (errno != 0 || str == endptr) {
		log_err(ERR_PARSE_INT, "Cannot parse '%s' as an integer value.", str);
		return -EINVAL;
	}
	if (result < min || max < result) {
		log_err(ERR_INT_OUT_OF_BOUNDS, "'%s' is out of bounds (%u-%u).", str, min, max);
		return -EINVAL;
	}

	*u16_out = result;
	return 0;
}

int str_to_hex(const char *str, __u16 *u16_out, __u16 min, __u16 max)
{
	long result;
	char *endptr;

	errno = 0;
	result = strtol(str, &endptr, 16);
	if (errno != 0 || str == endptr) {
		log_err(ERR_PARSE_INT, "Cannot parse '%s' as an integer value.", str);
		return -EINVAL;
	}
	if (result < min || max < result) {
		log_err(ERR_INT_OUT_OF_BOUNDS, "'%s' is out of bounds (%u-%u).", str, min, max);
		return -EINVAL;
	}

	*u16_out = result;
	return 0;
}

int str_to_u32(const char *str, __u32 *u32_out, __u32 min, __u32 max)
{
	long result;
	char *endptr;

	errno = 0;
	result = strtol(str, &endptr, 10);
	if (errno != 0 || str == endptr) {
		log_err(ERR_PARSE_INT, "Cannot parse '%s' as an integer value.", str);
		return -EINVAL;
	}
	if (result < min || max < result) {
		log_err(ERR_INT_OUT_OF_BOUNDS, "'%s' is out of bounds (%u-%u).", str, min, max);
		return -EINVAL;
	}

	*u32_out = result;
	return 0;
}

int str_to_u16_array(const char *str, __u16 **array_out, __u16 *array_len_out)
{
	const unsigned int str_max_len = 2048;
	/* strtok corrupts the string, so we'll be using this copy instead. */
	char str_copy[str_max_len];
	char *token;
	__u16 *array;
	__u16 array_len;

	/* Validate str and copy it to the temp buffer. */
	if (strlen(str) + 1 > str_max_len) {
		log_err(ERR_PARSE_INTARRAY, "'%s' is too long for this poor, limited parser...", str);
		return -EINVAL;
	}
	strcpy(str_copy, str);

	/* Count the number of ints in the string. */
	array_len = 0;
	token = strtok(str_copy, ",");
	while (token) {
		array_len++;
		token = strtok(NULL, ",");
	}

	if (array_len == 0) {
		log_err(ERR_PARSE_INTARRAY, "'%s' seems to be an empty list, which is not supported.", str);
		return -EINVAL;
	}

	/* Build the result. */
	array = malloc(array_len * sizeof(__u16));
	if (!array) {
		log_err(ERR_ALLOC_FAILED, "Memory allocation failed. Cannot parse the input...");
		return -ENOMEM;
	}

	strcpy(str_copy, str);

	array_len = 0;
	token = strtok(str_copy, ",");
	while (token) {
		int error;

		error = str_to_u16(token, &array[array_len], 0, 0xFFFF);
		if (error) {
			free(array);
			return error; /* Error msg already printed. */
		}

		array_len++;
		token = strtok(NULL, ",");
	}

	/* Finish. */
	*array_out = array;
	*array_len_out = array_len;
	return 0;
}

int str_to_addr4(const char *str, struct in_addr *result)
{
	if (!inet_pton(AF_INET, str, result)) {
		log_err(ERR_PARSE_ADDR4, "Cannot parse '%s' as an IPv4 address.", str);
		return -EINVAL;
	}
	return 0;
}

int str_to_addr6(const char *str, struct in6_addr *result)
{
	if (!inet_pton(AF_INET6, str, result)) {
		log_err(ERR_PARSE_ADDR6, "Cannot parse '%s' as an IPv6 address.", str);
		return -EINVAL;
	}
	return 0;
}

static char *get_error_msg(enum error_code code)
{
	switch (code) {
	case ERR_SUCCESS:
		return NULL;
	case ERR_NULL:
		return "'NULL' is not a legal value.";
	case ERR_L4PROTO:
		return "Unsupported transport protocol.";
	case ERR_L3PROTO:
		return "Unsupported network protocol.";
	case ERR_ALLOC_FAILED:
		return "A memory allocation failed, so the handling of the request could not be completed.";
	case ERR_MISSING_FRAG_HEADER:
		return "Missing fragment header in a IPv6 packet.";
	case ERR_UNKNOWN_ERROR:
		return "Unknown error.";
	case ERR_NETLINK:
		return "Netlink related error.";
	case ERR_PARSE_FILE:
		return "Can not read a file.";

		return "The TCP transitory timeout is out of range.";
	case ERR_PARSE_BOOL:
		return "Unable to parse value as a boolean.";
	case ERR_PARSE_INT:
		return "Unable to parse value as an integer.";
	case ERR_INT_OUT_OF_BOUNDS:
		return "Integer out of bounds.";
	case ERR_PARSE_INTARRAY:
		return "Invalid list of integers. Please provide numbers separated by commas. If you need "
				"spaces, please surround the entire list with quotes.";
	case ERR_PARSE_ADDR4:
		return "Could not parse the input as a IPv4 address (eg. '192.168.2.1').";
	case ERR_PARSE_ADDR6:
		return "Could not parse the input as a IPv6 address (eg. '12ab:450::1').";
	case ERR_UNKNOWN_OP:
		return "Unknown configuration operation.";
	case ERR_MISSING_PARAM:
		return "Missing input value.";
	case ERR_EMPTY_COMMAND:
		return "The command is empty. Type in 'nat64 --help' for instructions.";
	case ERR_SEND_FAILED:
		return "The kernel could not send the packet I just translated.";
	case ERR_PARSE_ARGS:
		return "Failure while parsing program's arguments.";

	case ERR_L3HDR_INIT_ERROR:
		return "Can not initialize network header.";
	case ERR_L4HDR_INIT_ERROR:
		return "Can not initialize transport header.";
	case ERR_SOCKET_FAILED:
		return "Can not create a socket.";
	case ERR_PAYLOAD_INIT_ERROR:
		return "Can not initialize the payload.";
	case ERR_ROUTE_FAILED:
		return "Can not find a route to send the packet.";

	case ERR_INIT_FAIL:
		return "Invalid value detected while initializing default values .";
	}

	return "Unknown result code.";
}

void print_code_msg(enum error_code code, char *success_msg)
{
	if (code == ERR_SUCCESS) {
		log_info("%s", success_msg);
		return;
	}

	log_err(code, "%s", get_error_msg(code));
}

void print_time(unsigned long millis)
{
	unsigned long seconds;
	unsigned long minutes;
	unsigned long hours;

	if (millis < 1000) {
		printf("%lu milliseconds\n", millis);
		return;
	}

	seconds = millis / 1000;

	if (seconds < 60) {
		printf("%lu seconds\n", seconds);
		return;
	}

	minutes = seconds / 60;
	seconds %= 60;

	if (minutes < 60) {
		printf("%lu minutes, %lu seconds\n", minutes, seconds);
		return;
	}

	hours = minutes / 60;
	minutes %= 60;

	printf("%lu hours, %lu minutes\n", hours, minutes);
}
