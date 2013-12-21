#ifndef _NF_NAT64_TYPES_H
#define _NF_NAT64_TYPES_H

/**
 * @file
 * The NAT64's core data types. Structures used all over the code.
 *
 * Both the kernel module and the userspace application can see this file.
 *
 * @author Miguel Gonzalez
 * @author Ramiro Nava
 * @author Robert Aceves
 * @author Alberto Leiva
 */

#include <linux/types.h>
#ifdef __KERNEL__
	#include <linux/in.h>
	#include <linux/in6.h>
#else
	#include <stdbool.h>
	#include <arpa/inet.h>
	#include <stdio.h>
#endif
#include <linux/netfilter.h>

#define MODULE_NAME "frags"


/**
 * Logging utilities, meant for standarization of error messages.
 */
#ifdef __KERNEL__
	#define log_error(func, id, text, ...) func("%s: ERR%d (%s): " text "\n", MODULE_NAME, id, \
			__func__, ##__VA_ARGS__)
	#define log_informational(func, text, ...) func(text "\n", ##__VA_ARGS__)
#else
	#define log_error(func, id, text, ...) printf("ERR%d: " text "\n", id, ##__VA_ARGS__)
	#define log_informational(func, text, ...) printf(text "\n", ##__VA_ARGS__)
#endif

/** Messages to help us walk through a run. */
#define log_debug(text, ...)	log_informational(pr_debug, text, ##__VA_ARGS__)
/** "I'm dropping the packet and it's perfectly normal." */
#define log_info(text, ...)		log_informational(pr_info, text, ##__VA_ARGS__)
/** "I'm dropping the packet because it's corrupted." (i. e. nothing's wrong with the NAT64) */
#define log_warning(text, ...)	log_informational(pr_warning, text, ##__VA_ARGS__)
/** "I'm dropping the packet because the config's flipped out or a kmalloc failed." */
#define log_err(id, text, ...)	log_error(pr_err, id, text, ##__VA_ARGS__)
/** "I'm dropping the packet because I detected a programming error." */
#define log_crit(id, text, ...)	log_error(pr_crit, id, text, ##__VA_ARGS__)

typedef enum {
	RES_FAILURE = -1,
	RES_SUCCESS = 0
} result_t;

enum error_code {
	/* General */
	ERR_SUCCESS = 0,
	ERR_NULL = 1,
	ERR_L4PROTO = 2,
	ERR_L3PROTO = 3,
	ERR_ALLOC_FAILED = 4,
	ERR_UNKNOWN_ERROR = 5,

	ERR_NETLINK = 10,

	ERR_L3HDR_INIT_ERROR = 20,
	ERR_L4HDR_INIT_ERROR = 21,

	ERR_PARSE_ADDR6 = 30,
	ERR_PARSE_ADDR4 = 31,

	ERR_PAYLOAD_INIT_ERROR = 50,

	ERR_MISSING_FRAG_HEADER = 100,

	ERR_PARSE_BOOL = 1000,
	ERR_PARSE_INT,
	ERR_INT_OUT_OF_BOUNDS,
	ERR_PARSE_INTARRAY,
	ERR_PARSE_ARGS,

	ERR_UNKNOWN_OP = 2000,
	ERR_MISSING_PARAM,
	ERR_EMPTY_COMMAND,
	ERR_PARSE_FILE,

	ERR_INIT_FAIL = 3000,

	/* Send packet */
	ERR_SEND_FAILED = 4501,
	ERR_ROUTE_FAILED = 4500,
	ERR_SOCKET_FAILED = 4502,
};

typedef enum verdict {
	/** No problems thus far, processing of the packet can continue. */
	VER_CONTINUE = -1,
	/** Packet is not meant for translation. Please hand it to the local host. */
	VER_ACCEPT = NF_ACCEPT,
	/** Packet is invalid and should be dropped. */
	VER_DROP = NF_DROP,
	/*
	 * Packet is a fragment, and I need more information to be able to translate it, so I'll keep
	 * it for a while.
	 */
	VER_STOLEN = NF_STOLEN,
} verdict;


/** Network protocol */
typedef enum {
	L3PROTO_IPV4 = AF_INET,
	L3PROTO_IPV6 = AF_INET6
#define L3PROTO_COUNT 2
} l3_protocol;

/** Transport protocol */
typedef enum {
	L4PROTO_NONE = 0,
	L4PROTO_UDP = IPPROTO_UDP,
	L4PROTO_TCP = IPPROTO_TCP,
	L4PROTO_ICMP = IPPROTO_ICMP,
	L4PROTO_ICMP6 = IPPROTO_ICMPV6,
#define L4PROTO_COUNT 5
} l4_protocol;

char *l3proto_to_string(l3_protocol proto);

char *l4proto_to_string(l4_protocol proto);




/**
 * All of these functions return "true" if the first parameter is the same as the second one, even
 * if they are pointers to different places in memory.
 *
 * @param addr_1 struct you want to compare to "addr_2".
 * @param addr_2 struct you want to compare to "addr_1".
 * @return (*addr_1) === (*addr_2).
 */
bool ipv4_addr_equals(struct in_addr *addr_1, struct in_addr *addr_2);
bool ipv6_addr_equals(struct in6_addr *addr_1, struct in6_addr *addr_2);

bool is_icmp6_info(__u8 type);
bool is_icmp6_error(__u8 type);
bool is_icmp4_info(__u8 type);
bool is_icmp4_error(__u8 type);


#endif
