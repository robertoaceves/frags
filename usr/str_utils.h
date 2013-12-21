/**
 * @file
 * Two-liners (since you need to check the return value) for string-to-something else conversions.
 * This is only used by the parser of the user's arguments, so it's very noisy on the console on
 * purpose.
 *
 * @author Alberto Leiva
 */

#ifndef _STR_UTILS_H_
#define _STR_UTILS_H_

#include <netinet/in.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>

#include "types.h"

#define u8 u_int8_t
#define __u8 u_int8_t
#define __u16 u_int16_t
#define __u32 u_int32_t


int str_to_bool(const char *str, bool *bool_out);
int str_to_u8(const char *str, __u8 *u8_out, __u8 min, __u8 max);
int str_to_u16(const char *str, __u16 *u16_out, __u16 min, __u16 max);
int str_to_u16_array(const char *str, __u16 **array_out, __u16 *array_len_out);
int str_to_u32(const char *str, __u32 *u32out, __u32 min, __u32 max);
int str_to_hex(const char *str, __u16 *u16_out, __u16 min, __u16 max);

/**
 * Converts "str" to a IPv4 address. Stores the result in "result".
 *
 * Useful mainly in code common to kernelspace and userspace, since their conversion functions
 * differ, but meant to be used everywhere to strip the parameters from in4_pton() we don't want.
 */
int str_to_addr4(const char *str, struct in_addr *result);
/**
 * Converts "str" to a IPv6 address. Stores the result in "result".
 *
 * Useful mainly in code common to kernelspace and userspace, since their conversion functions
 * differ, but meant to be used everywhere to strip the parameters from in6_pton() we don't want.
 */
int str_to_addr6(const char *str, struct in6_addr *result);


#endif /* _STR_UTILS_H_ */
