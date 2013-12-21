/*
 * parameters.c
 *
 *  Created on: Nov 23, 2013
 *      Author: user
 */

#include <netinet/ip.h>
#include <argp.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "str_utils.h"
#include "parameters.h"
#include "configuration.h"
#include "layer_transport.h"

/*
 * OPTIONS. Field 1 in ARGP.
 * Order of fields: { NAME, KEY, ARG, FLAGS, DOC }.
 */
static struct argp_option options[] = {
	{ 0, 0, 0, 0, "Operation options:", 1 },
	{ "rand",		ARGP_INPUT_MODE_NONE,	0, 0,		"Generate random payload (Default)." },
	{ "file",		ARGP_INPUT_MODE_FILE,	"FILE", 0,	"Read payload from file." },
	{ "stdin",		ARGP_INPUT_MODE_STDIN,	0, 0,		"Read payload from standard input." },
	{ "module",		ARGP_SEND_FROM_MODULE,	0, 0,		"Send packets from the kernel module." },
	{ "mtu",		ARGP_MTU,				"NUM", 0,	"Specify the MTU value." },
	{ "frag-off",	ARGP_FRAG_OFF,			"NUM", 0,	"Specify the fragment offset." },
	{ "frag-id",	ARGP_FRAG_ID,			"NUM", 0,	"Specify the fragment identification number." },
	{ "more-frags",	ARGP_FRAG_MORE_FRAGS, 	0, 0, 		"Turn on More fragments flag." },
	{ "inc-frag-hdr", ARGP_HAS_FRAG_HDR,	0, 0,		"Insert the fragment header." },

	{ 0, 0, 0, 0, "IPv6 options:", 10 },
	{ "ipv6", 	ARGP_IPV6, 				0, 0, 		"The program will send IPv6 packets." },
	{ "sa6", 	ARGP_IPV6_SRC_ADDR, 	"ADDR6", 0, "Source address." },
	{ "da6",	ARGP_IPV6_DST_ADDR, 	"ADDR6", 0, "Destination address." },
//	{ "frag-off", ARGP_IPV6_FRAG_OFF,	"NUM", 0,	"Set fragment offset value (8 bytes blocks)." },
//	{ "frag-id",  ARGP_IPV6_FRAG_ID,	"NUM", 0,	"Set fragment identification number." },
//	{ "mf",		ARGP_IPV6_MORE_FRAG, 	0, 0, 		"Turn on More fragments flag." },
	{ "next-hdr", ARGP_IPV6_NEXT_HDR,	0, 0,		"Set the next header value." },

	{ 0, 0, 0, 0, "IPv4 options:", 20 },
	{ "ipv4",	ARGP_IPV4, 				0, 0, 		"The program will send IPv4 packets." },
	{ "sa4",	ARGP_IPV4_SRC_ADDR,		"ADDR4", 0, "Source address." },
	{ "da4",	ARGP_IPV4_DST_ADDR,		"ADDR4", 0, "Destination address." },
	{ "df",		ARGP_IPV4_DONT_FRAG, 	0, 0, 		"Turn on Don't fragment flag." },
//	{ "mf",		ARGP_IPV4_MORE_FRAG,	0, 0, 		"Turn on More fragments flag." },
//	{ "frag-off", ARGP_IPV4_FRAG_OFF, 	"NUM", 0,	"Set fragment offset value (8 bytes blocks)." },
	{ "ttl", 	ARGP_IPV4_TTL, 			"NUM", 0,	"Set Time To Live." },

	{ 0, 0, 0, 0, "Transport protocol selection:", 30 },
	{ "icmp",	ARGP_ICMP, 		0, 0, 		"Create a ICMP packet." },
	{ "tcp", 	ARGP_TCP,		0, 0, 		"Create a TCP packet." },
	{ "udp", 	ARGP_UDP, 		0, 0,		"Create a UDP packet." },
	{ "sp",		ARGP_SRC_PORT, 	"NUM", 0,	"Specify source port." },
	{ "dp",		ARGP_DST_PORT, 	"NUM", 0,	"Specify destination port." },
	{ "id", 	ARGP_ICMP_ID,	"NUM", 0,	"Specify ID number." },

	{ 0, 0, 0, 0, "TCP protocol options:", 31 },
	{ "seq", 		ARGP_TCP_SEQ,		"NUM", 0, 	"Specify TCP sequence number." },
	{ "ack", 		ARGP_TCP_ACK,		"NUM", 0, 	"Specify TCP acknowledgment number." },
	{ "flag-urg",	ARGP_TCP_FLAG_URG, 	0, 0, 		"Rise TCP URG flag." },
	{ "flag-ack",	ARGP_TCP_FLAG_ACK, 	0, 0, 		"Rise TCP ACK flag." },
	{ "flag-rst",	ARGP_TCP_FLAG_RST, 	0, 0, 		"Rise TCP RST flag." },
	{ "flag-syn",	ARGP_TCP_FLAG_SYN, 	0, 0, 		"Rise TCP SYN flag." },
	{ "flag-fin",	ARGP_TCP_FLAG_FIN,	0, 0, 		"Rise TCP FIN flag." },
	{ "tcp-chksum",	ARGP_TCP_CHKSUM,	"NUM", 0, 	"Specify the TCP checksum manually." },

	{ 0, 0, 0, 0, "UDP protocol options:", 32 },
	{ "udp-len", 	ARGP_UDP_LEN,	"NUM", 0,	"Specify the total payload length (hdr + all_data)." },
	{ "udp-chksum",	ARGP_UDP_CHKSUM,"NUM", 0,	"Specify the UDP checksum." },

	{ 0, 0, 0, 0, "ICMP protocol options:", 33 },
	{ "icmp-type",	ARGP_ICMP_TYPE, 	"NUM", 0, 	"Specify the ICMP message type." },
	{ "icmp-code",	ARGP_ICMP_CODE, 	"NUM", 0,	"Specify the ICMP message code." },
	{ "icmp-rest",	ARGP_ICMP_REST, 	"NUM", 0,	"Specify the ICMP rest of header (4 bytes)." },
	{ "icmp-chksum", ARGP_ICMP_CHKSUM,	"NUM", 0, 	"Specify the ICMP checksum manually." },

	{ 0, 0, 0, 0, "Payload options:", 40 },
	{ "payload-size", ARGP_PAYLOAD_LEN,	"NUM", 0,	"Specify the payload length (or size)." },

	{ 0 },
};

/*
 * PARSER. Field 2 in ARGP.
 */
static int parse_opt(int key, char *arg, struct argp_state *state) {
	struct arguments *arguments = state->input;
	int error = 0;
	__u16 temp;
	__u32 temp32;

	switch (key) {
	case ARGP_INPUT_MODE_NONE:
		arguments->input_mode = INPUT_MODE_NONE;
		arguments->input_mode_set = true;
		break;
	case ARGP_INPUT_MODE_FILE:
		arguments->input_mode = INPUT_MODE_FILE;
		arguments->input_file = arg;
		arguments->input_file_set = true;
		arguments->input_mode_set = true;
		break;
	case ARGP_INPUT_MODE_STDIN:
		arguments->input_mode = INPUT_MODE_STDIN;
		arguments->input_mode_set = true;
		break;

	case ARGP_SEND_FROM_MODULE:
		arguments->send_from_kernel_module = true;
		break;
	case ARGP_MTU:
		error = str_to_u16(arg, &temp, 0, 0xFFFF);
		arguments->mtu = temp;
		arguments->mtu_set= true;
		break;
	case ARGP_FRAG_OFF:
		error = str_to_u16(arg, &temp, 0, 0xFFFF);
		arguments->frag_offset = temp;
		arguments->frag_offset_set = true;
		break;
	case ARGP_FRAG_ID:
		error = str_to_u16(arg, &temp, 0, 0xFFFF);
		arguments->frag_id = temp;
		arguments->frag_id_set = true;
		break;
	case ARGP_FRAG_MORE_FRAGS:
		arguments->frag_more_frags_set = true;
		break;
	case ARGP_HAS_FRAG_HDR:
		arguments->has_frag_hdr = true;
		break;

	case ARGP_IPV6:
		arguments->mode = MODE_IPV6;
		arguments->ipv6 = true;
		break;
	case ARGP_IPV4:
		arguments->mode = MODE_IPV4;
		arguments->ipv4 = true;
		break;
	case ARGP_ICMP:
		arguments->operation = OP_ICMP;
		arguments->icmp = true;
		break;
	case ARGP_TCP:
		arguments->operation = OP_TCP;
		arguments->tcp = true;
		break;
	case ARGP_UDP:
		arguments->operation = OP_UDP;
		arguments->udp = true;
		break;

	case ARGP_IPV6_SRC_ADDR:
		error = str_to_addr6(arg, &arguments->ipv6_src);
		arguments->ipv6_src_set = true;
		break;
	case ARGP_IPV6_DST_ADDR:
		error = str_to_addr6(arg, &arguments->ipv6_dst);
		arguments->ipv6_dst_set = true;
		break;

	case ARGP_IPV4_SRC_ADDR:
		error = str_to_addr4(arg, &arguments->ipv4_src);
		arguments->ipv4_src_set = true;
		break;
	case ARGP_IPV4_DST_ADDR:
		error = str_to_addr4(arg, &arguments->ipv4_dst);
		arguments->ipv4_dst_set = true;
		break;

//	case ARGP_IPV6_MORE_FRAG:
//		arguments->ipv6_flags |= IPV6_FLAG_MORE_FRAGS;
//		arguments->ipv6_flags_set = true;
//		break;
//	case ARGP_IPV6_FRAG_OFF:
//		error = str_to_u16(arg, &temp, 0, 0x7FFF);
//		arguments->ipv6_frag_off = temp;
//		arguments->ipv6_frag_off_set = true;
//		break;
//	case ARGP_IPV6_FRAG_ID:
//		error = str_to_u32(arg, &temp32, 0, 0xFFFFffff);
//		arguments->ipv6_frag_id = temp32;
//		arguments->ipv6_frag_id_set = true;
//		break;
	case ARGP_IPV6_NEXT_HDR:
		error = str_to_u16(arg, &temp, 0, 0xFF);
		arguments->ipv6_next_hdr = temp;
		arguments->ipv6_next_hdr_set = true;
		break;
	case ARGP_IPV4_DONT_FRAG:
		arguments->ipv4_flags |= IPV4_FLAG_DONT_FRAG;
		arguments->ipv4_flags_set = true;
		break;
//	case ARGP_IPV4_MORE_FRAG:
//		arguments->ipv4_flags |= IPV4_FLAG_MORE_FRAGS;
//		arguments->ipv4_flags_set = true;
//		break;
//	case ARGP_IPV4_FRAG_OFF:
//		error = str_to_u16(arg, &temp, 0, 0x7FFF);
//		arguments->ipv4_frag_off = temp;
//		arguments->ipv4_frag_off_set = true;
//		break;

	case ARGP_SRC_PORT:
		error = str_to_u16(arg, &temp, 0, 0xFFFF);
		arguments->port_src = temp;
		arguments->port_src_set = true;
		break;
	case ARGP_DST_PORT:
		error = str_to_u16(arg, &temp, 0, 0xFFFF);
		arguments->port_dst = temp;
		arguments->port_dst_set = true;
		break;
	case ARGP_ICMP_ID:
		error = str_to_u16(arg, &temp, 0, 0xFFFF);
		arguments->port_id = temp;
		arguments->port_id_set = true;
		break;

	case ARGP_TCP_SEQ:
		error = str_to_u32(arg, &temp32, 0, 0xFFFFFFFF);
		arguments->tcp_seq_num = temp32;
		arguments->tcp_seq_num_set = true;
		break;
	case ARGP_TCP_ACK:
		error = str_to_u32(arg, &temp32, 0, 0xFFFFFFFF);
		arguments->tcp_ack_num = temp32;
		arguments->tcp_ack_num_set = true;
		break;
	case ARGP_TCP_FLAG_URG:
		arguments->tcp_flags |= TCP_URG;
		arguments->tcp_flags_set = true;
		break;
	case ARGP_TCP_FLAG_ACK:
		arguments->tcp_flags |= TCP_ACK;
		arguments->tcp_flags_set = true;
		break;
	case ARGP_TCP_FLAG_RST:
		arguments->tcp_flags |= TCP_RST;
		arguments->tcp_flags_set = true;
		break;
	case ARGP_TCP_FLAG_SYN:
		arguments->tcp_flags |= TCP_SYN;
		arguments->tcp_flags_set = true;
		break;
	case ARGP_TCP_FLAG_FIN:
		arguments->tcp_flags |= TCP_FIN;
		arguments->tcp_flags_set = true;
		break;
	case ARGP_TCP_CHKSUM:
		error = str_to_hex(arg, &temp, 0, 0xFFFF);
		arguments->tcp_chksum = temp;
		arguments->tcp_chksum_set = true;
		break;

	case ARGP_UDP_LEN:
		error = str_to_u16(arg, &temp, 0, 0xFFFF);
		arguments->udp_len = temp;
		arguments->udp_len_set = true;
		break;
	case ARGP_UDP_CHKSUM:
		error = str_to_hex(arg, &temp, 0, 0xFFFF);
		arguments->udp_chksum = temp;
		arguments->udp_chksum_set = true;
		break;

	case ARGP_ICMP_TYPE:
		error = str_to_u16(arg, &temp, 0, 0xFFFF);
		arguments->icmp_type = temp;
		arguments->icmp_type_set = true;
		break;
	case ARGP_ICMP_CODE:
		error = str_to_u16(arg, &temp, 0, 0xFFFF);
		arguments->icmp_code = temp;
		arguments->icmp_code_set = true;
		break;
	case ARGP_ICMP_REST:
		error = str_to_u32(arg, &temp32, 0, 0xFFFFFFFF);
		arguments->icmp_rest = temp32;
		arguments->icmp_rest_set = true;
		break;
	case ARGP_ICMP_CHKSUM:
		error = str_to_hex(arg, &temp, 0, 0xFFFF);
		arguments->icmp_chksum = temp;
		arguments->icmp_chksum_set = true;
		break;

	case ARGP_PAYLOAD_LEN:
		error = str_to_u32(arg, &temp32, 0, 0xFFFFFFFF);
		arguments->payload_len = temp32;
		arguments->payload_len_set = true;
		break;

/* Future reference:
#define ARGP_ARGS_QTY_MIN 2
#define ARGP_ARGS_QTY_MAX 2
	case ARGP_KEY_ARG:
	   if (state->arg_num >= ARGP_ARGS_QTY_MAX)
		 / * Too many arguments. * /
		 argp_usage (state);
	   arguments->args[state->arg_num] = arg;
	   break;
	 case ARGP_KEY_END:
	   if (state->arg_num < ARGP_ARGS_QTY_MIN)
		 / * Not enough arguments. * /
		 argp_usage (state);
	   break;
*/

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return error;
}

const char *argp_program_version = "Frags userspace app 0.1";
const char *argp_program_bug_address = "<aleiva@nic.mx>";

/*
 * ARGS_DOC. Field 3 in ARGP.
 * A description of the non-option command-line arguments we accept.
 */
static char args_doc[] = "";

/*
 * DOC. Field 4 in ARGP.
 * Program documentation.
 */
static char doc[] = "frags -- The fragmented packets generator.\v";

/**
 * Uses argp.h to read the parameters from the user, validates them, and returns the result as a
 * structure.
 */
int parse_args(int argc, char **argv, struct arguments *result) {
	struct stat stats;
	int error;
	int input_fd;
	struct argp argp = { options, parse_opt, args_doc, doc };

	memset(result, 0, sizeof(*result));

	error = argp_parse(&argp, argc, argv, 0, 0, result);
	if (error != 0) {
		log_debug("Error en args_parse: %d", error);
		return error;
	}

	/* Operation */ /*
	if (!result->input_mode_set) {
		/ * Detect input method according this chart:
		cmd\method             ctermid    open   isatty   fstat
		――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
		./test                 /dev/tty   OK     YES      S_ISCHR
		./test ≺ test.cc       /dev/tty   OK     NO       S_ISREG
		cat test.cc | ./test   /dev/tty   OK     NO       S_ISFIFO
		echo ./test | at now   /dev/tty   FAIL   NO       S_ISREG  (Assume this will not happen)* /

		error = fstat(fileno(stdin), &stats);
		if (error) {
			perror("parse_args");
			return -EINVAL;
		}
		if (!isatty(fileno(stdin)) && (S_ISREG(stats.st_mode) || S_ISFIFO(stats.st_mode))) {
			result->input_mode = INPUT_MODE_STDIN;
			result->input_mode_set = true;
		} else { / * Generate payload * /
			result->input_mode = INPUT_MODE_NONE;
			result->input_mode_set = true;
		}
	} */

	if (result->input_mode_set) {
		switch (result->input_mode) {
		case INPUT_MODE_FILE:
			input_fd = open(result->input_file, O_RDONLY, S_IRUSR );
			if (!input_fd) { /* Can not open file */
				log_err(ERR_PARSE_FILE, "Cannot open file: %s", result->input_file);
				perror("parse_args");
				return -EINVAL;
			}
			error = fstat(input_fd, &stats);
			if (error || !S_ISREG(stats.st_mode)) {
				log_err(ERR_PARSE_FILE, "Cannot get statistics for file: %s", result->input_file);
				perror("parse_args");
				return -EINVAL;
			}
			result->input_fd = input_fd;
			result->payload_len = stats.st_size;
			result->payload_len_set = true;
			break;
		case INPUT_MODE_STDIN:
			result->input_fd = fileno(stdin);
			if (!result->payload_len_set)
				result->payload_len = 0; /*_*/
			break;
		case INPUT_MODE_NONE:
			if (!result->payload_len_set)
				result->payload_len = 0; /*_*/
			break;
		}
	}

	/* Network */
	switch (result->mode) {
	case MODE_IPV6:
		if (!result->ipv6_dst_set) {
			log_err(ERR_MISSING_PARAM, "Please enter the IPv6 destination address (--thing).");
			return -EINVAL;
		}
		break;
	case MODE_IPV4:
		if (!result->ipv4_dst_set) {
			log_err(ERR_MISSING_PARAM, "Please enter the IPv4 destination address (--thing).");
			return -EINVAL;
		}
		break;
	default:
		log_err(ERR_EMPTY_COMMAND, "Command seems empty; --help or --usage for info.");
		return -EINVAL;
	}
	if ((result->ipv6 + result->ipv4) > 1) {
		log_err(ERR_L3PROTO, "Multiple network protocol specified.");
		return -EINVAL;
	}
	if (!result->ipv6 && !result->ipv4) { /* TODO: It seems this will never happen. */
		log_err(ERR_L3PROTO, "No network protocol specified.");
		return -EINVAL;
	}

	/* Transport */
	switch (result->operation) {
	case OP_UDP:
		if (!result->port_dst_set) {
			log_err(ERR_MISSING_PARAM, "Please set the UDP destination port.");
			return -EINVAL;
		}
		break;
	case OP_TCP:
		if (!result->port_dst_set) {
			log_err(ERR_MISSING_PARAM, "Please set the TCP destination port.");
			return -EINVAL;
		}
		break;
	case OP_ICMP:
		if (!result->port_id_set) {
			log_err(ERR_MISSING_PARAM, "Please set the ICMP Identification number.");
			return -EINVAL;
		}
		break;
	default:
		log_err(ERR_L3PROTO, "No transport protocol specified.");
		return -EINVAL;
	}
	if ((result->tcp + result->udp + result->icmp) > 1 ) {
		log_err(ERR_L4PROTO, "Multiple transport protocol specified.");
		return -EINVAL;
	}

	return 0;
}

