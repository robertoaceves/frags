/*
 * config.c
 *
 *  Created on: Nov 25, 2013
 *      Author: user
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/skbuff.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/sock.h>
#include <net/netlink.h>

#include "config.h"
#include "types.h"
#include "config_proto.h"
#include "communication.h"
#include "ipv6_hdr_iterator.h"
#include "send_packet.h"



/**
 * Socket the userspace application will speak to.
 */
static struct sock *nl_socket;

/**
 * A lock, used to avoid sync issues when receiving messages from userspace.
 */
static DEFINE_MUTEX(my_mutex);


/**
 * Use this when data_len is known to be smaller than BUFFER_SIZE. When this might not be the case,
 * use the output stream instead (out_stream.h).
 */
static int respond_single_msg(struct nlmsghdr *nl_hdr_in, int type, void *payload, int payload_len)
{
	struct sk_buff *skb_out;
	struct nlmsghdr *nl_hdr_out;
	int res;

	skb_out = nlmsg_new(NLMSG_ALIGN(payload_len), GFP_ATOMIC);
	if (!skb_out) {
		log_err(ERR_ALLOC_FAILED, "Failed to allocate a response skb to the user.");
		return -ENOMEM;
	}

	nl_hdr_out = nlmsg_put(skb_out,
			0, /* src_pid (0 = kernel) */
			nl_hdr_in->nlmsg_seq, /* seq */
			type, /* type */
			payload_len, /* payload len */
			0); /* flags */
	memcpy(nlmsg_data(nl_hdr_out), payload, payload_len);
	/* NETLINK_CB(skb_out).dst_group = 0; */

	res = nlmsg_unicast(nl_socket, skb_out, nl_hdr_in->nlmsg_pid);
	if (res < 0) {
		log_err(ERR_NETLINK, "Error code %d while returning response to the user.", res);
		return res;
	}

	return 0;
}


/**
 * @note "ACK messages also use the message type NLMSG_ERROR and payload format but the error code
 * is set to 0." (http://www.infradead.org/~tgr/libnl/doc/core.html#core_msg_ack).
 */
static int respond_error(struct nlmsghdr *nl_hdr_in, int error)
{
	struct nlmsgerr payload = { abs(error), *nl_hdr_in };
	return respond_single_msg(nl_hdr_in, NLMSG_ERROR, &payload, sizeof(payload));
}

/*
 * Size includes fragment header if packet is IPv6. */
inline unsigned int net_hdr_size(struct request_hdr *r_hdr, void *pkt) {
	struct hdr_iterator iterator = HDR_ITERATOR_INIT((struct ipv6hdr *)pkt);
	enum hdr_iterator_result result;
	u_int16_t hdr_size = 0;
	struct iphdr *hdr4 = pkt;

	switch (r_hdr->mode) {
	case L3PROTO_IPV6:
		/* Skip to nexh hdr. */
		/*
		hdr_iterator_next(&iterator);
		if (iterator.hdr_type == NEXTHDR_FRAGMENT)
			hdr_size += sizeof(struct frag_hdr);
		hdr_size += sizeof(struct ipv6hdr);
		*/
		result = hdr_iterator_last(&iterator);
		if (result != HDR_ITERATOR_END) {
			log_err(ERR_SEND_FAILED, "Invalid network header found while iterating.");
			return -1;
		}
		hdr_size = iterator.data - pkt;
		break;

	case L3PROTO_IPV4:
//		hdr_size =  sizeof(struct iphdr);
//		hdr_size = sizeof(*hdr4) + (hdr4->ihl << 2);
		hdr_size = (hdr4->ihl << 2);
		break;

	default:
		log_err(ERR_L3PROTO, "Invalid mode: %u", r_hdr->mode);
		return -1;
	}

	return hdr_size;
}






u_int16_t trans_hdr_size(struct request_hdr *r_hdr) {
	switch (r_hdr->operation) {
	case L4PROTO_TCP:
		return sizeof(struct tcphdr);
	case L4PROTO_UDP:
		return sizeof(struct udphdr);
	case L4PROTO_ICMP:
		return sizeof(struct icmphdr);
	case L4PROTO_ICMP6:
		return sizeof(struct icmp6hdr);
	default:
		log_err(ERR_ROUTE_FAILED, "Invalid operation: %u", r_hdr->operation);
		return 0;
	}
}

struct dst_entry * route_packet(struct request_hdr *r_hdr, void *pkt) {
	void *l4_hdr = pkt + net_hdr_size(r_hdr, pkt);

//	l4_hdr += trans_hdr_size(r_hdr);

log_debug("(route_packet) request_hdr:	%p	+	%x:	%p", r_hdr, 12, (void *)r_hdr + 12);
log_debug("(route_packet) pkt:		%p	+	%x:	%p", pkt, net_hdr_size(r_hdr, pkt), (void *)pkt + net_hdr_size(r_hdr, pkt) );
log_debug("(route_packet) l4_hdr:		%p", l4_hdr);

log_debug("(route_packet) net_hdr_size(r_hdr, pkt):%d", net_hdr_size(r_hdr, pkt));
log_debug("(route_packet) trans_hdr_size(r_hdr):%d", trans_hdr_size(r_hdr));


	switch (r_hdr->mode) {
	case L3PROTO_IPV6:
		return route_ipv6(pkt, l4_hdr, r_hdr->operation, 0);
	case L3PROTO_IPV4:
		return route_ipv4(pkt, l4_hdr, r_hdr->operation, 0);
	default:
		log_err(ERR_ROUTE_FAILED, "Invalid mode: %u", r_hdr->mode);
	}

	return NULL;
}

static int skb_from_pkt(struct request_hdr *r_hdr, void *pkt, struct sk_buff **new_skb) {
//	struct sk_buff *new_skb = *skb;
	u_int16_t head_room = 0;
	u_int16_t tail_room = 0;
	u_int32_t actual_total_size = r_hdr->length - sizeof(*r_hdr);
	struct dst_entry *dst;

	u_int32_t l3hdr_size = net_hdr_size(r_hdr, pkt);
//	u_int32_t l4hdr_size = trans_hdr_size(r_hdr);

log_debug("(skb_from_pkt) actual_total_size:%d", actual_total_size);
	*new_skb = alloc_skb(head_room /* user's reserved. */
			+ LL_MAX_HEADER /* kernel's reserved + layer 2. */
			+ actual_total_size /* l3 header + l4 header + packet data. */
			+ tail_room, /* user's reserved+. */
			GFP_ATOMIC);
	if (!*new_skb) {
		log_err(ERR_ALLOC_FAILED, "Can not create any sk_buff at all!");
		return -EINVAL;
	}
	skb_reserve(*new_skb, head_room + LL_MAX_HEADER); /* Reserve space for Link Layer data. */
	skb_put(*new_skb, actual_total_size); /* Space for actual packet L3+L4+payload */
	skb_set_mac_header(*new_skb, 0);

//	skb_set_network_header(*new_skb, (*new_skb)->mac_header);
	skb_set_network_header(*new_skb, 0);

	skb_set_transport_header(*new_skb, l3hdr_size);
	(*new_skb)->ip_summed = CHECKSUM_UNNECESSARY; /* No offloading stuff. */


	dst = route_packet(r_hdr, pkt);
	if (!dst)
		return -EINVAL;
	(*new_skb)->dev = dst->dev;
	skb_dst_set(*new_skb, dst);

	(*new_skb)->mark = 0;

	/* Copy packet content to skb. */
	memcpy(skb_network_header(*new_skb), pkt, actual_total_size);

	switch (r_hdr->mode) {
	case L3PROTO_IPV6:
		(*new_skb)->protocol = htons(ETH_P_IPV6);
		break;

	case L3PROTO_IPV4:
		(*new_skb)->protocol = htons(ETH_P_IP);
		break;

	default:
		log_err(ERR_SEND_FAILED, "Invalid mode: %u.", r_hdr->mode);
		return -EINVAL;
	}
log_debug("Everyone happy in skb_from_pkt().");
	return 0;
}

/*
 * @param[in] r_hdr
 * */
static int handle_send_packet_order(struct nlmsghdr *nl_hdr, struct request_hdr *r_hdr,
		void *pkt)
{
	struct sk_buff *new_skb = NULL;
	int error = 0;

	error = skb_from_pkt(r_hdr, pkt, &new_skb);
	if (error) {
		log_err(ERR_SEND_FAILED, "Cannot obtain a skb from a packet.");
		return -EINVAL;
	}
if (new_skb)
	if (new_skb->dev)
		if (new_skb->dev->name)
			log_debug("Sending skb via device '%s'...", new_skb->dev->name);
		else
			log_debug("No new_skb->dev->name!");
	else
		log_debug("No new_skb->dev!");
else
	log_debug("No new_skb!");

//log_debug("Guessing!"); return -1;


	switch (r_hdr->mode){
	case L3PROTO_IPV6:

		error = ip6_local_out(new_skb);

		break;

	case L3PROTO_IPV4:

		error = ip_local_out(new_skb);

		break;

	default:
		return respond_error(nl_hdr, -EINVAL);
	}

	/* the ip*_local_out() functions free the skb, so prevent crashing during frag_kfree(). */
	new_skb = NULL;

	if (error) {
		log_err(ERR_SEND_FAILED, "The kernel's packet dispatch function returned errcode %d. "
				"Cannot send packet.", error);
	}

	return respond_error(nl_hdr, error);
}



/**
 * Gets called by "netlink_rcv_skb" when the userspace application wants to interact with us.
 *
 * @param skb packet received from userspace.
 * @param nlh message's metadata.
 * @return result status.
 */
static int handle_netlink_message(struct sk_buff *skb_in, struct nlmsghdr *nl_hdr)
{
	struct request_hdr *r_hdr;
	void *pkt;
	int error;

	if (nl_hdr->nlmsg_type != MSG_TYPE_FRAGS) {
		log_debug("Expecting %#x but got %#x.", MSG_TYPE_FRAGS, nl_hdr->nlmsg_type);
		return -EINVAL;
	}

	r_hdr = NLMSG_DATA(nl_hdr);
	pkt = r_hdr + 1;

log_debug("(handle_netlink_message) r_hdr->mode:%u, r_hdr->operation:%u, r_hdr->length:%u",
		r_hdr->mode, r_hdr->operation, r_hdr->length);

	error = handle_send_packet_order(nl_hdr, r_hdr, pkt);
	if (error){
//		log_err(ERR_UNKNOWN_OP, "Unknown configuration mode: %d", r_hdr->mode);
		error = respond_error(nl_hdr, -EINVAL);
	}

	return error;
//log_debug("I survived!"); return -1;
}



/**
 * Gets called by Netlink when the userspace application wants to interact with us.
 *
 * @param skb packet received from userspace.
 */
static void receive_from_userspace(struct sk_buff *skb)
{
	log_debug("Message arrived.");
	mutex_lock(&my_mutex);
	netlink_rcv_skb(skb, &handle_netlink_message);
	mutex_unlock(&my_mutex);
}

int config_init(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
	nl_socket = netlink_kernel_create(&init_net, NETLINK_USERSOCK, 0, receive_from_userspace,
			NULL, THIS_MODULE);
#else
	struct netlink_kernel_cfg nl_cfg = {
		.groups = 0,
		.input  = receive_from_userspace,
		.cb_mutex = NULL,
	};
	nl_socket = netlink_kernel_create(&init_net, NETLINK_USERSOCK, &nl_cfg);
#endif

	if (!nl_socket) {
		log_err(ERR_NETLINK, "Creation of netlink socket failed.");
		return -EINVAL;
	}
	log_debug("Netlink socket created.");

	return 0;
}

void config_destroy(void)
{
	netlink_kernel_release(nl_socket);
}

