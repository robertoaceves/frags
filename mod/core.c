/*
 * frags.c
 *
 *  Created on: Nov 22, 2013
 *      Author: user
 */

//#define __KERNEL__
//#define MODULE

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>                  /* For IP header */
#include <linux/netfilter_ipv4.h>



#include "config.h"




//#include "nat64/comm/nat64.h"
//#include "nat64/mod/packet.h"
//#include "nat64/mod/packet_db.h"
//#include "nat64/mod/pool4.h"
//#include "nat64/mod/pool6.h"
//#include "nat64/mod/bib.h"
//#include "nat64/mod/session.h"
//#include "nat64/mod/config.h"
//#include "nat64/mod/filtering_and_updating.h"
//#include "nat64/mod/translate_packet.h"
//#include "nat64/mod/core.h"


#define MODULE_NAME "Frags"

/**
 * Step the module will be injected in within Netfilter's prerouting hook.
 * (After defragmentation, before Conntrack).
 */
#define NF_PRI_FRAGS -500

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


MODULE_LICENSE("GPL");
MODULE_AUTHOR("NIC-ITESM");
MODULE_DESCRIPTION(MODULE_NAME " Fragments generator.");
MODULE_ALIAS("frags");

static char *pool6[5];
static int pool6_size;
module_param_array(pool6, charp, &pool6_size, 0);
MODULE_PARM_DESC(pool6, "The IPv6 pool's prefixes.");
static char *pool4[5];
static int pool4_size;
module_param_array(pool4, charp, &pool4_size, 0);
MODULE_PARM_DESC(pool4, "The IPv4 pool's addresses.");


//int core_4to6(struct sk_buff *skb) {
//	return 0;
//}
//
//int core_6to4(struct sk_buff *skb) {
//
//	return 0;
//}


//static unsigned int hook_ipv4(unsigned int hooknum, struct sk_buff *skb,
//		const struct net_device *in, const struct net_device *out,
//		int (*okfn)(struct sk_buff *))
//{
//	return core_4to6(skb);
//}
//
//static unsigned int hook_ipv6(unsigned int hooknum, struct sk_buff *skb,
//		const struct net_device *in, const struct net_device *out,
//		int (*okfn)(struct sk_buff *))
//{
//	return core_6to4(skb);
//}

//static unsigned int send_packet(struct sk_buff *skb)
//{
//
//	return 0;
//}



static void deinit(void)
{
	config_destroy();
}

//static struct nf_hook_ops nfho[] = {
//	{
//		.hook = hook_ipv6,
//		.hooknum = NF_INET_PRE_ROUTING,
//		.pf = PF_INET6,
//		.priority = NF_PRI_FRAGS,
//	},
//	{
//		.hook = hook_ipv4,
//		.hooknum = NF_INET_PRE_ROUTING,
//		.pf = PF_INET,
//		.priority = NF_PRI_FRAGS,
//	}
//};

//int __init frags_init(void)
int frags_init(void)
{
	int error;

//	log_debug("%s", banner);
	log_debug("Inserting the module...");

	error = config_init();
	if (error)
		goto failure;


	log_info(MODULE_NAME " module inserted.");
	return error;



failure:
	deinit();
	return error;
}

//void __exit frags_exit(void)
void frags_exit(void)
{
	deinit();
//	nf_unregister_hooks(nfho, ARRAY_SIZE(nfho));
	log_info(MODULE_NAME " module removed.");
}

module_init(frags_init);
module_exit(frags_exit);
