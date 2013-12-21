#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x8495e121, "module_layout" },
	{ 0x7a88059b, "ip_local_out" },
	{ 0xa7f6f440, "mutex_unlock" },
	{ 0x72aa82c6, "param_ops_charp" },
	{ 0x228e8bd3, "netlink_kernel_create" },
	{ 0x27e1a049, "printk" },
	{ 0x1f4dc3d4, "netlink_kernel_release" },
	{ 0xf5132983, "netlink_rcv_skb" },
	{ 0xb4390f9a, "mcount" },
	{ 0xf2516109, "mutex_lock" },
	{ 0xb123947d, "netlink_unicast" },
	{ 0xd40dbb60, "init_net" },
	{ 0x20869484, "ip6_route_output" },
	{ 0xf400a72a, "__alloc_skb" },
	{ 0xfea48b5a, "__ip_route_output_key" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x236c8c64, "memcpy" },
	{ 0xf59f197, "param_array_ops" },
	{ 0xff9ac3eb, "ip6_local_out" },
	{ 0xd80245f6, "skb_put" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "4F82821F25E95E9BB996B02");
