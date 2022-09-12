#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xe49bb82b, "module_layout" },
	{ 0x46cc0598, "nf_unregister_net_hook" },
	{ 0x41c0a893, "class_destroy" },
	{ 0x9b323606, "device_destroy" },
	{ 0x6091b333, "unregister_chrdev_region" },
	{ 0x24f11544, "cdev_del" },
	{ 0x37a0cba, "kfree" },
	{ 0xd047ef18, "cdev_add" },
	{ 0xa2822610, "cdev_init" },
	{ 0x6126cf1d, "device_create" },
	{ 0x5c7f3cc9, "__class_create" },
	{ 0xe3ec2f2b, "alloc_chrdev_region" },
	{ 0x2c95e02, "nf_register_net_hook" },
	{ 0xf3463887, "init_net" },
	{ 0x13c49cc2, "_copy_from_user" },
	{ 0x88db9f48, "__check_object_size" },
	{ 0xd0da656b, "__stack_chk_fail" },
	{ 0x87a21cb3, "__ubsan_handle_out_of_bounds" },
	{ 0x60f64c0d, "kmem_cache_alloc_trace" },
	{ 0x3703b5ff, "kmalloc_caches" },
	{ 0xe4c2c66c, "rtc_ktime_to_tm" },
	{ 0xc4f0da12, "ktime_get_with_offset" },
	{ 0xa648e561, "__ubsan_handle_shift_out_of_bounds" },
	{ 0x6b10bee1, "_copy_to_user" },
	{ 0x92997ed8, "_printk" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0xbdfb6dbb, "__fentry__" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "3EF632C01A97CD460F4A45A");
