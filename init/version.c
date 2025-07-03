// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/init/version.c
 *
 *  Copyright (C) 1992  Theodore Ts'o
 *
 *  May be freely distributed as part of Linux.
 */

#include <generated/compile.h>
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export.h>
#include <linux/uts.h>
#include <linux/utsname.h>
#include <generated/utsrelease.h>
#include <linux/version.h>
#include <linux/proc_ns.h>

struct uts_namespace init_uts_ns = {
	.ns.count = REFCOUNT_INIT(2),
	.name = {
		.sysname	= UTS_SYSNAME,
		.nodename	= UTS_NODENAME,
		.release	= UTS_RELEASE,
		.version	= UTS_VERSION,
		.machine	= UTS_MACHINE,
		.domainname	= UTS_DOMAINNAME,
	},
	.user_ns = &init_user_ns,
	.ns.inum = PROC_UTS_INIT_INO,
#ifdef CONFIG_UTS_NS
	.ns.ops = &utsns_operations,
#endif
};
EXPORT_SYMBOL_GPL(init_uts_ns);

/* FIXED STRINGS! Don't touch! */
const char linux_banner[] =
    "Linux version 5.15.167-android13-8-00014-gbf0a81a7f319-ab13297889 (zako@build-host) "
    "(Android 杂鱼, 你是可爱小猫娘, LLD 21.0.0) #1 SMP PREEMPT Tue Apr 1 14:07:47 UTC 2025\n";

const char linux_proc_banner[] =
    "Linux version 5.15.167-android13-8-00014-gbf0a81a7f319-ab13297889 (zako@build-host) "
    "(Android 杂鱼, 你是可爱小猫娘, LLD 21.0.0) #1 SMP PREEMPT Tue Apr 1 14:07:47 UTC 2025\n";

BUILD_SALT;
BUILD_LTO_INFO;
