// SPDX-License-Identifier: GPL-2.0
/*
 * RISC-V IEE checks based on Elkeid's anti_rootkit.c and Tyton's checks.
 * https://github.com/bytedance/Elkeid/blob/main/driver/LKM/src/anti_rootkit.c
 * https://github.com/nbulischeck/tyton
 * Original Tyton author: Nick Bulischeck <nbulisc@clemson.edu>.
 */
#ifdef CONFIG_IEE_ANTI_ROOTKIT

#include <linux/compiler.h>
#include <linux/fs.h>
#include <linux/iee_security.h>
#include <linux/init.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/rcupdate.h>

#include <asm/haoc/iee-def.h>

/* Bound each list walk; the experiment assumes otherwise valid metadata. */
#define ANTI_ROOTKIT_MAX_MODULES	4096U

static __always_inline bool
core_text(const struct iee_security_context *ctx, unsigned long addr)
{
	return addr >= ctx->text_start && addr < ctx->text_end;
}

static __always_inline int
check_syscalls(const struct iee_security_context *ctx,
	       void * const *table, unsigned int count, int finding)
{
	unsigned int i;
	int result = 0;

	for (i = 0; i < count; i++) {
		unsigned long addr = (unsigned long)READ_ONCE(table[i]);

		if (!core_text(ctx, addr))
			result |= finding;
	}
	return result;
}

static __always_inline bool same_name(const char *a, const char *b)
{
	unsigned int i;

	/* Module names are embedded in struct module, not external strings. */
	for (i = 0; i < MODULE_NAME_LEN; i++) {
		char left = READ_ONCE(a[i]);
		char right = READ_ONCE(b[i]);

		if (left != right)
			return false;
		if (!left)
			return true;
	}
	return false;
}

static __always_inline int
module_visible(const struct iee_security_context *ctx,
	       const struct module *candidate)
{
	const struct list_head *node;
	unsigned int visited = 0;

	for (node = rcu_dereference_raw(ctx->modules->next); node != ctx->modules;
	     node = rcu_dereference_raw(node->next)) {
		const struct module *mod;

		if (visited++ == ANTI_ROOTKIT_MAX_MODULES)
			return -1;
		mod = list_entry(node, struct module, list);
		if (READ_ONCE(mod->state) != MODULE_STATE_UNFORMED &&
		    same_name(mod->name, candidate->name))
			return 1;
	}
	return 0;
}

static __always_inline int
check_modules(const struct iee_security_context *ctx)
{
	const struct list_head *head = &ctx->module_kset->list;
	const struct list_head *node;
	unsigned int visited = 0;
	int result = 0;

	for (node = READ_ONCE(head->next); node != head;
	     node = READ_ONCE(node->next)) {
		const struct module_kobject *mkobj;
		const struct kobject *kobj;
		const struct module *mod;
		int visible;

		if (visited++ == ANTI_ROOTKIT_MAX_MODULES)
			return result | IEE_ANTI_ROOTKIT_INCOMPLETE;
		kobj = list_entry(node, struct kobject, entry);
		mkobj = container_of(kobj, struct module_kobject, kobj);
		mod = READ_ONCE(mkobj->mod);
		/* Built-in entries have no module; transient modules are skipped. */
		if (!mod || READ_ONCE(mod->state) != MODULE_STATE_LIVE)
			continue;
		visible = module_visible(ctx, mod);
		if (visible < 0)
			return result | IEE_ANTI_ROOTKIT_INCOMPLETE;
		if (!visible)
			result |= IEE_ANTI_ROOTKIT_HIDDEN_MODULE;
	}
	return result;
}

static __always_inline int
check_proc(const struct iee_security_context *ctx)
{
	const struct inode *inode = file_inode(ctx->proc_file);
	unsigned long addr;
	int result = 0;

	/*
	 * Detect replacement without dereferencing an untrusted operations
	 * pointer. Read the callback only from the known static root table.
	 */
	if (READ_ONCE(ctx->proc_file->f_op) != ctx->proc_root_ops ||
	    READ_ONCE(inode->i_fop) != ctx->proc_root_ops)
		result |= IEE_ANTI_ROOTKIT_PROC;
	addr = (unsigned long)READ_ONCE(ctx->proc_root_ops->iterate_shared);
	if (!core_text(ctx, addr))
		result |= IEE_ANTI_ROOTKIT_PROC;
	return result;
}

static int __iee_code notrace
anti_rootkit_check(const struct iee_security_context *ctx)
{
	int result;

	result = check_syscalls(ctx, ctx->syscalls, ctx->syscall_count,
				IEE_ANTI_ROOTKIT_SYSCALL);
#ifdef CONFIG_COMPAT
	result |= check_syscalls(ctx, ctx->compat_syscalls,
				 ctx->compat_syscall_count,
				 IEE_ANTI_ROOTKIT_COMPAT_SYSCALL);
#endif
	result |= check_proc(ctx);
	result |= check_modules(ctx);
	return result;
}

static const struct iee_security_ops anti_rootkit_ops = {
	.check = anti_rootkit_check,
};

static int __init anti_rootkit_init(void)
{
	return iee_security_register(&anti_rootkit_ops);
}

static void __exit anti_rootkit_exit(void)
{
	iee_security_unregister(&anti_rootkit_ops);
}

module_init(anti_rootkit_init);
module_exit(anti_rootkit_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("IEE anti-rootkit experiment contributors");
MODULE_DESCRIPTION("Silent Elkeid-style anti-rootkit checks inside RISC-V IEE");

#endif /* CONFIG_IEE_ANTI_ROOTKIT */
