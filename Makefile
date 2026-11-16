# SPDX-License-Identifier: GPL-2.0
# External Kbuild: use the matching kernel configured with this option.
ifeq ($(CONFIG_IEE_ANTI_ROOTKIT),y)
obj-m += anti_rootkit.o

# No instrumentation helpers may run on the IEE callback path.
CFLAGS_REMOVE_anti_rootkit.o += $(CC_FLAGS_FTRACE)
KASAN_SANITIZE_anti_rootkit.o := n
KCSAN_SANITIZE_anti_rootkit.o := n
UBSAN_SANITIZE_anti_rootkit.o := n
KCOV_INSTRUMENT_anti_rootkit.o := n
GCOV_PROFILE_anti_rootkit.o := n
endif
