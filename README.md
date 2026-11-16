# anti_rootkit

RISC-V IEE compatibility and overhead experiment based on
[Elkeid's anti_rootkit.c](https://github.com/bytedance/Elkeid/blob/main/driver/LKM/src/anti_rootkit.c)
and [Tyton](https://github.com/nbulischeck/tyton). It provides one resident
checker to the matching `linux-riscv-security-tool` kernel. No scan logging,
event stream, notifications or automatic remediation is added.

## Configuration and external module

Enable `CONFIG_IEE_ANTI_ROOTKIT=y` in the matching RISC-V kernel. It depends
on IEE, modules, sysfs and procfs and automatically selects shared
`CONFIG_IEE_SECURITY_TOOLS`. The option is off by default. It is mutually
exclusive with `CONFIG_IEE_RKSPOTTER` and `CONFIG_IEE_RKBREAKER` in Kconfig.
`CONFIG_IEE_SECURITY_NONE` (Disabled) is the default selection. Memory hotplug
and debug page allocation are excluded because the scanner relies on stable
direct-map memory. PREEMPT_RT is excluded because the IRQ path uses a regular
kset spinlock. Both SWMMU and CSRRSI use the normal IEE gate.

The Makefile is an external Kbuild file; it adds `anti_rootkit.ko` only when
that kernel configuration enables `CONFIG_IEE_ANTI_ROOTKIT`. Use the matching
configured kernel tree as the external-module build directory. This repository
does not generate or change the kernel configuration.

Loading the module opens and pins the current `/proc` root and registers an
RCU-published callback. Each hardware IRQ exit attempts one full check inside
IEE, after the interrupt handler and before `irq_exit_rcu()`. There is no
15-minute interval or periodic thread. The IRQ path tries the kset list lock
without waiting; a busy lock skips that IRQ's scan. With no checker it returns
without entering IEE. Unloading withdraws the callback and waits for RCU readers
before closing the file and freeing module code. Only the configured tool may
register, and a second registration returns `-EBUSY`. The alternative rkspotter
configuration reuses the same IRQ adapter, PGD-entry copying and shared lower
module mappings; it does not require this tool's option.

## Checks

The scope follows Elkeid's reduced subset of Tyton, adapted to RISC-V. The
goal is to measure compatibility and IEE execution overhead for common hiding
and entry-point hooks, rather than provide complete rootkit coverage.

All table reads, module walks and detection decisions execute inside IEE:

- Hidden modules: walk `module_kset` and look up each live module name in the
  ordinary module list. Built-in entries and modules loading or unloading are
  skipped. Each list walk is bounded at 4096 entries. This catches modules
  removed from the ordinary list while their sysfs registration remains.
- Syscall hooks: read every native table entry and test whether its numeric
  target lies in `[_stext, _etext)`. Check the complete compat table as well
  when `CONFIG_COMPAT=y`, using its own array length. Numeric comparisons
  detect dispatch targets outside core text without executing those targets.
- `/proc` hooks: check the opened root directory's file and inode operations
  against the known static proc root table, then check that table's current
  `iterate_shared` target against the kernel text range. Replacement tables
  set a finding bit without dereferencing their potentially invalid pointers.
  This checks the directory traversal entry point without invoking it.

Tyton also calls `iterate_dir()` to enumerate `/proc` entries and flag zero
inode numbers. That check is omitted, matching Elkeid: directory enumeration
would execute filesystem and potentially hooked callbacks, adding allocation
and sleeping-lock paths that do not fit this read-only IEE scan.

The x86 IDT checks, Tyton's other process/network checks, whole-module-address
space scans, signatures, instruction hashes and repairs are not included.
Modules removed from both sysfs and the module list are outside this check's
coverage. Redirects within core text and inline instruction patches are also
outside the address-range checks.

## Build enabled and disabled variants

From the matching kernel repository, use:

```sh
bash scripts/build-anti-rootkit-ab.sh both  # Both kernels; enabled variant also builds the LKM
bash scripts/build-anti-rootkit-ab.sh on    # Enabled kernel and anti_rootkit.ko only
bash scripts/build-anti-rootkit-ab.sh off   # Disabled kernel only
```

The base is `k3_bianbu_defconfig`. By default the script selects anti_rootkit,
toggling `CONFIG_IEE_ANTI_ROOTKIT` and automatically selected common
`CONFIG_IEE_SECURITY_TOOLS`, plus the Disabled choice
`CONFIG_IEE_SECURITY_NONE`, while keeping rkspotter and rkbreaker disabled.
It verifies that only those three options differ before building both images. Use `TOOL=rkspotter`
with the same script to select the alternative checker. Other base IEE settings
are preserved. `CROSS_COMPILE`, `JOBS`, `ARTIFACTS` and `TOOL_DIR`
are configurable; the default tool directory is this sibling repository.
Builds run sequentially in the kernel tree, saving separate images, configs,
symbols and logs under a fresh `../Image-dir/anti-rootkit-*` output directory.
The script backs up an existing `.config` and `Module.symvers`, leaves the tree
configured for the last variant, and does not clean, install or deploy.

## Kernel interface and safety assumptions

The shared API is `include/linux/iee_security.h` in the kernel tree.
Both ports use `struct iee_security_ops` with `check(ctx)`, register through
`iee_security_register()` and withdraw through `iee_security_unregister()`.
`iee_security_check()` exposes the same non-blocking path as the IRQ hook
for explicit measurements. It returns zero, `IEE_ANTI_ROOTKIT_*` finding bits,
`-ENODEV` without a checker, or `-EAGAIN` if the kset lock is busy or IEE is not
ready. The IRQ hook discards the result; there is no stored findings log. A
list limit returns the `INCOMPLETE` bit. Registration and unregistration may
sleep and must run in ordinary process context.

Registration prepares the pinned file and static context outside IEE. The IRQ
path uses RCU for the module list and a non-blocking kset list lock; it never
takes `module_mutex`, opens files or synchronizes mappings. Inside IEE the
callback only reads live inputs and returns status bits. It does not allocate,
sleep, log, invoke suspect callbacks, use exception probes or enter another
gate. A replacement `/proc` mount is not followed until the checker is reloaded.

IEE construction already copies `swapper_pg_dir`. Before linking any new module
into the visible list, the loader synchronizes missing module directory entries
in process context with `module_mutex` held. Registration also synchronizes
existing mappings. Lower tables are shared without allocation; cross-CPU TLB
flushes happen only on changes and never in the IRQ hook. Divergent private IEE
subtrees are not overwritten. Incompatible layouts fail before publishing the
module or checker, including some randomized layouts.

The experiment assumes valid list pointers and normal kernel object
lifetimes. RCU and the kset lock cover normal concurrent loading/unloading;
they do not make arbitrary hostile pointers safe. Bounded walks prevent endless
cycles but do not provide fault recovery. No guarantee is made for arbitrary
memory corruption or hardware faults. A gate disables interrupts for the
whole check, so its duration grows with the number of modules. Checking at
every successful IRQ can substantially increase CPU cost and interrupt latency.
The trigger avoids a monitor thread's scheduling dependency but does not ensure
unavoidable execution: lock contention and masked interrupts can delay scans.
