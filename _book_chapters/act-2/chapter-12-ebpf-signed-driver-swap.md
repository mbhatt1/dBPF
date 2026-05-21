---
layout: book
title: "Chapter 12: eBPF Signed-Driver Swap"
date: 2025-03-01
---

# Chapter 12: Forging the Module-Load Verdict

> **See also**: [Blog post]({{ site.baseurl }}/ebpf-signed-driver-swap.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch12-signed-driver-swap-syscall) · [Chapter 21]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html)

> **Proof status**: All three variants proved on Ubuntu 6.17.0-29-generic aarch64 (Lima VM); `ch12-signed-driver-swap` (observer), `ch12-signed-driver-swap-lsm` (real LSM flip on enforcing kernels), and `ch12-signed-driver-swap-syscall` (syscall illusion). The chapter is explicit about which does what. The syscall illusion fires on linuxkit; the real LSM flip requires `CONFIG_MODULE_SIG_FORCE=y` and BPF LSM active in `lsm=`.

`/sys/kernel/debug/error_injection/list` didn't have `mod_verify_sig` or `kernel_read_file`, so the LSM fmod_ret approach was dead on linuxkit. It did have `__arm64_sys_finit_module` and `__arm64_sys_init_module`; syscall entry points are exactly what the error-injection allowlist is for.

The working attack on linuxkit is smaller and more honest than the chapter draft I started from. I want to be explicit about what it is and isn't before going near the code.

## What failed first

The original plan was canonical: hook `mod_verify_sig` (or `kernel_read_file`) as an LSM fmod_ret, watch the kernel reject an unsigned module, flip the return to success, and watch the loader continue as if the signature had checked out.

Two independent failures killed this on the linuxkit kernel.

First, linuxkit doesn't enforce module signatures. `CONFIG_MODULE_SIG_FORCE` is off; the signature hooks are present but advisory. Nothing ever rejects, so there's nothing to flip.

Second, and more fatal: `insmod` of a non-ELF blob fails at ELF validation inside the module loader, long before any signature code runs. Even on a kernel that does fail-close on signatures, the simplest test payload; a file that isn't a valid ELF; never reaches `mod_verify_sig`. I was hooking a check the kernel wasn't performing on the code path I was triggering. Classic wrong-enforcement-point mistake.

When both of those settled in, I stopped trying to make the LSM variant work on linuxkit and went looking at the error-injection list.

## What loaded, and what it actually proves

`__arm64_sys_finit_module` and `__arm64_sys_init_module` are both in `/sys/kernel/debug/error_injection/list` on 6.12 aarch64 linuxkit. That means a kretprobe on either will accept `bpf_override_return(ctx, 0)`. The override runs on syscall exit, after every internal rejection path has already produced an errno. It doesn't care why the loader gave up.

```c
SEC("kretprobe/__arm64_sys_finit_module")
int BPF_KRETPROBE(kr_finit_module, long ret)
{
    if (is_target() && ret != 0) {
        bpf_override_return(ctx, 0);
        emit(ret, HOOK_FINIT_MODULE, /*flipped=*/1);
    }
    return 0;
}
```

Before the probe attaches, `insmod` on a non-ELF file returns rc=1 with `ENOEXEC`. After the probe attaches, `insmod` returns rc=0 and the shell script thinks the module loaded. The ringbuf event confirms the rewrite and preserves the kernel's original answer:

```
[ch12s] FORGE pid=<N> comm=insmod syscall=finit_module orig_ret=-8 -> 0
```

`-8` is `-ENOEXEC`. The kernel said "that isn't a valid ELF." Userspace saw `0`.

## The userspace-illusion framing, made explicit

This is a userspace-illusion bypass and nothing more.

The module does not load. The kernel still rejects the bytes at ELF validation. Kernel memory is unchanged. `lsmod` does not show the module. `/sys/module/<name>/` does not exist. `dmesg` still logs the original rejection reason. The only thing the attack changes is the integer the syscall returns to userspace.

That's the whole primitive. It fools any orchestrator or shell script that calls `finit_module(2)` and treats rc=0 as proof-of-load without cross-checking kernel state. It defeats `insmod x.ko && echo loaded`. It does not defeat `insmod x.ko && stat /sys/module/x`. Any orchestrator that post-checks `/proc/modules` catches it on the first call.

This is the same shape as ch14 (sched_setscheduler return forgery) and ch18 (getuid/geteuid return forgery). Find a syscall entry on the error-injection allowlist, attach a kretprobe, rewrite the return.

## The real flip: BPF LSM fmod_ret on enforcing kernels

The real primitive lives in `ch12-signed-driver-swap-lsm`. On a kernel with `CONFIG_MODULE_SIG_FORCE=y` and BPF LSM active in the `lsm=` boot string, three fmod_ret programs on `lsm/kernel_read_file`, `lsm/kernel_load_data`, and `lsm/locked_down` can flip the integrity gate. When signature enforcement is on and BPF LSM is in the chain, flipping the return of `kernel_read_file` from a denial to zero lets an unsigned blob through. The module bytes get read in and the loader continues toward actually inserting the module.

Fedora 42 aarch64 (booted with BPF LSM active by default and `module.sig_enforce` set) produces:

```
CH12_PROVEN flipped=N hook=kernel_read_file baseline=EBADMSG override=ENOEXEC
```

The errno shifted from `EBADMSG` (signature verification failed) to `ENOEXEC` (ELF validator rejected the fake blob). The LSM override changed the control flow; the subsequent ELF rejection is the fake `.ko` meeting its own separate check.

linuxkit emits `CH12_LSM_SKIP` because it doesn't enforce signatures and doesn't boot with `lsm=bpf,...`. The skip is honest.

## Detection

Discrepancies from the syscall illusion are visible to anyone who checks kernel state instead of syscall returns. `lsmod` and `/proc/modules` won't list the module. `/sys/module/<name>/` won't exist. `dmesg` shows the original loader error. Any orchestrator that does `finit_module()` followed by `stat("/sys/module/<name>")` catches the forgery immediately.

At the BPF layer, `bpftool prog show type kprobe` lists the retprobe attachments on `__arm64_sys_finit_module`/`__arm64_sys_init_module`. `/sys/kernel/tracing/kprobe_events` shows the registered probes. The defender's actual question is "which code path in my orchestration treats a syscall rc as authoritative." That's the surface this primitive attacks.

For the real LSM variant: `bpftool prog list type lsm` shows attached fmod_ret programs on `kernel_read_file`. Legitimate observability tools do not fmod_ret on module-load hooks. An fmod_ret attach from an unexpected loader on those hooks is high-signal. `dmesg` on an enforcing kernel still records the pre-flip integrity decision regardless of whether the LSM chain was subsequently overridden.

> **See also**: [POC source; ch12-signed-driver-swap-syscall](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch12-signed-driver-swap-syscall) · Harness entry: `Poc("ch12s", ...)` in `dBPF-pocs/harness/proof.py`
