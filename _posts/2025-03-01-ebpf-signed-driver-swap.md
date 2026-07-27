---
layout: book
title: "eBPF Signed-Driver Swap"
date: 2025-03-01
poc_dir: dBPF-pocs/pocs/ch12-signed-driver-swap-syscall
---

# eBPF Signed-Driver Swap

> **See also**: [Book chapter]({{ site.baseurl }}/book/act-2/chapter-12-ebpf-signed-driver-swap.html) · [Skip accounting (Ch 21)]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html) · [Workaround POC](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch12-signed-driver-swap-syscall)

`/sys/kernel/debug/error_injection/list` didn't have `mod_verify_sig` or `kernel_read_file`, so the LSM fmod_ret approach was dead. It did have `__arm64_sys_finit_module` and `__arm64_sys_init_module` — syscall entry points are exactly what the error-injection allowlist is for.

The working attack is smaller and more honest than the chapter draft I started from. I want to be explicit about what it is and isn't before going near the code.

## What failed first

The original plan was canonical: hook `mod_verify_sig` (or `kernel_read_file`) as an LSM fmod_ret, watch the kernel reject an unsigned module, flip the return to success, and watch the loader continue as if the signature had checked out. Two independent failures killed this on every kernel I had available.

First, my linuxkit test kernel doesn't enforce module signatures. `CONFIG_MODULE_SIG_FORCE` is off; the signature hooks are present but advisory. Nothing ever rejects, so there's nothing to flip. Debian's stock cloud-image kernels behave the same way — signatures are verified and logged, not enforced. On these kernels the LSM hook attaches, and silently never fires on a denial path, because no denial path exists.

Second, and more fatal: `insmod` of a non-ELF blob fails at ELF validation inside the module loader, long before any signature code runs. Even on a kernel that *does* fail-close on signatures, the simplest test payload — a file that isn't a valid ELF — never reaches `mod_verify_sig`. I was hooking a check the kernel wasn't performing on the code path I was triggering — a classic wrong-enforcement-point mistake.

When both of those settled in, I stopped trying to make the LSM variant work and went looking at the error-injection list.

## What loaded, and what it actually proves

`__arm64_sys_finit_module` and `__arm64_sys_init_module` are both in `/sys/kernel/debug/error_injection/list` on 6.12 aarch64 linuxkit. That means a kretprobe on either will verify when it calls `bpf_override_return(ctx, 0)`. The override runs on syscall exit, *after* every internal rejection path has already produced an errno. It doesn't care why the loader gave up; it only cares that userspace is about to read the return value.

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
CH12_CONCEPT_PROVEN syscall_override_landed=yes module_actually_loaded=no
```

`-8` is `-ENOEXEC`. The kernel said "that isn't a valid ELF." Userspace saw `0`. The marker keeps the two facts side by side: the override landed, and the module still didn't load.

## The userspace-illusion framing, made explicit

This is a userspace-illusion bypass and nothing more. I need to be unambiguous about that because it's easy to overclaim.

The module does not load. The kernel still rejects the bytes at ELF validation (or signature check, on a kernel that does that). Kernel memory is unchanged. `lsmod` does not show the module — because no module was loaded. `/sys/module/<name>/` does not exist. `dmesg` still logs the original rejection reason. The only thing the attack changes is the integer the syscall returns to userspace.

That's the whole primitive. It fools any orchestrator or shell script that calls `finit_module(2)` and treats rc=0 as proof-of-load without cross-checking kernel state. It defeats `insmod x.ko && echo loaded`. It does not defeat `insmod x.ko && stat /sys/module/x`. Any orchestrator that post-checks `/proc/modules` catches it on the first call.

This is the same shape as ch14 (sched_setscheduler return forgery) and ch18 (getuid/geteuid return forgery). Find a syscall entry on the error-injection allowlist, attach a kretprobe, rewrite the return. The value depends entirely on whether the defender treats the syscall return as load-bearing.

The real integrity flip — the one that actually lets an unsigned module through — is a separate program, the LSM variant, and it needs an enforcing kernel (`CONFIG_MODULE_SIG_FORCE=y`) with BPF LSM in the boot string. The book chapter walks through it; this post is about the cheap illusion that works everywhere the syscall entry is on the error-injection list.

## Detection

The discrepancies are visible to anyone who checks kernel state instead of syscall returns. `lsmod` and `/proc/modules` won't list the module; `/sys/module/<name>/` won't exist; `dmesg` shows the original loader error ("Invalid module format", signature failure, unknown symbol). Any orchestrator that does `finit_module()` followed by `stat("/sys/module/<name>")` catches the forgery immediately. At the BPF layer, `bpftool prog show type kprobe` lists the retprobe attachments on `__arm64_sys_finit_module`/`__arm64_sys_init_module`, which on a production host is a load-time alert by itself; `/sys/kernel/tracing/kprobe_events` shows the registered probes. The defender's actual question is "which code path in my orchestration treats a syscall rc as authoritative." That's the surface this primitive attacks, and the only surface.

---
**Related material**
- Full chapter: [Chapter 12 — eBPF Signed-Driver Swap]({{ site.baseurl }}/book/act-2/chapter-12-ebpf-signed-driver-swap.html)
- Workaround POC: [dBPF-pocs/pocs/ch12-signed-driver-swap-syscall/](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch12-signed-driver-swap-syscall)
- Harness entry: `Poc("ch12s", ...)` in `dBPF-pocs/harness/proof.py`
