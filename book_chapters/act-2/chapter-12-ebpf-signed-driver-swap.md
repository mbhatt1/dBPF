---
layout: book
title: "eBPF Signed-Driver Swap"
date: 2025-03-01
---

Act II: Kernel Intrusion

**Chapter 13: Forging the finit_module Return Value**

The question I started with: can a BPF program flip a rejected kernel module load into one that userspace believes succeeded? Not actually load a malicious module — that's a different, much harder problem — but defeat the class of orchestrators and monitors that treat the module-load syscall return as proof of load.

The first approach failed. I tried a BPF LSM program on `kernel_read_file` and `mod_verify_sig`, planning to flip their returns from a signature failure to success. Two independent problems killed it on my test kernels:

1. The linuxkit kernel I'm running in Docker Desktop doesn't enforce module signatures at all. `CONFIG_MODULE_SIG_FORCE` is off. There's no signature denial to flip, because nothing is checking. Same story on Debian cloud images — stock kernels ship with signature enforcement as a warning, not a fail-closed gate. My LSM hook attached fine and never fired.
2. `insmod` of a non-ELF blob fails inside the module loader at ELF validation, well before the signature LSM hooks run. Even on a kernel that does enforce signatures, if my test payload isn't a valid ELF I never reach `mod_verify_sig`.

Both are the same category of mistake: I was trying to hook a check that wasn't happening on the code path I was triggering. The chapter draft I started from described exactly this LSM-flipping plan. It doesn't work on stock kernels.

The approach that does work is coarser, and I have to be honest that it's a userspace-illusion bypass: the module doesn't actually load. The kernel still rejects the bytes. Only the syscall return lies.

I read `/sys/kernel/debug/error_injection/list` to see what was injectable. Two entries jumped out:

```
__arm64_sys_finit_module
__arm64_sys_init_module
```

Both syscall entry wrappers are ERRNO-injectable on 6.12 aarch64 linuxkit. That means a kretprobe attached to either of them can call `bpf_override_return(ctx, 0)` and the verifier will accept it. The override runs on syscall exit, after every internal rejection path has already produced an errno, so it works regardless of why the loader gave up.

I wrote a minimal kretprobe pair, and a trigger script that calls `insmod` on a non-ELF file to force the kernel into the ENOEXEC path. Before the probe attaches, `insmod` reports failure. After it attaches, `insmod` reports success — and `lsmod` agrees that no module was loaded, because no module was loaded.

```c
SEC("kretprobe/__arm64_sys_finit_module")
int BPF_KRETPROBE(kret_finit_module, long ret)
{
    // bpf_override_return(ctx, 0) via helper — allowlisted for this symbol
    return 0;
}

SEC("kretprobe/__arm64_sys_init_module")
int BPF_KRETPROBE(kret_init_module, long ret)
{
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

Evidence from the trigger script:

```
BEFORE: insmod_rc=1 error_text="ENOEXEC"
AFTER:  insmod_rc=0 lsmod_shows_module=no syscall_return_forged=yes
[ch12s] FORGE pid=<N> comm=insmod syscall=finit_module orig_ret=-8 -> 0
=== CH12_CONCEPT_PROVEN syscall_override_landed=yes module_actually_loaded=no ===
```

`orig_ret=-8` is `-ENOEXEC` — the kernel's actual verdict, observable inside the probe before the override rewrites it.

What this buys an attacker and what it doesn't. It fools any orchestrator that calls `finit_module(2)` and treats rc=0 as load-confirmation without cross-checking `/sys/module/<name>/` or `/proc/modules`. It defeats shell scripts that do `insmod x.ko && echo loaded`. It does not actually load code into the kernel. Kernel memory is unchanged. `lsmod` is honest. `dmesg` still logs the original rejection reason.

This is the same illusion-class trick as ch14 (sched_setscheduler return forgery) and ch18 (token syscall return forgery). The primitive is always the same: find a syscall entry in the error_injection allowlist, attach a kretprobe, rewrite the return. The value depends entirely on whether the defender treats the syscall return as load-bearing.

Detection. The discrepancies are visible to anyone who checks kernel state instead of syscall returns. `lsmod` / `/proc/modules` won't list the supposedly-loaded module. `/sys/module/<name>/` won't exist. `dmesg` shows the original loader error ("Invalid module format", signature failure, unknown symbol). Any orchestrator that does `finit_module()` followed by `stat("/sys/module/<name>")` catches the forgery instantly. `bpftool prog show type kprobe` lists the retprobe attachments; `/sys/kernel/tracing/kprobe_events` shows the registered probe.

The defender's question isn't "did this load" — that's easy to verify. It's "which code path in my orchestration treats a syscall rc as authoritative." That's the surface this primitive attacks.

Factual note: the chapter I started from described intercepting `module_sig_check()`, swapping signature blobs in flight, and loading a malicious driver the kernel believed was legitimate. None of that is what this POC does, and none of it works on the kernels I tested. The working attack is smaller, and its scope is strictly the syscall boundary.
