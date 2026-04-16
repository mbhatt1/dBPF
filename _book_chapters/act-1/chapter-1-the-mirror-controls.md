---
layout: book
title: "Chapter 1: The Mirror Controls"
date: 2025-01-31
---

# Chapter 1: The Mirror Controls

> **See also**: [Blog post]({{ site.baseurl }}/the-mirror-controls.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch01-mirror-controls) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

I was poking at `cap_capable` on a linuxkit 6.12 VM, trying to understand what an unprivileged observer could actually see from a kprobe. The function is the single choke point every capability check routes through (`security/commons.c`), so if you want to know who is asking for what, this is where you sit. What I wanted to know next was whether I could do anything about the answer.

The short version: on a stock kernel, you cannot. `cap_capable` is not in `ALLOW_ERROR_INJECTION`, so `bpf_override_return` against it loads but never fires. The verifier accepts the program; the kernel silently ignores the override. I confirmed this by checking `/sys/kernel/debug/kprobes/list` and then by reading `kernel/bpf/verifier.c` around `check_attach_btf_id`. The result is that this chapter is about an observation channel, not a bypass. If you want the bypass you need a kernel built with `CONFIG_BPF_KPROBE_OVERRIDE=y` and the target function annotated — two conditions that almost never coincide in production.

## What `cap_capable` Hands You

The signature hasn't changed meaningfully since 5.x:

```c
int cap_capable(const struct cred *cred,
                struct user_namespace *targ_ns,
                int cap, unsigned int opts);
```

Four arguments. That matters because `PT_REGS_PARM4_CORE` on x86_64 is `rcx`, and I've seen write-ups miss the fourth arg entirely. The `cred` pointer is stable for the life of the task; `cap` is the integer capability index (`CAP_SYS_ADMIN` is 21, `CAP_NET_ADMIN` is 12); `opts` carries the noaudit bit.

## The Probe

```c
SEC("kprobe/cap_capable")
int hook_cap_check(struct pt_regs *ctx) {
    const struct cred *cred = (void *)PT_REGS_PARM1(ctx);
    int cap = (int)PT_REGS_PARM3(ctx);

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (should_elevate(pid, cap)) {
        bpf_override_return(ctx, 0);
        return 1; // Grant capability silently
    }

    return 0; // Let normal checks proceed
}
```

The `bpf_override_return` line loads fine. On a stock Debian or Ubuntu kernel it will not change the return value. I verified by attaching, calling `capset` from an unprivileged shell, and watching the syscall still fail with `EPERM`. The kprobe fires; the override is a no-op. `dmesg` says nothing either way.

## The Kprobe-Then-Kretprobe Dance

To observe the decision rather than change it, you need both sides. The entry kprobe gives you the arguments; the kretprobe gives you the verdict. Pair them with a per-PID map keyed on `tgid << 32 | tid` so you can correlate entry and return under concurrency.

- Entry: capture `cred`, `cap`, `opts`, stash in a map.
- Return: read `PT_REGS_RC(ctx)`, join against the map, emit to ringbuf.

This is the shape of any decision-point observer: two probes, one map, one ringbuf. Nothing novel — it's the same pattern `bcc/tools/capable.py` has used since 2016. What you get in return is a per-syscall feed of "who asked for what capability and what did the kernel say."

## Other Decision Points

Same pattern applies to the LSM hook surface. `security_file_permission`, `security_bprm_check`, `security_inode_getattr` — all of them are kprobe-attachable and give you a view into the decision the kernel is about to make. On a kernel with `CONFIG_BPF_LSM=y` you can additionally attach sleepable or non-sleepable LSM programs via `SEC("lsm/...")`, which gives you a supported override path. My first attempt used `SEC("lsm.s/file_permission")`. The kernel refused: the hook is not sleepable on 6.12. I dropped the `.s`. The non-sleepable variant loaded.

Seccomp is a different story. Seccomp runs before the syscall dispatch reaches most BPF attach points, so a kprobe on `__x64_sys_openat` sees the call only if seccomp has already allowed it. You cannot use kprobes to bypass seccomp. You can use them to watch what gets through.

## Detection

Anything an auditor runs will find this. `bpftool prog show` lists the loaded program. `/sys/kernel/debug/kprobes/list` shows the attached kprobe. The audit subsystem fires `AUDIT_BPF` records on program load if `auditd` is running. A defender who runs `bpftool prog show id <n> --pretty` gets the BTF, the instruction count, and the load time.

The visible artifacts are:

- `bpftool prog list` output (program type `kprobe`, attach name `cap_capable`).
- `/sys/fs/bpf/` pins if the loader pins the program.
- `AUDIT_BPF_PROG_LOAD` in `auditd`.
- The process that called `bpf(BPF_PROG_LOAD)` in `execve` history.

None of that is hidden by this chapter. Hiding load events is a later problem and lives in its own chapter.

## What This Chapter Actually Gives You

A reliable observation channel on capability decisions, with the pair-probe plumbing worked out. Override is available in theory and mostly unavailable in practice. Treat the code as a telemetry primitive; upgrade it to enforcement only on kernels where you have checked `ALLOW_ERROR_INJECTION` for the target and `CONFIG_BPF_KPROBE_OVERRIDE` in the running config.
