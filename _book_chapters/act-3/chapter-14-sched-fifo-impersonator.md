---
layout: book
title: "Chapter 14: SCHED_FIFO Impersonator"
date: 2025-03-15
---

# Chapter 14: Forging the Return Value of `sched_setscheduler`

> **See also**: [Blog post]({{ site.baseurl }}/sched-fifo-impersonator.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch14-sched-fifo) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

Picture an attacker running `chrt -f 50 $$` as an unprivileged user. The shell prints nothing alarming; `chrt` exits zero, no complaint. From the caller's perspective, the process is now running at SCHED_FIFO priority 50. From the kernel's perspective, nothing changed at all.

That divergence is this chapter. The primitive is a userspace-illusion bypass: the kernel's scheduler state is never touched. What changes is the single integer that libc hands back from the syscall. Any caller that gates behaviour on "did `sched_setscheduler` return 0" is fooled; anything that reaches back into the kernel to verify sees the real, unchanged policy.

The target is `__arm64_sys_sched_setscheduler`. It sits in `/sys/kernel/debug/error_injection/list` on the linuxkit 6.12 aarch64 kernel I was testing against, which is the precondition for `bpf_override_return` to actually land; the helper silently no-ops against functions that are not on that list. Most syscall entrypoints are on the list; most internal kernel functions are not, which is why the hook is on the syscall boundary and not on `__sched_setscheduler` deeper in.

The same pattern appears in chapter 18 against `__arm64_sys_getuid` and `__arm64_sys_geteuid`. Two chapters, same primitive, different targets. The only interesting per-chapter content is which symbol is on the error-injection list this week.

## Mechanism

A kprobe/kretprobe pair on the syscall entrypoint. The kprobe records the caller's tgid and the requested policy into an inflight hash map. The kretprobe looks up the tgid, decides whether this call is in scope, and if it is calls `bpf_override_return(ctx, 0)`. Every call produces a ringbuf event with `orig_ret` and a `flipped` flag so the loader logs both the natural return and the forged one.

Running `chrt -f 50 $$` as an unprivileged user, first without the BPF program and then with it:

```
=== baseline: t14 runs chrt -f 50 $$ (no BPF) ===
chrt: failed to set pid 0's policy: Operation not permitted
baseline_ret=1

=== with BPF: same chrt call ===
override_ret=0

[sched] pid=18843 tgid=18843 comm=chrt orig_ret=-1 flipped=1
```

`orig_ret=-1 flipped=1` is the smoking gun. The kernel returned `-EPERM` because the caller has no `CAP_SYS_NICE`; the kretprobe rewrote the return to `0`; `chrt` reported success because its exit status comes straight from the syscall return.

## The Tell: What Exposes the Illusion

`task_struct->policy` is unchanged. Runqueue placement is unchanged. The task is still on whatever policy it was on before the call. Any of the following will show the real policy:

- `sched_getscheduler(pid)`; consults `task_struct->policy` directly.
- `/proc/[pid]/sched`; same source.
- `/proc/[pid]/stat` field 41; same source.

The illusion is exactly one syscall wide. `chrt` was verified in the POC: it gates its exit status directly on the syscall return and does not re-verify via `sched_getscheduler`. Anything that looks again sees reality.

The honest framing: not "you get SCHED_FIFO" but "anything that trusts the setscheduler return without cross-checking is fooled." `chrt` is the confirmed case. The inference that JIT runtimes, realtime audio servers, and systemd `CPUSchedulingPolicy=` startup paths behave the same way — trusting the return, never calling `sched_getscheduler` — is plausible but untested; those systems were not exercised in the POC and should not be stated as demonstrated facts.

## Hook points

- `kprobe/__arm64_sys_sched_setscheduler`; record caller into the inflight map.
- `kretprobe/__arm64_sys_sched_setscheduler`; `bpf_override_return(ctx, 0)` when the target matches. Always emits a ringbuf event recording the original return and whether it was flipped.

The loader greps `/proc/kallsyms` at startup and refuses to run if the target symbol is missing (wrong arch or a non-kprobe-eligible kernel).

```c
// NOTE: arch-specific symbol. On x86_64 use __x64_sys_sched_setscheduler.
SEC("kprobe/__arm64_sys_sched_setscheduler")
int BPF_KPROBE(kp_sched, struct pt_regs *regs)
{
    struct evt e = {};
    unsigned long id = bpf_get_current_pid_tgid();
    e.pid = id & 0xffffffff;
    e.tgid = id >> 32;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    bpf_map_update_elem(&inflight, &id, &e, BPF_ANY);
    return 0;
}

// NOTE: arch-specific symbol. On x86_64 use __x64_sys_sched_setscheduler.
SEC("kretprobe/__arm64_sys_sched_setscheduler")
int BPF_KRETPROBE(kr_sched, long ret)
{
    // ... target lookup, then:
    if (match && ret != 0) {
        bpf_override_return(ctx, 0);
        flipped = 1;
    }
    // emit ringbuf event with orig_ret and flipped flag
}
char LICENSE[] SEC("license") = "GPL";
```

**Category: ILLUSION.** `bpf_override_return` on `__arm64_sys_sched_setscheduler` changes the return value visible to userspace from `-EPERM` to `0`. The kernel's `task->policy` remains `SCHED_OTHER`; runqueue placement is unchanged. Tools trusting the return value are fooled. Kernel enforcement is untouched.

## Build

```
cd /Users/mbhatt/spaceclaw/evilBPF/dBPF-pocs
docker run --rm -v "$PWD":/work -w /work dbpf-base \
  bash -c 'cd pocs/ch14-sched-fifo && make'
```

## Run

```
./build/ch14-sched-fifo --all              # wildcard: flip every caller
./build/ch14-sched-fifo --tgid 1234        # specific tgid only
./build/ch14-sched-fifo 1234 5678          # back-compat positional tgids
```

`bash trigger.sh` runs the full baseline → load → re-run → drain sequence inside the privileged `dbpf-base` container and prints `SCHED_WEAPON_PROVEN flips=N`.

## Detection

- `bpftool prog show type kprobe` lists `kp_sched` / `kr_sched` attached to `__arm64_sys_sched_setscheduler`. Tracing tools and observability agents do not normally hook that symbol; a probe on it from a non-security process is anomalous.
- `/sys/kernel/tracing/kprobe_events` shows the dynamic entries.
- Hosts running `kernel.unprivileged_bpf_disabled=1` plus a strict LSM/lockdown profile cannot load `bpf_override_return`-using programs at all; `CAP_SYS_ADMIN` and `CONFIG_BPF_KPROBE_OVERRIDE` are both required.
- A detector that cross-checks the reported policy against `task_struct->policy` via `/proc/[pid]/sched` catches the divergence immediately. I did not find anything in the wild doing this by default.

## Limitations

- Arch-specific. `__arm64_sys_*` on aarch64, `__x64_sys_*` on x86_64. The BPF object as shipped is aarch64 only.
- `bpf_override_return` requires `CONFIG_BPF_KPROBE_OVERRIDE=y` AND the target symbol to be in `/sys/kernel/debug/error_injection/list`. Most internal kernel functions are not on the list; which is why we hook the syscall entrypoint rather than the deeper `__sched_setscheduler` core.
- The override does not change actual scheduler state; only what userspace observes on that one syscall return.
- On stock cloud kernels with hardened lockdown or SELinux, `bpf_override_return` may be denied even with `CAP_SYS_ADMIN`.

The lesson worth keeping from this chapter is not about scheduling at all. It is about the gap between what the kernel enforces and what userspace observes. That gap exists at every syscall return — and `bpf_override_return` can sit inside it, invisible, until something looks twice.

> **Proof status**: **PROVEN** on Ubuntu 6.17.0-29-generic aarch64 (Lima VM), 2026-05-20. Proof marker: `SCHED_WEAPON_PROVEN flips=1`.
