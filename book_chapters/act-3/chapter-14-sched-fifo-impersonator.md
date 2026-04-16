---
layout: book
title: "SCHED_FIFO Impersonator"
date: 2025-03-15
---

**Chapter 14: Forging the Return Value of `sched_setscheduler`**

This is a userspace-illusion bypass. Same shape as the token forgery in chapter 18: the kernel's internal state is unchanged, but the syscall return value is rewritten before it reaches libc. Anything that trusts the return value acts as if the call succeeded; anything that goes back and asks the kernel directly sees the truth.

The target is `__arm64_sys_sched_setscheduler`. I checked `/sys/kernel/debug/error_injection/list` on the linuxkit 6.12 aarch64 kernel I was testing against and it was there, which is the only reason this works — `bpf_override_return` silently no-ops against functions not on that list. Most syscall entrypoints are on the list; most internal kernel functions are not.

The mechanism is a kprobe/kretprobe pair. The kprobe records the caller's tgid and the requested policy into an inflight hash map. The kretprobe looks up the tgid, decides whether to flip, and calls `bpf_override_return(ctx, 0)`. I emit a ringbuf event on every call with `orig_ret` and a `flipped` flag so the loader can log both paths.

Baseline: an unprivileged shell calling `chrt -f 50 $$` fails with `EPERM` because it has no `CAP_SYS_NICE`. With the probe loaded in wildcard mode:

```
=== baseline: t14 runs chrt -f 50 $$ (no BPF) ===
chrt: failed to set pid 0's policy: Operation not permitted
baseline_ret=1

=== with BPF: same chrt call ===
override_ret=0

[sched] pid=18843 tgid=18843 comm=chrt orig_ret=-1 flipped=1
```

`orig_ret=-1 flipped=1` is the smoking gun. The kernel returned `-EPERM`, the kretprobe rewrote the return value to `0`, and `chrt` — which gates its exit status on the syscall return — reported success.

Here is what I want to be explicit about, because this is the honest scope of the bypass: `task_struct->policy` is not modified. The scheduler's runqueue placement is not modified. The task is still on whatever policy it was on before the call. If something in userspace calls `sched_getscheduler()` or reads `/proc/[pid]/sched` or `/proc/[pid]/stat` field 41, it will see the real, unchanged policy. The illusion is exactly one syscall wide.

That narrow scope is the whole point. `chrt`, `systemd`, and the many libraries that gate behaviour on "did setscheduler return 0" will proceed as though the task is now SCHED_FIFO. They won't re-verify. That's the class of target this primitive is aimed at.

## Hook points

- `kprobe/__arm64_sys_sched_setscheduler` — record caller into inflight map.
- `kretprobe/__arm64_sys_sched_setscheduler` — `bpf_override_return(ctx, 0)`
  when target matches; always emits a ringbuf event recording the
  original return and whether it was flipped.

The loader greps `/proc/kallsyms` at startup and refuses to run if the
target symbol is missing (wrong arch / non-kprobe-eligible kernel).

```c
SEC("kprobe/sched_setscheduler")
int impersonate_realtime(struct pt_regs *ctx) {
    pid_t pid = PT_REGS_PARM1(ctx);
    struct sched_param *param = (struct sched_param *)PT_REGS_PARM3(ctx);
    param->sched_priority = MAX_RT_PRIO - 1; // highest priority
    return 0; // bypass CAP_SYS_NICE
}
char LICENSE[] SEC("license") = "GPL";
```

## Build

```
cd /Users/mbhatt/spaceclaw/evilBPF/dBPF-pocs
docker run --rm -v "$PWD":/work -w /work dbpf-base \
  bash -c 'cd pocs/ch14-sched-fifo && make'
```

## Run

```
./build/ch14-sched-fifo --help
./build/ch14-sched-fifo --all              # wildcard: flip every caller
./build/ch14-sched-fifo --tgid 1234        # specific tgid only
./build/ch14-sched-fifo 1234 5678          # back-compat positional tgids
./build/ch14-sched-fifo --all > events.jsonl 2> status.log
```

## Detection

- `bpftool prog show type kprobe` lists `kp_sched` / `kr_sched` attached to `__arm64_sys_sched_setscheduler`. Neither tracing tools nor observability agents normally hook that symbol; a probe on it from a non-security process is anomalous.
- `/sys/kernel/tracing/kprobe_events` shows the dynamic entry.
- Hosts with `kernel.unprivileged_bpf_disabled=1` plus a strict LSM/lockdown profile cannot load `bpf_override_return`-using programs at all (requires `CAP_SYS_ADMIN` + `CONFIG_BPF_KPROBE_OVERRIDE`).
- A detector that cross-checks the reported policy against `task_struct->policy` via `/proc/[pid]/sched` would catch the divergence immediately. I did not see anything in the wild doing this.

## Limitations / arch notes

- The kprobe target is arch-specific — `__arm64_sys_*` on aarch64, `__x64_sys_*` on x86_64. The BPF object as shipped is aarch64 only.
- `bpf_override_return` requires `CONFIG_BPF_KPROBE_OVERRIDE=y` AND the target syscall to be in `/sys/kernel/debug/error_injection/list`. Most internal kernel functions are not on the list, which is why we hook the syscall entrypoint rather than the deeper `__sched_setscheduler` core.
- The override does not change actual scheduler state — only what userspace observes. A subsequent `sched_getscheduler()` returns the real, unchanged policy.
- On stock cloud kernels with hardened lockdown or SELinux, `bpf_override_return` may be denied even with `CAP_SYS_ADMIN`.
