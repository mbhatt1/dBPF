---
layout: book
title: "SCHED_FIFO Impersonator"
date: 2025-03-15
poc_dir: dBPF-pocs/pocs/ch14-sched-fifo
---

# SCHED_FIFO Impersonator

> **See also**: [Book chapter with investigation notes]({{ site.baseurl }}/book/act-3/chapter-14-sched-fifo-impersonator.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch14-sched-fifo)

**Chapter 14: Forging the return value of `sched_setscheduler`**

This is a userspace-illusion bypass. The kernel's scheduler state is not touched. What changes is the value libc gets back from the syscall — any caller that gates behaviour on "did `sched_setscheduler` return 0" is fooled; anything that reaches back into the kernel to verify sees the real, unchanged policy.

The target is `__arm64_sys_sched_setscheduler`. It sits in `/sys/kernel/debug/error_injection/list` on the linuxkit 6.12 aarch64 kernel I was testing against, which is the precondition for `bpf_override_return` to actually land — the helper silently no-ops against functions that are not on that list. Most syscall entrypoints are on the list; most internal kernel functions are not, which is why the hook is on the syscall boundary and not on `__sched_setscheduler` deeper in.

## Mechanism

A kprobe/kretprobe pair on the syscall entrypoint. The kprobe records the caller's tgid and the requested policy into an inflight hash map. The kretprobe looks up the tgid, decides whether this call is in scope, and if it is calls `bpf_override_return(ctx, 0)`. Every call produces a ringbuf event with `orig_ret` and a `flipped` flag so the loader logs both the natural return and the forged one.

Baseline and forge, running `chrt -f 50 $$` as an unprivileged user:

```
=== baseline: t14 runs chrt -f 50 $$ (no BPF) ===
chrt: failed to set pid 0's policy: Operation not permitted
baseline_ret=1

=== with BPF: same chrt call ===
override_ret=0

[sched] pid=18843 tgid=18843 comm=chrt orig_ret=-1 flipped=1
```

`orig_ret=-1 flipped=1` is the smoking gun. The kernel returned `-EPERM` because the caller has no `CAP_SYS_NICE`; the kretprobe rewrote the return to `0`; `chrt` reported success because its exit status comes straight from the syscall return.

## What is not happening

`task_struct->policy` is unchanged. Runqueue placement is unchanged. The task is still on whatever policy it was on before the call. Any of the following will show the real policy:

- `sched_getscheduler(pid)` — consults `task_struct->policy` directly.
- `/proc/[pid]/sched` — same source.
- `/proc/[pid]/stat` field 41 — same source.

The illusion is exactly one syscall wide. That is the honest scope: `chrt`, `systemd`, and libraries that gate on "setscheduler returned 0" will proceed as though SCHED_FIFO was granted and will not re-verify. Anything that looks again sees reality.

## Hook points

- `kprobe/__arm64_sys_sched_setscheduler` — record caller into the inflight map.
- `kretprobe/__arm64_sys_sched_setscheduler` — `bpf_override_return(ctx, 0)` when the target matches. Always emits a ringbuf event recording the original return and whether it was flipped.

The loader greps `/proc/kallsyms` at startup and refuses to run if the target symbol is missing (wrong arch or a non-kprobe-eligible kernel).

## Reproduction

```
cd /Users/mbhatt/spaceclaw/evilBPF/dBPF-pocs
docker run --rm -v "$PWD":/work -w /work dbpf-base \
  bash -c 'cd pocs/ch14-sched-fifo && make'

./build/ch14-sched-fifo --all              # flip every caller
./build/ch14-sched-fifo --tgid 1234        # one tgid only
./build/ch14-sched-fifo 1234 5678          # back-compat positional tgids
```

`bash trigger.sh` runs the full baseline → load → re-run → drain sequence inside the privileged `dbpf-base` container and prints `SCHED_WEAPON_PROVEN flips=N`.

## Detection

- `bpftool prog show type kprobe` lists `kp_sched` / `kr_sched` attached to `__arm64_sys_sched_setscheduler`. Tracing tools and observability agents do not normally hook that symbol; a probe on it from a non-security process is anomalous.
- `/sys/kernel/tracing/kprobe_events` shows the dynamic entries.
- Hosts running `kernel.unprivileged_bpf_disabled=1` plus a strict LSM/lockdown profile cannot load `bpf_override_return`-using programs at all — `CAP_SYS_ADMIN` and `CONFIG_BPF_KPROBE_OVERRIDE` are both required.
- A detector that cross-checks the reported policy against `task_struct->policy` via `/proc/[pid]/sched` catches the divergence immediately. I did not find anything in the wild doing this by default.

## Limitations

- Arch-specific. `__arm64_sys_*` on aarch64, `__x64_sys_*` on x86_64. The BPF object as shipped is aarch64 only.
- `bpf_override_return` requires `CONFIG_BPF_KPROBE_OVERRIDE=y` AND the target symbol to be in `/sys/kernel/debug/error_injection/list`.
- The override does not change actual scheduler state — only what userspace observes on that one syscall return.
- On stock cloud kernels with hardened lockdown or SELinux, `bpf_override_return` may be denied even with `CAP_SYS_ADMIN`.

---
**Related material**
- Full chapter: [Chapter 14 — SCHED_FIFO Impersonator]({{ site.baseurl }}/book/act-3/chapter-14-sched-fifo-impersonator.html)
- POC source: [dBPF-pocs/pocs/ch14-sched-fifo/](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch14-sched-fifo)
- Harness entry: `Poc("ch14", ...)` in `proof.py`
