---
layout: book
title: "Seccomp TID Hop"
date: 2025-04-20
---

**Chapter 16: Observing `__secure_computing` From a Peer Process**

Before anything else in this chapter: seccomp's threat model is the filtered process. It was never the gap between a filtered process and a sibling with `CAP_BPF`. When a privileged peer can load kprobes on `__secure_computing`, the filtered task's filter has already been bypassed in the threat-model sense — an attacker at that level does not need to break seccomp, they can just attach to it. What follows is not a seccomp bug; it is seccomp behaving exactly as documented, observed from the side.

I started with an observer: a kprobe on `__secure_computing` and a paired kretprobe. That function is called on every syscall made by a seccomp-filtered task. On 6.12.54-linuxkit aarch64 the symbol is present in `/proc/kallsyms` and kprobes attach cleanly. Every evaluation streams through a ringbuf with `{ts, pid, tid, tgid, comm, seccomp.mode, retval}`:

```
[seccomp] ts=145203418715 pid=649 tgid=649 comm=redis-server mode=FILTER target=1 nr/ret=-1 allow=0
[seccomp] ts=145203419842 pid=649 tgid=649 comm=redis-server mode=FILTER target=1 nr/ret=0  allow=1
[seccomp] ts=145203712001 pid=812 tgid=812 comm=python3      mode=FILTER target=1 nr/ret=-1 allow=0
[seccomp] ts=145203712110 pid=812 tgid=812 comm=python3      mode=FILTER target=1 nr/ret=0  allow=1
[seccomp] ts=145204018344 pid=812 tgid=812 comm=python3      mode=FILTER target=1 nr/ret=-1 allow=0
[seccomp] ts=145204018501 pid=812 tgid=812 comm=python3      mode=FILTER target=1 nr/ret=-1 allow=0  # getpriority denied
```

Two records per syscall: the kprobe entry (`nr/ret=-1`, `allow=0`) and the kretprobe paired tail carrying the real return value. On the final line `allow=0` on the tail corresponds to `SECCOMP_RET_ERRNO` — a `getpriority()` that the filter rejected. That is a full pre/post decision trace for every filter evaluation system-wide. For a defender this is useful; for a red-team it is a credentials-free enumeration of every seccomp policy running on the host, which filters are strict, which are permissive, and which syscalls each workload actually makes.

The chapter's original title calls for a "TID hop" — swap the current thread's TID for the TID of a permitted sibling, let the filter evaluate against the borrowed identity, and swap back. I could not implement this on the test kernel. Two independent reasons:

1. `task->seccomp.mode` and `task->seccomp.filter` cannot be mutated from eBPF. The verifier rejects writes to `task_struct`.
2. `__secure_computing` is not in `/sys/kernel/debug/error_injection/list` on 6.12.54-linuxkit. `bpf_override_return` against it refuses to attach and brings the program down with it.

So the override path is documented as aspirational and dormant. The loader still records `override_attempted` on every evaluation so that, on a kernel where `__secure_computing` is annotated with `ALLOW_ERROR_INJECTION`, switching the kretprobe body to `bpf_override_return(ctx, 0)` would turn the observer into an actual bypass. On this kernel, it is not one. Calling the observation path a seccomp "bypass" would be a lie; it is a seccomp mapper.

## Hook points

- `SEC("kprobe/__secure_computing")` — fires before every seccomp evaluation. Present in `/proc/kallsyms` on 6.12.54 aarch64.
- `SEC("kretprobe/__secure_computing")` — captures the final return value (0 = allow, non-zero = filtered).
- Maps: `events` (ringbuf), `target_tgids` (hash, wildcard via key 0), `inflight` (hash keyed by pid_tgid).

```c
SEC("kprobe/__secure_computing")
int bypass_seccomp(struct pt_regs *ctx) {
    u32 orig = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u32 alt = get_allowed_tid();
    bpf_override_current_tgid(alt);
    // allow syscall
    bpf_override_current_tgid(orig);
    return 0;
}
char LICENSE[] SEC("license") = "GPL";
```

(The snippet above is the aspirational bypass form. The shipped program is an observer/kretprobe pair; `bpf_override_current_tgid` is not a helper and `__secure_computing` is not error-injectable on this kernel.)

## Targeting

The loader takes the same flag shape as ch14:

| Flag | Meaning | Tradeoff |
|------|---------|----------|
| `--tgid <pid>` (repeatable, max 64) | Mark just this tgid as targeted | Surgical — events from other tasks still stream but with `target=0`. Preferred for production demos. |
| `--all` | Insert wildcard key 0 | Loud — every seccomp check system-wide gets `target=1`. Use when you specifically want to fingerprint every filter eval on the host. |
| (no targeting flag) | Pure observation | Every event still streams; `target=0`. Useful for baseline. |

## Build

```
docker run --rm -v "$PWD":/work -w /work dbpf-base \
  bash -c 'cd pocs/ch16-seccomp-tid-hop && make'
```

## Run

```
docker run --rm --privileged --pid=host \
  -v "$PWD":/work -w /work \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/fs/bpf:/sys/fs/bpf \
  dbpf-base bash pocs/ch16-seccomp-tid-hop/trigger.sh
```

## Detection

- `bpftool prog show | grep __secure_computing` lists kprobes on this symbol. Only security tooling should hook it; a probe from an unexpected process is a strong signal.
- `cat /sys/kernel/tracing/kprobe_events` shows dynamic probes.
- Any program calling `bpf_override_return` against a seccomp symbol is almost certainly malicious. `bpftool prog dump xlated` surfaces the helper-call opcode.

## Limitations / arch notes

- Docker Desktop linuxkit aarch64 (6.12.54): `__secure_computing` is not in `/sys/kernel/debug/error_injection/list`, so the override path is dormant — observation only. The `override_attempted` flag records intent.
- `task->seccomp.filter` chain is itself a BPF program, not data — there is no in-place mutation primitive even on x86.
- Reading the syscall number from `__secure_computing` is arch-specific (arm64 stashes `nr` in `pt_regs->regs[8]`); the shipped program returns `-1` for `syscall_nr` on entry and uses the kretprobe's return value as the meaningful field. Userspace can correlate via `comm` + `ts_ns` if a precise `nr` is needed.
