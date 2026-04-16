---
layout: book
title: "Seccomp TID Hop"
date: 2025-04-20
poc_dir: dBPF-pocs/pocs/ch16-seccomp-tid-hop
---

# Seccomp TID Hop

> **See also**: [Book chapter with investigation notes]({{ site.baseurl }}/book/act-3/chapter-16-seccomp-tid-hop.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch16-seccomp-tid-hop)

**Chapter 16: Observing `__secure_computing` from a peer process**

The framing matters before anything else. Seccomp's threat model is the filtered process itself — the one wearing the restrictive filter. The model has never included "a privileged peer on the same host holding `CAP_BPF`." When that peer can attach kprobes to `__secure_computing`, the filter has already been bypassed in the threat-model sense: an attacker at that level does not need to break seccomp, they can observe it, enumerate it, and (on an error-injectable kernel) override it. What's in this POC is not a seccomp bug. It is seccomp behaving exactly as specified, observed from the side.

## Mechanism

A kprobe/kretprobe pair on `__secure_computing`, the function the kernel calls on every syscall made by a seccomp-filtered task. On 6.12.54-linuxkit aarch64 the symbol is present in `/proc/kallsyms` and kprobes attach cleanly. Every evaluation streams through a ringbuf with `{ts, pid, tid, tgid, comm, seccomp.mode, retval}`:

```
[seccomp] ts=145203418715 pid=649 tgid=649 comm=redis-server mode=FILTER target=1 nr/ret=-1 allow=0
[seccomp] ts=145203419842 pid=649 tgid=649 comm=redis-server mode=FILTER target=1 nr/ret=0  allow=1
[seccomp] ts=145203712001 pid=812 tgid=812 comm=python3      mode=FILTER target=1 nr/ret=-1 allow=0
[seccomp] ts=145203712110 pid=812 tgid=812 comm=python3      mode=FILTER target=1 nr/ret=0  allow=1
[seccomp] ts=145204018344 pid=812 tgid=812 comm=python3      mode=FILTER target=1 nr/ret=-1 allow=0
[seccomp] ts=145204018501 pid=812 tgid=812 comm=python3      mode=FILTER target=1 nr/ret=-1 allow=0  # getpriority denied
```

Two records per syscall: the kprobe entry (`nr/ret=-1`, `allow=0`) and the kretprobe tail carrying the real return value. The last line's `allow=0` on the tail is `SECCOMP_RET_ERRNO` — a `getpriority()` the filter rejected. That is a complete pre/post trace of every filter decision system-wide. For a defender this is useful. For a red-team it is a credentials-free enumeration of every seccomp policy running on the host, which filters are strict, which are permissive, and which syscalls each workload actually makes.

## Why the "TID hop" is aspirational here

The original plan was to swap the current thread's TID for a permitted sibling's TID, let the filter evaluate against the borrowed identity, and swap back. I could not implement that on the test kernel. Two independent blockers:

1. `task->seccomp.mode` and `task->seccomp.filter` cannot be mutated from eBPF. The verifier rejects writes to `task_struct`. And the filter chain itself is a BPF program, not data — there is no in-place mutation primitive even on x86.
2. `__secure_computing` is not in `/sys/kernel/debug/error_injection/list` on 6.12.54-linuxkit. `bpf_override_return` against it refuses to attach.

So the override path is documented as dormant. The loader still records `override_attempted` on every evaluation, so on a kernel where `__secure_computing` is annotated with `ALLOW_ERROR_INJECTION`, swapping the kretprobe body to `bpf_override_return(ctx, 0)` turns this observer into an actual bypass. On this kernel it is not one. Calling what shipped a seccomp "bypass" would be a lie — it is a seccomp mapper.

## Hook points

- `SEC("kprobe/__secure_computing")` — fires before every seccomp evaluation.
- `SEC("kretprobe/__secure_computing")` — captures the final return value (`0` = allow, non-zero = filtered).
- Maps: `events` (ringbuf), `target_tgids` (hash, wildcard via key 0), `inflight` (hash keyed by `pid_tgid`).

## Targeting

The loader takes the same flag shape as ch14:

| Flag | Meaning | Tradeoff |
|------|---------|----------|
| `--tgid <pid>` (repeatable, max 64) | Mark just this tgid as targeted | Surgical; events from other tasks still stream but with `target=0`. |
| `--all` | Insert wildcard key 0 | Loud; every seccomp check system-wide gets `target=1`. Use when you want to fingerprint every filter eval on the host. |
| (no flag) | Pure observation | Every event streams; `target=0` throughout. |

## Reproduction

```
docker run --rm -v "$PWD":/work -w /work dbpf-base \
  bash -c 'cd pocs/ch16-seccomp-tid-hop && make'

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

## Limitations

- Docker Desktop linuxkit aarch64 (6.12.54): `__secure_computing` is not in `/sys/kernel/debug/error_injection/list`, so the override path is dormant — observation only. The `override_attempted` flag records intent.
- `task->seccomp.filter` chain is itself a BPF program, not data — there is no in-place mutation primitive even on x86.
- Reading the syscall number from `__secure_computing` is arch-specific (arm64 stashes `nr` in `pt_regs->regs[8]`); the shipped program returns `-1` for `syscall_nr` on entry and uses the kretprobe's return value as the meaningful field. Userspace can correlate via `comm` + `ts_ns` if a precise `nr` is needed.

---
**Related material**
- Full chapter: [Chapter 16 — Seccomp TID Hop]({{ site.baseurl }}/book/act-3/chapter-16-seccomp-tid-hop.html)
- POC source: [dBPF-pocs/pocs/ch16-seccomp-tid-hop/](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch16-seccomp-tid-hop)
- Harness entry: `Poc("ch16", ...)` in `proof.py`
