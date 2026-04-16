# ch03 — FUSE Audit Black-Hole (observer)

The chapter's premise: intercept audit events at `audit_log_start()` and
either drop them or divert them to a sinkhole FUSE mount. The real kernel
primitive you'd need is `bpf_override_return()` on the audit entry points.

## What this POC does

It attaches a kprobe to each of the three key audit message-construction
functions and streams every call through a ring buffer:

| Hook              | Meaning                                           |
|-------------------|---------------------------------------------------|
| `audit_log_start` | A new audit record is about to be built          |
| `audit_log_format`| Format string being appended to the record       |
| `audit_log_end`   | Record finalized and queued to the audit daemon  |

Each event emits `{pid, tgid, comm, hook, audit_type, fmt_preview}`. The
userspace loader prints a human-readable decode of common `AUDIT_*` type
constants.

## Why observer-only, not mutator

The chapter calls for `bpf_override_return(0)` (or similar) on
`audit_log_start()` to make the record vanish. On this kernel image
(linuxkit 6.12 aarch64) the audit functions are **not** listed in
`/sys/kernel/debug/error_injection/list`. The kernel enforces that
`bpf_override_return()` is only permitted on functions marked
`ALLOW_ERROR_INJECTION`, which is essentially only `__arm64_sys_*`
syscall entry points. Attempting to attach an override to
`audit_log_start` fails at `bpf(BPF_PROG_LOAD)` with `-EINVAL`.

The "black-hole" vector is therefore documented but not exercised. On a
kernel built with `ALLOW_ERROR_INJECTION(audit_log_start, ...)` — or via a
kprobe-based patch that clobbers `ab` to `NULL` through writable kernel
memory — the same ring-buffer events would be joined by a one-line hook
that forces an early return. The detection surface is identical, which is
the point of running the observer: defenders can use exactly this feed to
alarm on audit-subsystem tampering.

## Files
- `ch03-fuse-blackhole.bpf.c` — three kprobes, one ringbuf, one ctrl array
- `ch03-fuse-blackhole.c`     — loader, ringbuf poller, AUDIT_* decoder
- `trigger.sh`                — provokes audit-worthy events
- `Makefile`                  — `APP := ch03-fuse-blackhole`

## Build

    cd /Users/mbhatt/spaceclaw/evilBPF/dBPF-pocs && \
    docker run --rm -v "$PWD":/work -w /work dbpf-base \
      bash -c 'cd pocs/ch03-fuse-blackhole && make'

## Run

    cd /Users/mbhatt/spaceclaw/evilBPF/dBPF-pocs && \
    docker run --rm --privileged --pid=host \
      -v "$PWD":/work -w /work \
      -v /sys/kernel/debug:/sys/kernel/debug \
      -v /sys/fs/bpf:/sys/fs/bpf \
      dbpf-base bash -c 'cd /work/pocs/ch03-fuse-blackhole && \
        ./build/ch03-fuse-blackhole & L=$!; sleep 1; \
        bash trigger.sh; sleep 2; kill $L'

Expected output: a stream of `[audit]` lines showing each audit_log_start
record being built, what format strings are appended, and when the record
is ended. Even without an audit daemon the hooks fire because the kernel
unconditionally calls into this path for task-context recording.

## Detection (for the defender)

- `bpftool prog show` lists three `kprobe` programs named `kp_als`,
  `kp_ale`, `kp_alf`. A normal system has zero kprobes on audit symbols.
- `cat /sys/kernel/tracing/kprobe_events` shows the attached probes.
- Signed-kernel environments can refuse `bpf(BPF_PROG_LOAD)` via
  `kernel.unprivileged_bpf_disabled=2` and LSM (lockdown integrity).
- auditd itself can subscribe to its own self-monitoring records; a
  sudden drop in `AUDIT_SYSCALL` volume while login activity continues
  is a classic black-hole signature.

## Mutation path the chapter describes

On a kernel where `audit_log_start` is injection-allowlisted, add:

```c
SEC("kprobe/audit_log_start")
int BPF_KPROBE(drop_als, void *actx, unsigned gfp, int type)
{
    if (type == AUDIT_SYSCALL || type == AUDIT_EXECVE)
        bpf_override_return(ctx, 0);  // return NULL ab; record discarded
    return 0;
}
```

The kernel subsequently treats `ab == NULL` as "out of memory / disabled"
and the record is silently dropped. No corresponding `audit_log_end`
fires. Defenders watching pairing ratios between `audit_log_start` and
`audit_log_end` will see the drift.

## Blog post

See the chapter write-up: [`2025-02-02-the-fuse-audit-black-hole`](../../../_posts/2025-02-02-the-fuse-audit-black-hole.md) in the Diabolical eBPF Field Manual.
