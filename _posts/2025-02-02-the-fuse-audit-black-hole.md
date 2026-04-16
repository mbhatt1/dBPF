---
layout: book
title: "The FUSE Audit Black-Hole"
date: 2025-02-02
poc_dir: dBPF-pocs/pocs/ch03-fuse-blackhole
---

# The FUSE Audit Black-Hole

> **See also**: [Full investigation notes in the book]({{ site.baseurl }}/book/act-1/chapter-3-the-fuse-audit-black-hole.html) · [POC source](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch03-fuse-blackhole)

I went into this one expecting it to work.

The primitive I wanted: a kretprobe on `audit_log_start` that returns `NULL`, or an `fmod_ret` on the fentry variant, to stop certain records from ever being built. On a stock 6.12 linuxkit kernel, neither landed. `grep audit_log_start /sys/kernel/debug/error_injection/list` returns nothing, so `bpf_override_return` is inert. The fentry variant loads in its own directory (`ch03-fuse-blackhole-fentry/`) but `audit_log_start` is not in the `bpf_modify_return_targets` BTF set through 6.8 and linuxkit 6.12 did not backport the audit suppression patch series from 2022. The kretprobe attaches; overriding does nothing.

What the POC does instead is an observation channel: kprobes on `audit_log_start`, `audit_log_format`, and `audit_log_end` copy every kernel-side audit record into a ringbuf that the loader reads. On a host without `auditd` running, userspace sees no records at all; with the loader running, an unprivileged peer with CAP_BPF sees every one. Exfil, not suppression.

## Mechanism

```c
SEC("kprobe/audit_log_start")
int BPF_KPROBE(kp_start, struct audit_context *ctx, gfp_t gfp, int type) {
    emit_audit_start(ctx, type);
    return 0;
}

SEC("kprobe/audit_log_format")
int BPF_KPROBE(kp_fmt, struct audit_buffer *ab, const char *fmt) {
    emit_audit_fmt(ab, fmt);
    return 0;
}

SEC("kprobe/audit_log_end")
int BPF_KPROBE(kp_end, struct audit_buffer *ab) {
    emit_audit_end(ab);
    return 0;
}
```

Records stream as `[audit] hook=audit_log_start pid=... comm=... type=1300(AUDIT_SYSCALL) ctx=1`. The trigger in this POC installs an audit rule (`auditctl -a always,exit -F arch=aarch64 -S execve`) to ensure the subsystem has something to emit, then counts records the loader captured.

On the test kernel, the harness pulled 139 records in a short trigger window — every execve, every config change, whatever the kernel decided to log. None of those records would have been readable by the unprivileged test user via the regular audit netlink API (it requires `CAP_AUDIT_READ`); with CAP_BPF, they all come out.

## Hook points

- `kprobe/audit_log_start` — new record being constructed.
- `kprobe/audit_log_format` — format string being appended.
- `kprobe/audit_log_end` — record finalized.

All three exist in `/proc/kallsyms` on the test kernel; all attach; none of them are in `ALLOW_ERROR_INJECTION`.

## Reproduction

```bash
cd dBPF-pocs/pocs/ch03-fuse-blackhole
make
sudo bash trigger.sh
# expect: =-- CH03_PROVEN variant=B before=0 after=<N> ===
```

Prior art: Dileo DEF CON 27 (2019) on subverting audit via BPF; Willcox / Hogan 2020–2022 exploration of the same class; a short-lived lkml patch series to expose `audit_log_start` via fmod_ret was rejected in 2023.

## Detection

- Audit in-tree loader integrity is fine; the problem is visibility. A BPF program attached to `audit_log_start` shows up in `bpftool prog list` with `kprobe` attach type.
- The audit subsystem itself does not flag peer observers. Defenders need a separate tamper-evident sink that doesn't share the CAP_BPF perimeter with the thing being audited.
- If you require suppression-proof audit, route records off-host via the netlink multicast group before they hit any userland consumer a BPF program could watch.

## Scope

This is a Class III primitive from chapter 20 (ringbuf exfil). The kernel's audit integrity is untouched; what's broken is the assumption that audit records are confidential to readers with `CAP_AUDIT_READ`. With CAP_BPF on the host, the peer observer is free.

---

**Related material**

- Full chapter: [Chapter 3 — The FUSE Audit Black-Hole]({{ site.baseurl }}/book/act-1/chapter-3-the-fuse-audit-black-hole.html)
- POC source: [dBPF-pocs/pocs/ch03-fuse-blackhole/](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch03-fuse-blackhole)
- Harness entry: search for `Poc("ch03", ...)` in `dBPF-pocs/harness/proof.py`
