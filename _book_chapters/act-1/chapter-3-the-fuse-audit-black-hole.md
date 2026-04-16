---
layout: book
title: "Chapter 3: The FUSE Audit Black-Hole"
date: 2025-02-02
---

# Chapter 3: The FUSE Audit Black-Hole

> **See also**: [Blog post]({{ site.baseurl }}/the-fuse-audit-black-hole.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch03-fuse-blackhole) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

I went into this one expecting it to work. The plan was standard: attach a kprobe to `audit_log_start`, call `bpf_override_return(ctx, 0)`, and watch audit records stop. That idea is not new — Jeff Dileo, Grant Willcox, and others have written about override-return against audit functions for years, and the technique shows up in at least one Black Hat talk from 2021. I expected to reproduce it, write it up, move on.

It didn't reproduce. On a stock linuxkit 6.12 kernel the probe loads, the program attaches, and audit records keep flowing to `/var/log/audit/audit.log` exactly as before. That is the honest result, and the rest of this chapter is about why.

## What Actually Happens

`audit_log_start` is defined in `kernel/audit.c`. On 6.12 it's around line 1720. The function allocates an `audit_buffer`, grabs the audit context, and returns a pointer that callers fill in via `audit_log_format`. If it returns `NULL`, the caller bails and no record is emitted. That's the theory of the attack: force `NULL`, get silence.

The problem is `ALLOW_ERROR_INJECTION`. Grep the tree:

```
$ grep -rn ALLOW_ERROR_INJECTION kernel/audit*.c
(no output)
```

`audit_log_start` is not annotated. `bpf_override_return` against it is a no-op on a stock kernel, for the same reason `cap_capable` was a no-op in chapter 1. The verifier accepts the program; the kernel runs the kprobe; the override has nowhere to land.

I confirmed by attaching and running `auditctl -w /etc/shadow -p r -k shadow_read`, then `cat /etc/shadow` as root. Audit records appeared. `dmesg` had nothing unusual. `bpftool prog show` confirmed the kprobe was attached and had a non-zero run count. The program was running. The override was inert.

## The Workarounds That Don't Help

I tried three.

**1. LSM hook override.** `SEC("lsm/audit_rule_match")` loads on 6.12 and the return value is respected. But `audit_rule_match` is called per-rule during evaluation, not on the emission path. Forcing it to zero disables matching, which silences rule-driven records but leaves syscall auditing (`-a always,exit`) and login records untouched. It's a partial silence.

**2. Ringbuf the audit payload, don't block it.** Attach to `audit_log_end` and snapshot the buffer contents to userspace. This works as an observer — you see every audit record before it hits disk — but it does not suppress them. Different chapter, different primitive.

**3. The FUSE sinkhole.** The idea was to mount a FUSE filesystem at a path the audit daemon writes to, then drop writes in the FUSE handler. This works against `auditd`'s log file if you can convince it to write there, but `auditd` on a default install writes to `/var/log/audit/audit.log` and will not follow a bind-mount into FUSE without config changes that a defender would notice. More importantly, the kernel audit subsystem writes to netlink, not to a file — `auditd` reads from netlink and then writes the log. Sinking the log file doesn't stop the kernel from emitting. It stops one consumer from recording.

None of these is the silver bullet the original framing suggested. I'm writing that down because the write-ups that made the technique sound turnkey glossed over the `ALLOW_ERROR_INJECTION` constraint, and I wasted two days reproducing their results before I read the verifier source.

## What Does Work: An Honest Observer

```c
SEC("kprobe/audit_log_start")
int observe_audit(struct pt_regs *ctx) {
    struct audit_context *ctx_ptr = (void *)PT_REGS_PARM1(ctx);
    int type = (int)PT_REGS_PARM3(ctx);

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->type = type;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

This gives you a stream of "the kernel is about to emit an audit record of type X for PID Y." You can use it to know what the auditor is seeing. You cannot use it to prevent the auditor from seeing it on a stock kernel.

## The Narrow Window Where Override Lands

On a kernel built with `CONFIG_BPF_KPROBE_OVERRIDE=y` and a patch that adds `ALLOW_ERROR_INJECTION(audit_log_start, ERRNO)` — which you'd have to apply yourself — the override works. I tested this on a custom-built 6.12 kernel with the annotation added, and audit records dropped to zero for the target PID. The technique is real. The kernel that ships on a defender's box is almost never the kernel where it works.

If you're reading this looking for a reliable audit-silencing primitive on an arbitrary target, this chapter is not it. If you're reading it to understand the decision surface, the observer above plus the netlink-level alternatives (AUDIT_GET / AUDIT_DEL via `NETLINK_AUDIT` from a privileged process) are the honest path.

## Detection

- `bpftool prog show` lists a kprobe attached to `audit_log_start`. Any defender auditing BPF program loads sees this by name.
- `AUDIT_BPF` records fire on `bpf(BPF_PROG_LOAD)` with default auditd config. The observer gets logged before it starts observing.
- If the defender is running `bpftool prog tracelog` or equivalent, they see the program's bpf_printk output if any.
- A process silently consuming the ringbuf shows up in `lsof` against the bpf fs pins.

## Prior Art

- Jeff Dileo, "eBPF, I thought we were friends" (DEF CON 27, 2019) — covers override-return semantics.
- Grant Willcox / Pat Hogan, various writeups on bpf_override_return against audit functions (2020–2022).
- `bpf: allow error injection of security functions` patch series, which has been proposed and rejected several times on lkml. Search the archives for `ALLOW_ERROR_INJECTION` + `security_` to see the objections.

The contribution here is the reproducible observer and the honest accounting for why the override path doesn't land on a stock kernel. If a prior write-up claimed otherwise without specifying the kernel build, treat it with suspicion.
