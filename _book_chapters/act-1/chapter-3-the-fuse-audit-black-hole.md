---
layout: book
title: "Chapter 3: The FUSE Audit Black-Hole"
date: 2025-02-02
---

# Chapter 3: The FUSE Audit Black-Hole

> **See also**: [Blog post]({{ site.baseurl }}/the-fuse-audit-black-hole.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch03-fuse-blackhole) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

> **Proof status**: Both `ch03-fuse-blackhole` (kprobe observer) and `ch03-fuse-blackhole-fentry` (fentry + lsm/syslog fallback) have been proved on Ubuntu 6.17.0 aarch64 (Lima VM, kernel 6.17.0-29-generic). No code changes were required. **Runtime note**: `auditd` must be running before the loader starts. The kernel audit subsystem skips `audit_log_start` entirely when no consumer is registered on the netlink socket. Start it with `sudo systemctl start auditd` (or `sudo auditd -n &`) before running the POC.

I went into this one expecting it to work.

The primitive I wanted: a kretprobe on `audit_log_start` that returns `NULL`, stopping certain records from ever being built. On a stock 6.12 linuxkit kernel, neither path landed. `grep audit_log_start /sys/kernel/debug/error_injection/list` returns nothing, so `bpf_override_return` is inert. The fentry variant loads but `audit_log_start` is not in the `bpf_modify_return_targets` BTF set. The kretprobe attaches; overriding does nothing.

What the POC does instead is an observation channel: kprobes on `audit_log_start`, `audit_log_format`, and `audit_log_end` copy every kernel-side audit record into a ringbuf that the loader reads. On a host without `auditd` running, userspace sees no records at all; with the loader running, an unprivileged peer with `CAP_BPF` sees every one. Exfil, not suppression.

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

Records stream as `[audit] hook=audit_log_start pid=... comm=... type=1300(AUDIT_SYSCALL) ctx=1`. The trigger installs an audit rule (`auditctl -a always,exit -F arch=aarch64 -S execve`) to ensure the subsystem has something to emit, then counts records the loader captured.

On the test kernel, the harness pulled 139 records in a short trigger window; every execve, every config change, whatever the kernel decided to log. None of those records would have been readable by the unprivileged test user via the regular audit netlink API (it requires `CAP_AUDIT_READ`); with `CAP_BPF`, they all come out.

That is a real capability escalation for a BPF-loaded sidecar. An attacker in the Tetragon-shaped sidecar position; BPF-loading, with some mount-namespace visibility, but not otherwise privileged; can reconstruct the audit stream in parallel with auditd. The reconstruction is invisible to auditd: nothing in the kernel tells the audit subsystem that a BPF program has attached to its internal functions.

## Hook points

- `kprobe/audit_log_start`; new record being constructed.
- `kprobe/audit_log_format`; format string being appended.
- `kprobe/audit_log_end`; record finalized.

All three exist in `/proc/kallsyms` on the test kernel; all attach; none are in `ALLOW_ERROR_INJECTION`.

## The dead ends, documented

### kprobe override

The plan was `bpf_override_return(ctx, 0)` in a kretprobe on `audit_log_start`. If `audit_log_start` returns `NULL`, every downstream caller bails early and no record is emitted. The program compiles. The verifier accepts it. The kretprobe attaches. Audit records keep flowing. `dmesg` has nothing unusual. `bpftool prog show` confirms the kprobe ran. The override is inert because `audit_log_start` is not in `ALLOW_ERROR_INJECTION`. Same failure mode as `cap_capable` in Chapter 1.

I wasted two days reproducing prior write-ups that glossed over this constraint. If you find a write-up claiming turnkey audit silencing via `bpf_override_return`, check whether it specifies a kernel built with the annotation applied.

### fentry/fmod_ret

After the kprobe override failed, I tried `fmod_ret/audit_log_start`. The program compiles. The verifier accepts it. The attach succeeds. The program never fires. The reason is `check_attach_modify_return` in `kernel/bpf/verifier.c`: on 6.12 that function allows `fmod_ret` on exactly two classes of targets; functions in `ALLOW_ERROR_INJECTION`, and functions whose name starts with `security_`. `audit_log_start` is in neither class.

On closer inspection, the verifier rejects `fmod_ret` programs for targets outside the allowed set at load time with the message `"<func>() is not modifiable"`. The POC in `ch03-fuse-blackhole-fentry` avoids triggering this by checking at runtime; via BTF introspection and a `lsm=` boot cmdline check; whether to autoload the fmod_ret program at all. On any LSM-capable kernel the loader calls `bpf_program__set_autoload(..., false)` on the fmod_ret program before `__load()` is invoked. The fmod_ret variant is skipped; the fallback runs instead.

There was a patch series in mid-2023 to add `audit_log_start` to the approved set. The audit maintainer (Paul Moore) rejected it: audit is a tamper-evident log, and letting a BPF program drop records silently breaks the tamper-evidence. As of 6.12 the override path is still not available. I agree with the decision.

### LSM hook override

`SEC("lsm/audit_rule_match")` loads on 6.12 and the return value is respected. But `audit_rule_match` is called per-rule during evaluation, not on the emission path. Forcing it to zero disables matching, which silences rule-driven records but leaves syscall auditing (`-a always,exit`) and login records untouched. Partial silence, not full.

### The FUSE sinkhole

The original idea: mount a FUSE filesystem at a path `auditd` writes to, then drop writes in the FUSE handler. Two problems. First, `auditd` on a default install writes to `/var/log/audit/audit.log` on the root filesystem; changing that requires modifying `/etc/audit/auditd.conf`, which is itself a root-only edit and an audited event. Second, the kernel audit subsystem writes to netlink, not to a file. `auditd` reads from netlink and writes to a file. Sinking the file output stops `auditd` from persisting records but does not stop the kernel from emitting or queuing them. A second netlink consumer sees every record `auditd` saw.

The FUSE angle does not work for audit silencing. That is where the chapter title came from: the investigation into why a FUSE sinkhole fails leads to the actual primitive, which is observation, not suppression.

## The lsm/syslog fallback

The fentry POC ships a second program that actually runs on the linuxkit image:

```c
SEC("lsm/syslog")
int BPF_PROG(lsm_syslog, int type, int ret) {
    if (!is_enabled()) return ret;
    if (ret != 0) return ret;
    emit(2, 1, type);
    return -EPERM;
}
```

`security_syslog` is called when a process invokes `syslog(2)` or reads `/dev/kmsg` / `/proc/kmsg`. Returning `-EPERM` from the fmod_ret-on-LSM-hook denies the operation. LSM hook names start with `security_`, so this is in the second class `check_attach_modify_return` allows. No special annotation needed.

The fallback is narrower than the primary path: it denies the dmesg / kmsg read channel, not `/var/log/audit/audit.log`. For an incident responder running `dmesg | grep` looking for kernel-level tells, the fallback is enough. For a responder running `ausearch`, it is not. The POC's loader makes this tradeoff explicit.

## Reproduction

```bash
cd dBPF-pocs/pocs/ch03-fuse-blackhole
make
sudo bash trigger.sh
# expect: === CH03_PROVEN variant=B before=0 after=<N> ===
```

Prior art: Dileo DEF CON 27 (2019) on subverting audit via BPF; Willcox / Hogan 2020–2022 exploration of the same class; a short-lived lkml patch series to expose `audit_log_start` via fmod_ret was rejected in 2023.

## Observation as exfil

With override dead, the primitive that remains is observation. On the first read that sounds like a consolation prize. On closer inspection it is the more interesting result.

`CAP_AUDIT_READ` plus `NETLINK_AUDIT` multicast membership is what normally grants access to audit records. A sidecar with `CAP_BPF` alone cannot join the audit multicast group. But with `SEC("fentry/audit_log_end")`, that same sidecar reads every record the kernel produces. An unprivileged peer with `CAP_BPF` sees what only `CAP_AUDIT_READ` normally sees.

The observation is invisible to auditd. Nothing in the kernel tells the audit subsystem that a BPF program has attached to its internal functions. A BPF program attached to `audit_log_end` sees the `sk_buff` before netlink dispatch, reads from it, and the buffer is still handed off to netlink afterwards. The BPF observer and auditd both get the record. There is no interference.

The concrete data that becomes accessible: a syscall record (`AUDIT_SYSCALL`, 1300) contains the syscall number and arch, process UID/GID/EUID/EGID/auid, `exe=` path, `tty=`, `subj=` SELinux context, `key=` from matched auditctl rules, and the syscall return value. Paired with `AUDIT_PATH`, `AUDIT_EXECVE`, and `AUDIT_CWD`, the observer reconstructs a complete audit trail for every syscall matching a rule.

The most interesting use is audit observation as a timing oracle. If auditd just logged a failed login, the attacker knows someone is poking at ssh. If auditd logged a policy load for SELinux, the attacker knows the SELinux state just changed. An adaptive attacker running a long-lived sidecar can react in real time to what the incident responder's tooling is doing.

## Detection

- Audit in-tree loader integrity is fine; the problem is visibility. A BPF program attached to `audit_log_start` shows up in `bpftool prog list` with `kprobe` attach type. No production observability tool I am aware of attaches to audit construction functions by default. If a defender sees such an attachment, it should trigger immediate investigation.
- The audit subsystem itself does not flag peer observers. Defenders need a separate tamper-evident sink that doesn't share the `CAP_BPF` perimeter with the thing being audited.
- If you require suppression-proof audit, route records off-host via the netlink multicast group before they hit any userland consumer a BPF program could watch. Once the records are in a remote sink in a separate security domain, the local kernel's state doesn't matter.
- `auditd` with `-a always,exit -F arch=b64 -S bpf -k bpf_load` makes every BPF load a logged event. A defender who sees a `bpf_load` event followed by a gap in other audit activity for a specific PID has a strong signal.

## Scope

This is a Class III primitive from chapter 20 (ringbuf exfil). The kernel's audit integrity is untouched; what's broken is the assumption that audit records are confidential to readers with `CAP_AUDIT_READ`. With `CAP_BPF` on the host, the peer observer reads freely. If you are a defender, ship records off-host. If you are an attacker, hope they didn't.

---

**Related material**

- Blog post: [The FUSE Audit Black-Hole]({{ site.baseurl }}/the-fuse-audit-black-hole.html)
- POC source: [dBPF-pocs/pocs/ch03-fuse-blackhole/](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch03-fuse-blackhole)
- Harness entry: search for `Poc("ch03", ...)` in `dBPF-pocs/harness/proof.py`
