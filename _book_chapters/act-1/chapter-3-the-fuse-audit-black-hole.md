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

## What audit_log_start Actually Does

Before I went deeper on the override problem, I spent a couple of hours reading `kernel/audit.c` to make sure I understood the data flow. A lot of the writeups I had been leaning on were vague on what `audit_log_start` actually produces, and vagueness at this layer is where attack claims go to die.

The function signature on 6.12 is:

```c
struct audit_buffer *audit_log_start(struct audit_context *ctx,
                                     gfp_t gfp_mask, int type);
```

Three arguments. The `ctx` is the per-task audit context — either the current task's, if we're in a syscall-auditable path, or `NULL` for records that aren't tied to a syscall (config changes, AVC denials during policy load, login events). `gfp_mask` controls the allocation flags for the underlying `audit_buffer`, and `type` is an `AUDIT_*` constant that identifies the record class. The 1300-series constants (`AUDIT_SYSCALL`, `AUDIT_PATH`, `AUDIT_IPC`, etc.) are per-syscall records. The 1400-series (`AUDIT_AVC`, `AUDIT_SELINUX_ERR`, etc.) are LSM events. The 1000-series (`AUDIT_GET`, `AUDIT_SET`, `AUDIT_LIST`) are control messages. There are a few hundred constants total, defined in `include/uapi/linux/audit.h`.

The function's first job is to decide whether to emit at all. It checks a per-type rate limit, a global rate limit, and whether `audit_enabled` is nonzero. On a default install, `audit_enabled=1` if `auditd` is running and 0 otherwise. The rate limits are important: the kernel will drop records if either limit is exceeded, which shows up as `audit: X audit messages lost` in `dmesg`. I measured this under load; on linuxkit with a tight `auditctl -a always,exit -S openat` rule, the 1000-per-second default rate limit is easy to hit.

If the rate check passes, `audit_log_start` allocates a `struct audit_buffer`. This is a small structure holding a `struct sk_buff` pointer and a few bookkeeping fields. The `sk_buff` is where the record text is built — it's the same data structure netlink uses for messages, which makes sense because audit records are ultimately shipped over netlink. The allocation comes from a per-type queue when the queue is available, falling back to `kmalloc(GFP_ATOMIC)` when it isn't.

The buffer is then handed back to the caller, which fills it via a series of `audit_log_format` calls:

```c
struct audit_buffer *ab = audit_log_start(NULL, GFP_KERNEL, AUDIT_CONFIG_CHANGE);
if (ab) {
    audit_log_format(ab, "audit_backlog_limit=%u old=%u auid=%u",
                     new, old, from_kuid(&init_user_ns, audit_get_loginuid(current)));
    audit_log_format(ab, " ses=%u", audit_get_sessionid(current));
    audit_log_format(ab, " res=1");
    audit_log_end(ab);
}
```

This three-step pattern — `audit_log_start` to allocate, `audit_log_format` to fill, `audit_log_end` to dispatch — is the universal audit emission idiom. Every record in the kernel uses it. A handful of convenience wrappers (`audit_log`, `audit_log_user_message`) collapse the three steps into one, but under the hood they still call through `audit_log_start`.

`audit_log_end` is where the record is shipped. If `auditd` is running and has subscribed to the netlink multicast group (`NETLINK_AUDIT`, group `AUDIT_NLGRP_READLOG`), the record is sent via `audit_log_n_hex` and eventually `netlink_broadcast`. If `auditd` is not running, the record is appended to a kernel-side queue (`audit_skb_queue`) that holds up to `audit_backlog_limit` records (default 64). When the queue is full, new records are either dropped or block the emitter, depending on whether `audit_failure_action` is set to `AUDIT_FAIL_SILENT` or `AUDIT_FAIL_PANIC`.

The upshot is that `audit_log_start` is the single point where the kernel decides whether a record will be born. If you can force it to return `NULL`, every downstream caller bails out early and no record is emitted, no netlink broadcast happens, no queue is filled. That's why it was the obvious target. That's also why the maintainers are careful about it.

I also found that there are subsidiary entry points — `audit_log_start_multi`, `audit_multicast_log`, and a handful of direct `skb_alloc` + `nlmsg_put` paths used by the kernel when it wants to emit outside the normal record-construction framework. Those are niche. The common-case emission all routes through `audit_log_start`. Silencing that one function would silence ~99% of audit traffic on a typical host. The remaining 1% would come from the odd direct netlink broadcasts, which I measured as roughly five records per hour on an idle linuxkit box.

## The Workarounds That Don't Help

I tried three.

**1. LSM hook override.** `SEC("lsm/audit_rule_match")` loads on 6.12 and the return value is respected. But `audit_rule_match` is called per-rule during evaluation, not on the emission path. Forcing it to zero disables matching, which silences rule-driven records but leaves syscall auditing (`-a always,exit`) and login records untouched. It's a partial silence.

**2. Ringbuf the audit payload, don't block it.** Attach to `audit_log_end` and snapshot the buffer contents to userspace. This works as an observer — you see every audit record before it hits disk — but it does not suppress them. Different chapter, different primitive.

**3. The FUSE sinkhole.** The idea was to mount a FUSE filesystem at a path the audit daemon writes to, then drop writes in the FUSE handler. This works against `auditd`'s log file if you can convince it to write there, but `auditd` on a default install writes to `/var/log/audit/audit.log` and will not follow a bind-mount into FUSE without config changes that a defender would notice. More importantly, the kernel audit subsystem writes to netlink, not to a file — `auditd` reads from netlink and then writes the log. Sinking the log file doesn't stop the kernel from emitting. It stops one consumer from recording.

None of these is the silver bullet the original framing suggested. I'm writing that down because the write-ups that made the technique sound turnkey glossed over the `ALLOW_ERROR_INJECTION` constraint, and I wasted two days reproducing their results before I read the verifier source.

## The fentry Variant

After the kprobe-override failed, I spent another day on `fentry`/`fmod_ret` because those are the "modern" BPF attach types and they have a different override story. `fmod_ret` programs can override the return value of a function without requiring `ALLOW_ERROR_INJECTION`, provided the target is in the `BTF_SET_START(bpf_modify_return_targets)` set. On paper, `audit_log_start` is a reasonable candidate for that set: it returns a pointer, `NULL` is a meaningful sentinel value, and the kernel already handles the `NULL` path cleanly in every caller. Overriding to `NULL` should be safe.

The POC I wrote lives in `ch03-fuse-blackhole-fentry/`. Core of the program:

```c
SEC("fmod_ret/audit_log_start")
int BPF_PROG(override_audit_log_start, struct audit_context *ctx,
             gfp_t gfp_mask, int type, struct audit_buffer *ret)
{
    // ret is the current return value; we replace it.
    return 0;  // NULL pointer.
}
```

The program compiles. The verifier accepts it, which surprised me — my expectation was that the load would fail immediately. What happens instead is that the load succeeds, the attach succeeds, and the program never fires. `bpftool prog show` reports a non-zero run count for a few seconds, and then it stalls at a fixed number and never increments. Audit records keep flowing.

The reason took some digging. `fmod_ret` requires the target to be in a specific BTF set, and the set is populated by the `BTF_SET_START(bpf_modify_return_targets)` macro in `kernel/trace/bpf_trace.c`. On 6.12 (and through 6.8, which is the newest mainline I checked) that set does not include `audit_log_start`. The set contains a small list of hand-picked functions: mostly security hook wrappers, a few filesystem helpers, and the cgroup subsystem's hooks. No audit functions.

What threw me is that the verifier does not reject `fmod_ret` programs for targets outside the set at load time. The check happens at attach time, and the attach "succeeds" in a narrow sense — the program is linked in — but the runtime dispatch is gated by a secondary check that silently skips the override. I found this by reading `kernel/bpf/trampoline.c` around `bpf_trampoline_link_prog`. The trampoline is installed; the return-value replacement is a no-op because the target isn't in the approved set.

There was a patch series in mid-2023 to add `audit_log_start` and a few other audit-emission functions to the approved set. I found it by searching lkml for `bpf: audit: allow fmod_ret`. The thread is worth reading in full; I'll paraphrase.

The proposer's argument was that audit is a security subsystem and security subsystems benefit from being instrumentable by BPF. If Falco, Tetragon, and the like can already observe audit, letting them override `audit_log_start` would let them filter records proactively and reduce downstream audit volume. The proposer included benchmarks showing meaningful auditd CPU reduction on hosts with aggressive rules.

The maintainers' counter, as I read the thread, was twofold. First: audit is a tamper-evident log, and the whole point of a tamper-evident log is that the kernel emits every record that rule evaluation says it should emit. Letting a BPF program drop records silently breaks the tamper-evidence. Second: the `fmod_ret` attach surface is a general backdoor shape, and the subsystem maintainer's job is to say no to new surfaces unless the case is overwhelming. The audit maintainer (Paul Moore) closed the thread with a clear "no," and as of the 6.12 tree the override path is still not available.

I respect the decision. I note that the decision means this attack does not work via the fentry/fmod_ret path on any kernel currently in support. If someone ships a downstream kernel that carries a patch adding `audit_log_start` to the set, that downstream kernel is vulnerable. I am not aware of any such shipping kernel. If you find one, I would like to know.

The other variant I considered was `fentry` without the modify-return, which is pure observation. That works. `fentry/audit_log_start` is accepted, it fires on every call, and the program runs at roughly the same rate as the kprobe (a few percent faster, because `fentry` trampolines are lighter than kprobe dispatch). For observation, `fentry` is the better choice on 5.5+. For override, it doesn't matter — neither attach type lands.

## Observation as Exfil

With override dead, the primitive that remains is observation. On the first read that sounds like a consolation prize; on closer inspection it is the more interesting result, and I want to spend time on why.

Every audit record the kernel constructs passes through `audit_log_start`, `audit_log_format`, and `audit_log_end`. A BPF program attached to any of those sees the data. A program attached to `audit_log_end` sees the fully-formatted record, including the syscall arguments, process context, working directory, and (on SELinux-active hosts) the AVC denial fields. That is a rich data stream.

Typical record volume on a production host, based on measurements I took on a few internal boxes, runs from a few hundred records per minute on a quiet web server to several thousand per minute on a host with aggressive `auditctl` rules (`-a always,exit -S execve` alone generates a record per exec; a busy host doing lots of fork/exec can hit 10k/min briefly). The records average 200-400 bytes each. At the low end, that's about 60 KB/hour; at the high end, several MB/hour. A ringbuf sized for a few MB handles the high end easily.

The value proposition, for an attacker, is that an unprivileged peer (a process with `CAP_BPF` but no other special rights) sees what only `CAP_AUDIT_READ` plus `NETLINK_AUDIT` multicast membership normally sees. On a default install, the audit multicast group is readable by auditd and by any process that joins the multicast group with the right capability. `CAP_BPF` does not imply `CAP_AUDIT_READ`. A sidecar with `CAP_BPF` alone cannot join the audit multicast group. But with a `SEC("fentry/audit_log_end")` program, that same sidecar can read every record the kernel produces.

That is a real capability escalation for an observability-adjacent process. Concretely, it means an attacker in the Tetragon-shaped sidecar position (BPF-loading, with some mount-namespace visibility, but not otherwise privileged) can reconstruct the audit stream in parallel with auditd. And the reconstruction is invisible to auditd: nothing in the kernel tells the audit subsystem that a BPF program has attached to its internal functions, so auditd does not log the attach and cannot differentiate between "someone is observing my output" and "nobody is."

The specific data that becomes accessible is worth naming. A syscall record (`AUDIT_SYSCALL`, 1300) contains:

- the syscall number and arch
- the process's UID, GID, EUID, EGID, auid (login UID), session ID
- `exe=` path of the executing binary
- `tty=` for the controlling terminal
- `subj=` SELinux context
- `key=` from matched auditctl rules
- the syscall return value

Paired with it are `AUDIT_PATH` records (one per file argument), `AUDIT_EXECVE` records (one per argv element), and `AUDIT_CWD`. Together these reconstruct a complete audit trail for every syscall that matched a rule. A BPF observer that snapshots all of them ends up with a forensic-grade log of every interesting syscall on the host.

The exfil side is the obvious next question. How do you get the data off the host without tripping every defense the host has? The ringbuf is a ring buffer, not a remote channel — something has to read it and ship it somewhere. That "something" is a userspace process, and if it opens a network socket the network policy catches it. A few options I considered:

- Write the observed records to the filesystem, in a place the attacker can retrieve later. This leaks via disk forensics but avoids network egress.
- Stuff the records into a map that is pinned at a well-known path, then have a separate process (on some other schedule) read the map and exfil. This separates the observation from the exfil in time, which complicates detection but doesn't remove it.
- Use the observed records as inputs to a local decision: for example, detect that `auditd` just logged an `execve` of `sshd`, then modify something based on that timing. This keeps the data local and uses it as a timing signal rather than as exfil-grade content.

The third option is the one I found most interesting. Audit observation as a timing oracle is a primitive I have not seen named explicitly in prior work. It converts the audit subsystem, which is a defensive tool, into a side-channel the attacker can use to know what the defender's tools are doing in real time. If auditd just logged a failed login, the attacker knows someone is poking at ssh. If auditd just logged a policy load for SELinux, the attacker knows the SELinux state just changed. The attacker doesn't need to parse the records at the attacker layer; they just need the timing.

## Auditctl Rule Interactions

Kernel audit rules control which syscalls and file operations produce records. The rules are set via `auditctl(8)` or persisted in `/etc/audit/rules.d/`. Understanding them matters because the BPF observer only sees the records that rule evaluation allows to be emitted — if no rule matches, `audit_log_start` is not called in the first place, and the observer never sees the event.

There are three rule types that matter for the observer:

1. **Watches** (`-w path -p perms -k key`). These generate records when a specific path is accessed with specific permissions. Example: `-w /etc/shadow -p wa -k shadow`. Every write or attribute change to `/etc/shadow` produces an `AUDIT_PATH` record and (if the triggering operation is in a syscall rule's scope) an `AUDIT_SYSCALL` record. Watches are evaluated during the inode operation, not at the syscall boundary.

2. **Syscall rules** (`-a filter,action -S syscall -F field=value -k key`). These generate records when a matching syscall completes. Example: `-a always,exit -S execve -k exec`. Every `execve` produces an `AUDIT_SYSCALL` + `AUDIT_EXECVE` + `AUDIT_PATH` + `AUDIT_CWD` tuple. Syscall rules are evaluated at the end of the syscall path, so the record reflects the actual outcome (success or failure, return value, etc.).

3. **Exit rules** (`-a exit,filter -F exit=-EACCES -k denied`). These fire when a syscall returns a specific error. They are a subtype of syscall rule with an extra filter. I mention them separately because the field-match logic is nontrivial and affects what the observer sees.

Rule evaluation order matters. The audit subsystem maintains separate rule lists per filter (`user`, `exit`, `task`, `exclude`, `filesystem`), and within each list the rules are evaluated in order until a match is found. The first matching rule wins; subsequent rules don't evaluate. A rule with a `never` action suppresses emission even if a later rule would have matched. This means a defender can accidentally hide an event by putting a `never` rule early.

Walk a realistic ruleset. Here is one I pulled from a Debian server I maintain:

```
# From /etc/audit/rules.d/audit.rules:
-D
-b 8192

# Rule 1: silence our own audit management tool.
-a never,exit -F auid=103 -F subj=system_u:system_r:auditctl_t:s0 -k mgmt

# Rule 2: log all execve.
-a always,exit -S execve -F auid>=1000 -F auid!=-1 -k exec

# Rule 3: watch /etc/shadow.
-w /etc/shadow -p wa -k shadow

# Rule 4: log setuid/setgid changes.
-a always,exit -S setuid,setgid,setreuid,setregid -k identity
```

For the BPF observer, this ruleset means:

- Every execve by a normal user produces a multi-record tuple. The observer sees all four.
- Every write to `/etc/shadow` produces a path+syscall tuple. The observer sees both.
- setuid-family syscalls produce syscall records. The observer sees these.
- Anything auditctl itself does is suppressed by rule 1. The observer **does not see this**, because rule 1 has `never` action and rule evaluation stops there — `audit_log_start` is never called for those events.

The last point is the one that matters. An attacker running the BPF observer sees exactly the set of events the defender's ruleset permits. If the defender has aggressive `never` rules for certain paths or users, the observer's view is narrowed correspondingly. If the defender has a minimal ruleset (only the distro defaults), the observer sees very little because the kernel is not building many records in the first place.

This cuts both ways. A defender who writes aggressive audit rules gives the observer a richer stream. A defender who writes minimal rules starves the observer but also starves themselves — they get less visibility into what's happening on their host. The optimal attacker position is a host with moderately aggressive rules: enough records for the attacker to find interesting signal, not so many that ringbuf memory pressure becomes a problem.

One detail worth calling out: the `exclude` filter. Records matching an exclude filter are never emitted, and the exclude filter is evaluated inside `audit_filter_syscall` before `audit_log_start` is called. A BPF observer attached to `audit_log_start` does not see excluded records. An observer attached earlier — say, a kprobe on `audit_filter_syscall` — could in principle see them, but I did not explore that path because the `audit_filter_syscall` signature is less stable across kernel versions and the effort to extract record fields from there is substantially higher.

## What About auditd Itself

A question I kept coming back to: if auditd is running and consuming the netlink stream, does the BPF observer compete with it? Does one of them get to see the records and the other get a truncated view? Does the order of attach matter?

The short answer is no, they don't compete. The longer answer is worth walking through.

Audit records are constructed once in the kernel, inside `audit_log_start` / `audit_log_format` / `audit_log_end`. The buffer is built up in-place on an `sk_buff`. At the end of `audit_log_end`, the kernel calls into the netlink layer to broadcast the record to every subscriber of the audit multicast group. The broadcast is a multiplex: netlink makes a copy per subscriber (or uses skb cloning, depending on the size). Each subscriber gets their own copy.

A BPF program attached to `audit_log_end` sees the `sk_buff` before the broadcast. It reads from the buffer directly. Reading does not consume; the buffer is still handed off to netlink afterwards. So the BPF observer and auditd both get the record, in the same form, with no interference. The BPF observer sees it slightly earlier (before netlink dispatch), but the difference is microseconds.

There is one exception: if the BPF program holds a reference to the `sk_buff` and the record is large, the `netlink_broadcast` path may take a slower allocation path to clone the buffer. I did not see this in practice, because BPF `fentry` programs do not hold refcounts on kernel objects — they read through helpers and return. If you write a more aggressive program that grabs a reference, you might see auditd's performance change subtly. For straightforward observation, the two run in parallel without interaction.

Neither one sees the other. The BPF attach is not recorded in the audit stream (the `AUDIT_BPF` record type fires on `bpf(BPF_PROG_LOAD)`, which is a syscall-level event, but it is only emitted if a rule matches the syscall — and a defender who did not write such a rule will not see the attach). And auditd's consumption of the netlink stream is invisible from the BPF side because it happens in a different process and a different subsystem.

The practical consequence is that you can run both, indefinitely, without one affecting the other. The attacker can observe auditd's stream in parallel with auditd itself, and the defender has no in-band way to know.

## Prior Art

I want to be specific and honest about what has and has not been demonstrated.

Jeff Dileo, "eBPF, I thought we were friends" (DEF CON 27, 2019). This talk covered override-return semantics in general, including examples against several security-relevant kernel functions. The audit-specific angle was not the focus of the talk, but the technique was described in enough detail to be a clear progenitor of every later write-up. If you want to understand why override-return is attractive as a primitive, this is where to start. I am less sure about exactly which audit functions Dileo targeted in the demo; the slides I have do not spell out `audit_log_start` specifically.

Grant Willcox and Pat Hogan, various write-ups 2020-2022. Willcox in particular has a series of blog posts and conference talks on BPF-based audit subversion. The 2021 piece (I believe on the Trustwave SpiderLabs blog, but I'm working from memory here — search the archive) walks through the `bpf_override_return` against audit targets in some detail. My reading is that the posts assume a kernel built with the annotation applied, but they do not always say so explicitly, which is part of why I wasted two days trying to reproduce on a stock kernel. This is not a criticism of the posts; it is a note that readers should verify the kernel build assumptions before attempting to reproduce.

Matt Day, "Forging Audit Records via BPF" (2022). I believe this was presented at a Linux security conference, possibly Linux Security Summit that year, though I am less sure about the venue. The talk covered the construction side rather than the suppression side — using BPF to inject forged records into the audit stream by overriding `audit_log_format` return paths. The technique is clever and I have not reproduced it on 6.12; if anyone has, I would like to compare notes.

Broader context: the `bpf: allow error injection of security functions` patch series, which has been proposed and rejected several times on lkml since roughly 2020. Search the archives for `ALLOW_ERROR_INJECTION` + `security_` + `audit_` to see the objections. The maintainers' position has been consistent: adding security-critical functions to the error-injection set is a bad tradeoff, and the burden is on the proposer to show overwhelming benefit. Nobody has yet.

The contribution in this chapter, as best I can tell, is the reproducible demonstration that the override does not land on a stock kernel, the detailed walk of why the fmod_ret variant is silently broken, and the framing of observation-as-exfil as the actual primitive. If a prior write-up claimed a turnkey audit-silencing technique without specifying the kernel build, treat it with suspicion. If someone has later work I have missed, please email.

## An Honest Observer

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

The primary signal is `bpftool prog list | grep audit_log_`. Just like the overlayfs case in chapter 2, no production observability tool I am aware of attaches to audit construction functions by default. Falco uses syscall tracepoints and a few LSM hooks, not audit internals. Tetragon attaches to LSM hooks and fs operations, not audit. If a defender sees a kprobe or fentry program attached to `audit_log_start`, `audit_log_end`, or `audit_log_format`, that is an anomaly strong enough to justify immediate investigation.

Concrete checks:

```bash
# List BPF programs attached to audit functions:
$ bpftool prog show | grep -B1 audit_log
49: kprobe  name observe_audit  tag ...  gpl
    loaded_at 2025-02-02T08:15:02+0000  uid 0
    xlated 168B  jited 198B  memlock 4096B
    btf_id 12  bpf_modify_return_targets no

# Enumerate kprobes:
$ cat /sys/kernel/debug/kprobes/list | grep audit
ffffffff8120aa30  k  audit_log_start+0x0  [FTRACE]

# Check the trampoline state for fentry attach:
$ bpftool link list | grep audit
23: tracing  prog 49  fentry_audit_log_start  target audit_log_start
```

The second-order defense, which is the one I would actually recommend in a production environment, is an independent tamper-evident sink. If auditd is shipping its output to a remote syslog over TLS (`auditd.conf`'s `dispatcher=` hook combined with `audisp-remote`), the records leave the host before any in-kernel BPF observer can interfere. Once the records are in the remote sink, the local kernel's state doesn't matter — the log has already been committed somewhere the local attacker cannot reach.

The same pattern works with `journald` + `systemd-journal-upload` + a remote journal server, if you prefer that stack. The key property is that the sink is a separate security domain, reachable only by write-append and not by tampering from the host itself.

This does not stop the BPF observation; it just reduces the observation to a useless local copy. The attacker can still see the records going by, but the records are already on a remote server the attacker does not control. The local-vs-remote split is the only architectural defense I trust against this class of attack. Everything else — in-kernel integrity checks, lockdown mode, signed modules — is defeatable by a sufficiently determined attacker on the host. Off-host replication is the one property the attacker cannot unwind.

One more: if you are running a host-based IDS that watches `bpf(2)` syscalls, you should ensure that the audit rule `-a always,exit -S bpf -k bpf_load` is in place. This makes every BPF load a logged event. A defender who sees a `bpf_load` event followed by a gap in other audit activity for a specific PID has a strong signal that something just happened at the audit layer. This is noisy in environments where BPF is in regular use (most Kubernetes clusters), but on a host where BPF is rare, the signal is clean.

## Summary

Override against `audit_log_start` does not land on stock 6.12 kernels via kprobe (no `ALLOW_ERROR_INJECTION`) or via fmod_ret (not in the modify-return target set). The 2023 lkml proposal to add it was rejected by the audit maintainer and I agree with the rejection. What remains is an observation primitive: a BPF program that sees every audit record the kernel constructs, running in parallel with auditd and invisible to it. The primitive is defeatable by shipping audit records off-host before the local observer can see them. If you are a defender, do that. If you are an attacker, hope they didn't.
