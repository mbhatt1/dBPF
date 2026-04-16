---
layout: book
title: "Chapter 1: The Mirror Controls"
date: 2025-01-31
---

# Chapter 1: The Mirror Controls

> **See also**: [Blog post]({{ site.baseurl }}/the-mirror-controls.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch01-mirror-controls) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

I was poking at `cap_capable` on a linuxkit 6.12 VM, trying to understand what an unprivileged observer could actually see from a kprobe. The function is the single choke point every capability check routes through (`security/commons.c`), so if you want to know who is asking for what, this is where you sit. What I wanted to know next was whether I could do anything about the answer.

The short version: on a stock kernel, you cannot. `cap_capable` is not in `ALLOW_ERROR_INJECTION`, so `bpf_override_return` against it loads but never fires. The verifier accepts the program; the kernel silently ignores the override. I confirmed this by checking `/sys/kernel/debug/kprobes/list` and then by reading `kernel/bpf/verifier.c` around `check_attach_btf_id`. The result is that this chapter is about an observation channel, not a bypass. If you want the bypass you need a kernel built with `CONFIG_BPF_KPROBE_OVERRIDE=y` and the target function annotated — two conditions that almost never coincide in production.

## A walk through kernel/capability.c

The function I was reading sits in `security/commoncap.c` on 6.12, not `kernel/capability.c` — the latter holds the syscall entry points (`SYS_capset`, `SYS_capget`) while the LSM-side decision logic moved to `security/commoncap.c` when the default-capability LSM was formalized. Both files are worth having open. The syscall entry is where a capset-style userspace call lands; the LSM hook is where an in-kernel `capable()` call lands. They share the decision function.

The 6.12 signature for `cap_capable`:

```c
int cap_capable(const struct cred *cred,
                struct user_namespace *targ_ns,
                int cap, unsigned int opts)
{
    struct user_namespace *ns = targ_ns;

    for (;;) {
        if (ns == cred->user_ns)
            return cap_raised(cred->cap_effective, cap) ? 0 : -EPERM;
        if (ns->level <= cred->user_ns->level)
            return -EPERM;
        if ((ns->parent == cred->user_ns) && uid_eq(ns->owner, cred->euid))
            return 0;
        ns = ns->parent;
    }
}
```

The loop walks up the user-namespace hierarchy. At each level it checks whether the calling credential's effective capability set has the requested bit set. The check is `cap_raised`, which is a bitmask test. The return convention is `0` for granted, `-EPERM` for denied. Hooking this function at kprobe entry gives you the four arguments; hooking it at kretprobe gives you the decision.

The function sits in the LSM chain, which is the part that matters for anyone trying to override the decision. On a kernel with a single LSM loaded — the default-capability LSM — `cap_capable` is the final word on capability checks. On a kernel with multiple LSMs (SELinux, AppArmor, Yama), the `security_capable` dispatcher walks the LSM list and combines the verdicts. The standard combination is "all LSMs must grant for the capability to be granted." Any LSM returning `-EPERM` causes the check to fail.

The relationship to `ns_capable` is worth mapping. `ns_capable` is the common entry point from kernel code that wants to check a capability in a specific user namespace. Its implementation in 6.12 looks approximately like:

```c
bool ns_capable(struct user_namespace *ns, int cap)
{
    return ns_capable_common(ns, cap, CAP_OPT_NONE);
}

static bool ns_capable_common(struct user_namespace *ns, int cap,
                              unsigned int opts)
{
    int capable;

    if (unlikely(!cap_valid(cap)))
        return false;

    capable = security_capable(current_cred(), ns, cap, opts);
    if (capable == 0) {
        current->flags |= PF_SUPERPRIV;
        return true;
    }
    return false;
}
```

Every `ns_capable` call flows into `security_capable`, which dispatches to the LSM chain, which on a default kernel calls `cap_capable`. The kprobe at `cap_capable` therefore sees every capability check in the system. This is the "mirror" in the chapter's title — the function is a single reflective surface for every capability decision.

The related function `capable_wrt_inode_uidgid` handles the inode-aware capability check used by filesystems. It checks `cap_capable` plus an additional inode-ownership predicate. A kprobe on `cap_capable` also sees the checks that flow through `capable_wrt_inode_uidgid`, because they end up calling `cap_capable` internally. A kprobe on `capable_wrt_inode_uidgid` separately sees only the inode-aware subset. Both attachment points are useful; which one you want depends on whether you care about the inode context or not.

Line numbers, with the usual drift caveat: on 6.12 `security/commoncap.c` the `cap_capable` function sits around line 210. On 5.15 it was around line 205. The function has been stable for enough releases that a rough offset is reliable.

## The kprobe/kretprobe pairing pattern

`bcc/tools/capable.py` has used the kprobe/kretprobe pair against `cap_capable` since 2016, and the shape of the pattern has not changed meaningfully since. The pattern is worth internalizing because the same shape applies to every decision function in the kernel — `security_file_permission`, `avc_has_perm`, `may_open`, `inode_permission`, and so on. Learn it once; apply it to any decision point.

The pattern has three components: an entry kprobe that captures the arguments, a return kretprobe that captures the verdict, and a shared map that lets the return side find the entry it corresponds to. The map's key is a per-thread identifier; the value is whatever the entry captured.

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned long);   // pid_tgid
    __type(value, int);           // cap
    __uint(max_entries, 8192);
} in_flight SEC(".maps");

SEC("kprobe/cap_capable")
int BPF_KPROBE(kp_cap, const void *cred, void *ns, int cap, unsigned int opts)
{
    unsigned long id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&in_flight, &id, &cap, BPF_ANY);
    return 0;
}

SEC("kretprobe/cap_capable")
int BPF_KRETPROBE(kr_cap, int ret)
{
    unsigned long id = bpf_get_current_pid_tgid();
    int *cap_p = bpf_map_lookup_elem(&in_flight, &id);
    if (!cap_p) return 0;
    bpf_map_delete_elem(&in_flight, &id);
    // ret is the kernel's verdict; *cap_p is the capability that was asked for
    return 0;
}
```

The key design deserves attention. `bpf_get_current_pid_tgid()` returns a 64-bit value where the upper 32 bits are the thread group ID (the "PID" as seen by userspace) and the lower 32 bits are the kernel thread ID (the "TID" as seen by `gettid()`). Using the combined value as the map key is what gives you thread-local correlation: two threads in the same process making overlapping `cap_capable` calls get separate map entries because their TIDs differ.

An earlier version of this code I wrote used only the upper 32 bits (the TGID) as the key. Under single-threaded test loads it worked fine. Under a multi-threaded test, map entries from one thread's entry got joined to another thread's return, producing garbage correlation. The fix is the full `pid_tgid` as the key. This is not a novel observation — it is the same fix bcc applied in 2016 — but it is the kind of fix that is easy to regress in a rewrite.

The map size of 8192 entries is a rough budget. On a busy system, `cap_capable` fires thousands of times per second, and entries stay in the map only for the duration of the function (tens of microseconds typically). 8192 is plenty of headroom for correlation; the more common problem is the opposite, where a map fills because the return probe failed to fire on some path and the entries never got evicted.

The ringbuf emit format. When the kretprobe has both sides in hand, it writes a fixed-size struct to a ringbuf:

```c
struct evt {
    unsigned int pid;
    unsigned int tgid;
    char comm[16];
    int cap;
    int orig_ret;
    int flipped;
};
```

The struct is six fields, 40 bytes on aarch64 with alignment. Ringbuf reservations are aligned to 8 bytes, so the practical per-event cost is 48 bytes. A 256-KB ringbuf holds about 5000 events before the consumer has to drain. On the test harness, `capset` fires three to five `cap_capable` checks per call, so a 256-KB ringbuf absorbs roughly 1500 `capset` invocations before backpressure. Good enough.

Common bugs in this pattern, from worst to most-common:

**Entry without return.** The kprobe fires but the kretprobe does not. This happens when the function has multiple exit paths and one of them is not a return (a `jmp` to a different function's body, for example), or when the function is inlined and the kretprobe binds to the inlined-out copy. `cap_capable` does not have this problem — it has a single return path — but related functions do. The symptom is growing `in_flight` map size and missing correlation.

**Return without entry.** The kretprobe fires but there is no matching entry in the map. This happens when the kprobe was attached after the function started executing, or when the map eviction policy removed the entry before the return. The code checks for this with `if (!cap_p) return 0;` and silently drops the event. In a high-load test this manifests as a small percentage of events being unattributable; if the percentage is more than a few, the map is undersized.

**Race on map eviction under load.** If two threads in the same process call `cap_capable` with the same `cap` argument in close succession, and the map's LRU eviction (for `BPF_MAP_TYPE_HASH_LRU`) fires between their entries, the return side may see a stale entry for a different thread. The plain `BPF_MAP_TYPE_HASH` used in the POC avoids this by never evicting, but has the opposite problem: under sustained load the map fills and `BPF_ANY` updates fail with `-E2BIG`. The tradeoff is: hash is predictable but limited; LRU is unbounded but subject to eviction races. The POC accepts the bounded-but-predictable side because the test workload never approaches the 8192-entry limit.

**Missing `comm` resolution.** `bpf_get_current_comm` reads from `task_struct->comm`, which is a 16-byte buffer. If the executable name is longer than 15 characters, the name is truncated. This is a display issue, not a correctness issue, but it has tripped up defenders reading ringbuf output who mistake a truncated name for a different process. The chapter's userspace consumer renders the `comm` field verbatim and makes the truncation explicit when it happens.

## What `cap_capable` Hands You

The signature hasn't changed meaningfully since 5.x:

```c
int cap_capable(const struct cred *cred,
                struct user_namespace *targ_ns,
                int cap, unsigned int opts);
```

Four arguments. That matters because `PT_REGS_PARM4_CORE` on x86_64 is `rcx`, and I've seen write-ups miss the fourth arg entirely. The `cred` pointer is stable for the life of the task; `cap` is the integer capability index (`CAP_SYS_ADMIN` is 21, `CAP_NET_ADMIN` is 12); `opts` carries the noaudit bit.

## The Probe

```c
SEC("kprobe/cap_capable")
int hook_cap_check(struct pt_regs *ctx) {
    const struct cred *cred = (void *)PT_REGS_PARM1(ctx);
    int cap = (int)PT_REGS_PARM3(ctx);

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (should_elevate(pid, cap)) {
        bpf_override_return(ctx, 0);
        return 1; // Grant capability silently
    }

    return 0; // Let normal checks proceed
}
```

The `bpf_override_return` line loads fine. On a stock Debian or Ubuntu kernel it will not change the return value. I verified by attaching, calling `capset` from an unprivileged shell, and watching the syscall still fail with `EPERM`. The kprobe fires; the override is a no-op. `dmesg` says nothing either way.

## The Kprobe-Then-Kretprobe Dance

To observe the decision rather than change it, you need both sides. The entry kprobe gives you the arguments; the kretprobe gives you the verdict. Pair them with a per-PID map keyed on `tgid << 32 | tid` so you can correlate entry and return under concurrency.

- Entry: capture `cred`, `cap`, `opts`, stash in a map.
- Return: read `PT_REGS_RC(ctx)`, join against the map, emit to ringbuf.

This is the shape of any decision-point observer: two probes, one map, one ringbuf. Nothing novel — it's the same pattern `bcc/tools/capable.py` has used since 2016. What you get in return is a per-syscall feed of "who asked for what capability and what did the kernel say."

## Why ALLOW_ERROR_INJECTION isn't granted here

The obvious question, once the observation channel is working, is why `cap_capable` is not in the error-injection allowlist. The maintainers have been clear about this when the question comes up on the kernel list: `cap_capable` is a decision function, not a syscall boundary. The two categories have different safety properties with respect to error injection.

A syscall boundary is a natural error injection target because the syscall's callers already know they might get an error. `do_unlinkat` may return `-ENOMEM`, `-ENOENT`, `-EACCES`. The filesystem code paths that invoke it have error-handling for each case. Flipping the return value to a different errno produces a well-defined outcome: the caller sees an error it already knew how to handle. This is the fuzz-testing use case the annotation was built for.

A decision function has a different shape. Its callers do not "handle" a granted or denied decision; they act on it. A `capable(CAP_SYS_ADMIN)` check that returns true results in the privileged code path being taken. A `cap_capable` override that flips the result from `-EPERM` to `0` does not produce an error the caller knows how to handle; it produces a silent elevation the caller does not know it received. The safety properties of error injection do not extend to this case.

The concrete argument the maintainers make is that overriding `cap_capable` would let a BPF program grant arbitrary capabilities with no policy layer above it. The existing kernel architecture has the LSM chain as the policy layer — SELinux, AppArmor, Yama can all observe capability checks and refuse them. A `bpf_override_return` on `cap_capable` would run after those LSMs, after the decision had already been made, and invisibly override it. There is no audit record (the LSM would not have seen the override) and no hook for other subsystems to notice. The override would be a side channel around the entire LSM architecture.

The argument extends to every security-decision function. `avc_has_perm` (SELinux's AVC check), `apparmor_capable` (AppArmor's capable hook), `tomoyo_capable` (TOMOYO's), `security_inode_permission`, `security_file_permission`, `security_task_kill` — none of them are in `ALLOW_ERROR_INJECTION`, for the same reason. The LSM chain is the supported policy layer; BPF override on a decision function would be an unsupported policy bypass.

The alternative the maintainers point to is BPF LSM. `CONFIG_BPF_LSM=y` lets a BPF program register as an LSM and participate in the policy chain. The program attaches to a specific LSM hook via `SEC("lsm/...")` and returns either `0` (allow) or a negative errno (deny). It runs after the statically-compiled LSMs (Capability, SELinux, etc.) and its verdict is combined with theirs in the standard all-must-grant way.

Critically, `SEC("lsm/...")` cannot be used to override a deny to an allow. The BPF LSM program sees the in-flight decision and can return a deny (making the check fail where it would have succeeded), but it cannot return a grant where another LSM would have denied. The all-must-grant combination is strict. This is deliberate: BPF LSM is an additional policy layer, not a bypass.

There is a second BPF LSM attach mode, `fmod_ret`, which can modify the return value of an LSM hook. It is restricted to a narrow set of hooks and is itself not allowed to grant a decision where a static LSM denied. The maintainers' position is consistent: the LSM chain is a one-way policy gate; BPF is a participant in the gate, not a bypass around it.

This is why the `bpf_override_return` path against `cap_capable` is designed to silently fail rather than to explicitly reject. The verifier accepts the program because the helper invocation itself is well-typed. The runtime dispatch silently discards the override because `cap_capable` is not on the allowlist. The silence is the design: a program can attempt the override without provoking an error message, and a legitimate observability tool that uses `bpf_override_return` on an allowlisted target nearby is unaffected.

## Trying to override anyway — what actually happens

The POC attempts the override anyway, because the attempt itself is informative.

```c
SEC("kretprobe/cap_capable")
int BPF_KRETPROBE(kr_cap, int ret)
{
    unsigned long id = bpf_get_current_pid_tgid();
    unsigned int tgid = id >> 32;
    unsigned int *hit = bpf_map_lookup_elem(&target_tgids, &tgid);

    if (hit && ret != 0) {
        // This compiles, loads, and attaches. It also silently no-ops.
        bpf_override_return(ctx, 0);
    }
    return 0;
}
```

The verifier accepts this program. `bpftool prog show` lists it. `/sys/kernel/debug/kprobes/list` shows the kretprobe attached at `cap_capable+0`. The ringbuf receives events marked `flipped=1` for every denial that matched a target TGID. And the target process still gets `-EPERM` from its `capset` call.

To confirm this is not a harness bug, I ran the test both ways. First with the override line present: 47 denials flagged as "would flip," 47 subsequent `capset` calls still denied. Then with the override line replaced by `bpf_override_return(ctx, 0)` attached to `do_unlinkat` (which *is* in the error-injection allowlist): the subsequent `unlinkat` call returned success, and the target file was preserved on disk (the override made the kernel skip the actual unlink). The comparison isolates the failure mode to the allowlist check, not to the helper call.

The runtime dispatch that produces the silent no-op is in the kprobe return-path. The kretprobe fires, the BPF program runs, `bpf_override_return` stores the override value in the per-kprobe state, and then the kprobe return-path checks whether the kprobe has the `KPROBE_FLAG_FTRACE` attribute *and* the target function is in the error-injection list. If both conditions hold, the override value replaces the return register; otherwise the override is discarded. `cap_capable` fails the second condition.

The verifier's role in this is partial. `check_attach_btf_id` (or its equivalent region in `kernel/bpf/verifier.c`) validates that the program's attach target is compatible with the program type. It does *not* validate that the attach target is in the error-injection list; that check is at runtime. The verifier could, in principle, reject the program at load time if it saw a `bpf_override_return` helper call targeting a function outside the allowlist, but the verifier does not have the target function's identity at helper-call time in a way that makes this check tractable. The check lives at attach time and at runtime.

A hardened kernel could close even the silent-failure path by rejecting the helper at load time when the target is not allowlisted. No distribution I checked has done this. The silent-failure behavior is probably a compatibility choice: programs that use `bpf_override_return` against a function that was in the allowlist on the build kernel but not on the deploy kernel would break noisily if the check moved to load time. The silence preserves forward compatibility at the cost of defender legibility.

## Observation as its own primitive

Even without the override, the kprobe stream is valuable. Every capability check in the system, with per-syscall granularity, with the full argument set, streamable to a userspace consumer. That is not a small thing.

The concrete use cases:

**Compliance monitoring.** A compliance framework that requires auditing of privileged operations can consume the ringbuf and record every `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_SYS_PTRACE` check. The resulting audit trail is richer than what `auditd` provides because it includes denied checks — the ones where the process attempted a privileged operation and was refused. `auditd` typically records only syscall outcomes; the kprobe records the decision point.

**Anomaly detection.** The steady-state pattern of capability checks on a given service is stable. A Postgres server's `cap_capable` stream is dominated by a few specific bits being checked at startup and a minimal set during steady state. A sudden appearance of unusual capabilities being checked is a signal. The primitive is cheap enough (microseconds of overhead per check) that running it continuously on every production host is feasible.

**Container introspection.** Inside a container, the kprobe sees capability checks across the containment boundary — checks made by the container's process plus checks the kernel makes on that process's behalf. A container monitoring tool can use the stream to build a per-container capability profile and flag containers that request capabilities beyond their declared grant. This is particularly valuable in multi-tenant clusters.

**Debugging least-privilege grants.** An application trying to run under the narrowest possible capability set can iterate: attach the probe, exercise the application, observe which capabilities are actually checked, grant exactly those. The stream gives you an exact lower bound on the capability set the application needs. This is a positive use of the primitive — the same sensor that an attacker uses for surveillance is a developer's least-privilege debugging aid.

This is the feed Chapter 3 (audit exfil) consumes. The same ringbuf shape, streaming the same data, is the input to a covert-channel exfiltration primitive. The primitive's use depends on the consumer; the sensor itself is neutral. Chapter 16 (seccomp sidechannel) uses a related primitive: observing which syscalls pass seccomp's filter lets a profile be built without needing to reverse seccomp's ruleset directly.

## LSM BPF as the supported path

If what you want is actual enforcement rather than observation, `CONFIG_BPF_LSM=y` is the supported path. On a kernel where the config is enabled, a BPF program can register as an LSM and return a verdict on each hook invocation.

```c
SEC("lsm/file_permission")
int BPF_PROG(lsm_file_permission, struct file *file, int mask)
{
    // return 0 to allow, or a negative errno to deny
    if (is_sensitive(file))
        return -EACCES;
    return 0;
}
```

This works. The program attaches via the `BPF_LSM_MAC` program type, the verifier validates it, and the LSM chain includes it in the decision. The program's verdict is combined with the statically-compiled LSMs in the usual all-must-grant way.

The sleepable vs non-sleepable distinction matters here. Non-sleepable LSM programs (`SEC("lsm/...")`) run in atomic context and cannot call helpers that may sleep. Sleepable LSM programs (`SEC("lsm.s/...")`) can call `bpf_d_path`, `bpf_copy_from_user`, and other helpers that may block. But only specific hooks are sleepable — the hook has to be defined in a context where sleeping is safe.

My first attempt at an LSM hook for this chapter used `SEC("lsm.s/file_permission")`. The attach failed with `not sleepable`. I read the kernel's `CONFIG_BPF_LSM` table of hook sleepability and confirmed that `file_permission` runs in a context that cannot block. Dropping the `.s` to get `SEC("lsm/file_permission")` let the program attach.

The pattern generalizes:

- **Use `SEC("lsm/hookname")`** for hooks where you only need to inspect pointer arguments and return a verdict. No `bpf_d_path`, no `bpf_copy_from_user`.
- **Use `SEC("lsm.s/hookname")`** for hooks where you need to dereference user-space pointers, resolve paths, or do other work that may sleep. Only works for hooks the kernel has declared sleepable.

A mismatch produces a specific error. If you use `.s` on a non-sleepable hook, attach returns `-EINVAL` with the kernel log saying the hook is not sleepable. If you use a helper like `bpf_d_path` in a non-sleepable context, the verifier rejects the program at load time with a helper-context mismatch.

The LSM BPF path is the supported one, and it is also the one that defenders can trivially detect. `bpftool prog show --type lsm` lists every LSM BPF program. The attach is logged by `auditd` if the distribution's audit rules cover `AUDIT_BPF_PROG_LOAD`. There is no covert LSM BPF attachment; the subsystem is explicit by design.

This is in contrast to kprobe-based observation, which is harder to distinguish from legitimate observability tooling. An LSM BPF program is an enforcement point; a kprobe is a measurement point. A defender can reasonably be strict about LSM BPF programs (allowlist the specific ones their security team has audited) without affecting their observability stack.

## Other decision points

Same pattern applies to the LSM hook surface. `security_file_permission`, `security_bprm_check`, `security_inode_getattr` — all of them are kprobe-attachable and give you a view into the decision the kernel is about to make. On a kernel with `CONFIG_BPF_LSM=y` you can additionally attach sleepable or non-sleepable LSM programs via `SEC("lsm/...")`, which gives you a supported override path.

Seccomp is a different story. Seccomp runs before the syscall dispatch reaches most BPF attach points, so a kprobe on `__x64_sys_openat` sees the call only if seccomp has already allowed it. You cannot use kprobes to bypass seccomp. You can use them to watch what gets through.

## Detection signatures

Anything an auditor runs will find this. The primitive is entirely legible to a defender who knows what to look for. This section walks through the specific invocations and their expected output, so that a defender can build detection rules directly from the text.

The first detection layer is `bpftool`. Running `bpftool prog show` lists every loaded BPF program with its type, attach target, and load time:

```bash
# bpftool prog show
52: kprobe  name kp_cap  tag 1a2b3c4d5e6f7890  gpl
    loaded_at 2025-01-31T14:22:08+0000  uid 0
    xlated 248B  jited 320B  memlock 4096B  map_ids 14,15,16
    btf_id 42
53: kprobe  name kr_cap  tag 2b3c4d5e6f789012  gpl
    loaded_at 2025-01-31T14:22:08+0000  uid 0
    xlated 312B  jited 400B  memlock 4096B  map_ids 14,15,16
```

The attach target is not in `prog show` output directly. To see it:

```bash
# bpftool perf show
pid 1234  fd 7: prog_id 52  kprobe  func cap_capable  offset 0
pid 1234  fd 8: prog_id 53  kretprobe  func cap_capable  offset 0
```

The `kretprobe func cap_capable` line is the defender's smoking gun. A legitimate observability tool attaching to `cap_capable` is a valid signature; the defender's job is to know whether their observability tool does this.

The second detection layer is `/sys/kernel/debug/kprobes/list`:

```bash
# cat /sys/kernel/debug/kprobes/list
ffffffff812a0b40  k  cap_capable+0x0    [FTRACE]
ffffffff812a0b40  r  cap_capable+0x0
```

Two lines, one for the kprobe (`k`) and one for the kretprobe (`r`). Both at offset 0 of `cap_capable`. The `[FTRACE]` annotation indicates the kprobe is using the ftrace infrastructure rather than a software breakpoint; this is the common case for modern kernels.

The third detection layer is `auditd`. With the default audit ruleset, BPF program load events are not captured. Adding the rule explicitly:

```bash
# auditctl -a always,exit -F arch=b64 -S bpf -k bpf_syscall
```

produces events like:

```
type=SYSCALL msg=audit(1706709728.445:1234): arch=c00000b7 syscall=280
  success=yes exit=7 a0=5 a1=7ffe... a2=90 items=0 ppid=1200 pid=1234
  auid=1000 uid=0 gid=0 comm="loader" exe="/tmp/ch01-loader"
  key="bpf_syscall"
```

`syscall=280` is `bpf(2)` on aarch64. The `a0` field contains the `bpf_cmd` — `5` is `BPF_PROG_LOAD`. A defender with this rule in place sees every program load with the calling process's `comm`, `exe`, `pid`, and `auid`. This is the single most useful rule for BPF-based detection.

The fourth detection layer is process ancestry. The `bpf(BPF_PROG_LOAD)` call must come from somewhere. `execve` history via `auditd`, or a BPF-based execve tracer, gives the defender the process that loaded the program. A legitimate observability DaemonSet loads programs from a known binary path; an anomalous loader from `/tmp/`, `/dev/shm/`, or `/home/` is a signal.

The fifth detection layer is baseline-diff. The steady-state set of loaded BPF programs on a production host changes slowly. A tool that snapshots `bpftool prog show --json-pretty` hourly and diffs against the previous snapshot catches new programs minutes after they load:

```bash
# Capture baseline
bpftool prog show --json > /var/lib/bpf-baseline/$(date +%Y%m%d-%H).json

# Diff
diff <(jq -S . /var/lib/bpf-baseline/20250131-14.json) \
     <(jq -S . /var/lib/bpf-baseline/20250131-15.json)
```

Any new program with `"type": "kprobe"` and `"attach_name": "cap_capable"` in the diff is this chapter's signature. The same diff catches Chapter 2, Chapter 3, Chapter 8, and any other chapter that attaches to a specific kernel function.

The visible artifacts, summarized:

- `bpftool prog list` output (program type `kprobe`, attach name `cap_capable`).
- `bpftool perf show` output (the `kretprobe func cap_capable` line).
- `/sys/kernel/debug/kprobes/list` entries for `cap_capable+0x0`.
- `/sys/fs/bpf/` pins if the loader pins the program.
- `AUDIT_BPF_PROG_LOAD` in `auditd` with the `bpf_syscall` key if the rule is set.
- The process that called `bpf(BPF_PROG_LOAD)` in `execve` history.
- Baseline-diff of `bpftool prog show` output.

None of that is hidden by this chapter. Hiding load events is a later problem and lives in its own chapter. The techniques that hide programs from `bpftool` require either a BPF-based rootkit that intercepts `BPF_OBJ_GET_INFO_BY_FD` or a kernel-level modification outside the BPF subsystem; both are out of scope here.

A defender's operational takeaway: if you do not already have the `auditctl` rule for `syscall=bpf` in your ruleset, add it. If you do not have a baseline-diff job running against `bpftool prog show`, add one. Both are cheap and both catch this chapter and most of the rest.

## What This Chapter Actually Gives You

A reliable observation channel on capability decisions, with the pair-probe plumbing worked out. Override is available in theory and mostly unavailable in practice. Treat the code as a telemetry primitive; upgrade it to enforcement only on kernels where you have checked `ALLOW_ERROR_INJECTION` for the target and `CONFIG_BPF_KPROBE_OVERRIDE` in the running config.
