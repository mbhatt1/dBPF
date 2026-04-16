---
layout: book
title: "EBPF Token Bypass"
date: 2025-05-09
---

**Chapter 18: Forging `uid=0` at the Syscall Return**

> **See also**: [Blog post]({{ site.baseurl }}/ebpf-token-bypass.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch18-token-bypass) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

This is the canonical wrong-enforcement-point bug reimplemented with a kretprobe. The pattern goes back decades: a program consults `getuid()` to decide whether the caller is root, and trusts the return value rather than consulting the actual `current->cred` at the point of enforcement. Every time this bug shipped — Sendmail, several SUID binaries through the 2000s, a long tail of misconfigured services — the fix was the same: do the capability check at the kernel enforcement point, not via a userspace query. The eBPF version just makes it mechanical.

Two kretprobes, two `bpf_override_return(ctx, 0)` calls:

- `kretprobe/__arm64_sys_getuid` → 0
- `kretprobe/__arm64_sys_geteuid` → 0

Both symbols are in `/sys/kernel/debug/error_injection/list` on the linuxkit 6.12 aarch64 kernel I tested on, so the override lands. Symbols are verified via `/proc/kallsyms` at load time; missing symbols are tolerated (`bpf_program__set_autoload(prog, false)`).

What libc gets back on every `getuid()`/`geteuid()` call is `0`. Programs like `id` and `whoami` then ask NSS for "the user with uid 0" and print `root`:

```
=== baseline: id -u / whoami as t18 (no BPF interference expected) ===
1000
t18
=== with BPF attached: should report uid=0 / root ===
0
root

[token] FORGE pid=19481 comm=sh getuid: 1000 -> 0 (root)
[token] FORGE pid=19482 comm=id geteuid: 1000 -> 0 (root)
[token] FORGE pid=19483 comm=whoami getuid: 1000 -> 0 (root)
```

Here is the clean tell that this is an illusion and not a real privilege escalation. Run `id` with the probe attached:

```
uid=0(root) gid=1001 groups=1001
```

Only the uid was forged. `getgid()` was not hooked, so `gid=1001` passed through untouched. A real root process has `gid=0`. Any tool that correlates uid and gid (or that reads `/proc/self/status`, which sources `Uid:` / `Gid:` straight from `task_struct->cred`) will see the divergence. The attack works against `id`/`whoami`/any script that just checks `$(id -u) -eq 0`; it does not work against anything that actually cares.

And critically, kernel-side credential checks do not consult `sys_getuid`. VFS checks, capability checks, LSM hooks — they all go through `current->cred`, which is unchanged. `cat /etc/shadow` still returns `EACCES`. This is the entire point: the exploit class is narrow, well-known, and exactly as scoped as the historical userspace-query-based auth bugs it descends from.

## Hook points

- `kretprobe/__arm64_sys_getuid`  → `bpf_override_return(ctx, 0)`
- `kretprobe/__arm64_sys_geteuid` → `bpf_override_return(ctx, 0)`

```c
// @interactive: true
// @copyable: true
// eBPF Token Bypass - Proof of Concept
// This demonstrates bypassing authentication and authorization at the kernel level

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/cred.h>
#include <linux/capability.h>
#include <linux/fs.h>

SEC("kprobe/security_file_permission")
int forge_tokens(struct pt_regs *ctx) {
    struct cred *new_cred = prepare_kernel_cred(NULL);
    if (!new_cred) return 0;
    new_cred->uid.val = 0;
    new_cred->gid.val = 0;
    commit_creds(new_cred);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

(The snippet above is the original draft — `prepare_kernel_cred` / `commit_creds` are not callable from BPF context. The shipped program uses `bpf_override_return(ctx, 0)` from kretprobes on `__arm64_sys_getuid` and `__arm64_sys_geteuid`, which is a userspace-facing illusion and not a real credential swap.)

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
- Requires `CAP_BPF` + `CAP_PERFMON` (or root). Inside Docker, run with `--privileged --pid=host`.
