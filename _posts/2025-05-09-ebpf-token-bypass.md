---
layout: book
title: "EBPF Token Bypass"
date: 2025-05-09
poc_dir: dBPF-pocs/pocs/ch18-token-bypass
---

# eBPF Token Bypass

> **See also**: [Book chapter with investigation notes]({{ site.baseurl }}/book/act-3/chapter-18-ebpf-token-bypass.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch18-token-bypass)

**Chapter 18: Forging `uid=0` at the syscall return**

This is the canonical wrong-enforcement-point bug, reimplemented with a kretprobe. The pattern is decades old: a program consults `getuid()` to decide whether the caller is root and trusts the return value rather than consulting the actual `current->cred` at the point of enforcement. Sendmail shipped this bug. Several SUID binaries shipped it through the 2000s. A long tail of misconfigured services still ship it. The fix, every time, was the same: do the capability check at the kernel enforcement point, not via a userspace query. The eBPF version just makes it mechanical.

## Mechanism

Two kretprobes, two `bpf_override_return(ctx, 0)` calls:

- `kretprobe/__arm64_sys_getuid` → `0`
- `kretprobe/__arm64_sys_geteuid` → `0`

Both symbols are in `/sys/kernel/debug/error_injection/list` on the linuxkit 6.12 aarch64 kernel I tested on, so the override lands. Symbols are verified via `/proc/kallsyms` at load time; missing symbols are tolerated by disabling the affected program via `bpf_program__set_autoload(prog, false)`.

What libc gets back on every `getuid()`/`geteuid()` call is `0`. Programs like `id` and `whoami` then ask NSS for "the user with uid 0" and print `root`:

```
=== baseline: id -u / whoami as t18 (no BPF interference expected) ===
1000
t18

=== with BPF attached: should report uid=0 / root ===
0
root

[token] FORGE pid=19481 comm=sh     getuid:  1000 -> 0 (root)
[token] FORGE pid=19482 comm=id     geteuid: 1000 -> 0 (root)
[token] FORGE pid=19483 comm=whoami getuid:  1000 -> 0 (root)
```

## The tell

Run `id` with the probe attached:

```
uid=0(root) gid=1001 groups=1001
```

Only `uid` was forged. `getgid()` was not hooked, so `gid=1001` passed through untouched. A real root process has `gid=0`. Any tool that correlates `uid` and `gid` — or that reads `/proc/self/status`, which sources `Uid:` and `Gid:` straight from `task_struct->cred` — sees the divergence.

The attack works against `id`/`whoami`/any script that just checks `$(id -u) -eq 0`. It does not work against anything that actually cares.

And critically, kernel-side credential checks do not consult `sys_getuid`. VFS checks, capability checks, LSM hooks — they all go through `current->cred`, which is unchanged. `cat /etc/shadow` still returns `EACCES`. This is the entire point: the exploit class is narrow, well-known, and exactly as scoped as the historical userspace-query-based auth bugs it descends from.

## Hook points

- `kretprobe/__arm64_sys_getuid`  → `bpf_override_return(ctx, 0)`
- `kretprobe/__arm64_sys_geteuid` → `bpf_override_return(ctx, 0)`

## Reproduction

```
cd pocs/ch18-token-bypass
docker run --rm -v "$PWD/../..":/work -w /work dbpf-base \
  bash -c 'cd pocs/ch18-token-bypass && make'

# Wildcard: forge every getuid/geteuid call system-wide.
sudo ./build/ch18-token-bypass --all

# Targeted: forge only calls from a specific tgid.
sudo ./build/ch18-token-bypass --tgid 1234

# Multiple targets are accepted.
sudo ./build/ch18-token-bypass --tgid 1234 --tgid 5678
```

In another shell, run `sudo bash trigger.sh`. Send `SIGINT` to detach cleanly.

## Detection

- Audit subsystem does not see this. There is no syscall failure, only a forged return.
- `bpftool prog show` reveals two attached kretprobes on `sys_getuid` and `sys_geteuid`. On a production host these are highly anomalous attachment points and should be alerted on.
- File-integrity and kernel-module monitoring will not catch it. No module is loaded.
- Detection works best at the BPF load layer: `bpf()` syscall auditing with `BPF_PROG_LOAD` records, plus a policy rejecting kretprobes that call `bpf_override_return`.
- Consistency check: any monitoring agent that compares `getuid()` return against `/proc/self/status` `Uid:` will flag the divergence. I have not seen anything in the wild doing this by default.

## Limitations

- aarch64 only. Symbols are spelled `__arm64_sys_getuid` / `__arm64_sys_geteuid`. On x86_64 they would be `__x64_sys_getuid` / `__x64_sys_geteuid`. The loader's symbol preflight disables affected programs cleanly if absent.
- `bpf_override_return` only succeeds on functions present in `/sys/kernel/debug/error_injection/list`. Both targets happen to be on the linuxkit 6.12 list. On a hardened kernel without those entries, the kretprobe attaches but the override silently no-ops; the loader still emits events, but `flipped=0` and the userspace illusion does not occur.
- Userspace illusion only. No kernel access check is bypassed. This is intentional — the POC demonstrates the class of bug, which is identical in shape to the historical "trust-the-query, not-the-cred" CVEs.
- Requires `CAP_BPF` + `CAP_PERFMON` (or root). Inside Docker, run with `--privileged --pid=host`.

---
**Related material**
- Full chapter: [Chapter 18 — eBPF Token Bypass]({{ site.baseurl }}/book/act-3/chapter-18-ebpf-token-bypass.html)
- POC source: [dBPF-pocs/pocs/ch18-token-bypass/](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch18-token-bypass)
- Harness entry: `Poc("ch18", ...)` in `proof.py`
