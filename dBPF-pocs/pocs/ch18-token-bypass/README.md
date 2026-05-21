# ch18 — eBPF Token Bypass

**Status: PROVEN** on Ubuntu 6.17.0-29-generic aarch64 (Lima VM), 2026-05-20.

Proof marker: `TOKEN_FORGE_PROVEN`.

## Mechanism

Forge `uid=0` in userspace by overriding the return value of the
`getuid` and `geteuid` syscalls. Both `__arm64_sys_getuid` and
`__arm64_sys_geteuid` are listed in
`/sys/kernel/debug/error_injection/list` on Ubuntu 6.17 aarch64, so
`bpf_override_return(ctx, 0)` from a kretprobe takes effect: glibc
receives `0`, programs like `id`/`whoami` then ask NSS for "the user
with uid 0" and print `root`.

This is a **userspace-illusion** bypass. Kernel-side credential checks
(VFS uid checks, capability checks, LSM hooks) do **not** consult
`sys_getuid`, so e.g. `cat /etc/shadow` still returns `EACCES`. The
exploit class is the same as historical "tokens not checked at the
enforcement point" CVEs.

## Hook points

- `kretprobe/__arm64_sys_getuid`  → `bpf_override_return(ctx, 0)`
- `kretprobe/__arm64_sys_geteuid` → `bpf_override_return(ctx, 0)`

Symbols are verified via `/proc/kallsyms` at load time; missing symbols
are tolerated (`bpf_program__set_autoload(prog, false)`).

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

## Evidence

Captured runtime output (Ubuntu 6.17.0-29-generic aarch64 Lima VM, --all mode):

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

Loader status lines (stderr):

```
[token] symbol=__arm64_sys_getuid	status=present
[token] symbol=__arm64_sys_geteuid	status=present
[token] attached=2	skipped=0
[token] tag=target	mode=wildcard
[token] status=ready	msg=token bypass active
```

## Detection

- Audit subsystem doesn't see this — there is no syscall failure, only a
  forged return.
- `bpftool prog show` reveals two attached kretprobes on `sys_getuid`
  and `sys_geteuid`. On a production host these are highly anomalous
  attachment points and should be alerted on.
- File-integrity / kernel-module monitoring will not catch it (no
  module is loaded).
- Detection works best at the BPF-load layer: `bpf()` syscall auditing
  with `BPF_PROG_LOAD` records, plus a policy rejecting kretprobes that
  use `bpf_override_return`.

## Limitations / arch notes

- **aarch64 only.** Symbols are spelled `__arm64_sys_getuid` /
  `__arm64_sys_geteuid`. On x86_64 they would be `__x64_sys_getuid` /
  `__x64_sys_geteuid`. The loader's symbol preflight will disable the
  affected programs cleanly if absent.
- **error_injection allowlist.** `bpf_override_return` only succeeds
  on functions present in `/sys/kernel/debug/error_injection/list`.
  Both targets happen to be on the linuxkit 6.12 list. On a hardened
  kernel without these entries, the kretprobe will attach but the
  override silently no-ops; the loader will still emit non-`flipped`
  events but the userspace illusion will not occur.
- **Userspace illusion only.** No kernel access check is bypassed.
  This is intentional — the POC demonstrates the *class* of bug.
- Requires `CAP_BPF` + `CAP_PERFMON` (or root). Inside Docker, run with
  `--privileged --pid=host`.
