# Ch18 -- eBPF Token Bypass

**Category**: REAL
**Primitive**: kretprobe + bpf_override_return on getuid/geteuid syscalls
**Hook(s)**: `SEC("kretprobe/__arm64_sys_getuid")`, `SEC("kretprobe/__arm64_sys_geteuid")`
**Architecture**: aarch64 only

## What this demonstrates

Forges `uid=0` in userspace by overriding the return value of `getuid` and `geteuid` syscalls. Both symbols are in the error-injection allowlist on linuxkit 6.12. `bpf_override_return(ctx, 0)` takes effect: glibc receives `0`, programs like `id`/`whoami` print `root`. This is a userspace-illusion bypass in the same class as historical "tokens not checked at the enforcement point" CVEs.

## What this does NOT do

Kernel state unchanged -- only the syscall return value to userspace is forged. Kernel-side credential checks (VFS uid checks, capability checks, LSM hooks) do NOT consult `sys_getuid`, so `cat /etc/shadow` still returns `EACCES`. On x86_64, symbols would be `__x64_sys_getuid`/`__x64_sys_geteuid` (not wired in this BPF object). On hardened kernels without these error-injection entries, the override silently no-ops.

## Prerequisites

- `__arm64_sys_getuid` and `__arm64_sys_geteuid` in `/sys/kernel/debug/error_injection/list`
- `CONFIG_BPF_KPROBE_OVERRIDE=y`
- `CAP_BPF` + `CAP_PERFMON` (or root)
- Docker: `--privileged --pid=host`

## Files

| File | Purpose |
|------|---------|
| `ch18-token-bypass.bpf.c` | Kernel-side BPF program (kretprobe + bpf_override_return on getuid/geteuid) |
| `ch18-token-bypass.c` | Userspace loader with wildcard/targeted modes |
| `trigger.sh` | Activity generator (id, whoami as unprivileged user) |
| `Makefile` | Build (uses shared/common.mk) |

## Build & Run

```bash
# Inside the harness container:
make
sudo ./build/ch18-token-bypass --all
# In another terminal:
bash trigger.sh
```

## Detection

- `bpftool prog show` reveals two attached kretprobes on `sys_getuid` and `sys_geteuid` -- highly anomalous attachment points on a production host.
- Audit subsystem doesn't see this (no syscall failure, only a forged return).
- Detection works best at the BPF-load layer: `bpf()` syscall auditing with `BPF_PROG_LOAD` records, plus a policy rejecting kretprobes that use `bpf_override_return`.
- File-integrity / kernel-module monitoring will not catch it (no module is loaded).
