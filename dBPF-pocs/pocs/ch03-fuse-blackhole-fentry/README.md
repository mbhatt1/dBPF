# Ch03 -- FUSE Audit Black-Hole (fentry/LSM variant)

**Category**: REAL
**Primitive**: fmod_ret on `audit_log_start` (preferred) or LSM fmod_ret on `syslog` (fallback)
**Hook(s)**: `SEC("fmod_ret/audit_log_start")`, `SEC("lsm/syslog")`
**Architecture**: aarch64 + x86_64

## What this demonstrates

Delivers real mutation of the audit subsystem. The preferred path uses `fmod_ret` on `audit_log_start` -- returning NULL causes the caller to silently drop the audit record. The fallback path uses the `syslog` LSM hook to block dmesg-channel peeks at kernel-log-adjacent audit data. The loader picks the best available primitive at runtime via BTF introspection and test-attach.

## What this does NOT do

The preferred path's availability is entirely kernel-dependent (`audit_log_start` must be in `bpf_modify_return_targets` BTF set). The fallback scope is narrower (syslog channel only); it does not hide audit records from `/var/log/audit/audit.log`. Neither path is available on kernels without both `CONFIG_AUDIT=y` and `CONFIG_BPF_LSM=y`.

## Prerequisites

- Preferred: `audit_log_start` in `bpf_modify_return_targets` BTF set; `CONFIG_AUDIT=y`; `CAP_SYS_ADMIN`
- Fallback: `CONFIG_BPF_LSM=y` and `lsm=...,bpf,...` on the boot cmdline; `CAP_SYS_ADMIN`
- Loader exits with code 3 if neither is available

## Files

| File | Purpose |
|------|---------|
| `ch03-fuse-blackhole-fentry.bpf.c` | Kernel-side BPF program (fmod_ret on audit_log_start, LSM syslog fallback) |
| `ch03-fuse-blackhole-fentry.c` | Userspace loader with auto-fallback |
| `trigger.sh` | Provokes audit-worthy events |
| `Makefile` | Build (uses shared/common.mk) |

## Build & Run

```bash
# Inside the harness container:
make
sudo ./build/ch03-fuse-blackhole-fentry
# In another terminal:
bash trigger.sh
```

## Detection

- `bpftool prog list type lsm` or `bpftool prog show` reveals attached fmod_ret/lsm programs on audit or syslog symbols.
- `trigger.sh` shows `audit records: before=N after=N delta=0` when fmod_ret is active.
- A sudden stop in audit record growth while system activity continues is the primary signature.
- `bpf()` syscall auditing records program load.
