# ch03 FUSE Audit Black-Hole — fentry + bpf_modify_return variant

Sibling POC to `ch03-fuse-blackhole/`. Delivers **real mutation** — not
just observation — of the audit subsystem. The loader picks one of two
primitives at runtime based on kernel introspection.

## Primitives

### Preferred: `SEC("fmod_ret/audit_log_start")`
`audit_log_start` is the entry point every audit record flows through:
every `audit_log(...)` eventually calls it to reserve an
`audit_buffer`. If our fmod_ret program returns NULL, the caller
believes allocation failed and **silently drops the record**. No audit
line is ever written.

This requires `audit_log_start` to be in the kernel's
`BTF_SET_START(bpf_modify_return_targets)` allowlist. That set is
compile-time; userspace cannot enumerate it directly. The loader uses:

1. **BTF introspection** (`btf__find_by_name_kind(..., BTF_KIND_FUNC)`)
   on vmlinux to confirm the symbol exists as a function type.
2. **Test attach** — libbpf returns `-EINVAL` on attach if the symbol
   is in BTF but not in the modify-return allowlist. This is the ground
   truth.

**Kernel version caveat**: Through mainline **6.8** the
`bpf_modify_return_targets` set in `kernel/trace/bpf_trace.c` does
**not** include `audit_log_start` upstream. Distro kernels that
backport audit-suppression hardening — or any future mainline version
that extends the set — light up this path. If the attach fails, the
loader falls back automatically. No modification to the POC is needed
when your kernel gains the symbol.

### Fallback: `SEC("lsm.s/syslog")`
`security_syslog(int type)` is the LSM hook gating
`SYSLOG_ACTION_READ_ALL` / `READ_CLEAR` / `SIZE_UNREAD`. fmod_ret → -EPERM
blocks dmesg-channel peeks at kernel-log-adjacent audit data. Narrower
than full audit record suppression but works on **any CONFIG_BPF_LSM=y
kernel** without any allowlist dependency.

## Status

**PROVEN** on Ubuntu 6.17.0 aarch64 (Lima VM, kernel 6.17.0-29-generic).

**Runtime requirement**: `auditd` must be running before the loader starts.
The kernel audit subsystem skips `audit_log_start` when no consumer is
registered on the netlink socket. Start auditd first:

```
sudo systemctl start auditd   # or: sudo auditd -n &
```

No code changes were required — the POC worked as-is once auditd was running.

## Host prereqs

| Path | Requires |
|------|----------|
| Preferred | `audit_log_start` in `bpf_modify_return_targets` BTF set; `CONFIG_AUDIT=y`; `CAP_SYS_ADMIN` |
| Fallback  | `CONFIG_BPF_LSM=y` and `lsm=...,bpf,...` on the boot cmdline; `CAP_SYS_ADMIN` |

The loader exits with code 3 if **neither** is available.

## Build
```
docker run --rm -v "$PWD/../..":/work -w /work dbpf-selinux \
  bash -c 'cd pocs/ch03-fuse-blackhole-fentry && make'
```

## Run
```
sudo ./build/ch03-fuse-blackhole-fentry
sudo bash trigger.sh
```

## Evidence (expected)

Preferred path (allowlisted kernel):
```
[ch03-fe] attached fmod_ret/audit_log_start (preferred)
[ch03-fe] active — audit suppression engaged (fmod_ret)
[ch03-fe] audit_log_start pid=1234 comm=dd    type=1300 -> SUPPRESSED
```
`trigger.sh` shows `audit records: before=N after=N delta=0` **after**
the BPF program loads — despite generating five more openat events.

Fallback path:
```
[ch03-fe] fmod_ret/audit_log_start not in allowlist (attach=Invalid argument) — falling back to lsm/syslog
[ch03-fe] attached lsm.s/syslog (fallback)
[ch03-fe] active — audit suppression engaged (lsm)
```
`trigger.sh` shows audit.log still growing, but `dmesg` exits non-zero
(EPERM from the LSM hook).

## Limitations
- The preferred path's availability is **entirely kernel-dependent**.
  There is no sysctl or runtime knob to toggle membership in the
  modify-return allowlist.
- Fallback scope is narrower (syslog channel only); it does not hide
  audit records from `/var/log/audit/audit.log`.
- fmod_ret requires `CAP_SYS_ADMIN`; CAP_BPF alone is insufficient.
- No regression test inside this repo exercises the modify-return path
  because it requires a kernel with the right BTF set membership.
