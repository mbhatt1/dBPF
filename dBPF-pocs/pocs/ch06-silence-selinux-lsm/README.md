# Ch06 -- Silencing SELinux (LSM variant)

**Category**: REAL
**Primitive**: LSM fmod_ret on `file_permission`, `inode_permission`, `bprm_check_security`
**Hook(s)**: `SEC("lsm/file_permission")`, `SEC("lsm/inode_permission")`, `SEC("lsm/bprm_check_security")`
**Architecture**: aarch64 + x86_64

## What this demonstrates

Overrides SELinux access decisions at the outer `security_*` entry points via BPF LSM fmod_ret. Returning 0 from the sleepable program pre-empts the deny: SELinux's verdict never gets a chance to apply. Three hooks cover file I/O, path traversal, and binary execution -- flipping denials to grants for targeted tgids.

## What this does NOT do

Only flips decisions the LSM framework would have been able to deny. DAC (unix perms) and other pre-LSM checks still apply. Capability checks are at `security_capable` (see `ch01-mirror-controls-lsm`), not covered here. No attempt is made to spoof the audit record that SELinux didn't write.

## Prerequisites

- `CONFIG_BPF_LSM=y` and `CONFIG_SECURITY_SELINUX=y`
- Boot cmdline: `lsm=...,bpf,...,selinux` (both `bpf` and `selinux` required)
- `bpftool feature probe | grep lsm_fmod_ret` must show `ok`
- `CAP_SYS_ADMIN`
- Satisfied by Fedora 38+ with SELinux enforcing

## Files

| File | Purpose |
|------|---------|
| `ch06-silence-selinux-lsm.bpf.c` | Kernel-side BPF LSM program (fmod_ret on three hooks) |
| `ch06-silence-selinux-lsm.c` | Userspace loader with wildcard/targeted modes |
| `trigger.sh` | Activity generator |
| `Makefile` | Build (uses shared/common.mk) |

## Build & Run

```bash
# Inside the harness container:
make
sudo ./build/ch06-silence-selinux-lsm -a             # wildcard: flip every deny
sudo ./build/ch06-silence-selinux-lsm -t 12345       # only tgid 12345
# In another terminal:
bash trigger.sh
```

## Detection

- `bpftool prog list type lsm` shows the attached sleepable programs.
- SELinux auditd logs will stop showing AVC denials for the targeted processes -- a sudden drop in denies is itself a tell.
- Kernel `bpf()` syscall audit records program load from a non-init namespace.
