# Ch01 -- Mirror Controls (LSM variant)

**Category**: REAL
**Primitive**: LSM fmod_ret on `security_inode_permission` (VFS access check)
**Hook(s)**: `SEC("lsm/inode_permission")`
**Architecture**: aarch64 + x86_64

## What this demonstrates

Overrides the kernel's VFS inode-permission check at the LSM layer. The BPF LSM fmod_ret program's return value replaces the hook's verdict, flipping `-EACCES` to 0 for targeted tgids on `vfs_read` / `vfs_write` paths. This is the first-class override primitive -- not gated by the error-injection allowlist.

The hook choice is `lsm/inode_permission` rather than `lsm/capable` because on 6.14+ kernels, `security_capable` bypasses the LSM chain for non-root processes and the chapter's original `lsm/capable` hook does not fire reliably. `inode_permission` is called from `vfs_read`/`vfs_write` on every access and fires on every open path, which is what this POC needs.

## What this does NOT do

Does not work on kernels without BPF LSM enabled. Docker Desktop linuxkit lacks `CONFIG_BPF_LSM`; the loader exits with code 3 and a clear diagnostic. Requires a proper Linux host or VM with `lsm=bpf` in the boot cmdline.

## Prerequisites

- `CONFIG_BPF_LSM=y` in the kernel config
- Boot cmdline contains `bpf` in `lsm=...` (check `cat /sys/kernel/security/lsm`)
- `CAP_SYS_ADMIN` (fmod_ret on LSM hooks requires full sysadmin, not just CAP_BPF)
- Typically satisfied by Fedora 38+ default

## Files

| File | Purpose |
|------|---------|
| `ch01-mirror-controls-lsm.bpf.c` | Kernel-side BPF LSM program (fmod_ret on inode_permission) |
| `ch01-mirror-controls-lsm.c` | Userspace loader with wildcard/targeted modes |
| `trigger.sh` | Activity generator |
| `Makefile` | Build (uses shared/common.mk) |

## Build & Run

```bash
# Inside the harness container:
make
sudo ./build/ch01-mirror-controls-lsm -a             # flip every deny
sudo ./build/ch01-mirror-controls-lsm -t 12345       # targeted tgid
# In another terminal:
bash trigger.sh
```

## Detection

- `bpftool prog list type lsm` shows the attached program on `inode_permission`.
- `cat /sys/kernel/debug/tracing/enabled_functions` may show the BPF trampoline.
- Kernel `bpf()` syscall audit records program load from a non-init namespace.
- A sudden disappearance of capability denials for specific processes is a tell.
