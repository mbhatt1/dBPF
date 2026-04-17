# Ch02 -- OverlayFS Trojan Horse (LSM variant)

**Category**: REAL
**Primitive**: LSM fmod_ret on `inode_copy_up` + LSM observer on `inode_permission`
**Hook(s)**: `SEC("lsm/inode_copy_up")`, `SEC("lsm/inode_permission")`
**Architecture**: aarch64 + x86_64

## What this demonstrates

Delivers selective DENY of overlay copy-up for sensitive basenames via `fmod_ret` on the `inode_copy_up` LSM hook. Returning `-EPERM` prevents the upper layer from receiving a writable copy, so readers keep hitting the lower layer (which an attacker with write access to the lower backing store controls). Combined with an observer on `inode_permission` for attack timing.

## What this does NOT do

This is the gating primitive, not the complete exploit. Full "inject payload" requires a userspace racer. Uses basename filter only -- no full-path matching (dentry-walk from BPF is not practical). Direct writes to upperdir are not intercepted.

## Prerequisites

- `CONFIG_BPF_LSM=y` and `lsm=bpf` in boot cmdline
- `CONFIG_OVERLAY_FS=y`
- `security_inode_copy_up` LSM hook (present since Linux 4.10)
- `CAP_SYS_ADMIN` to attach fmod_ret LSM programs

## Files

| File | Purpose |
|------|---------|
| `ch02-overlayfs-lsm.bpf.c` | Kernel-side BPF LSM program (fmod_ret on inode_copy_up, observer on inode_permission) |
| `ch02-overlayfs-lsm.c` | Userspace loader with basename targeting |
| `trigger.sh` | Activity generator |
| `Makefile` | Build (uses shared/common.mk) |

## Build & Run

```bash
# Inside the harness container:
make
sudo ./build/ch02-overlayfs-lsm -p secret.txt
# In another terminal:
bash trigger.sh
```

## Detection

- `bpftool prog list type lsm` shows the attached sleepable programs on `inode_copy_up` and `inode_permission`.
- Unexpected `-EPERM` on overlay write operations while the overlay mount is healthy.
- Kernel `bpf()` syscall audit records program load.
