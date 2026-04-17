# Ch07 -- Device-cgroup Houdini (LSM variant)

**Category**: ANALOG
**Primitive**: LSM fmod_ret on `inode_mknod`, `file_open`, `dev_open` with map-driven deny/flip stages
**Hook(s)**: `SEC("lsm/inode_mknod")`, `SEC("lsm/file_open")`, `SEC("lsm/dev_open")`
**Architecture**: aarch64 + x86_64

## What this demonstrates

Proves the primitive that turns device-gate denies into allows. A single sleepable LSM program implements both the denier and the flipper, selected at runtime via a `ctrl_map` stage control (SIGUSR1=deny, SIGUSR2=flip, SIGHUP=off). Three LSM hooks are compiled in; the loader prunes absent ones via vmlinux BTF introspection before loading.

## What this does NOT do

The synthesized denial is a property of the BPF program, not of a real cgroup constraint. On the standard Linux LSM chain, `vfs_mknod` direct-calls `capable(CAP_MKNOD)` before `security_inode_mknod`, so the BPF LSM hook sits after the cap check. Proving the flipper against a real cgroup deny requires `bpf_lsm_dev_open` (not present on all kernels) and an LSM chain ordering that puts `bpf` ahead of `capability`.

## Prerequisites

- `CONFIG_BPF_LSM=y`
- Boot cmdline: `lsm=...bpf...` (verify `cat /sys/kernel/security/lsm` contains `bpf`)
- `bpftool feature probe | grep lsm_fmod_ret` must show `ok`
- `CAP_SYS_ADMIN` on the loader process

## Files

| File | Purpose |
|------|---------|
| `ch07-devcgroup-houdini-lsm.bpf.c` | Kernel-side BPF LSM program (fmod_ret on inode_mknod, file_open, dev_open) |
| `ch07-devcgroup-houdini-lsm.c` | Userspace loader with signal-based stage control and BTF-driven hook pruning |
| `trigger.sh` | Activity generator (three-phase: baseline, deny, flip) |
| `Makefile` | Build (uses shared/common.mk) |

## Build & Run

```bash
# Inside the harness container:
make
sudo ./build/ch07-devcgroup-houdini-lsm -t 0 -p /tmp/ch07.pid -s deny
# In another terminal:
kill -USR2 "$(cat /tmp/ch07.pid)"   # flip
bash trigger.sh
```

## Detection

- `bpftool prog list type lsm` shows the attached sleepable programs.
- Audit of `bpf()` syscalls records each program load.
- Unexpected `-EPERM` bursts on char/block mknod while the in-kernel cap/cgroup state says operations should succeed.
