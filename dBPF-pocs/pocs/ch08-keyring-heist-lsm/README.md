# Ch08 -- Keyring Heist (LSM variant)

**Category**: REAL
**Primitive**: LSM fmod_ret on `security_key_permission`
**Hook(s)**: `SEC("lsm/key_permission")`
**Architecture**: aarch64 + x86_64

## What this demonstrates

Weaponizes the keyring observation: on a kernel with `CONFIG_BPF_LSM=y` and `lsm=bpf`, uses fmod_ret on `security_key_permission` to flip deny->allow for targeted tgids. LSM fmod_ret is a first-class override primitive -- no error_injection allowlist, no tracefs tricks. An unprivileged user's `keyctl print` succeeds with BPF loaded vs `EACCES` baseline.

## What this does NOT do

Fails attach on kernels without BPF LSM. Some hardened kernels short-circuit `key_permission` inside `key_task_permission` before the LSM hook is reached for revoked or uninstantiated keys -- those paths won't flip. On linuxkit 6.12 aarch64, BTF may forward-declare `struct key` causing verifier rejection.

## Prerequisites

- `CONFIG_BPF_LSM=y` in the kernel config
- Boot cmdline contains `bpf` in `lsm=...`
- `keyctl(1)` from `keyutils`
- `CAP_SYS_ADMIN`
- Typically satisfied by Fedora 38+ default

## Files

| File | Purpose |
|------|---------|
| `ch08-keyring-heist-lsm.bpf.c` | Kernel-side BPF LSM program (fmod_ret on key_permission) |
| `ch08-keyring-heist-lsm.c` | Userspace loader with wildcard/targeted modes |
| `trigger.sh` | Activity generator |
| `Makefile` | Build (uses shared/common.mk) |

## Build & Run

```bash
# Inside the harness container:
make
sudo ./build/ch08-keyring-heist-lsm -a              # flip every deny
sudo ./build/ch08-keyring-heist-lsm -t 12345        # targeted tgid
# In another terminal:
bash trigger.sh
```

## Detection

- `bpftool prog list type lsm` shows the attached sleepable program on `key_permission`.
- Kernel `bpf()` syscall audit records program load.
- Unexpected keyring access grants for unprivileged processes that should be denied.
