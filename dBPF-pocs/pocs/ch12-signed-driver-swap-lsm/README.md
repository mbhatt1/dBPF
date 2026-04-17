# Ch12 -- Signed-Driver Swap (LSM variant)

**Category**: REAL
**Primitive**: LSM fmod_ret on `kernel_read_file`, `kernel_load_data`, `locked_down`
**Hook(s)**: `SEC("lsm/kernel_read_file")`, `SEC("lsm/kernel_load_data")`, `SEC("lsm/locked_down")`
**Architecture**: aarch64 + x86_64

## What this demonstrates

Weaponizes module-load observation: uses fmod_ret on three LSM hooks in the module-load path to flip deny->allow for targeted tgids. The signature/lockdown gate collapses. Evidence is the errno shift from EBADMSG (signature rejected) to ENOEXEC (ELF validator rejected after signature gate was bypassed).

## What this does NOT do

Fails attach on kernels without BPF LSM. The errno shift depends on in-tree modules and post-gate validators; on kernels with `CONFIG_MODULE_SIG_FORCE=y` the final errno may remain the same even though the LSM flip fired. `kernel_load_data` and `locked_down` hooks only fire on specific paths (e.g. `request_firmware`, `kexec_file_load`).

## Prerequisites

- `CONFIG_BPF_LSM=y` in the kernel config
- Boot cmdline contains `bpf` in `lsm=...`
- `insmod(8)` from `kmod`
- `CAP_SYS_ADMIN`
- Typically satisfied by Fedora 38+ default

## Files

| File | Purpose |
|------|---------|
| `ch12-signed-driver-swap-lsm.bpf.c` | Kernel-side BPF LSM program (fmod_ret on three module-load hooks) |
| `ch12-signed-driver-swap-lsm.c` | Userspace loader with wildcard/targeted modes |
| `trigger.sh` | Activity generator (insmod of a fabricated fake .ko) |
| `Makefile` | Build (uses shared/common.mk) |

## Build & Run

```bash
# Inside the harness container:
make
sudo ./build/ch12-signed-driver-swap-lsm -a              # flip every deny
sudo ./build/ch12-signed-driver-swap-lsm -t 12345        # targeted tgid
# In another terminal:
bash trigger.sh
```

## Detection

- `bpftool prog list type lsm` shows the attached sleepable programs.
- The errno shift EBADMSG->ENOEXEC on `insmod` is direct evidence the LSM override changed control flow.
- Kernel `bpf()` syscall audit records program load.
