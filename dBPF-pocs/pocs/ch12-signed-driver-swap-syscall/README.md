# Ch12 -- Signed-Driver Swap (syscall variant)

**Category**: ILLUSION
**Primitive**: kretprobe + bpf_override_return on module-load syscalls
**Hook(s)**: `SEC("kretprobe/__arm64_sys_finit_module")`, `SEC("kretprobe/__arm64_sys_init_module")`
**Architecture**: aarch64 only

## What this demonstrates

Forges the return value of the module-load syscalls to 0 via `bpf_override_return`. Both `__arm64_sys_finit_module` and `__arm64_sys_init_module` are on the kernel's error-injection allowlist on linuxkit 6.12. The kernel's actual module loader still rejects the bytes -- only what userspace sees is rewritten. `lsmod` and `/proc/modules` show no change.

## What this does NOT do

Kernel state unchanged -- only the syscall return value to userspace is forged. The module is NOT actually loaded: `lsmod`, `/proc/modules`, and `/sys/module/<name>/` all show nothing. Any post-load verification via kernel state (procfs/sysfs) defeats this primitive. Only fools workflows that treat the syscall return as authoritative proof of load.

## Prerequisites

- `__arm64_sys_finit_module` and `__arm64_sys_init_module` in `/sys/kernel/debug/error_injection/list`
- `CONFIG_BPF_KPROBE_OVERRIDE=y`
- `CAP_SYS_ADMIN`
- Docker: `--privileged --pid=host`

## Files

| File | Purpose |
|------|---------|
| `ch12-signed-driver-swap-syscall.bpf.c` | Kernel-side BPF program (kretprobe + bpf_override_return on module-load syscalls) |
| `ch12-signed-driver-swap-syscall.c` | Userspace loader with wildcard/targeted modes |
| `trigger.sh` | Activity generator (insmod of a fabricated fake .ko, before/after comparison) |
| `Makefile` | Build (uses shared/common.mk) |

## Build & Run

```bash
# Inside the harness container:
make
sudo ./build/ch12-signed-driver-swap-syscall --all
# In another terminal:
bash trigger.sh
```

## Detection

- `lsmod` / `/proc/modules` does not list the supposedly-loaded module.
- Kernel log (`dmesg`) shows the original module-loader error.
- `insmod` success with no entry in `/sys/module/<name>/`.
- `bpftool prog show type kprobe` reveals kretprobes on `sys_finit_module` / `sys_init_module`.
- Orchestrators that call `finit_module(2)` and then `stat("/sys/module/<name>")` catch the discrepancy immediately.
