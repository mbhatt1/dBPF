# Ch06 -- Silencing SELinux

**Category**: REAL
**Primitive**: kprobe on SELinux AVC and file-permission functions
**Hook(s)**: `SEC("kprobe/avc_has_perm")`, `SEC("kprobe/avc_has_perm_noaudit")`, `SEC("kprobe/selinux_file_permission")`
**Architecture**: aarch64 + x86_64

## What this demonstrates

Kprobes the SELinux access-vector cache (AVC) and the file-permission LSM hook. Every labeled decision -- granted or denied -- streams a ringbuf event containing `{pid, comm, hook, ssid, tsid, tclass, requested}`. Provides full visibility into every SELinux access check on the system.

## What this does NOT do

Cannot mutate -- `avc_has_perm` is not on the error-injection allowlist of stock kernels, so `bpf_override_return` is blocked. True silencing of SELinux requires BPF LSM `fmod_ret` -- see `ch06-silence-selinux-lsm/`. On kernels where SELinux is compiled out, every symbol is absent; the loader exits with `CH06_SKIP`.

## Prerequisites

- `CONFIG_SECURITY_SELINUX=y` (SELinux compiled into the kernel)
- `CONFIG_KPROBES=y`
- SELinux symbols (`avc_has_perm` etc.) present in `/proc/kallsyms`
- Docker: `--privileged --pid=host`

## Files

| File | Purpose |
|------|---------|
| `ch06-silence-selinux.bpf.c` | Kernel-side BPF program (three kprobes on SELinux AVC + file_permission) |
| `ch06-silence-selinux.c` | Userspace loader and ringbuf consumer |
| `trigger.sh` | Activity generator |
| `Makefile` | Build (uses shared/common.mk) |

## Build & Run

```bash
# Inside the harness container:
make
sudo ./build/ch06-silence-selinux          # observe-only
# In another terminal:
bash trigger.sh
```

## Detection

- `bpftool prog show | grep avc_has_perm` lists the attached kprobes.
- `cat /sys/kernel/debug/tracing/kprobe_events` shows the live kprobe records.
- `bpftool map show` lists the `events` ringbuf.
- A monitoring system can watch for `/proc/kallsyms`-resident kprobes on `avc_*` symbols.
