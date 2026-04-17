# Ch08 -- Keyring Heist (kprobe variant)

**Category**: REAL
**Primitive**: kprobe on keyring access functions (BTF FWD workaround)
**Hook(s)**: `SEC("kprobe/key_task_permission")`, `SEC("kprobe/lookup_user_key")`
**Architecture**: aarch64 + x86_64

## What this demonstrates

Sidesteps a BTF-specific loader failure where `security_key_permission` forward-declares `struct key` (BTF FWD kind) instead of defining it. This variant attaches kprobes at `key_task_permission` and `lookup_user_key`, pulling the first argument via `PT_REGS_PARM1` and letting CO-RE resolve `struct key` fields against `vmlinux.h`. Reads `{serial, type->name, description}` for every keyring access.

## What this does NOT do

Observer-only. The unprivileged `keyctl print` still returns EACCES before and after attach -- the kernel's access decision is preserved. Does not read `key->payload`. For actual override, use `ch08-keyring-heist-lsm/` on a kernel whose BTF doesn't forward-declare `struct key`.

## Prerequisites

- Both symbols present in `/proc/kallsyms`
- CO-RE BTF available (vmlinux BTF shipped with the kernel)
- `keyctl(1)` from `keyutils` (the trigger uses it)

## Files

| File | Purpose |
|------|---------|
| `ch08-keyring-heist-kprobe.bpf.c` | Kernel-side BPF program (kprobes with PT_REGS_PARM1 for BTF FWD workaround) |
| `ch08-keyring-heist-kprobe.c` | Userspace loader and ringbuf consumer |
| `trigger.sh` | Activity generator |
| `Makefile` | Build (uses shared/common.mk) |

## Build & Run

```bash
# Inside the harness container:
make
sudo ./build/ch08-keyring-heist-kprobe
# In another terminal:
bash trigger.sh
```

## Detection

- `bpftool prog show | grep key_` lists the attached kprobes.
- `/sys/kernel/debug/tracing/kprobe_events` shows live entries.
- The `events` ringbuf appears in `bpftool map show`.
