# Ch08 -- Keyring Heist

**Category**: REAL
**Primitive**: kprobe on keyring access functions with CO-RE metadata extraction
**Hook(s)**: `SEC("kprobe/key_task_permission")`, `SEC("kprobe/lookup_user_key")`
**Architecture**: aarch64 + x86_64

## What this demonstrates

Kprobes `key_task_permission` and `lookup_user_key`. For each call, CO-RE reads `struct key -> {serial, datalen, type->name, description}` and emits a ringbuf event. Provides full metadata disclosure of every kernel keyring access without mutation.

## What this does NOT do

Observer-only. Real mutation requires BPF LSM fmod_ret on `security_key_permission` -- see `ch08-keyring-heist-lsm/`. Does not attempt to read `key->payload` (requires invoking the key's `type->read` method, which is not safe from BPF).

## Prerequisites

- `key_task_permission` and `lookup_user_key` present in `/proc/kallsyms`
- CO-RE BTF available (vmlinux BTF shipped with the kernel)
- `keyctl(1)` from `keyutils` (the trigger uses it)
- Docker: `--privileged --pid=host`

## Files

| File | Purpose |
|------|---------|
| `ch08-keyring-heist.bpf.c` | Kernel-side BPF program (kprobes on key_task_permission, lookup_user_key) |
| `ch08-keyring-heist.c` | Userspace loader and ringbuf consumer |
| `trigger.sh` | Activity generator (keyctl operations) |
| `Makefile` | Build (uses shared/common.mk) |

## Build & Run

```bash
# Inside the harness container:
make
sudo ./build/ch08-keyring-heist
# In another terminal:
bash trigger.sh
```

## Detection

- `bpftool prog show | grep key_` lists the attached kprobes.
- `/sys/kernel/debug/tracing/kprobe_events` shows live entries.
- The `events` ringbuf appears in `bpftool map show`.
