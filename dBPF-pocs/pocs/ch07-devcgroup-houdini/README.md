# Ch07 -- Device-cgroup Houdini

**Category**: OBSERVER
**Primitive**: kprobe + kretprobe on `devcgroup_check_permission`
**Hook(s)**: `SEC("kprobe/devcgroup_check_permission")`, `SEC("kretprobe/devcgroup_check_permission")`
**Architecture**: aarch64 + x86_64

## What this demonstrates

Streams every device cgroup decision (type=char/block, major, minor, access mask, verdict) via kprobe/kretprobe on `devcgroup_check_permission`. Provides full visibility into every device access check the cgroup subsystem performs.

## What this does NOT do

Cannot mutate -- the inner `__devcgroup_check_permission` is usually inlined and not kprobe-able, and `devcgroup_check_permission` is not in the error-injection allowlist. Actual mutation (grant unrestricted device access) requires BPF LSM -- see `ch07-devcgroup-houdini-lsm/`. Privileged Docker containers set `devices.list = a *:* rwm` which bypasses the cgroup entirely, so no denies are observed unless running inside an unprivileged cgroup.

## Prerequisites

- `devcgroup_check_permission` present in `/proc/kallsyms`
- `CONFIG_KPROBES=y`
- Docker: `--privileged --pid=host`

## Files

| File | Purpose |
|------|---------|
| `ch07-devcgroup-houdini.bpf.c` | Kernel-side BPF program (kprobe/kretprobe on devcgroup_check_permission) |
| `ch07-devcgroup-houdini.c` | Userspace loader and ringbuf consumer |
| `trigger.sh` | Activity generator |
| `Makefile` | Build (uses shared/common.mk) |

## Build & Run

```bash
# Inside the harness container:
make
sudo ./build/ch07-devcgroup-houdini
# In another terminal:
bash trigger.sh
```

## Detection

- `bpftool prog show | grep devcgroup` lists the attached kprobes.
- `/sys/kernel/debug/tracing/kprobe_events` shows live entries.
- The `events` ringbuf appears in `bpftool map show`.
