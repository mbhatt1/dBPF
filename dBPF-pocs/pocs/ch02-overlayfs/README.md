# Ch02 -- OverlayFS Trojan Horse

**Category**: REAL
**Primitive**: kprobe on overlayfs copy-up functions + userspace racer
**Hook(s)**: `SEC("kprobe/ovl_copy_up")`, `SEC("kprobe/ovl_maybe_copy_up")`, `SEC("kprobe/ovl_copy_up_with_data")`
**Architecture**: aarch64 + x86_64

## What this demonstrates

Observes every overlayfs copy-up event via three kprobes. In racer mode (`-r`), uses the ringbuf event as a race signal to overwrite the upper-layer file from userspace immediately after promotion. A later victim `read()` on the merged mount sees the attacker's payload instead of what was written.

## What this does NOT do

The kernel-side BPF is observation-only; the mutation is applied from userspace via standard `open()`/`write()` on the upper-dir path. A full kernel-side inject would require `bpf_probe_write_user` or an LSM hook (see `ch02-overlayfs-lsm`). The race window depends on timing and may not succeed on every attempt.

## Prerequisites

- `CONFIG_OVERLAY_FS=y`
- `CONFIG_KPROBES=y`
- At least one of `ovl_copy_up`, `ovl_maybe_copy_up`, `ovl_copy_up_with_data` in `/proc/kallsyms`
- Docker: `--privileged --pid=host`

## Files

| File | Purpose |
|------|---------|
| `ch02-overlayfs.bpf.c` | Kernel-side BPF program (three kprobes on overlay copy-up) |
| `ch02-overlayfs.c` | Userspace loader with observer + racer modes |
| `trigger.sh` | Activity generator (seeds and triggers copy-ups on tmpfs-backed overlay) |
| `Makefile` | Build (uses shared/common.mk) |

## Build & Run

```bash
# Inside the harness container:
make
sudo ./build/ch02-overlayfs                  # observe all overlay copy-ups
# In another terminal:
sudo bash trigger.sh
```

## Detection

- `bpftool prog show | grep ovl_` lists the attached kprobes.
- `cat /sys/kernel/debug/tracing/kprobe_events` shows live kprobe entries.
- The `events` ringbuf appears in `bpftool map show`.
- Monitor upper-layer directories for unexpected file modifications shortly after copy-up events.
