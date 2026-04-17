# Ch01 -- Mirror Controls

**Category**: REAL
**Primitive**: kprobe + kretprobe on `cap_capable` (observe + mark for `bpf_override_return`)
**Hook(s)**: `SEC("kprobe/cap_capable")`, `SEC("kretprobe/cap_capable")`
**Architecture**: aarch64 + x86_64

## What this demonstrates

Observes every `cap_capable()` decision in the kernel. The kprobe stashes the `cap` argument keyed by `pid_tgid`; the matching kretprobe reads the return value, emits a ringbuf event, and for targeted tgids marks what WOULD be flipped from "denied" to "granted". True override would call `bpf_override_return(0)` from the kretprobe.

## What this does NOT do

Override is gated by the kernel's error-injection allowlist. On Docker Desktop linuxkit 6.12 aarch64, `cap_capable` is not in `/sys/kernel/debug/error_injection/list`, so `bpf_override_return` is rejected by the verifier. The POC ships in observe-and-mark mode only. For actual capability override, use the LSM variant (`ch01-mirror-controls-lsm`).

## Prerequisites

- `cap_capable` present in `/proc/kallsyms`
- `CONFIG_KPROBES=y`
- For override: `ALLOW_ERROR_INJECTION(cap_capable, ERRNO)` and `CONFIG_FUNCTION_ERROR_INJECTION=y`, or BPF LSM (`CONFIG_BPF_LSM=y` + `lsm=bpf`)
- Docker: `--privileged --pid=host`

## Files

| File | Purpose |
|------|---------|
| `ch01-mirror-controls.bpf.c` | Kernel-side BPF program (kprobe/kretprobe on cap_capable) |
| `ch01-mirror-controls.c` | Userspace loader and ringbuf consumer |
| `trigger.sh` | Activity generator (`cat /etc/shadow` as unprivileged user) |
| `Makefile` | Build (uses shared/common.mk) |

## Build & Run

```bash
# Inside the harness container:
make
sudo ./build/ch01-mirror-controls            # observe-only
sudo ./build/ch01-mirror-controls -t 12345   # mark tgid 12345 as flip-target
# In another terminal:
bash trigger.sh
```

## Detection

- `bpftool prog show | grep cap_capable` lists the attached kprobe/kretprobe.
- `cat /sys/kernel/debug/tracing/kprobe_events` shows live kprobe entries.
- The `events` ringbuf map appears in `bpftool map show`.
