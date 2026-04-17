# Ch03 -- FUSE Audit Black-Hole

**Category**: REAL
**Primitive**: kprobe on audit message-construction functions
**Hook(s)**: `SEC("kprobe/audit_log_start")`, `SEC("kprobe/audit_log_end")`, `SEC("kprobe/audit_log_format")`
**Architecture**: aarch64 + x86_64

## What this demonstrates

Attaches kprobes to the three key audit message-construction functions and streams every call through a ring buffer. Each event emits `{pid, tgid, comm, hook, audit_type, fmt_preview}`. The userspace loader prints human-readable decodes of common `AUDIT_*` type constants.

## What this does NOT do

Cannot mutate -- the audit functions are not in `/sys/kernel/debug/error_injection/list` on this kernel. `bpf_override_return()` on `audit_log_start` to drop records is documented but not exercised. The "black-hole" vector requires `ALLOW_ERROR_INJECTION(audit_log_start, ...)` or BPF LSM. See `ch03-fuse-blackhole-fentry` for the mutation variant.

## Prerequisites

- `CONFIG_AUDIT=y`
- `CONFIG_KPROBES=y`
- `audit_log_start`, `audit_log_end`, `audit_log_format` in `/proc/kallsyms`
- Docker: `--privileged --pid=host`

## Files

| File | Purpose |
|------|---------|
| `ch03-fuse-blackhole.bpf.c` | Kernel-side BPF program (three kprobes, one ringbuf, one ctrl array) |
| `ch03-fuse-blackhole.c` | Userspace loader, ringbuf poller, AUDIT_* decoder |
| `trigger.sh` | Provokes audit-worthy events |
| `Makefile` | Build (uses shared/common.mk) |

## Build & Run

```bash
# Inside the harness container:
make
./build/ch03-fuse-blackhole &
# In another terminal:
bash trigger.sh
```

## Detection

- `bpftool prog show` lists three `kprobe` programs named `kp_als`, `kp_ale`, `kp_alf`. A normal system has zero kprobes on audit symbols.
- `cat /sys/kernel/tracing/kprobe_events` shows the attached probes.
- Signed-kernel environments can refuse `bpf(BPF_PROG_LOAD)` via `kernel.unprivileged_bpf_disabled=2` and LSM (lockdown integrity).
- auditd self-monitoring: a sudden drop in `AUDIT_SYSCALL` volume while login activity continues is a classic black-hole signature.
