# Ch17 -- ACPI / WSMI Ping (analog variant)

**Category**: ANALOG
**Primitive**: tracepoint + bpf_probe_write_user for openat path rewriting
**Hook(s)**: `SEC("tp/syscalls/sys_enter_openat")`
**Architecture**: aarch64 + x86_64

## What this demonstrates

Reproduces the primitive shape of the ACPI/firmware string-swap attack ("kernel-mediated string content substituted in flight") against a userspace "firmware requester" binary whose `openat()` path argument gets rewritten via `bpf_probe_write_user` before the syscall body runs. The requester opens one file but actually gets a different one.

## What this does NOT do

Does not exercise ACPI or the firmware loader. No ACPI method is evaluated; no firmware loader path is touched. The target is a userspace binary named `fw_requester` opening files under `/tmp`. Comm-based match (`fw_requester`) is trivial to evade. `bpf_probe_write_user` can fault on non-resident pages and fail silently.

## Prerequisites

- `CONFIG_BPF_EVENTS=y`, syscalls tracepoints enabled
- `bpf_probe_write_user` available
- `/tmp` writable (trigger seeds the original + replacement files)

## Files

| File | Purpose |
|------|---------|
| `ch17-acpi-wsmi-analog.bpf.c` | Kernel-side BPF program (tracepoint on sys_enter_openat + bpf_probe_write_user) |
| `ch17-acpi-wsmi-analog.c` | Userspace loader and ringbuf consumer |
| `fw_requester.c` | Userspace "firmware requester" binary (opens a path that gets rewritten) |
| `trigger.sh` | Activity generator (seeds files, runs fw_requester, verifies swap) |
| `Makefile` | Build (uses shared/common.mk) |

## Build & Run

```bash
# Inside the harness container:
make
sudo bash trigger.sh
```

## Detection

- `bpftool prog show` lists the tracepoint program on `sys_enter_openat`.
- `bpf_probe_write_user()` invocations emit a kernel taint message.
- Compare the file path a process intended to open (from strace) vs what was actually opened.
