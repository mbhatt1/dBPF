# Ch13 -- Powercap Override (analog variant)

**Category**: ANALOG
**Primitive**: tracepoint + bpf_probe_write_user (same primitive shape as RAPL override)
**Hook(s)**: `SEC("tp/syscalls/sys_enter_read")`, `SEC("tp/syscalls/sys_exit_read")`
**Architecture**: aarch64 + x86_64

## What this demonstrates

Reproduces the primitive shape of the RAPL powercap override attack ("rewrite `read()` buffer in flight via `bpf_probe_write_user` on `sys_exit_read`") against a surface that exists on aarch64: a userspace sensor daemon writing to a plain file, and a reader cat-ing that file. The reader sees zeroed-out values while the daemon writes real data.

## What this does NOT do

Does not touch the real RAPL/powercap subsystem. Intel RAPL / powercap is x86-only; this kernel is aarch64 linuxkit where the real subsystem does not exist. No powercap sysfs node is touched; the target is a plain file under `/tmp`. Drawing any conclusion about actual Intel RAPL behavior from this POC is a category error.

## Prerequisites

- `CONFIG_BPF_EVENTS=y`, syscalls tracepoints enabled
- `bpf_probe_write_user` available (taints the kernel when called)
- `/tmp` writable (daemon stages `/tmp/ch13_sensor_energy_uj`)

## Files

| File | Purpose |
|------|---------|
| `ch13-powercap-override-analog.bpf.c` | Kernel-side BPF program (tracepoint pair + bpf_probe_write_user) |
| `ch13-powercap-override-analog.c` | Userspace loader and ringbuf consumer |
| `sensor_daemon.c` | Userspace sensor daemon (writes energy values) |
| `sensor_reader.c` | Userspace sensor reader (reads and displays values) |
| `trigger.sh` | Activity generator (three-phase: before, during, after BPF) |
| `Makefile` | Build (uses shared/common.mk) |

## Build & Run

```bash
# Inside the harness container:
make
sudo bash trigger.sh
```

## Detection

- `bpftool prog show` lists the two tracepoint programs.
- `bpf_probe_write_user()` invocations emit a kernel taint message.
- Cross-check sensor readings from multiple sources; readings from the file will diverge from the daemon's actual writes.
