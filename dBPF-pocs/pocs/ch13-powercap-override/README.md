# Ch13 -- Powercap Override

**Category**: REAL
**Primitive**: kprobe on powercap/RAPL framework functions
**Hook(s)**: `SEC("kprobe/powercap_register_control_type")`, `SEC("kprobe/powercap_set_max_power_uw")`, `SEC("kprobe/powercap_get_max_power_uw")`, `SEC("kprobe/thermal_zone_device_update")`
**Architecture**: x86_64 only

## What this demonstrates

Kprobes the powercap framework -- the kernel's generic interface for CPU/package/DRAM TDP caps, RAPL, Intel PowerClamp, and thermal zone update notifications. Each call streams a ringbuf event tagged with hook id, PID, comm, and raw arguments. Provides full visibility into power/thermal envelope manipulation.

## What this does NOT do

Pure observer. The real exploit path (forging `set_max_power_uw` or flipping `get_max_power_uw` results) requires `bpf_override_return`, which is blocked by the error-injection allowlist. On aarch64 linuxkit, all four symbols are absent (no `CONFIG_POWERCAP`/RAPL) -- the loader emits `CH13_SKIP` and exits 2. This is architectural, not fixable from BPF.

## Prerequisites

- `CONFIG_POWERCAP=y` and/or `CONFIG_INTEL_RAPL=y` (x86 Intel hosts)
- At least one of the four powercap/thermal symbols in `/proc/kallsyms`
- Docker: `--privileged --pid=host`

## Files

| File | Purpose |
|------|---------|
| `ch13-powercap-override.bpf.c` | Kernel-side BPF program (four kprobes on powercap/thermal functions) |
| `ch13-powercap-override.c` | Userspace loader and ringbuf consumer |
| `trigger.sh` | Activity generator (reads powercap sysfs entries) |
| `Makefile` | Build (uses shared/common.mk) |

## Build & Run

```bash
# Inside the harness container:
make
sudo ./build/ch13-powercap-override
# In another terminal:
bash trigger.sh
```

## Detection

- `bpftool prog show | grep powercap` lists the attached kprobes.
- `cat /sys/kernel/debug/tracing/kprobe_events` shows live entries.
- The `events` ringbuf appears in `bpftool map show`.
- Monitor `/sys/class/powercap/` sysfs reads for unexpected access patterns.
