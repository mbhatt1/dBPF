# Ch17 -- ACPI / WSMI Ping

**Category**: REAL
**Primitive**: kprobe on ACPI evaluation functions (x86) or firmware-request functions (aarch64 fallback)
**Hook(s)**: `SEC("kprobe/acpi_evaluate_object")`, `SEC("kprobe/acpi_ns_evaluate")`, `SEC("kprobe/acpi_ex_execute_method")`, `SEC("kprobe/request_firmware")`, `SEC("kprobe/_request_firmware")`, `SEC("kprobe/firmware_request_nowarn")`
**Architecture**: aarch64 + x86_64

## What this demonstrates

Kprobes the ACPI method evaluation path (`acpi_evaluate_object -> acpi_ns_evaluate -> acpi_ex_execute_method`) and streams `{pid, comm, hook, arg_string}` for every evaluation. On aarch64 where ACPI is absent, falls back to firmware-request kprobes as the closest moral equivalent. The loader auto-detects which symbols are present and adapts.

## What this does NOT do

Pure observer. A true ACPI WSMI bypass would need `bpf_override_return` on `acpi_ex_execute_method` (not allowlisted for error injection on stock kernels), or a BPF LSM hook on the firmware loader. Neither is wired up here. On aarch64 linuxkit, ACPI symbols are absent; the firmware-request fallback is a best-effort moral-equivalent.

## Prerequisites

- x86: ACPI symbols in `/proc/kallsyms` (`CONFIG_ACPI=y`)
- aarch64: firmware-request symbols (`request_firmware` etc.) in `/proc/kallsyms`
- If none of the 6 candidates exist, loader exits with `CH17_SKIP`
- Docker: `--privileged --pid=host`

## Files

| File | Purpose |
|------|---------|
| `ch17-acpi-wsmi.bpf.c` | Kernel-side BPF program (six kprobes: three ACPI + three firmware) |
| `ch17-acpi-wsmi.c` | Userspace loader with auto-detection of available hooks |
| `trigger.sh` | Activity generator |
| `Makefile` | Build (uses shared/common.mk) |

## Build & Run

```bash
# Inside the harness container:
make
sudo ./build/ch17-acpi-wsmi
# In another terminal:
bash trigger.sh
```

## Detection

- `bpftool prog show | grep -E 'acpi|firmware'` lists the attached kprobes.
- `cat /sys/kernel/debug/tracing/kprobe_events` shows attached probes.
- `events` ringbuf visible in `bpftool map show`.
