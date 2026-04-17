# Ch12 -- Signed-Driver Swap

**Category**: REAL
**Primitive**: kprobe on module signature verification functions
**Hook(s)**: `SEC("kprobe/load_module")`, `SEC("kprobe/module_sig_check")`, `SEC("kprobe/mod_verify_sig")`, `SEC("kretprobe/mod_verify_sig")`
**Architecture**: aarch64 + x86_64

## What this demonstrates

Attaches kprobes to the three functions the kernel calls when a module is loaded: `load_module`, `module_sig_check`, and `mod_verify_sig` (plus kretprobe). Each invocation emits a ringbuf event `{pid, comm, hook, modname, ret}`, providing full visibility into the module signature verification pipeline.

## What this does NOT do

Pure observer. `bpf_override_return` on `mod_verify_sig` is not in the kernel's error-injection allowlist. On Docker Desktop linuxkit (6.12, aarch64) with `CONFIG_MODULE_SIG=n`, all symbols are absent and the loader emits `CH12_SKIP`. For mutation, use `ch12-signed-driver-swap-lsm/` or `ch12-signed-driver-swap-syscall/`.

## Prerequisites

- `CONFIG_MODULE_SIG=y` (module signing enabled)
- At least one of `load_module`, `module_sig_check`, `mod_verify_sig` in `/proc/kallsyms`
- `insmod(8)` from `kmod`
- Docker: `--privileged --pid=host`

## Files

| File | Purpose |
|------|---------|
| `ch12-signed-driver-swap.bpf.c` | Kernel-side BPF program (kprobes + kretprobe on module-load path) |
| `ch12-signed-driver-swap.c` | Userspace loader and ringbuf consumer |
| `trigger.sh` | Activity generator (insmod of a fabricated fake .ko) |
| `Makefile` | Build (uses shared/common.mk) |

## Build & Run

```bash
# Inside the harness container:
make
sudo ./build/ch12-signed-driver-swap
# In another terminal:
bash trigger.sh
```

## Detection

- `bpftool prog show | grep -E 'load_module|mod_verify_sig|module_sig_check'` lists the attached probes.
- `cat /sys/kernel/debug/tracing/kprobe_events` shows live entries.
- The `events` ringbuf is listed in `bpftool map show`.
