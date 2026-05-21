# ch13-analog — Powercap Override (Analog / Standalone Variant)

**Status: PROVEN** on Ubuntu 6.17.0-29-generic aarch64 (Lima VM), 2026-05-20.

Proof marker: `CH13_ANALOG_PROVEN`.

## What this is

This is a standalone analog of the ch13 powercap primitive that does not
require RAPL hardware or Intel-specific powercap symbols. It proves the
same `bpf_probe_write_user` primitive used to rewrite in-flight kernel
reads in a hardware-agnostic way.

A userspace sensor daemon reads a synthetic power/temperature value via
`read(2)` from a file or pipe. A BPF program hooks `sys_exit_read` and
rewrites the user-space buffer mid-flight using `bpf_probe_write_user`,
substituting a forged sensor value before the daemon sees it.

No RAPL hardware is needed. No Intel-specific powercap kernel symbols are
required. The primitive works on any kernel with `CONFIG_BPF_WRITE_USER`
support.

## Mechanism

1. A sensor daemon loop calls `read(fd, buf, len)` to fetch a sensor reading.
2. A BPF `tracepoint/syscalls/sys_exit_read` (or `kretprobe/__arm64_sys_read`)
   program fires on return.
3. The program inspects `pid` to confirm this is the target daemon, then calls
   `bpf_probe_write_user(buf, &forged_val, sizeof(forged_val))` to overwrite
   the buffer the daemon just received.
4. The daemon reads a value the kernel never produced.

## Hook points
- `tracepoint/syscalls/sys_exit_read` (or `kretprobe/__arm64_sys_read`) —
  fires on every `read(2)` return for the targeted PID.
- Uses `bpf_probe_write_user` to rewrite the userspace buffer in-flight.

## Build
```
cd pocs/ch13-powercap-override-analog
make
```

## Run
```
sudo bash trigger.sh
```

The trigger:
1. Starts a sensor daemon that reads and prints a value each second.
2. Loads the BPF program targeting that daemon's PID.
3. Shows baseline (real) readings, then forged readings after BPF attach.
4. Emits `CH13_ANALOG_PROVEN` when a forged value is confirmed.

## Evidence (Ubuntu 6.17 aarch64, Lima VM)
```
=== baseline: sensor daemon reads (no BPF) ===
sensor_value=42

=== with BPF: bpf_probe_write_user active ===
sensor_value=9999   # forged by BPF

CH13_ANALOG_PROVEN
```

## Why this matters

On aarch64 hardware where `powercap_get_max_power_uw` does not exist, this
variant proves the same fundamental primitive: a BPF program can intercept
a `read(2)` return and substitute arbitrary data into the caller's buffer.
Applied to a real power/thermal monitoring daemon reading from sysfs or a
sensor device, the effect is identical to the x86 RAPL override: the
monitoring stack sees fabricated values.

## Detection
- `bpftool prog show | grep read` reveals probes on the `read` syscall path.
- `bpftool prog dump xlated` for those programs shows `bpf_probe_write_user`
  helper calls, which are unusual in legitimate observability tooling.
- The targeted daemon can cross-check by reading the same sysfs path via a
  second fd or via a different syscall (`pread`); the forged value is
  path/fd-specific if the BPF program keys on fd.

## Limitations / arch notes
- `bpf_probe_write_user` requires `CAP_SYS_ADMIN` (or `CAP_BPF` +
  `CAP_PERFMON` depending on kernel version).
- The write is best-effort: if the user buffer pointer is invalid at the
  time of the kretprobe, the helper returns an error and the write is skipped.
- Rewriting a streaming read is inherently racy; the daemon must not have
  already consumed the buffer before the kretprobe fires. In practice on
  6.17 aarch64 the timing is reliable for slow (≥1 Hz) sensor loops.
