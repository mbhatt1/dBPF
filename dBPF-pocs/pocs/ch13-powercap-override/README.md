# ch13 — Powercap Override (observer)

**Status: PROVEN** on Ubuntu 6.17.0-29-generic aarch64 (Lima VM), 2026-05-20.

## Proof summary (aarch64)

RAPL / `powercap_get_max_power_uw` / `powercap_set_max_power_uw` are
x86-only; they do not exist on aarch64. However, `powercap_register_control_type`
IS present. The trigger builds and loads a small out-of-tree kernel module
(`powercap_dummy.ko`) that calls `powercap_register_control_type()` to
register a dummy control type. The BPF kprobe on that symbol fires,
streams a ringbuf event, and the trigger emits:

```
CH13_PROVEN hook=powercap_register_control_type
```

Proof marker: `CH13_PROVEN hook=powercap_register_control_type`.

## Mechanism
Kprobes the powercap framework — the kernel's generic interface for
CPU/package/DRAM TDP caps, RAPL (Running Average Power Limit on Intel),
Intel PowerClamp, and thermal zone update notifications. Each call
streams a ringbuf event tagged with the hook id, PID, comm, and the raw
first two arguments. From there, userspace can see exactly when and
with what magnitude the kernel (or a privileged userspace tool) is
manipulating power/thermal envelopes.

This POC is pure observation. The real exploit path — forging a
`set_max_power_uw` call from BPF, or silently flipping the result of
`get_max_power_uw` — requires `bpf_override_return`, which is blocked
here by the error-injection allowlist.

## Hook points
- `kprobe/powercap_register_control_type` — fires once per driver init
  (rapl, intel_pmc, etc.) or when the dummy kernel module is loaded.
- `kprobe/powercap_set_max_power_uw`     — any write to `max_power_uw` (x86 only).
- `kprobe/powercap_get_max_power_uw`     — any read from `max_power_uw` (x86 only).
- `kprobe/thermal_zone_device_update`    — thermal engine notifications.

## Build
```
cd pocs/ch13-powercap-override
make
```

## Run
```
sudo ./build/ch13-powercap-override -h
sudo ./build/ch13-powercap-override          # observe-only
sudo ./build/ch13-powercap-override -v       # verbose libbpf
```

## Evidence (aarch64 Ubuntu 6.17, Lima VM)
```
[ch13] === symbol availability ===
  powercap_register_control_type       : present
  powercap_set_max_power_uw            : ABSENT
  powercap_get_max_power_uw            : ABSENT
  thermal_zone_device_update           : present
[ch13] attached=2	status=ready
# trigger.sh loads powercap_dummy.ko:
[ch13] tag=powercap	ts=...	pid=...	comm=insmod	hook=powercap_register_control_type	arg0=...
[ch13] CH13_PROVEN hook=powercap_register_control_type
```

## Evidence (expected on x86 Intel hosts)
```
[ch13] === symbol availability ===
  powercap_register_control_type       : present
  powercap_set_max_power_uw            : present
  powercap_get_max_power_uw            : present
  thermal_zone_device_update           : present
[ch13] attached=4	status=ready
[ch13] CH13_PROVEN hook=powercap_get_max_power_uw events=1
[ch13] tag=powercap	ts=12345678	pid=4321	comm=cat             	hook=powercap_get_max_power_uw	arg0=0x0	arg1=0xffff888100...
```

## Limitations
- **arm64 / aarch64**: RAPL (`powercap_get_max_power_uw`,
  `powercap_set_max_power_uw`) are absent — Intel-specific hardware.
  `powercap_register_control_type` IS present and is used as the hook
  target on aarch64 via the `powercap_dummy.ko` kernel module built by
  trigger.sh. The proof marker is `CH13_PROVEN hook=powercap_register_control_type`.
- Read-only: we record the call; we do not overwrite the returned max
  power value. Doing so needs either
    - the symbols added to `/sys/kernel/debug/error_injection/list` plus
      `CONFIG_FUNCTION_ERROR_INJECTION=y`, or
    - a BPF LSM hook (there isn't one native to powercap — you'd have
      to go via `security_file_permission` on the sysfs path), or
    - kernel module side-loading.
- `powercap_register_control_type` normally fires only at boot / driver
  module load; trigger.sh exercises it by loading the dummy module.

## Real exploit path (x86 Intel)
1. Attach BPF LSM to `security_file_permission` for
   `/sys/class/powercap/intel-rapl:0/constraint_0_power_limit_uw` and
   `max_power_uw`.
2. Return `-EACCES` to defender processes inspecting the cap, so they
   see a value that was never actually set.
3. Meanwhile, a privileged helper writes a high limit; sibling BPF
   observes via `kprobe/powercap_set_max_power_uw` to confirm.
4. Net effect: the CPU boosts past its nominal TDP while userspace
   monitors still read the baseline envelope. The TDP cap is a power
   policy primitive used by turbo, throttling decisions, and by platform
   thermal governors — overriding it at the sysfs read path is enough
   to defeat most monitoring stacks without touching the driver itself.
