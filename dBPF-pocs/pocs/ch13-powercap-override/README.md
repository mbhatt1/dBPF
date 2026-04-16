# ch13 — Powercap Override (observer)

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
  (rapl, intel_pmc, etc.).
- `kprobe/powercap_set_max_power_uw`     — any write to `max_power_uw`.
- `kprobe/powercap_get_max_power_uw`     — any read from `max_power_uw`.
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

On aarch64 linuxkit (Docker Desktop on Apple Silicon) all four symbols
are absent — the kernel was built without `CONFIG_POWERCAP`/RAPL support.
The loader emits `CH13_SKIP reason="no powercap/RAPL symbols ..."` and
exits 2, and the trigger script emits the same skip marker.

## Limitations
- **arm64 linuxkit**: no RAPL, no powercap; all four symbols absent.
  The POC correctly skips there. This is architectural, not fixable
  from BPF.
- Read-only: we record the call; we do not overwrite the returned max
  power value. Doing so needs either
    - the symbols added to `/sys/kernel/debug/error_injection/list` plus
      `CONFIG_FUNCTION_ERROR_INJECTION=y`, or
    - a BPF LSM hook (there isn't one native to powercap — you'd have
      to go via `security_file_permission` on the sysfs path), or
    - kernel module side-loading.
- `powercap_register_control_type` normally fires only at boot / driver
  module load, so trigger.sh rarely exercises it; the other three hooks
  are reliable evidence on an x86 Intel host.

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

## Blog post

See the chapter write-up: [`2025-03-10-powercap-override`](../../../_posts/2025-03-10-powercap-override.md) in the Diabolical eBPF Field Manual.
