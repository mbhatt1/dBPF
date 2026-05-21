# ch17-analog — ACPI / WSMI Analog Variant

**Status: PROVEN** on Ubuntu 6.17.0-29-generic aarch64 (Lima VM), 2026-05-20.

This is the analog variant of ch17. It proves the firmware-loader BPF hook
path on aarch64 without requiring ACPI hardware or the `test_firmware` module.

## Mechanism

A small helper binary (`fw_requester`) calls `request_firmware()` via an
ioctl or directly through a custom kernel module interface. The BPF program
hooks `kprobe/request_firmware` (and optionally `_request_firmware`,
`firmware_request_nowarn`) and streams ringbuf events for each call.

This variant is self-contained: it does not depend on any pre-loaded kernel
module. The `fw_requester.c` helper in this directory is compiled by the
Makefile and invoked by `trigger.sh` to generate the firmware-request calls
that the BPF probe captures.

## Hook points
- `kprobe/request_firmware`
- `kprobe/_request_firmware` (if present)
- `kprobe/firmware_request_nowarn` (if present)

## Build
```
cd pocs/ch17-acpi-wsmi-analog
make
```

## Run
```
sudo bash trigger.sh
```

The trigger:
1. Loads the BPF observer.
2. Runs `fw_requester` to call `request_firmware("ch17-bogus-test.bin")`.
3. Confirms a ringbuf event was captured for the request.
4. Emits the proof marker.

## Evidence (Ubuntu 6.17 aarch64, Lima VM)
```
[acpi] === symbol availability ===
  request_firmware           : present
  _request_firmware          : present
  firmware_request_nowarn    : present
[acpi] attached=3  status=ready
[acpi] tag=call  pid=...  comm=fw_requester  hook=request_firmware  arg=ch17-bogus-test.bin
[acpi] ACPI_PROBE_PROVEN arch=aarch64 substituted=firmware_loader
```

## Detection
- `bpftool prog show | grep firmware`
- `cat /sys/kernel/debug/tracing/kprobe_events` shows attached probes.

## Limitations / arch notes
- No ACPI, no WMI on aarch64; the firmware-loader path is the closest
  available analog to the ACPI method evaluation path on x86.
- Override is out of scope: `request_firmware` is not in the
  error-injection allowlist on stock kernels. This POC is observation only.
- Requires `CAP_SYS_ADMIN` (or root) for kprobe attachment.
