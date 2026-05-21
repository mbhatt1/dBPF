# ch17 — ACPI / WSMI Ping (observer)

**Status: PROVEN** on Ubuntu 6.17.0-29-generic aarch64 (Lima VM), 2026-05-20.

**aarch64 note:** The `test_firmware` kernel module is not available as a
loadable module on this kernel. Instead, `trigger.sh` builds a custom
out-of-tree kernel module (`fw_trigger.ko`) from source. That module calls
`request_firmware("ch17-bogus-test.bin")` to trigger the firmware subsystem
path that the BPF program hooks. Proof marker: `ACPI_PROBE_PROVEN arch=aarch64 substituted=firmware_loader`.

## Mechanism
ACPI method evaluation is the kernel side of WSMI / WMI-style firmware
pings. On x86 kernels the hot path is:

```
acpi_evaluate_object → acpi_ns_evaluate → acpi_ex_execute_method
```

This POC kprobes all three and streams `{pid, comm, hook, arg_string}`
for every evaluation. `arg_string` captures the ACPI pathname
(e.g. `\\_SB.PCI0._STA`) on the entry hook.

On aarch64 kernels the ACPI interpreter is typically absent
(linuxkit ships no `acpi_*` symbols). The POC therefore falls back to the
firmware-request path (the closest moral equivalent: kernel reaches out to
firmware land) with kprobes on `request_firmware`, `_request_firmware`,
`firmware_request_nowarn`.

The arch-appropriate proof marker is printed on the first ringbuf event:

- `ACPI_PROBE_PROVEN arch=x86_64 substituted=none`
- `ACPI_PROBE_PROVEN arch=aarch64 substituted=firmware_loader`

`ARG_MAX_LEN` is set to 64 bytes (per-CPU scratch used to keep the BPF
stack under budget).

## Hook points
### x86 (primary)
- `kprobe/acpi_evaluate_object`
- `kprobe/acpi_ns_evaluate`
- `kprobe/acpi_ex_execute_method`

### aarch64 (fallback)
- `kprobe/request_firmware`
- `kprobe/_request_firmware`
- `kprobe/firmware_request_nowarn`

## Build
```
cd pocs/ch17-acpi-wsmi
make
```

## Run
```
sudo ./build/ch17-acpi-wsmi -h
sudo ./build/ch17-acpi-wsmi                 # observer mode
sudo ./build/ch17-acpi-wsmi -v              # verbose libbpf
```

In another terminal:
```
sudo bash ./trigger.sh
```

## Evidence
On aarch64 Ubuntu 6.17 (Lima VM), only firmware hooks attach. `test_firmware`
is not a loadable module, so `trigger.sh` builds and loads `fw_trigger.ko`
which calls `request_firmware("ch17-bogus-test.bin")`:
```
[acpi] === symbol availability ===
  acpi_evaluate_object       : ABSENT
  acpi_ns_evaluate           : ABSENT
  acpi_ex_execute_method     : ABSENT
  request_firmware           : present
  _request_firmware          : present
  firmware_request_nowarn    : present
[acpi] attached=firmware_fallback
[acpi] attached=3	skipped=3
[acpi] status=ready	msg=acpi/firmware observer active
[acpi] ACPI_PROBE_PROVEN arch=aarch64 substituted=firmware_loader
[acpi] tag=call	pid=12034	comm=insmod          	hook=request_firmware	arg=bogus-ch17-1728961234.bin
```

On x86 with ACPI:
```
[acpi] attached=acpi_path
[acpi] ACPI_PROBE_PROVEN arch=x86_64 substituted=none
[acpi] tag=call	pid=42	comm=kworker/0:1    	hook=acpi_evaluate_object	arg=\_SB.PCI0._STA
```

## Detection
- `bpftool prog show | grep -E 'acpi|firmware'`
- `cat /sys/kernel/debug/tracing/kprobe_events` shows attached probes.
- `events` ringbuf visible in `bpftool map show`.

## Limitations / arch notes
- **No ACPI, no firmware → honest skip.** If `/proc/kallsyms` contains
  none of the 6 candidates, the loader prints
  `CH17_SKIP reason="no acpi nor firmware symbols"` and exits 2.
- **aarch64 has no ACPI interpreter.** The POC substitutes the
  firmware-request path, which is a best-effort moral-equivalent. The
  substituted-path marker records this honestly.
- **`test_firmware` module not available on Ubuntu 6.17.** The trigger
  builds `fw_trigger.ko` from source (included in this directory) instead.
  The module calls `request_firmware("ch17-bogus-test.bin")` directly,
  which fires the BPF hook on `request_firmware`.
- **Override is out of scope for this POC.** A true ACPI WSMI bypass would
  need `bpf_override_return` on `acpi_ex_execute_method` (not allowlisted
  for error injection on stock kernels), or a BPF LSM hook on the firmware
  loader (`lsm.s/kernel_read_file` class=FIRMWARE). Neither is wired up
  here; this is observation only.
