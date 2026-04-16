# ch17 ACPI / WSMI — ANALOG variant

**DISCLAIMER.** The real ACPI method evaluation path
(`acpi_evaluate_object` / `acpi_ns_evaluate` / `acpi_ex_execute_method`)
does not fire on this kernel — aarch64 linuxkit ships no ACPI
interpreter. The `request_firmware` fallback hook used by the primary
POC (`ch17-acpi-wsmi/`) only fires if a driver actually calls it, and
no such driver is loaded on the dev host. This analog is clearly marked
as a variant: it does NOT exercise ACPI or the firmware loader. It
reproduces the *primitive shape* of the attack ("kernel-mediated string
content substituted in flight") against a userspace "firmware requester"
binary (`fw_requester.c`) whose `openat()` path argument gets rewritten
via `bpf_probe_write_user` before the syscall body runs.

## Mechanism

- `tp/syscalls/sys_enter_openat` — when `comm == "fw_requester"` and the
  user-supplied path bytes match `ORIG_PATH`
  (`/tmp/CH17_REQ_real_firmware.bin`), overwrite the user buffer with
  `REPL_PATH` (`/tmp/CH17_REQ_attacker_replacement.bin`). The requester
  allocates a 256-byte buffer so the longer replacement fits.
- Ringbuf event carries `{pid, tgid, comm, swapped, matched, orig[96]}`
  captured from per-CPU scratch to keep the BPF stack under budget.

Both the original and replacement strings are compared with an unrolled
byte-diff loop to keep the verifier happy across kernels.

## Hook(s)

- `tracepoint/syscalls/sys_enter_openat`
- Writes back into userspace with `bpf_probe_write_user` (requires
  `CAP_SYS_ADMIN`; taints the kernel on first use).

## Host prereqs

- `CONFIG_BPF_EVENTS=y`, syscalls tracepoints enabled.
- `bpf_probe_write_user` available.
- `/tmp` writable (trigger seeds the original + replacement files).

## Build / Run

```
cd pocs/ch17-acpi-wsmi-analog && make
sudo bash trigger.sh
```

## Evidence

Per-event loader line:
```
[ch17-analog] pid=12345 comm=fw_requester swapped=1 orig="/tmp/CH17_REQ_real_firmware.bin"
```

Trigger verdict line:
```
=== CH17_ANALOG_PROVEN requested=CH17_REQ_real_firmware.bin served=REPLACED before_content=ORIGINAL swapped_events=1 disclaimer="same primitive as kernel request_firmware string swap; real request_firmware needs drivers that actually call it" ===
```

## Limitations

- Not an ACPI or WSMI exploit. No ACPI method is evaluated; no
  firmware loader path is touched. The target is a userspace binary
  named `fw_requester` opening files under `/tmp`.
- Comm-based match (`fw_requester`) is trivial to evade; the POC deliberately
  chooses a specific comm so the demo stays scoped to the harness.
- `bpf_probe_write_user` can fault on non-resident pages and fail the
  swap; the trigger retries to accommodate this.
- ACPI override proper is out of scope here and in the primary POC —
  see that README for the real-world blocker (error-injection allowlist).

## Blog post

See the chapter write-up: [`2025-05-07-acpi-wsmi-ping`](../../../_posts/2025-05-07-acpi-wsmi-ping.md) in the Diabolical eBPF Field Manual.
