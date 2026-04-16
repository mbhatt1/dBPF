---
layout: book
title: "ACPI WSMI Ping"
date: 2025-05-07
---

**Chapter 17: Where the ACPI Interpreter Isn't**

> **Note**: This primitive's natural hook did not fire on the test kernel. See [Chapter 21]({{ site.baseurl }}/book/act-3/chapter-21-the-autopsy-what-refused-to-die.html) for the skip reasoning and [the surviving workaround variant in dBPF-pocs](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs) (e.g. `ch17-acpi-wsmi-analog/`).

The chapter as originally drafted hooks `acpi_evaluate_object`, watches for a specific ACPI pathname (`\_SB._WS0.Ping`), and swaps in custom AML parameters. That scenario is architecturally x86. I was working on aarch64 and the first thing I did was check whether the symbols exist:

```
$ grep acpi_evaluate_object /proc/kallsyms
$ grep acpi_ns_evaluate /proc/kallsyms
$ grep acpi_ex_execute_method /proc/kallsyms
```

All three returned nothing. Docker Desktop's linuxkit kernel (6.12 aarch64) ships without the ACPI interpreter. There is no `acpi_*` symbol to kprobe. The chapter's primary scenario cannot fire on this platform.

The pragmatic pivot was to pick a different kernel path with the same shape — kernel code reaching out to firmware-land on behalf of a userspace request — and demonstrate the primitive against that. The analog is `request_firmware`, `_request_firmware`, and `firmware_request_nowarn`, all present:

```
[acpi] === symbol availability ===
  acpi_evaluate_object       : ABSENT
  acpi_ns_evaluate           : ABSENT
  acpi_ex_execute_method     : ABSENT
  request_firmware           : present
  _request_firmware          : present
  firmware_request_nowarn    : present
[acpi] attached=firmware_fallback
[acpi] ACPI_PROBE_PROVEN arch=aarch64 substituted=firmware_loader
[acpi] tag=call pid=12034 comm=insmod hook=request_firmware arg=bogus-ch17-1728961234.bin
```

The observer streams `{pid, comm, hook, arg_string}` for every firmware request. `arg_string` captures the filename the caller asked for (truncated to 64 bytes; a per-CPU scratch keeps the BPF stack under budget). On x86 with ACPI present the same observer attaches the `acpi_*` trio instead and captures the ACPI pathname on the entry hook, producing records like `hook=acpi_evaluate_object arg=\_SB.PCI0._STA`. The loader's first ringbuf event carries a proof marker — `ACPI_PROBE_PROVEN arch=x86_64 substituted=none` or `ACPI_PROBE_PROVEN arch=aarch64 substituted=firmware_loader` — so a reviewer can tell at a glance which path was attached and whether any substitution happened.

This is scoped as observation. I did not attempt `bpf_override_return` on any of these symbols for this POC. On x86 a real WSMI-style bypass would require `bpf_override_return` against `acpi_ex_execute_method` (not on the error-injection list on stock kernels) or a BPF LSM program on `kernel_read_file` with `class=FIRMWARE`. Neither is wired up here. Calling the firmware-loader variant an "ACPI WSMI bypass" would be dishonest; it is a userspace-analog demonstration of the primitive shape — watch a string flow from user to kernel as it is loaded, which is the same shape as intercepting AML pathnames — running in the place where the real thing would run on a platform that has it.

If `/proc/kallsyms` contains none of the six candidates, the loader prints `CH17_SKIP reason="no acpi nor firmware symbols"` and exits 2 rather than pretending to succeed.

## Hook points

### x86 (primary)
- `kprobe/acpi_evaluate_object`
- `kprobe/acpi_ns_evaluate`
- `kprobe/acpi_ex_execute_method`

### aarch64 (fallback)
- `kprobe/request_firmware`
- `kprobe/_request_firmware`
- `kprobe/firmware_request_nowarn`

```c
SEC("kprobe/acpi_evaluate_object")
int hijack_acpi(struct pt_regs *ctx) {
    const char target[] = "\\_SB._WS0.Ping";
    char path[MAX_ACPI_PATH_LEN];
    bpf_probe_read_str(path, sizeof(path), (void *)PT_REGS_PARM1(ctx));
    if (strncmp(path, target, sizeof(target)-1) == 0) {
        struct acpi_param param = {};
        param.type = ACPI_TYPE_INTEGER;
        param.data[0] = 0xdeadbeef;
        param.data_len = sizeof(u64);
        bpf_map_update_elem(&replacement_params, target, &param, BPF_ANY);
    }
    return 0;
}
char LICENSE[] SEC("license") = "GPL";
```

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

## Detection

- `bpftool prog show | grep -E 'acpi|firmware'`
- `cat /sys/kernel/debug/tracing/kprobe_events` shows attached probes.
- `events` ringbuf visible in `bpftool map show`.
- On production x86 hosts, any kprobe on `acpi_ex_execute_method` is worth investigating. Legitimate telemetry rarely hooks it.

## Limitations / arch notes

- No ACPI, no firmware → honest skip. If `/proc/kallsyms` contains none of the six candidates, the loader prints `CH17_SKIP` and exits 2.
- aarch64 linuxkit has no ACPI interpreter. The POC substitutes the firmware-request path, which is a best-effort moral equivalent. The substituted-path marker records this honestly in the first ringbuf event.
- Override is out of scope for this POC. A real ACPI WSMI bypass would need `bpf_override_return` on `acpi_ex_execute_method` (not error-injectable on stock kernels) or a BPF LSM hook on `kernel_read_file` with `class=FIRMWARE`. Neither is wired up here.
