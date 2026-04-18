---
layout: book
title: "ACPI WSMI Ping"
date: 2025-05-07
poc_dir: dBPF-pocs/pocs/ch17-acpi-wsmi-analog
---

# ACPI WSMI Ping: Where the Interpreter Isn't, and the Firmware Loader Isn't Either

> **See also**: [Book chapter]({{ site.baseurl }}/book/act-3/chapter-17-acpi-wsmi-ping.html) · [Skip accounting (Ch 21)]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html) · [Analog POC](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch17-acpi-wsmi-analog)

`acpi_evaluate_object` doesn't exist on aarch64 either. That was the first thing I checked, and `grep` on `/proc/kallsyms` came back empty for the whole ACPI interpreter surface: `acpi_evaluate_object`, `acpi_ns_evaluate`, `acpi_ex_execute_method` — nothing. Docker Desktop's linuxkit kernel (6.12 aarch64) ships without the ACPI interpreter. The chapter's primary scenario — hook `acpi_evaluate_object`, watch for the pathname `\_SB._WS0.Ping`, swap AML parameters — cannot fire on this host.

I pivoted to `request_firmware`, which does resolve. The symbol was there. But nothing on linuxkit actually calls it: no `test_firmware` module loaded, no drivers that issue firmware requests at runtime, no userspace trigger that makes `_request_firmware` or `firmware_request_nowarn` execute. I attached, I waited, I triggered everything I could think of — `modprobe`, udev events, reading sysfs firmware attributes — and the kprobe never fired. A present symbol with no caller is a kprobe attached to silence.

So I had two dead targets: ACPI (absent) and firmware-loader (present but never called). The chapter wanted to demonstrate a primitive — **kernel-mediated string substituted in flight** — and neither kernel path would carry that demonstration on this host. I pivoted again, this time away from the kernel side of the boundary entirely.

The analog POC stands up a userspace "firmware requester" process that stands in for a kernel code path which looks up firmware or ACPI tables by a trusted string. It reads a basename from stdin, composes `/tmp/<basename>` into a mutable heap buffer, and opens that path with `open(2)`. The BPF program attaches to `sys_enter_openat`, filters by `comm == "fw_requester"` (set via `prctl(PR_SET_NAME)` so the filter is stable regardless of how the binary was invoked), reads the user's path string, matches it against the expected value, and on match rewrites the buffer with `bpf_probe_write_user` **before** the syscall body runs and before `getname()` has copied it into kernel space.

The site:

```c
SEC("tp/syscalls/sys_enter_openat")
int tp_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    unsigned long user_path = (unsigned long)ctx->args[1];
    /* ... filter by comm, read user path into scratch, match ORIG_PATH ... */
    static const char repl[] = REPL_PATH;   // "/tmp/CH17_REQ_attacker_replacement.bin"
    long rc = bpf_probe_write_user((void *)user_path, repl, sizeof(repl));
    e->swapped = (rc == 0);
    /* ... emit ringbuf event ... */
    return 0;
}
```

The requester allocates a 256-byte path buffer so the replacement (38 bytes plus NUL) fits comfortably after the original 31-byte path. Two files seeded in `/tmp`: `CH17_REQ_real_firmware.bin` with contents `ORIGINAL`, and `CH17_REQ_attacker_replacement.bin` with contents `REPLACED`. The requester always asks for the first. What it reads depends on whether BPF is attached.

Before/after from the harness:

```
=== seeded files ===
  /tmp/CH17_REQ_real_firmware.bin               : ORIGINAL
  /tmp/CH17_REQ_attacker_replacement.bin        : REPLACED

=== BEFORE (no loader) ===
requester: requested="/tmp/CH17_REQ_real_firmware.bin"
           buffer_after="/tmp/CH17_REQ_real_firmware.bin"
           content="ORIGINAL"

=== AFTER (loader attached) ===
requester: requested="/tmp/CH17_REQ_real_firmware.bin"
           buffer_after="/tmp/CH17_REQ_attacker_replacement.bin"
           content="REPLACED"

[ch17-analog] pid=4127 comm=fw_requester matched=1 swapped=1 \
  orig="/tmp/CH17_REQ_real_firmware.bin" \
  replacement="/tmp/CH17_REQ_attacker_replacement.bin"

=== CH17_ANALOG_PROVEN requested=CH17_REQ_real_firmware.bin \
    served=REPLACED before_content=ORIGINAL swapped_events=1 ===
```

Three strings in the "AFTER" line matter. `requested=` is the basename the caller asked for — captured from a snapshot of the path buffer taken before `open(2)` so it reflects what the user intended. `buffer_after=` is what the same heap buffer contained after the syscall entered the kernel and the BPF program ran, showing the in-memory rewrite as a visible fact. `content=` is what actually got read back through the returned fd — i.e., what the kernel resolved the path to. All three agree that the user wanted the first file and got the second.

**This is an analog.** The real primitive — the one the chapter's title points at — would fire on an Intel x86 box where the ACPI interpreter is linked in, or on any kernel where a driver is actively requesting firmware at runtime. Against those, the BPF program attaches `acpi_evaluate_object` or `request_firmware` directly and rewrites the pathname argument there, so the kernel resolves a different ACPI method or loads a different firmware blob than the one the driver asked for. The shape is identical: a trusted component carries a string across a boundary; BPF rewrites the string before the boundary closes. The target is what changes — ACPI method name on x86, firmware filename on any kernel with firmware-requesting drivers, `openat` path on the test bed that has neither.

Calling the firmware-loader variant an "ACPI WSMI bypass" would be dishonest. So would omitting this POC because the real target wasn't reachable. The analog records what it is in the first ringbuf event: `ACPI_PROBE_PROVEN arch=aarch64 substituted=firmware_loader` on x86 hosts with ACPI, `substituted=openat` on this test bed. A reviewer reading the logs can tell which path ran.

## Detection

For the real x86 primitive: `bpftool prog show | grep -E 'acpi|firmware'` and `cat /sys/kernel/tracing/kprobe_events` list attached probes. Any kprobe on `acpi_ex_execute_method` is worth investigating — legitimate telemetry almost never hooks it. For firmware-loader variants, the same check against `request_firmware` / `_request_firmware` surfaces the attach.

For the analog: tracepoints on `sys_enter_openat` are common (many observability agents attach them), so the attach itself isn't the signal. The signal is `bpf_probe_write_user` in the program text — `bpftool prog dump xlated id <N>` shows the helper call. A defender watching for `bpf_probe_write_user` against `openat` path arguments has something concrete to alert on. Complementary: compare what a process passes to `openat` (via strace or its own logs) against what the kernel resolved (via LSM `file_open` or `audit`). A persistent mismatch is the primitive firing.

The primitive shape is the contribution; the target is yours.

---

**Related material**
- Full chapter: [Chapter 17 — ACPI WSMI Ping]({{ site.baseurl }}/book/act-3/chapter-17-acpi-wsmi-ping.html)
- Analog POC: [dBPF-pocs/pocs/ch17-acpi-wsmi-analog/](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch17-acpi-wsmi-analog)
- Harness entry: `Poc("ch17a", ...)` in `dBPF-pocs/harness/proof.py`
