---
layout: book
title: "Powercap Override"
date: 2025-03-10
poc_dir: dBPF-pocs/pocs/ch13-powercap-override-analog
---

# Powercap Override: An x86-Only Primitive, Tested on a Synthetic Sensor

> **See also**: [Book chapter]({{ site.baseurl }}/book/act-2/chapter-13-powercap-override.html) · [Skip accounting (Ch 21)]({{ site.baseurl }}/book/act-3/chapter-21-the-autopsy-what-refused-to-die.html) · [Analog POC](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch13-powercap-override-analog)

`grep powercap /proc/kallsyms` returned nothing. RAPL is an x86 subsystem; aarch64 linuxkit doesn't have it. The primitive I wanted — a kretprobe on `powercap_get_max_power_uw` returning a fixed low value so defender processes would read a flat energy counter while the real hardware silently cooked — had no landing site. The same was true for `powercap_register_control_type`, `powercap_set_max_power_uw`, and `thermal_zone_device_update`. Four hooks, four ABSENTs in the loader's preflight. This POC could not fire on this kernel.

I spent an hour trying to be clever about that. Could I fake the symbol? Could I stand up a kernel module that exposed a `powercap_*` named function so the kprobe would at least resolve? Both paths were dishonest. What I wanted wasn't a kprobe that attached — it was a demonstration that a BPF program can quietly rewrite what a power-monitoring defender sees while the hardware keeps draining its envelope. The attach is the means; the rewrite is the contribution.

So I pivoted to an analog. The subsystem that doesn't exist on aarch64 is RAPL. The syscall path that **does** exist is `read(2)`, and the primitive shape — intercept a read, rewrite the returned bytes before they cross the user/kernel boundary — ports directly. I wrote a tiny userspace daemon that behaves the way `/sys/class/powercap/intel-rapl:0/energy_uj` behaves on x86: every 100 ms it writes a monotonically increasing energy counter to a plain file (`/tmp/ch13_sensor_energy_uj`), replaced atomically with `rename(2)` so readers never see a torn value. A separate reader process opens the file and `read()`s it into a heap buffer. The BPF program attaches to `sys_enter_read` / `sys_exit_read`, walks `current->files->fdt->fd[n]->f_path.dentry->d_name.name` with CO-RE to identify the file by basename, and on the exit path calls `bpf_probe_write_user` against the reader's buffer.

The site that matters is short:

```c
if (ret > 0 && r->is_sensor) {
    static const char fake[] = "0\n";
    long n = sizeof(fake) - 1;
    if (n > ret) n = ret;
    bpf_probe_write_user((void *)r->buf, fake, n);
    // NUL out a few trailing bytes so a naive reader that keeps scanning
    // doesn't see leftover digits from the real read.
    if (ret > n) {
        static const char zeros[16] = {};
        long tail = ret - n;
        if (tail > (long)sizeof(zeros)) tail = sizeof(zeros);
        bpf_probe_write_user((void *)(r->buf + n), zeros, tail);
    }
    patched = 1;
}
```

The sensor publishes 100, 200, 300, 400 — the counter that on a real Intel box would be the package energy in microjoules, climbing as the CPU does work. With no loader attached, the reader sees exactly that climb. With the loader attached, every `read()` of `ch13_sensor_energy_uj` returns `"0\n"` regardless of what the daemon wrote. The before/after from the harness:

```
=== BEFORE (no loader) ===
[before] iter=0 value=100
[before] iter=1 value=1100
[before] iter=2 value=2100

=== AFTER (loader attached) ===
[after] iter=0 value=0
[after] iter=1 value=0
[after] iter=2 value=0

[ch13-analog] pid=2891 comm=sensor_reader sensor_read_bytes=5 patched=1
[ch13-analog] pid=2891 comm=sensor_reader sensor_read_bytes=5 patched=1
[ch13-analog] pid=2891 comm=sensor_reader sensor_read_bytes=5 patched=1

=== CH13_ANALOG_PROVEN before_climb=100->2100 after=0 zero_reads=3 patched_events=3 ===
```

The climb stopped. The hardware didn't stop climbing; the illusion did.

I want to be explicit about what this proves and what it doesn't. **This is an analog.** The real primitive — the one that matters on a production fleet — would fire on an Intel box with RAPL active, attaching a BPF LSM hook to `security_file_permission` against `/sys/class/powercap/intel-rapl:0/constraint_0_power_limit_uw` and returning a forged value to defender processes while a privileged helper writes the real high limit. I didn't build that. I don't have an x86 host in this test lab. What I built is the motion: tracepoint-plus-`bpf_probe_write_user` on the syscall exit path, already used in ch10 for dirent hiding, aimed at any file-backed sensor a defender trusts. The filename-matching changes. The payload changes. The mechanism doesn't.

A second reader that bypasses `read(2)` — one that `mmap`s the file, or that reads the real sysfs attribute via a different accessor — sees the true value. In the RAPL analog that matters: a defender reading `energy_uj` via `cat` sees a flat counter, but an MSR-direct read (`rdmsr 0x611` on Intel) shows the truth. The illusion is load-bearing but not deep.

## Detection

For the x86 primitive: `bpftool prog show type kprobe | grep -iE 'powercap|rapl|thermal_zone'` lists attached probes. Any telemetry that hooks the powercap framework is worth investigating; legitimate agents rarely do. Cross-check `read(2)`-derived values from sysfs against MSR reads — any persistent discrepancy is the attack.

For the analog: `bpftool map dump` on the `inflight` hash shows which PIDs are currently being targeted. Comparing a `read(2)`-based reader against an `mmap`-based one exposes the rewrite immediately. `cat /sys/kernel/tracing/kprobe_events` and `bpftool prog show type tracepoint` surface the attached tracepoints on `sys_enter_read` / `sys_exit_read`, which are themselves an unusual attach point for production telemetry.

The primitive shape is the contribution; the target is yours.

---

**Related material**
- Full chapter: [Chapter 13 — Powercap Override]({{ site.baseurl }}/book/act-2/chapter-13-powercap-override.html)
- Analog POC: [dBPF-pocs/pocs/ch13-powercap-override-analog/](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch13-powercap-override-analog)
- Harness entry: `Poc("ch13a", ...)` in `dBPF-pocs/harness/proof.py`
