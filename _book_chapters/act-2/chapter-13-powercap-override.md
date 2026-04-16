---
layout: book
title: "Chapter 13: Powercap Override"
date: 2025-03-10
---

**Chapter 13: An x86-Only Primitive, Tested on aarch64**

> **Note**: This primitive's natural hook did not fire on the test kernel. See [Chapter 21 — Skip Accounting]({{ site.baseurl }}/book/act-3/chapter-21-the-autopsy-what-refused-to-die.html) and the surviving workaround variant at [dBPF-pocs/pocs/ch13-powercap-override-analog/](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs).

I want to be honest about this one before describing anything. Intel RAPL and the powercap framework are x86-only. On the aarch64 linuxkit kernel I'm using as my test bed, `CONFIG_POWERCAP` is off and none of the RAPL symbols exist. My loader preflighted four targets — `powercap_register_control_type`, `powercap_set_max_power_uw`, `powercap_get_max_power_uw`, `thermal_zone_device_update` — and every single one came back absent. The primary POC cannot fire on this host. I don't get to pretend otherwise.

So this chapter documents two things: what the primitive shape of a powercap override would look like on an x86 Intel host where the symbols exist, and an analog I actually ran on aarch64 to demonstrate the same userspace-illusion mechanic against a synthetic sensor.

The primitive shape, on an x86 host. The powercap framework is the generic kernel interface behind RAPL (CPU/package/DRAM TDP caps), Intel PowerClamp, and thermal-zone update notifications. The hooks of interest:

| Hook | Purpose | On aarch64 linuxkit |
| --- | --- | --- |
| `kprobe/powercap_register_control_type` | fires once per driver init (rapl, intel_pmc) | ABSENT |
| `kprobe/powercap_set_max_power_uw` | any write to `max_power_uw` | ABSENT |
| `kprobe/powercap_get_max_power_uw` | any read from `max_power_uw` | ABSENT |
| `kprobe/thermal_zone_device_update` | thermal engine notifications | ABSENT |

On an Intel host where these resolve, the observer half of the POC attaches cleanly and streams ringbuf events tagged with PID, comm, and the raw first two arguments to each call. That gives a defender precise visibility into who is touching the power envelope and when.

The override half — forging a `set_max_power_uw` call from BPF, or flipping the return of `get_max_power_uw` so monitors read the wrong value — requires `bpf_override_return`, which in turn requires the target to be in the error-injection allowlist. On the x86 host I'd need to check against, none of the powercap symbols are in that allowlist by default. The exploit path that does work end-to-end on x86 is to attach a BPF LSM to `security_file_permission` for `/sys/class/powercap/intel-rapl:0/constraint_0_power_limit_uw`, return a forged value to defender processes, and have a privileged helper write the real high limit. That's the shape. I didn't build it, because I don't have an x86 host in this series. Flagging it as untested-by-me is better than claiming it fires.

What I did build: a userspace analog that reproduces the *motion* of the attack — intercept a read, rewrite the returned bytes before the syscall returns to userspace — against a surface that exists on aarch64. I wrote a trivial "sensor daemon" that writes an incrementing energy counter to a plain file at `ch13_sensor_energy_uj`. A reader process `cat`s the file. The BPF program attaches to `sys_enter_read` and `sys_exit_read`, matches the open file's basename via the standard ch05 CO-RE walk (current → files → fdt → fd[n] → f_path.dentry → d_name.name), and on exit rewrites the user buffer with "0\n" followed by zero bytes.

```c
SEC("tp/syscalls/sys_enter_read")
int tp_read_enter(struct trace_event_raw_sys_enter *ctx) {
    // stash user buf + is_sensor flag keyed by pid_tgid
    return 0;
}

SEC("tp/syscalls/sys_exit_read")
int tp_read_exit(struct trace_event_raw_sys_exit *ctx) {
    // if is_sensor and ret > 0: bpf_probe_write_user(buf, "0\n", 2)
    //                          zero a few trailing bytes
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

This is not a RAPL exploit. It's a demonstration that the same primitive — tracepoint-plus-`bpf_probe_write_user` on the syscall exit path, already used in ch10 for dirent hiding — can be aimed at any file-backed sensor a defender trusts. A real energy counter read from `/sys/class/powercap/intel-rapl:0/energy_uj` goes through the same `sys_enter_read` / `sys_exit_read` path as my synthetic file. The illusion mechanic ports; only the filename matching and the fake payload change.

What you actually see when you run it:

```
# baseline (no BPF)
$ cat ch13_sensor_energy_uj
12345678

# with BPF attached
$ cat ch13_sensor_energy_uj
0

[ch13a] pid=1234 comm=cat orig_bytes=9 patched=1
```

The defender's monitoring tool, if it reads the counter via `read(2)`, sees the rewritten value. A second reader that bypasses the syscall — for instance, one that mmaps the file, or that reads the sysfs attribute through a different interface path — sees the true value. On a real RAPL attack, the analog would be: userspace monitoring tools that `cat` the sysfs file see a zeroed or flat energy counter, while hardware performance counters read from MSRs directly still show the truth.

The honest posture. The primary POC (direct kprobes on the powercap framework) cannot fire on aarch64 linuxkit because the subsystem doesn't exist. The analog demonstrates the primitive shape using a userspace sensor. Neither claims to be a working RAPL override on this host, and I haven't tested the LSM-over-sysfs path on an Intel host.

Detection. For the x86 primitive: `bpftool prog show type kprobe | grep -iE 'powercap|rapl|thermal_zone'` lists attached probes. Cross-check sysfs reads against direct MSR reads (`rdmsr 0x611` for package energy on Intel) — any persistent discrepancy is the attack. For the analog: comparing a `read(2)`-based reader against one that uses `mmap` or an alternate accessor exposes the rewrite. `bpftool map dump` on the inflight map shows which PIDs are currently being targeted.

Factual note: the chapter draft I started from described "attaching an eBPF program to `rapl_write_power_limit()`" and "forcing the limit to its maximum" so that "temperatures spiked and hardware warnings fired." That language implied the attack had run. It had not. On my test kernel the function doesn't exist. What ran was the analog described above.
