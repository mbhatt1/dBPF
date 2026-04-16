---
layout: book
title: "PID Namespace Doppelgänger"
date: 2025-02-09
---

Act II: Kernel Intrusion

**Chapter 10: Mapping Host PID to Namespace PID**

> **See also**: [Blog post]({{ site.baseurl }}/2025/02/09/pid-namespace-doppelg-nger.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch09-pid-doppel) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

This one is almost embarrassingly straightforward once you know where to look. The primitive — recovering the host-visible PID of a task along with its namespace-local PID — has been shipping in bpftrace examples for years. Academic work on PID-namespace side channels via `sched_process_fork` goes back to at least 2020 (there's a USENIX Security paper I reread while writing this). My contribution, if it counts as one, is bundling the observation with an end-to-end confirmation: kill a process across the namespace boundary using only the PID my BPF program recovered.

The key fact is that `struct task_struct` contains both views. `task->pid` and `task->tgid` are the host PIDs. The namespace-local PID lives off `task->thread_pid`, which is a `struct pid *`, and within it `numbers[level].nr` gives you the per-level PID. The namespace inode comes from `task->nsproxy->pid_ns_for_children->ns.inum`, or for the active PID namespace, `task->thread_pid->numbers[level].ns->ns.inum`.

I started with a raw tracepoint on `sched_process_fork`:

```
SEC("raw_tp/sched_process_fork")
```

`raw_tp` gets you the task pointer as `(struct task_struct *)ctx[1]` (the child). Using `tp_btf` instead gets you typed access, but I hit a BTF resolution issue on my first attempt where the child argument came through as an opaque `u64` — turned out to be a clang version mismatch with vmlinux.h, not a kernel issue. Rebuilding with clang 16 against a freshly-dumped vmlinux.h fixed it.

The read chain:

```c
struct task_struct *child = (struct task_struct *)ctx[1];
pid_t host_pid = BPF_CORE_READ(child, pid);
unsigned int pidns_inum = BPF_CORE_READ(child, nsproxy, pid_ns_for_children, ns.inum);
unsigned int level = BPF_CORE_READ(child, nsproxy, pid_ns_for_children, level);
pid_t ns_pid = BPF_CORE_READ(child, thread_pid, numbers[0].nr); // depends on level
```

The `numbers[0]` indexing is subtle. `struct pid` has a `numbers[1]` flexible array at tail that extends based on the nesting depth. A task at level 1 (first container) has `numbers[0]` for the init ns and `numbers[1]` for the container ns. For a direct child of a container's init, you want `numbers[level]`, not `numbers[0]`. I got this wrong the first pass and was logging the same number for host and container PID, which led to ten minutes of confusion before I reread `kernel/pid.c`.

What I confirmed end-to-end. I ran a Docker container (`docker run --rm -it busybox sleep 3600`), let the BPF program populate the map, then from the host read back the (host_pid, ns_pid) pair. The container reported the sleep as PID 7 inside its namespace. The host saw it as PID 481203. `kill -TERM 481203` from the host terminated it; the container saw its PID 7 die with SIGTERM. This is not novel — it's exactly what `ps -ef` on the host already shows — but doing it from BPF map state means you can do it without `/proc` walking or any userspace introspection, and the map lookup is O(1).

```c
SEC("kprobe/switch_task_namespaces")
int probe_ns_switch(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)PT_REGS_PARM1(ctx);
    u32 host_pid = task->pid;
    u32 child_ns = task->nsproxy->pid_ns_for_children->level;
    bpf_map_update_elem(&ns_mappings, &host_pid, &child_ns, BPF_ANY);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

Two factual corrections from the earlier draft. First: `switch_task_namespaces` fires on `setns()`, which is only one path to namespace entry — it misses the common case of fork-into-new-ns via `clone(CLONE_NEWPID)`. For the general case, `sched_process_fork` as a raw tracepoint is the right hook. I kept the kprobe snippet above because it's still valid for the setns path, but the raw_tp version is what I actually used for the confirmation. Second: the snippet dereferences `task->pid` and `task->nsproxy` directly. That works on current kernels with relaxed verifier rules, but the portable form is `BPF_CORE_READ(task, pid)` and friends, which is what I'd recommend.

Detection. The attach is visible (tracepoint registration shows in audit and in `/sys/kernel/debug/tracing/events/...`). The read produces no signal. If you want to catch a host process using BPF-derived namespace PIDs to send cross-namespace signals, the right place is the `kill` audit trail — a host uid sending SIGTERM to a container's init process is already flagged by most container runtime monitors regardless of where the PID came from.

Prior art I should have cited in the first pass: bpftrace ships `pidnss.bt` and similar scripts that do the same lookup. The Cilium project's `cilium-agent` uses essentially this pattern for PID tracking in its tetragon-adjacent code. I'm not inventing anything here; I'm documenting a concrete end-to-end recipe.