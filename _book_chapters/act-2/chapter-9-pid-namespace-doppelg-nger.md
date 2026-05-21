---
layout: book
title: "Chapter 9: PID Namespace Doppelgänger"
date: 2025-02-09
---

# Chapter 9: Mapping Host PID to Namespace PID

> **See also**: [Blog post]({{ site.baseurl }}/pid-namespace-doppelg-nger.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch09-pid-doppel) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

> **Proof status**: Proved on Ubuntu 6.17.0-29-generic aarch64 (Lima VM). **Runtime note**: `trigger.sh` must be run directly in the Lima/host VM shell, not inside Docker with `--pid=host`. The `--pid=host` flag causes "unable to start container process: can't get final child's PID from pipe: EOF" when the trigger spawns `unshare --pid`. Run the trigger directly in the VM.

This one is almost embarrassingly straightforward once you know where to look. The primitive; recovering the host-visible PID of a task together with its namespace-local PID; has been shipping in bpftrace examples for years. Academic work on PID-namespace side channels via `sched_process_fork` goes back to at least 2020. The POC's contribution is narrow: package the observation as a CO-RE BPF program, confirm the mapping end-to-end by terminating a container process from the host using only the PID recovered from a BPF map, and document the hook choice.

## Mechanism

The key fact is that `struct task_struct` carries both views. `task->pid` and `task->tgid` are the host PIDs. The namespace-local PID lives off `task->thread_pid`, which is a `struct pid *`, and within it `numbers[level].nr` gives you the per-level PID. The namespace inode comes from `task->nsproxy->pid_ns_for_children->ns.inum`.

The `numbers[]` indexing is subtle. `struct pid` has a `numbers[1]` flexible array at tail that extends based on nesting depth. A task at level 1 (first container) has `numbers[0]` for the init ns and `numbers[1]` for the container ns. For a task at depth `level`, the innermost PID lives at `numbers[level]`, not `numbers[0]`. I got this wrong the first pass and was logging identical numbers for host and container PID. Ten minutes of rereading `kernel/pid.c` fixed it.

## Hook points

The POC attaches two programs and picks the one that fires:

- **`raw_tp/sched_process_fork`**; primary hook. Fires on every task creation, including the common `unshare --pid` / `clone(CLONE_NEWPID)` path. The raw tracepoint gives access to both parent and child `task_struct *` as typed args. I compare their `pid_ns_for_children->ns.inum` and only emit when the child entered a fresh namespace.
- **`kprobe/copy_namespaces`**; secondary hook, preflighted against `/proc/kallsyms` at load time. `copy_namespaces` can be inlined on some kernels. The loader disables autoload for this program when the symbol is absent, so the load stays clean.

A factual correction from the earlier draft: `switch_task_namespaces` fires only on the `setns()` path, which misses the common fork-into-new-ns case. `sched_process_fork` is the right hook for general coverage.

The per-event read chain in BPF:

```c
struct task_struct *child = (struct task_struct *)ctx[1];
e->host_pid  = BPF_CORE_READ(child, pid);
e->host_tgid = BPF_CORE_READ(child, tgid);

struct pid *pp = BPF_CORE_READ(child, thread_pid);
unsigned int level = BPF_CORE_READ(pp, level);
struct upid u = {};
bpf_probe_read_kernel(&u, sizeof(u),
    (void *)&pp->numbers[0] + level * sizeof(struct upid));
e->ns_pid  = u.nr;
e->ns_inum = BPF_CORE_READ(child, nsproxy, pid_ns_for_children, ns.inum);
```

Events land in a ringbuf for live streaming. A `BPF_MAP_TYPE_HASH` keyed by host PID retains the mapping so the loader can dump a summary table on SIGINT.

```c
SEC("raw_tp/sched_process_fork")
int BPF_PROG(rt_fork, struct task_struct *parent, struct task_struct *child)
{
    unsigned long pi = BPF_CORE_READ(parent, nsproxy, pid_ns_for_children, ns.inum);
    unsigned long ci = BPF_CORE_READ(child,  nsproxy, pid_ns_for_children, ns.inum);
    if (pi == ci) return 0;   // no namespace transition; ignore
    capture(child, 1);
    return 0;
}
```

## Active primitive: bpf_send_signal into the forked child

The POC also gates a `bpf_send_signal(SIGUSR1)` call via a one-entry `cfg` control map. When `cfg[0] == 1`, the BPF program delivers SIGUSR1 directly from inside the kernel at the moment a task crosses a PID-namespace boundary, in addition to emitting the observation event. The `struct evt` carries a `signal_sent` field the loader uses to distinguish "armed and delivered" from "observer only."

From the raw tracepoint on `sched_process_fork`, `current` is the *parent* task. `bpf_send_signal` targets current. From the `kprobe/copy_namespaces` hook, `current` is the task being copied into the new namespace, so the same helper call hits the child directly.

The loader arms the signal path by writing `1` into `cfg[0]` before attaching. The harness proof marker regex accepts `SIGUSR1_SENT` as an alternative to `CH09_PROVEN` and `PID_NS_ESCAPE_PROVEN`, covering the kernel-signal path, the userspace-kill path, and the observer-only path as three independent pieces of proof.

## Reproduction

The bundled `trigger.sh` drives a BEFORE/AFTER:

1. Spawn a victim inside a fresh user+pid namespace: `unshare -Upf --mount-proc bash -c 'echo "ns_side_pid=$$"; sleep 15'`. The victim reports its own ns-side PID (typically 1), but no unprivileged userspace API tells an outside observer which host PID backs that ns_pid.
2. Start the BPF loader and wait for `status=ready`.
3. Fire a second `unshare -Upf` so the tracepoint observes it post-attach.
4. Parse the loader's stdout for an event whose `host_pid != ns_pid`; that line is the mapping.
5. Confirm with `/proc/<host_pid>/status`; the `NSpid:` line shows both numbers and matches what BPF reported.
6. `kill -TERM <host_pid>` from the host. The victim dies; the container sees its own PID receive SIGTERM.

A representative exit summary from a run:

```
[ch09] src=fork  host_pid=481203  ns_pid=1  level=1  ns_inum=4026532567  comm=bash
[ch09] === post-run mapping table ===
[ch09] host_pid   host_tgid  ns_pid     level  ns_inum      comm
[ch09] 481203     481203     1          1      4026532567   bash
[ch09] === 1 entries ===
=== CH09_PROVEN host_pid=481203 mapped=yes kill_from_outside=ok ===
```

This is not novel; `ps -ef` on the host already shows the same thing, as does `/proc/<pid>/status`. The useful property is that the BPF map lookup is O(1) and requires no `/proc` walking, which matters at scale or inside another BPF program.

## Detection

The attach is visible. `bpftool prog show` lists the raw tracepoint and kprobe programs. The map dump (`bpftool map dump name mapping`) reveals both host and ns PIDs of every observed namespace entry in cleartext; the loudest tell, because the attacker has to keep the map populated for the primitive to be useful. The `cfg` array is also worth checking: `cfg[0] == 1` means the program is armed to deliver SIGUSR1 on every matching fork, not just observe.

The read itself produces no syscall-level signal. If you want to catch a host process using BPF-derived namespace PIDs to send cross-namespace signals, the right place is the `kill` audit trail.

Prior art worth citing: bpftrace ships `pidnss.bt` and similar scripts that do essentially this lookup, and Cilium/Tetragon uses the same pattern for PID tracking in its observation code.

> **See also**: [POC source; ch09-pid-doppel](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch09-pid-doppel) · Harness entry: `Poc("ch09", ...)` in `dBPF-pocs/harness/proof.py`
