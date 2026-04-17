# Ch09 -- PID Namespace Doppelganger

**Category**: OBSERVER
**Primitive**: raw_tracepoint + kprobe for PID namespace transition tracking
**Hook(s)**: `SEC("raw_tp/sched_process_fork")`, `SEC("kprobe/copy_namespaces")`
**Architecture**: aarch64 + x86_64

## What this demonstrates

Builds a side channel between PID namespaces: every `CLONE_NEWPID` transition is captured live, and at exit the loader prints the full host<->ns translation table. An attacker holding this table can target a container's "PID 1" via its host-side PID for kill, ptrace, or `/proc/<host_pid>/` access.

## What this does NOT do

Cannot mutate -- this is a pure observer. There is no override path because the goal is intelligence, not interference. Acting on the mapping (kill, ptrace, /proc lookup) happens from userspace using the printed host PID. The mapping table grows unbounded over long runs (BPF map sized at 8192 entries).

## Prerequisites

- `CONFIG_TRACEPOINTS=y` and sched tracepoint subsystem (on for every distro kernel)
- `copy_namespaces` in `/proc/kallsyms` (optional; sometimes inlined, loader handles absence)
- Docker: `--privileged --pid=host`

## Files

| File | Purpose |
|------|---------|
| `ch09-pid-doppel.bpf.c` | Kernel-side BPF program (raw_tp on sched_process_fork, kprobe on copy_namespaces) |
| `ch09-pid-doppel.c` | Userspace loader, ringbuf consumer, mapping table printer |
| `trigger.sh` | Activity generator (unshare CLONE_NEWPID) |
| `Makefile` | Build (uses shared/common.mk) |

## Build & Run

```bash
# Inside the harness container:
make
sudo ./build/ch09-pid-doppel
# In another terminal:
bash trigger.sh
# Press Ctrl-C to print the mapping table and exit
```

## Detection

- `bpftool prog show | grep -E 'sched_process_fork|copy_namespaces'` -- raw tracepoints / kprobes on these symbols are uncommon; treat unexpected attachments as a strong IOC.
- `bpftool map show` -- a HASH map keyed by host PID alongside the ringbuf is the doppelganger table being built.
- Kernel auditing: any process opening `/proc/<host_pid>/` for a `host_pid` that does not belong to its own pid_ns is a tampering signal.
