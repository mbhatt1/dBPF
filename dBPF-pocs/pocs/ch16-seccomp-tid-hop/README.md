# Ch16 -- Seccomp TID Hop

**Category**: REAL
**Primitive**: kprobe + kretprobe on seccomp evaluation entry point
**Hook(s)**: `SEC("kprobe/__secure_computing")`, `SEC("kretprobe/__secure_computing")`
**Architecture**: aarch64 + x86_64

## What this demonstrates

Observes and streams every seccomp evaluation with `{ts, pid, tid, tgid, comm, seccomp.mode, retval}` through a ring buffer. The kprobe fires before every seccomp check; the kretprobe captures the return value. Defenders can see exactly which evaluations allowed vs denied, and fingerprint which daemons run with seccomp on a host.

## What this does NOT do

Cannot bypass seccomp on this kernel. `__secure_computing` is NOT in `/sys/kernel/debug/error_injection/list` on 6.12.54-linuxkit, so `bpf_override_return` would refuse to attach. `task->seccomp.mode`/`task->seccomp.filter` cannot be mutated via BPF helpers -- the verifier rejects writes to `task_struct`. On an injection-enabled kernel, the kretprobe body could be swapped for `bpf_override_return(ctx, 0)`.

## Prerequisites

- `__secure_computing` present in `/proc/kallsyms`
- `CONFIG_KPROBES=y`
- Docker: `--privileged --pid=host`

## Files

| File | Purpose |
|------|---------|
| `ch16-seccomp-tid-hop.bpf.c` | Kernel-side BPF program (kprobe/kretprobe on __secure_computing) |
| `ch16-seccomp-tid-hop.c` | Userspace loader with wildcard/targeted modes |
| `trigger.sh` | Activity generator |
| `Makefile` | Build (uses shared/common.mk) |

## Build & Run

```bash
# Inside the harness container:
make
sudo ./build/ch16-seccomp-tid-hop --all
# In another terminal:
bash trigger.sh
```

## Detection

- `bpftool prog show | grep __secure_computing` lists kprobes on this symbol. Only security tooling should hook it.
- `cat /sys/kernel/tracing/kprobe_events` shows dynamic probes.
- Unexplained kprobe/kretprobe pairs attached to seccomp internals in production are a strong red flag.
- Any program calling `bpf_override_return` against a seccomp symbol is almost certainly malicious; `bpftool prog dump xlated` surfaces the helper call opcode.
