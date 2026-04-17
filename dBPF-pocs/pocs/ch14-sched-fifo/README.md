# Ch14 -- SCHED_FIFO Impersonator

**Category**: ILLUSION
**Primitive**: kprobe + kretprobe + bpf_override_return on sched_setscheduler syscall
**Hook(s)**: `SEC("kprobe/__arm64_sys_sched_setscheduler")`, `SEC("kretprobe/__arm64_sys_sched_setscheduler")`
**Architecture**: aarch64 only

## What this demonstrates

Overrides the return value of `__arm64_sys_sched_setscheduler` via `bpf_override_return(ctx, 0)`. This syscall entrypoint IS in the error-injection allowlist on linuxkit 6.12. When an unprivileged process calls `sched_setscheduler(SCHED_FIFO, ...)`, the kernel returns `-EPERM` but BPF rewrites it to `0`. Userspace tooling (chrt, systemd) then acts as if SCHED_FIFO was granted.

## What this does NOT do

Kernel state unchanged -- only the syscall return value to userspace is forged. The kernel `task_struct->policy` is NOT modified; this is a userspace-illusion attack. A subsequent `sched_getscheduler()` would still report the real (unchanged) policy. The kprobe target is arch-specific (`__arm64_sys_*`); the BPF object as shipped is aarch64 only.

## Prerequisites

- `__arm64_sys_sched_setscheduler` in `/proc/kallsyms` and `/sys/kernel/debug/error_injection/list`
- `CONFIG_BPF_KPROBE_OVERRIDE=y`
- `CAP_SYS_ADMIN`
- Docker: `--privileged --pid=host`

## Files

| File | Purpose |
|------|---------|
| `ch14-sched-fifo.bpf.c` | Kernel-side BPF program (kprobe/kretprobe + bpf_override_return) |
| `ch14-sched-fifo.c` | Userspace loader with wildcard/targeted modes |
| `trigger.sh` | Activity generator (chrt -f as unprivileged user) |
| `run-demo.sh` | Alternative demo script |
| `Makefile` | Build (uses shared/common.mk) |

## Build & Run

```bash
# Inside the harness container:
make
sudo ./build/ch14-sched-fifo --all
# In another terminal:
bash trigger.sh
```

## Detection

- `bpftool prog show type kprobe` lists `kp_sched`/`kr_sched` attached to `__arm64_sys_sched_setscheduler` -- neither tracing nor observability tooling normally hooks that symbol.
- Audit `/sys/kernel/tracing/kprobe_events` for unexpected entries on syscall entrypoints.
- Hosts with `kernel.unprivileged_bpf_disabled=1` and a strict LSM/lockdown profile cannot load `bpf_override_return`-using programs.
