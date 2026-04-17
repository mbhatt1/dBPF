# Ch05 -- Slipping the Cgroup Leash

**Category**: REAL
**Primitive**: tracepoint + bpf_probe_write_user
**Hook(s)**: `SEC("tp/syscalls/sys_enter_read")`, `SEC("tp/syscalls/sys_exit_read")`
**Architecture**: aarch64 + x86_64

## What this demonstrates

Slips the cgroup CPU controller by rewriting `cpu.stat` read results in flight. On `sys_enter_read`, BPF walks `current->files->fdt->fd[fd]->f_path.dentry->d_name.name` to identify reads of files named `cpu.stat`. On `sys_exit_read`, BPF calls `bpf_probe_write_user()` to overwrite the user's buffer with `usage_usec 0\nuser_usec 0\nsystem_usec 0\n`. Workload monitors see zero usage while kernel accounting is untouched.

## What this does NOT do

Does not modify actual kernel cgroup accounting. Scheduler throttling based on real runtime still happens -- the "escape" is perception, not physics. Filename match is exact basename `cpu.stat` with no path validation; a user file literally named `cpu.stat` would also be rewritten.

## Prerequisites

- `CONFIG_FTRACE_SYSCALLS=y` (syscall tracepoints enabled)
- `CONFIG_BPF_EVENTS=y` and `bpf_probe_write_user` available
- `CAP_BPF` + `CAP_SYS_ADMIN` (or root)
- Docker: `--privileged --pid=host` on a stock Linux host (linuxkit may lack `bpf_probe_write_user`)

## Files

| File | Purpose |
|------|---------|
| `ch05-cgroup-leash.bpf.c` | Kernel-side BPF program (tracepoint pair + bpf_probe_write_user) |
| `ch05-cgroup-leash.c` | Userspace loader and ringbuf consumer |
| `trigger.sh` | Activity generator |
| `Makefile` | Build (uses shared/common.mk) |

## Build & Run

```bash
# Inside the harness container:
make
sudo ./build/ch05-cgroup-leash
# In another terminal:
bash trigger.sh
```

## Detection

- `bpftool prog show` lists the two tracepoint programs (`tp_read_enter`, `tp_read_exit`).
- `bpf_probe_write_user()` invocations emit a one-shot kernel taint message.
- Cross-check: compare `cpu.stat` against `/proc/<pid>/schedstat` or `/proc/stat` aggregate counters -- they will diverge.
- `bpftool map dump name inflight` shows the per-pid stash during a hot read.
