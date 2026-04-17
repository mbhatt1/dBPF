# Ch04 -- The Phantom Syscall

**Category**: REAL
**Primitive**: tracepoint + bpf_tail_call for covert kernel data exfiltration
**Hook(s)**: `SEC("tp/syscalls/sys_enter_write")` (stage1 + stage2 via PROG_ARRAY tail call)
**Architecture**: aarch64 + x86_64

## What this demonstrates

Userspace issues exactly one syscall: `write(fd, "PHANTOM\0..payload..", N)`. A tracepoint on `sys_enter_write` sniffs the magic, then tail-calls stage 2, which reads kernel-only data (`current->cred` uid/euid, `real_parent->comm`) and exfiltrates via ringbuf. Seccomp would only see `write` -- yet kernel-space data reached the attacker.

## What this does NOT do

Does not modify any kernel state. The exfiltration is read-only: credential fields and task metadata are copied out, not altered. The tail-call chain is limited to the PROG_ARRAY size. Seccomp filters see only the `write` syscall number; the BPF-side exfiltration is invisible to userspace-level syscall auditing.

## Prerequisites

- `CONFIG_FTRACE_SYSCALLS=y` (syscall tracepoints enabled)
- `CAP_BPF` + `CAP_PERFMON` (or root)
- Docker: `--privileged --pid=host`

## Files

| File | Purpose |
|------|---------|
| `ch04-phantom-syscall.bpf.c` | Kernel-side BPF program (tracepoint + tail call stages) |
| `ch04-phantom-syscall.c` | Userspace loader and ringbuf consumer |
| `trigger.sh` | Activity generator |
| `Makefile` | Build (uses shared/common.mk) |

## Build & Run

```bash
# Inside the harness container:
make
sudo ./build/ch04-phantom-syscall
# In another terminal:
bash trigger.sh
```

## Detection

- Rings loud on syscall tracepoint audit; ringbuf map visible in `bpftool map list`.
- `PROG_ARRAY` usage and tail_call are flags -- `bpftool map show` reveals the jump table.
- `bpftool prog show` lists the tracepoint programs attached to `sys_enter_write`.
