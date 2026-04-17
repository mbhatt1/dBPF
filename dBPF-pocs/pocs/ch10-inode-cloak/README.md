# Ch10 -- Inode Cloak

**Category**: REAL
**Primitive**: tracepoint + bpf_probe_write_user for getdents64 dirent rewriting
**Hook(s)**: `SEC("tp/syscalls/sys_enter_getdents64")`, `SEC("tp/syscalls/sys_exit_getdents64")`
**Architecture**: aarch64 + x86_64

## What this demonstrates

Hides files from `getdents64` by rewriting `d_reclen` of the preceding dirent to swallow the hidden entry. No filesystem writes; purely in-flight mutation of the kernel-to-user buffer via `bpf_probe_write_user`. `ls`, `find`, and any tool that calls `getdents64` will not see the cloaked files, but `stat` and `open` by name still work.

## What this does NOT do

This is a readdir-layer cloak only -- `stat`, `open`, `inotify`, and filesystem snapshot tools see the file as normal. Buffer walk is bounded to 64 dirents per syscall (verifier loop ceiling); directories with more entries may leak names past the bound. Only hooks `getdents64`, not the legacy 32-bit `getdents`.

## Prerequisites

- `CONFIG_BPF_EVENTS=y` and `bpf_probe_write_user` available
- `CONFIG_FTRACE_SYSCALLS=y` (syscall tracepoints enabled)
- `CAP_BPF` + `CAP_SYS_ADMIN` (or root)
- Docker: `--privileged --pid=host`

## Files

| File | Purpose |
|------|---------|
| `ch10-inode-cloak.bpf.c` | Kernel-side BPF program (tracepoint pair + dirent rewriting) |
| `ch10-inode-cloak.c` | Userspace loader (populates hidden-name hash map) |
| `trigger.sh` | Activity generator (creates test files, runs ls/find/stat) |
| `Makefile` | Build (uses shared/common.mk) |

## Build & Run

```bash
# Inside the harness container:
make
sudo ./build/ch10-inode-cloak .backdoor evil.so
# In another terminal:
bash trigger.sh
```

## Detection

- `strace -e getdents64 ls /tmp/cloak` -- strace observes the post-mutation buffer; comparing with a syscall-level inspector that reads the buffer before BPF runs reveals the diff.
- `bpftool prog show` lists the two tracepoint programs and their map fds.
- `bpftool map dump name hidden` reveals the cloaked filename set.
- `cat /sys/kernel/debug/tracing/events/syscalls/sys_exit_getdents64/enable` shows the tracepoint is enabled.
