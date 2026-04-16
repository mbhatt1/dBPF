# POC SPEC — read this before writing code

## Target environment
- Host: Docker Desktop 4.56 on macOS (arm64)
- Container kernel: 6.12.54-linuxkit aarch64
- BTF is available at /sys/kernel/btf/vmlinux (CONFIRMED)
- Base image: `dbpf-base:latest` — has clang-18, libbpf-dev, bpftool, libelf, keyutils
- Privileged mode granted at runtime: `--privileged --pid=host --cap-add=ALL`,
  `-v /sys/kernel/debug:/sys/kernel/debug -v /sys/fs/bpf:/sys/fs/bpf`

## Mandatory build system
Every POC directory must contain:
```
<appname>.bpf.c        # kernel side
<appname>.c            # userspace loader
Makefile               # one-liner: APP := <appname>
                       #             include ../../shared/common.mk
trigger.sh             # userspace activity that exercises the hook
README.md              # what it does, how to verify, how to detect
```

## Kernel offset strategy — CO-RE ONLY
- Generate vmlinux.h at build time: `bpftool btf dump file /sys/kernel/btf/vmlinux format c`
- Never use fixed struct offsets. Use BPF_CORE_READ / bpf_core_read() / CO-RE relocations.
- If accessing a field that may have renamed across kernels, use
  `bpf_core_field_exists()` or `BPF_CORE_READ_BITFIELD_PROBED`.
- For kprobe targets: hook by *function name*, not address. Verify availability
  at load time via /sys/kernel/tracing/available_filter_functions. If missing on
  this kernel, find equivalent (e.g., security_* LSM hook, or sys_enter_* tp).

## Hook selection fallbacks (kernel 6.12 aarch64)
Known-good hook points you can use without surprises:
- LSM-ish: use kprobe on `security_*` functions (they exist and are stable)
- Capability: `cap_capable` (kprobe) — stable
- Syscalls: prefer raw tracepoints `raw_tracepoint/sys_enter` / `sys_exit`
  or `tp/syscalls/sys_enter_<name>` (available on this kernel)
- VFS/FS: `vfs_read`, `vfs_open`, `vfs_getattr`, `filldir64`, `iterate_dir`
- Net: XDP via `SEC("xdp")`, sockops via `SEC("sockops")`, TC via `SEC("tc")`
- Cgroup: `SEC("cgroup/...")` attach types
- Scheduler: `__sched_setscheduler` (kprobe)
- Keyrings: `key_permission`, `key_task_permission`
- Namespaces: `switch_task_namespaces`, `copy_namespaces`

If your target symbol is not in kallsyms on this kernel, pick the closest
equivalent and document the substitution in README.md.

## Build command (run from your POC dir)
```
docker run --rm -v "$PWD":/work -w /work dbpf-base make
```

## Run command (after build)
```
docker run --rm --privileged --pid=host \
  -v "$PWD":/work -w /work \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/fs/bpf:/sys/fs/bpf \
  dbpf-base ./build/<appname>
```

## Quality bar
- No educational stubs. The BPF program must actually modify behavior or
  observe the real event and stream evidence through a ring buffer.
- Userspace loader must open skeleton, attach programs, poll ring buffer,
  print events with PID/comm/timestamp.
- trigger.sh must deterministically cause the hook to fire and produce
  visible output proving the POC works.
- README.md has: Mechanism, Hook points, Verification (exact commands
  the reviewer runs), Detection (how defenders would spot this).
