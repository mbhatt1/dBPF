# ch05 — Cgroup Leash

## Mechanism
Slip the cgroup CPU controller by rewriting `cpu.stat` read results in
flight. On `sys_enter_read`, BPF walks
`current->files->fdt->fd[fd]->f_path.dentry->d_name.name` to identify reads
of files named `cpu.stat`, and stashes the user buffer pointer in a per-pid
hash. On `sys_exit_read`, if the syscall succeeded and the file matched, BPF
calls `bpf_probe_write_user()` to overwrite the user's buffer with
`usage_usec 0\nuser_usec 0\nsystem_usec 0\n`.

Workload monitors, orchestrators, and humans running `cat cpu.stat` see
zero usage. Kernel accounting itself is untouched (so scheduler throttling
based on actual runtime still happens — the "escape" is perception, not
physics).

## Hook points
- `tp/syscalls/sys_enter_read` — resolve `fd → file → dentry → d_name.name`,
  flag the inflight entry if the basename is `cpu.stat`.
- `tp/syscalls/sys_exit_read` — if the read succeeded and was flagged,
  overwrite the user buffer and emit a ringbuf event.

## Build
```
cd pocs/ch05-cgroup-leash
make
```

## Run
```
sudo ./build/ch05-cgroup-leash            # status to stderr, events to stdout
sudo ./build/ch05-cgroup-leash --help     # usage
sudo ./build/ch05-cgroup-leash -v         # libbpf debug logs

# In another shell:
./trigger.sh
```

## Evidence
Captured runtime output:
```
$ cat /sys/fs/cgroup/cpu.stat | head -3
usage_usec 8864
user_usec 3324
system_usec 5540

# loader running:
$ sudo ./build/ch05-cgroup-leash
[ch05] attached — cgroup leash active (Ctrl-C to exit)
[ch05] pid=21388  tgid=21388  comm=cat              cpu.stat_bytes=133   patched=1

# same read, with loader attached:
$ cat /sys/fs/cgroup/cpu.stat | head -3
usage_usec 0
user_usec 0
system_usec 0
```
`usage_usec 8864 → 0`.

## Detection
- `bpftool prog show` lists the two tracepoint programs (`tp_read_enter`,
  `tp_read_exit`) and their pinned maps.
- `bpftool map dump name inflight` shows the per-pid stash during a hot read.
- `bpf_probe_write_user()` invocations emit a one-shot kernel taint message
  and `process X (...) is using bpf_probe_write_user` (varies by kernel).
- Cross-check: compare `cpu.stat` against `/proc/<pid>/schedstat` or
  `/proc/stat` aggregate counters — they will diverge.

## Limitations / arch notes
- Requires `CAP_BPF` + `CAP_SYS_ADMIN` (or root). Tracepoints
  `syscalls/sys_enter_read` and `syscalls/sys_exit_read` must be present in
  `/sys/kernel/debug/tracing/events/syscalls/` (built with
  `CONFIG_FTRACE_SYSCALLS=y`).
- `bpf_probe_write_user()` requires `CONFIG_BPF_EVENTS=y` and is gated by
  `bpf_capable()`. It will not function inside hardened sandboxes that drop
  `CAP_PERFMON`.
- Docker Desktop (linuxkit aarch64) typically ships a kernel that lacks
  `bpf_probe_write_user` (`-EOPNOTSUPP` at verifier load) and the syscall
  tracepoints may be stripped — load fails up front. Run on a stock
  Linux host.
- This POC uses tracepoints, not kprobes, so the kallsyms preflight is not
  applicable — the tracepoint event existence is checked at attach time
  by libbpf and reported with `strerror()`.
- Filename match is exact basename `cpu.stat` (no path validation), so a
  user file literally named `cpu.stat` would also be rewritten.

## Blog post

See the chapter write-up: [`2025-02-05-slipping-the-cgroup-leash`](../../../_posts/2025-02-05-slipping-the-cgroup-leash.md) in the Diabolical eBPF Field Manual.
