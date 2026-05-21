# ch14 — SCHED_FIFO Impersonator

**Status: PROVEN** on Ubuntu 6.17.0-29-generic aarch64 (Lima VM), 2026-05-20.

## Mechanism
Overrides the return value of `__arm64_sys_sched_setscheduler` via
`bpf_override_return(ctx, 0)`. This syscall entrypoint IS in
`/sys/kernel/debug/error_injection/list` on linuxkit 6.12, so the
override actually takes effect.

When an unprivileged process calls `sched_setscheduler(SCHED_FIFO, …)`:
- baseline: `-1` / `EPERM` (no `CAP_SYS_NICE`)
- with BPF loaded + tgid (or wildcard) registered: returns `0`

Userspace tooling (chrt, systemd, libraries that gate behaviour on the
return) then acts as if SCHED_FIFO was granted. The kernel
`task_struct->policy` is **not** modified; this is a userspace-illusion
attack — anything that trusts the syscall return is fooled.

## Hook points
- `kprobe/__arm64_sys_sched_setscheduler` — record caller into inflight map.
- `kretprobe/__arm64_sys_sched_setscheduler` — `bpf_override_return(ctx, 0)`
  when target matches; always emits a ringbuf event recording the
  original return and whether it was flipped.

The loader greps `/proc/kallsyms` at startup and refuses to run if the
target symbol is missing (wrong arch / non-kprobe-eligible kernel).

## Build
```
cd /Users/mbhatt/spaceclaw/evilBPF/dBPF-pocs
docker run --rm -v "$PWD":/work -w /work dbpf-base \
  bash -c 'cd pocs/ch14-sched-fifo && make'
```

## Run
```
./build/ch14-sched-fifo --help
./build/ch14-sched-fifo --all              # wildcard: flip every caller
./build/ch14-sched-fifo --tgid 1234        # specific tgid only
./build/ch14-sched-fifo 1234 5678          # back-compat positional tgids
./build/ch14-sched-fifo --all > events.jsonl 2> status.log
```
Status messages are on stderr; one event per line on stdout.

## Evidence
Captured running `bash trigger.sh` inside the privileged dbpf-base container:
```
=== baseline: t14 runs chrt -f 50 $$ (no BPF) ===
chrt: failed to set pid 0's policy: Operation not permitted
baseline_ret=1

=== loading ch14 SCHED_FIFO impersonator (wildcard mode) ===
[ch14] tag=preflight target=__arm64_sys_sched_setscheduler status=present
[ch14] tag=mode wildcard=1
[ch14] tag=ready hook=__arm64_sys_sched_setscheduler

=== with BPF: same chrt call ===
override_ret=0

=== loader output ===
[sched] pid=18843 tgid=18843 comm=chrt             orig_ret=-1 flipped=1
```
`orig_ret=-1 flipped=1` is the smoking gun: the kernel returned `-EPERM`,
the BPF kretprobe rewrote it to `0`, and `chrt`/`bash` saw success.

## Detection
- `bpftool prog show type kprobe` will list `kp_sched`/`kr_sched`
  attached to `__arm64_sys_sched_setscheduler` — neither tracing nor
  observability tooling normally hooks that symbol.
- Audit `/sys/kernel/tracing/kprobe_events` for unexpected entries on
  syscall entrypoints.
- Hosts with `kernel.unprivileged_bpf_disabled=1` and a strict
  LSM/lockdown profile cannot load `bpf_override_return`-using
  programs at all (CAP_SYS_ADMIN + `CONFIG_BPF_KPROBE_OVERRIDE`
  required).

## Limitations / arch notes
- The kprobe target is **arch-specific** — `__arm64_sys_*` on aarch64,
  `__x64_sys_*` on x86_64. The BPF object as shipped is aarch64 only.
- `bpf_override_return` requires `CONFIG_BPF_KPROBE_OVERRIDE=y` AND
  the target syscall to be in
  `/sys/kernel/debug/error_injection/list`. Most internal kernel
  functions are not, which is why we hook the syscall entrypoint.
- The override does not change actual scheduler state — only what
  userspace observes. A subsequent `sched_getscheduler()` would still
  report the real (unchanged) policy.
- Ubuntu 6.17.0-29-generic aarch64 (Lima VM): works as shown. On stock
  cloud kernels with hardened lockdown / SELinux,
  `bpf_override_return` may be denied even with CAP_SYS_ADMIN.
