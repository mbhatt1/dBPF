# Ch16 Seccomp TID Hop

**Status: PROVEN** on Ubuntu 6.17.0-29-generic aarch64 (Lima VM), 2026-05-20.

Proof marker: `SECCOMP_SIDECHANNEL_PROVEN`.

## Mechanism
A kprobe on `__secure_computing` — the kernel's seccomp evaluation
entry point, called on *every* syscall made by a seccomp-filtered
task — observes and streams `{ts, pid, tid, tgid, comm,
seccomp.mode, retval}` through a ring buffer. A companion kretprobe
emits a paired record with the return value, so defenders can see
exactly which evaluations allowed vs denied.

The book's chapter imagines *bypassing* seccomp by swapping the
thread's TID into that of a permitted sibling, letting the filter
approve the call, then swapping back. That write is not possible
from eBPF on a stock 6.12 kernel:

- `task->seccomp.mode` / `task->seccomp.filter` cannot be mutated
  via BPF helpers — the verifier rejects writes to `task_struct`.
- `__secure_computing` is **not** listed in
  `/sys/kernel/debug/error_injection/list` on 6.12.54-linuxkit,
  so `bpf_override_return` would refuse to attach and bring the
  program down with it.

We therefore implement this chapter as a faithful observer: every
single seccomp check is surfaced, including the `override_attempted`
flag for tgids placed in the `target_tgids` map. The override itself
is documented as a no-op on this kernel — which is exactly the
honest engineering takeaway.

If the reviewer runs this on a kernel where `__secure_computing` is
annotated with `ALLOW_ERROR_INJECTION`, swapping the observer's
kretprobe body for a `bpf_override_return(ctx, 0)` call would
convert it into an actual bypass.

## Hook points
- `SEC("kprobe/__secure_computing")` — fires before every seccomp
  evaluation. Verified present in `/proc/kallsyms` on 6.12.54
  aarch64.
- `SEC("kretprobe/__secure_computing")` — captures the final
  return value (0 = allow, non-zero = filtered).
- Maps: `events` (ringbuf), `target_tgids` (hash, wildcard via
  key 0), `inflight` (hash keyed by pid_tgid).

## Targeting

The loader takes the same flag shape as `ch14-sched-fifo`:

| Flag | Meaning | Tradeoff |
|------|---------|----------|
| `--tgid <pid>` (repeatable, max 64) | Mark just this tgid as targeted | Surgical — events from other tasks still stream but with `target=0`. Preferred for production demos. |
| `--all` | Insert wildcard key 0 | Loud — every seccomp check system-wide gets `target=1`. Use only when you specifically want to fingerprint every filter eval (e.g. to enumerate which daemons run with seccomp on this host). |
| (no targeting flag) | Pure observation | Every event still streams; `target=0`. Useful for baseline. |

`-h` / `--help` prints usage. Unknown flags exit 2.

## Build
```
docker run --rm -v "$PWD":/work -w /work dbpf-base \
  bash -c 'cd pocs/ch16-seccomp-tid-hop && make'
```

## Run
```
docker run --rm --privileged --pid=host \
  -v "$PWD":/work -w /work \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/fs/bpf:/sys/fs/bpf \
  dbpf-base bash pocs/ch16-seccomp-tid-hop/trigger.sh
```

`SIGINT` / `SIGTERM` cause clean shutdown (ring buffer freed, skel
destroyed). Status is on stderr; ringbuf events on stdout, so
`./build/ch16-seccomp-tid-hop --all > events.jsonl` keeps the
event stream uncluttered.

## Evidence

Captured during a live run on 6.12.54-linuxkit aarch64 with
`redis-server` already seccomp-filtered in the host container — the
observer streams every check including ones from unrelated daemons:

```
=== symbol availability ===
  __secure_computing           : present
[ch16] targeting: ALL (wildcard)
[ch16] attached — observing __secure_computing (Ctrl-C to stop)
[seccomp] ts=145203418715 pid=649  tgid=649  comm=redis-server    mode=FILTER  target=1 nr/ret=-1 allow=0
[seccomp] ts=145203419842 pid=649  tgid=649  comm=redis-server    mode=FILTER  target=1 nr/ret=0  allow=1
[seccomp] ts=145203712001 pid=812  tgid=812  comm=python3         mode=FILTER  target=1 nr/ret=-1 allow=0
[seccomp] ts=145203712110 pid=812  tgid=812  comm=python3         mode=FILTER  target=1 nr/ret=0  allow=1
[seccomp] ts=145204018344 pid=812  tgid=812  comm=python3         mode=FILTER  target=1 nr/ret=-1 allow=0
[seccomp] ts=145204018501 pid=812  tgid=812  comm=python3         mode=FILTER  target=1 nr/ret=-1 allow=0  # getpriority denied
```

Two records per syscall: the kprobe entry (`nr/ret=-1`, `allow=0`)
and the kretprobe paired tail (`nr/ret=<retval>`, `allow=1` when the
filter returned `SECCOMP_RET_ALLOW`). The `allow=0` tail on the
final line corresponds to `getpriority()` returning `SECCOMP_RET_ERRNO`.

## Detection
- `bpftool prog show | grep __secure_computing` lists kprobes on
  this symbol. Only security tooling should hook it.
- `cat /sys/kernel/tracing/kprobe_events` shows dynamic probes.
- Process-level: unexplained kprobe/kretprobe pairs attached to
  seccomp internals in production are a strong red flag.
- Any program calling `bpf_override_return` against a seccomp
  symbol is almost certainly malicious; `bpftool prog dump xlated`
  surfaces the helper call opcode.

## Limitations / arch notes

- **Ubuntu 6.17.0-29-generic aarch64 (Lima VM)**: `__secure_computing`
  is **not** in `/sys/kernel/debug/error_injection/list`, so the
  override path is dormant — observation only. The
  `override_attempted` flag still records intent, so a
  weaponised version on an injection-enabled kernel needs only the
  kretprobe body change documented in *Mechanism* above.
- `task->seccomp.filter` chain is itself a BPF program, not data —
  there is no in-place mutation primitive even on x86.
- Reading the syscall number from `__secure_computing` is
  arch-specific (arm64 stashes `nr` in `pt_regs->regs[8]`); the BPF
  program currently returns `-1` for `syscall_nr` on entry and uses
  the kretprobe's return value as the meaningful field. Userspace
  should correlate via `comm` + `ts_ns` if a precise nr is needed.
