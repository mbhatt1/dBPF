# ch09 — PID Namespace Doppelgänger

## Mechanism
Every `unshare(CLONE_NEWPID)` / `clone(CLONE_NEWPID)` creates a child PID
namespace; inside it processes see PID 1, while the host kernel still
identifies them by their host-side `task_struct->pid`. Anyone holding a
side-channel between the two namespaces can target a "PID 1" inside a
container with a kill against the corresponding host PID, observe its
files via `/proc/<host_pid>/`, attach a debugger, and so on. This POC
builds that side channel: every namespace transition is captured live,
and at exit the loader prints the full host<->ns translation table.

## Hook points
- `raw_tp/sched_process_fork` — fires on every fork; emit only when the
  child's `pid_ns_for_children->ns.inum` differs from the parent's, i.e.
  a CLONE_NEWPID just took effect.
- `kprobe/copy_namespaces`    — best-effort; covers ns transitions that
  are not visible at the fork tracepoint. Disabled at load if the symbol
  is not in `/proc/kallsyms` (it is often inlined).

## Build
```
cd pocs/ch09-pid-doppel
make
```

## Run
```
sudo ./build/ch09-pid-doppel -h
sudo ./build/ch09-pid-doppel
sudo ./build/ch09-pid-doppel > evt.jsonl 2> ch09.log
```
Events stream to stdout; status and the post-run mapping table land on
stderr. Press Ctrl-C to print the table and exit.

In a second shell:
```
sudo bash pocs/ch09-pid-doppel/trigger.sh
```

## Evidence
Captured live during `trigger.sh` (kernel 6.12-linuxkit aarch64):
```
[ch09] symbol=copy_namespaces	status=present
[ch09] attached=2	skipped=0	failed=0
[ch09] status=ready	msg=doppelganger tracker active
[ch09] src=fork	host_pid=15882	host_tgid=15882	ns_pid=1	level=1	ns_inum=4026532731	comm=sh
[ch09] src=fork	host_pid=15903	host_tgid=15903	ns_pid=1	level=1	ns_inum=4026532733	comm=sh
^C
[ch09] === post-run mapping table ===
[ch09] host_pid   host_tgid  ns_pid     level  ns_inum      comm
[ch09] 15882      15882      1          1      4026532731   sh
[ch09] 15903      15903      1          1      4026532733   sh
[ch09] === 2 entries ===
[ch09] status=exit	code=0
```
The "host_pid=15882 ns_pid=1 level=1" line is the doppelgänger: from
inside the namespace, `getpid()` returns 1, but the host kernel knows it
as 15882 — and so does anyone who can attach this kprobe.

## Proof status

**PROVEN** on Ubuntu 6.17.0-29-generic aarch64 (Lima VM).

**Runtime note**: `trigger.sh` must be run **directly in the Lima/host VM**,
not inside Docker with `--pid=host`. The `--pid=host` Docker flag causes
"unable to start container process: can't get final child's PID from pipe: EOF"
when the trigger tries to `unshare --pid`. Run `bash trigger.sh` in the Lima
VM shell (outside any Docker container).

## Detection
- `bpftool prog show | grep -E 'sched_process_fork|copy_namespaces'` —
  raw tracepoints / kprobes on these symbols are not common observability
  surface; treat unexpected attachments as a strong IOC.
- `bpftool map show` — a HASH map keyed by host PID alongside the ringbuf
  is the doppelgänger table being built.
- Kernel auditing: any process opening `/proc/<host_pid>/` for a `host_pid`
  that does not belong to its own pid_ns is a tampering signal.

## Limitations / arch notes
- `copy_namespaces` is sometimes inlined; the loader detects this via
  `/proc/kallsyms` and disables `kp_copy` so the load still succeeds.
- The raw tracepoint requires `CONFIG_TRACEPOINTS=y` and the sched
  tracepoint subsystem; both are on for every distro kernel and for
  Docker Desktop linuxkit.
- This is a pure observer — there is no override path because the goal
  is intelligence, not interference. Acting on the mapping (kill, ptrace,
  /proc lookup) happens from userspace using the printed host PID.
- The mapping table grows unbounded over long runs; the BPF map is sized
  at 8192 entries and oldest-eviction is handled by the kernel's HASH
  map full behaviour.
