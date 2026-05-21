# ch01 — Mirror Controls

## Mechanism
Observe every `cap_capable()` decision in the kernel. The kprobe stashes the
`cap` argument keyed by `pid_tgid`; the matching kretprobe reads the return
value, emits a ringbuf event, and (for tgids registered via `-t`) marks what
WOULD be flipped from "denied" to "granted".

True override would call `bpf_override_return(0)` from the kretprobe, but
that is gated by the kernel's error-injection allowlist — see
**Limitations** below.

## Hook points
- `kprobe/cap_capable`    — stash `cap` argument keyed by `pid_tgid`.
- `kretprobe/cap_capable` — read return, emit ringbuf event, flag flips.

## Build
```
cd pocs/ch01-mirror-controls
make
```

## Run
```
sudo ./build/ch01-mirror-controls -h
sudo ./build/ch01-mirror-controls            # observe-only
sudo ./build/ch01-mirror-controls -t 12345   # mark tgid 12345 as flip-target
sudo ./build/ch01-mirror-controls > evt.jsonl 2> ch01.log
```
Events go to stdout; status to stderr. SIGINT / SIGTERM cleanly tear down
the ring buffer and skeleton.

## Evidence
Captured during `cat /etc/shadow` as a non-root user:
```
[ch01] symbol=cap_capable	status=present
[ch01] attached=2	skipped=0
[ch01] status=ready	msg=mirror active
[ch01] tag=deny	pid=17125	comm=cat             	cap=2	ret=-1
[ch01] tag=deny	pid=17125	comm=cat             	cap=1	ret=-1
```
(`cap=2` = `CAP_DAC_READ_SEARCH`; `cap=1` = `CAP_DAC_OVERRIDE`.)

## Detection
- `bpftool prog show | grep cap_capable` lists the attached kprobe/kretprobe.
- `cat /sys/kernel/debug/tracing/kprobe_events` shows live kprobe entries.
- The `events` ringbuf map appears in `bpftool map show`.

## Status

**PROVEN** on Ubuntu 6.17.0 aarch64 (Lima VM, kernel 6.17.0-29-generic).

The kretprobe now delivers `SIGUSR1` to the target process on every capability
denial via `bpf_send_signal(SIGUSR1)`. The ringbuf event field `signal_sent`
is `1` when the signal was delivered successfully. The event tag is `FLIP`.
The `-a` wildcard flag arms wildcard mode in the userspace loader (key `0`
sentinel in `target_tgids`).

## Limitations / arch notes
- **Override is disabled on stock kernels.**
  `cap_capable` is not in `/sys/kernel/debug/error_injection/list`, so
  `bpf_override_return` is rejected by the verifier. The POC therefore
  ships in observe-and-signal mode: `bpf_send_signal(SIGUSR1)` delivers a
  real signal to the target, but the capability denial still takes effect.
- To get true verdict override, use the BPF LSM variant in
  `ch01-mirror-controls-lsm/`.
- If `/proc/kallsyms` lacks `cap_capable`, the loader disables both
  programs via `bpf_program__set_autoload(..., false)` and exits cleanly
  with no programs attached.
