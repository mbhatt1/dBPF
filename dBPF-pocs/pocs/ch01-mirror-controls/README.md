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

## Limitations / arch notes
- **Override is disabled on Docker Desktop linuxkit (6.12, aarch64).**
  `cap_capable` is not in `/sys/kernel/debug/error_injection/list`, so
  `bpf_override_return` is rejected by the verifier. The POC therefore
  ships in observe-and-mark mode.
- To make override work, the kernel must either:
  1. Expose `cap_capable` via `ALLOW_ERROR_INJECTION(cap_capable, ERRNO)`
     and `CONFIG_FUNCTION_ERROR_INJECTION=y`, or
  2. Enable BPF LSM (`CONFIG_BPF_LSM=y` + `lsm=bpf` boot cmdline).
     Then replace the kretprobe with `lsm/capable` + `fmod_ret`.
- If `/proc/kallsyms` lacks `cap_capable`, the loader disables both
  programs via `bpf_program__set_autoload(..., false)` and exits cleanly
  with no programs attached.

## Blog post

See the chapter write-up: [`2025-01-31-the-mirror-controls`](../../../_posts/2025-01-31-the-mirror-controls.md) in the Diabolical eBPF Field Manual.
