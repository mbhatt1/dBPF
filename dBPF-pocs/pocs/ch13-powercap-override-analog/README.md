# ch13 Powercap Override — ANALOG variant

**DISCLAIMER.** Intel RAPL / powercap is x86-only; this kernel is
aarch64 linuxkit, where the real subsystem does not exist (all four
`powercap_*` symbols are absent — see the primary POC
`ch13-powercap-override/` for the observer that honest-skips on this
host). This analog is clearly marked as a variant: it does NOT touch
RAPL. It reproduces the *primitive shape* of the attack ("rewrite
`read()` buffer in flight via `bpf_probe_write_user` on `sys_exit_read`")
against a surface that does exist on aarch64: a userspace sensor daemon
writing to a plain file, and a reader cat-ing that file.

## Mechanism

Same pattern as ch05:
- `tp/syscalls/sys_enter_read` — walk `current->files->fdt->fd[fd]`,
  read the file's `dentry->d_name.name`, match basename
  `ch13_sensor_energy_uj`, and stash the user-buffer pointer in a
  per-task `inflight` hash map keyed by `pid_tgid`.
- `tp/syscalls/sys_exit_read` — if the matching read is returning data,
  overwrite the reader's user buffer with zeros via
  `bpf_probe_write_user`, update `orig_bytes`, emit a ringbuf event.

The daemon (`sensor_daemon.c`) and reader (`sensor_reader.c`) are
dedicated userspace helpers shipped alongside the loader.

## Hook(s)

- `tracepoint/syscalls/sys_enter_read`
- `tracepoint/syscalls/sys_exit_read`
- Writes back into userspace with `bpf_probe_write_user` (requires
  `CAP_SYS_ADMIN`; the kernel taints on first use).

## Host prereqs

- `CONFIG_BPF_EVENTS=y`, syscalls tracepoints enabled.
- `bpf_probe_write_user` available (taints the kernel when called).
- `/tmp` writable (daemon stages `/tmp/ch13_sensor_energy_uj`).

## Build / Run

```
cd pocs/ch13-powercap-override-analog && make
sudo bash trigger.sh
```

## Evidence

Per-event loader line:
```
[ch13-analog] pid=4321    comm=sensor_reader    sensor_read_bytes=5    patched=1
```

Trigger verdict line:
```
=== CH13_ANALOG_PROVEN before_climb=100->300 after=0 zero_reads=3 patched_events=3 disclaimer="same primitive as RAPL override; real RAPL is x86-only" ===
```

## Limitations

- Not a RAPL exploit. No powercap sysfs node is touched; the target is
  a plain file under `/tmp`. Drawing any conclusion about actual Intel
  RAPL behaviour from this POC is a category error.
- `bpf_probe_write_user` is best-effort by design — it can fault and
  fail silently if the user page isn't resident at the moment the TP
  fires. The trigger tolerates that via retry iterations.
- Basename match is exact; no full-path validation (the same basename
  anywhere on the filesystem would be rewritten).

## Blog post

See the chapter write-up: [`2025-03-10-powercap-override`](../../../_posts/2025-03-10-powercap-override.md) in the Diabolical eBPF Field Manual.
