# ch02 — OverlayFS Trojan Horse

## Mechanism
On the first write/chmod/setattr to a lower-dir file, overlayfs promotes
the file to the upper-dir ("copy-up"). Three kprobes cover the decision
points; each event streams `{pid, comm, filename, inode, mode, hook}` via
ringbuf. The loader detects which symbols are present and disables
autoload for the absent ones, so it runs cleanly on kernels with any
subset of the three.

## Hook points
- `kprobe/ovl_maybe_copy_up`     — entry gate (read-before-write path).
- `kprobe/ovl_copy_up`           — synchronous copy-up.
- `kprobe/ovl_copy_up_with_data` — data-preserving variant.

## Build
```
cd pocs/ch02-overlayfs
make
```

## Run
```
sudo ./build/ch02-overlayfs -h
sudo ./build/ch02-overlayfs                  # observe all overlay copy-ups
sudo ./build/ch02-overlayfs > evt.jsonl 2> ch02.log
```
Events to stdout, status to stderr. SIGINT/SIGTERM cleans up.

In a second shell, run `sudo ./trigger.sh` to seed and trigger copy-ups
on a tmpfs-backed overlay mount.

## Evidence
Captured during `./trigger.sh` — writing to `$merged/secret.txt` and
`chmod 0755 $merged/bin.sh` on a tmpfs-backed overlay:
```
[ch02] symbol=ovl_copy_up	status=present
[ch02] symbol=ovl_maybe_copy_up	status=present
[ch02] symbol=ovl_copy_up_with_data	status=present
[ch02] attached=3	skipped=0
[ch02] status=ready	msg=overlay copy-up observer
[ch02] hook=ovl_maybe_copy_up    	pid=22198	comm=bash            	name=secret.txt              	ino=6	mode=100644
[ch02] hook=ovl_copy_up          	pid=22205	comm=chmod           	name=bin.sh                  	ino=7	mode=100755
```
The Docker container's own root overlay also fires — any binary execution
or library load triggers `ovl_maybe_copy_up`, observable by this POC.

## Detection
- `bpftool prog show | grep ovl_` lists the attached kprobes.
- `cat /sys/kernel/debug/tracing/kprobe_events` shows live kprobe entries.
- The `events` ringbuf appears in `bpftool map show`.

## Weaponization (racer mode)
With `-r <upperdir> -t <basename> -w <payload>` the loader uses the
ringbuf copy-up event as a race signal: the instant the kernel promotes
`<basename>` to the upper layer, the userspace handler opens
`<upperdir>/<basename>` `O_WRONLY|O_TRUNC` and overwrites its contents
with `<payload>`. A later victim `read()` on the merged mount sees the
attacker's payload instead of what was written.

`trigger.sh` automates a BEFORE/AFTER demonstration and prints
`[ch02] RACE_WIN` on success (harness-friendly marker). Per-mutation the
loader logs `[ch02] PWNED\tpath=…\tbytes=…\thits=N` on stderr.

## Limitations / arch notes
- Pure-kprobe variant: the kernel side is still observation-only; the
  mutation is applied from userspace via a standard `open()`/`write()`
  on the upper-dir path. A full kernel-side inject would require P2
  `bpf_probe_write_user` or an LSM hook (see `ch02-overlayfs-lsm`).
- On older overlayfs builds, only `ovl_copy_up` exists; on newer ones,
  `ovl_copy_up_with_data` may be inlined and absent from kallsyms.
  The loader handles both — absent symbols are disabled, present ones
  attach.
- Docker Desktop linuxkit (6.12, aarch64) exposes all three symbols.
- Nested overlay-on-overlay is unsupported by Docker's storage driver,
  hence `trigger.sh` mounts a tmpfs backing first.

## Blog post

See the chapter write-up: [`2025-02-01-the-overlayfs-trojan-horse`](../../../_posts/2025-02-01-the-overlayfs-trojan-horse.md) in the Diabolical eBPF Field Manual.
