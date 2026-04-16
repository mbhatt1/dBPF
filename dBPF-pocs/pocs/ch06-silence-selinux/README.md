# ch06 — Silencing SELinux (observer)

## Mechanism
Kprobes the SELinux access-vector cache (AVC) and the file-permission
LSM hook. Every labeled decision — granted or denied — streams a ringbuf
event containing `{pid, comm, hook, ssid, tsid, tclass, requested}`.

Pure observation: true silencing of SELinux requires mutating the return
value on the decision path, which is only safe via BPF LSM
(`fmod_ret`). See the override path below.

## Hook points
- `kprobe/avc_has_perm`            — audited AVC lookup; ssid/tsid/tclass/requested in regs.
- `kprobe/avc_has_perm_noaudit`    — inner, used by hot paths; args differ across kernels (see note).
- `kprobe/selinux_file_permission` — per-file read/write mask check.

Cross-kernel note: `avc_has_perm_noaudit` has two shapes
(`(state, ssid, tsid, tclass, requested, ...)` on some trees, scalar-first
on others). The BPF program records both argument positions and reports
whichever is non-zero.

## Build
```
cd pocs/ch06-silence-selinux
make
```

## Run
```
sudo ./build/ch06-silence-selinux -h
sudo ./build/ch06-silence-selinux          # observe-only
sudo ./build/ch06-silence-selinux -v       # verbose libbpf
```
Events go to stdout (`[ch06] tag=avc ...`); status to stderr.
SIGINT / SIGTERM cleanly tear down the ring buffer.

## Evidence (expected on a SELinux host)
```
[ch06] === symbol availability ===
  avc_has_perm                 : present
  avc_has_perm_noaudit         : present
  selinux_file_permission      : present
[ch06] attached=3	status=ready
[ch06] CH06_PROVEN hook=avc_has_perm events=1
[ch06] tag=avc	pid=2134	comm=cat             	hook=avc_has_perm	ssid=27	tsid=42	tclass=6	req=0x2
[ch06] CH06_PROVEN hook=selinux_file_permission events=1
[ch06] tag=avc	pid=2134	comm=cat             	hook=selinux_file_permission	ssid=0	tsid=0	tclass=0	req=0x1
```

On hosts without SELinux (linuxkit aarch64, minimal containers) the loader
exits with `CH06_SKIP reason="SELinux not loaded"` and the harness records
an honest skip.

## Detection
- `bpftool prog show | grep avc_has_perm` lists the attached kprobes.
- `cat /sys/kernel/debug/tracing/kprobe_events` shows the live kprobe records.
- `bpftool map show` lists the `events` ringbuf.
- AVC activity volume drops to zero if the probe is attached but the
  ringbuf is not drained; a monitoring system can watch for
  `/proc/kallsyms`-resident kprobes on `avc_*` symbols.

## Limitations
- No mutation: `bpf_override_return` is blocked — `avc_has_perm` is not on
  the error-injection allowlist of stock kernels.
- On kernels where SELinux is compiled out, every symbol is absent; the
  loader disables autoload on each program and exits 2 with `CH06_SKIP`.
- `avc_has_perm_noaudit`'s signature skew across kernels means the
  recorded ssid/tsid may be shifted by one slot on certain trees — the
  heuristic in the BPF program picks the likely-scalar arguments.

## Override path
To actually silence denials you need BPF LSM + `fmod_ret`. See
[`../ch06-silence-selinux-lsm/`](../ch06-silence-selinux-lsm/), which
attaches `SEC("lsm.s/file_permission")`, `SEC("lsm.s/inode_permission")`,
and `SEC("lsm.s/bprm_check_security")` and returns 0 for target tgids —
flipping denial to grant on kernels with `CONFIG_BPF_LSM=y` and
`lsm=bpf,selinux` on the boot cmdline.

## Blog post

See the chapter write-up: [`2025-02-06-silencing-selinux`](../../../_posts/2025-02-06-silencing-selinux.md) in the Diabolical eBPF Field Manual.
