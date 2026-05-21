# ch06 Silence SELinux — LSM variant (REAL override)

Sibling POC to `ch06-silence-selinux/` (kprobe observer on SELinux's AVC).
The observer variant only *watches* decisions; this one *changes* them.

## Mechanism

BPF LSM hooks run at the outer `security_*` entry points, **before**
SELinux's in-kernel `avc_has_perm` chain executes. Returning 0 from a
sleepable `fmod_ret` program on `security_file_permission` (etc.) pre-empts
the deny: SELinux's verdict never gets a chance to apply.

Three hooks cover the realistic attack surface:

| Hook | When it fires | What a flip unlocks |
|------|---------------|---------------------|
| `lsm.s/file_permission` | vfs read/write/exec on an open file | labeled file I/O |
| `lsm.s/inode_permission` | path-walk / open-time permission check | path traversal + open |
| `lsm.s/bprm_check_security` | execve of a binary | execution of label-restricted programs |

Each program inspects the trailing `ret` arg. If the current tgid is in
`target_tgids` (or the wildcard sentinel `0` is present) **and** `ret != 0`,
it rewrites the return to 0 and emits a ringbuf event
`{pid, comm, hook, orig_ret, flipped}`. The loader transcribes flips to
stdout as `[ch06] FLIP hook=<name> pid=... orig=... -> 0`.

## Primitive

`P3` from `shared/PRIMITIVES.md`: `SEC("lsm.s/<hook>")` sleepable
`fmod_ret`. Not gated by the error_injection allowlist — LSM fmod_ret is
the first-class override primitive.

## Host prereqs

- Kernel built with `CONFIG_BPF_LSM=y` and `CONFIG_SECURITY_SELINUX=y`.
- Boot cmdline contains both in `lsm=…`, e.g.
  `lsm=landlock,lockdown,yama,bpf,integrity,apparmor,selinux`.
- Check: `cat /sys/kernel/security/lsm` must contain **both** `bpf` and
  `selinux`.
- `bpftool feature probe | grep lsm_fmod_ret` must show `ok`.
- CAP_SYS_ADMIN (loading LSM fmod_ret requires full sysadmin, not just
  CAP_BPF).
- Satisfied by Fedora 38+ with SELinux enforcing. Docker Desktop linuxkit
  aarch64 has neither — the loader and trigger will honest-skip.

## Build

```
docker run --rm -v "$PWD/../..":/work -w /work dbpf-selinux \
  bash -c 'cd pocs/ch06-silence-selinux-lsm && make'
```

## Run

```
sudo ./build/ch06-silence-selinux-lsm -h
sudo ./build/ch06-silence-selinux-lsm -a             # wildcard: flip every deny
sudo ./build/ch06-silence-selinux-lsm -t 12345       # only tgid 12345
sudo bash trigger.sh                                 # end-to-end demo
```

## Evidence (expected on BPF-LSM + SELinux host)

Loader stderr:
```
[ch06] BPF LSM is active — proceeding
[ch06] mode=wildcard — every deny will flip
[ch06] active — SELinux denies for targeted tgids will be flipped to allow
```

Loader stdout (proof markers the harness scans for):
```
[ch06] FLIP hook=inode_permission pid=4211 comm=cat orig=-13 -> 0
[ch06] FLIP hook=file_permission  pid=4211 comm=cat orig=-13 -> 0
```

Trigger terminal line:
```
CH06_PROVEN flipped=2
```

On a host missing BPF LSM or SELinux, the loader emits
`CH06_SKIP reason="..."` on stderr and exits 3; the trigger emits
`=== CH06_SKIP reason="..." ===` and exits 0. Both are honest-skips the
harness records as "skipped, not failed".

## Detection

- `cat /sys/kernel/debug/tracing/enabled_functions 2>/dev/null` and
  `bpftool prog list type lsm` will show the attached sleepable programs.
- SELinux auditd logs will stop showing AVC denials for the targeted
  processes — a sudden drop in denies is itself a tell.
- Kernel `bpf()` syscall audit (if enabled) records program load from
  a non-init namespace.

## Status

**PROVEN** on Ubuntu 6.17.0 aarch64 (Lima VM, kernel 6.17.0-29-generic).
No code changes were required — the POC worked as-is.

A companion synthetic variant (`ch06-silence-selinux-lsm-synthetic/`) was
created to handle cases where the `selinux_loaded()` preflight check returns
false. The synthetic variant bypasses the preflight and attaches kprobes
directly to SELinux symbols found in `/proc/kallsyms`.

## Limitations

- fmod_ret → 0 only flips decisions the LSM framework *would have been
  able to deny*. DAC (unix perms) and other pre-LSM checks still apply.
- Capability checks are at `security_capable` (see `ch01-mirror-controls-lsm`),
  not covered here.
- LSM fmod_ret requires CAP_SYS_ADMIN, not just CAP_BPF.
- On kernels without `lsm=bpf`, attach fails loudly (exit 3) rather than
  silently becoming a no-op.
- No attempt is made to spoof the audit record that SELinux *didn't*
  write because the decision was overridden — a forensic analyst
  comparing "expected denies vs. logged denies" could spot this.
