# ch07 Device-cgroup Houdini — LSM variant (synthetic deny + flip)

Sibling POC to `ch07-devcgroup-houdini/` (kprobe observer on
`devcgroup_check_permission`). The observer watches the cgroup verdict;
this variant proves the primitive that turns device-gate *denies* into
*allows*.

## Why synthetic

The chapter frames this as "flip the device cgroup's deny to an allow".
On a standard Linux LSM chain that cannot actually work end-to-end from
a natural denial: `vfs_mknod` direct-calls `capable(CAP_MKNOD)` **before**
`security_inode_mknod`, and the BPF LSM hook sits last in the chain,
after `capability`. A cap_mknod drop or an unprivileged user gets
`-EPERM` from the cap check path *before* our sleepable LSM program is
called, so there is nothing for the flipper to observe. (This is also
why the `ch06-silence-selinux-lsm-synthetic/` POC exists alongside
`ch06-silence-selinux-lsm/`.)

The primitive itself — "a BPF LSM program can deny or allow a device
operation at the outer `inode_mknod`/`file_open` hook" — is still the
target. This variant proves it the same way ch06-synthetic does: a
single sleepable LSM program implements **both** the denier and the
flipper, selected at runtime via a `ctrl_map` stage control.

## BTF-driven hook prune

Three LSM hooks are compiled in. Before loading the skeleton, the
loader consults vmlinux BTF for each `bpf_lsm_<hook>` FUNC and calls
`bpf_program__set_autoload(prog, false)` on any that are absent. This
is the correct source of truth for LSM attach targets — kallsyms has
too many false positives (the `security_<hook>` wrapper can exist while
the `bpf_lsm_<hook>` trampoline stub does not).

| Hook                  | Kernel FUNC              | Status on linuxkit 6.12 aarch64 |
|-----------------------|--------------------------|----------------------------------|
| `lsm.s/inode_mknod`   | `bpf_lsm_inode_mknod`    | present (kept)                  |
| `lsm.s/file_open`     | `bpf_lsm_file_open`      | present (kept)                  |
| `lsm.s/dev_open`      | `bpf_lsm_dev_open`       | absent (pruned)                 |

Without the prune the whole skeleton load fails with
`failed to find kernel BTF type ID of 'dev_open'`.

## Stage control

Each program looks up `ctrl_map[0]`:

| Stage        | Behavior |
|--------------|----------|
| `STAGE_OFF`  | pass through (return 0 from the BPF program; chain result unchanged) |
| `STAGE_DENY` | for char/block dev ops from the target tgid, return `-EPERM` |
| `STAGE_FLIP` | same match, return 0 (proves the flipper primitive end-to-end) |

Runtime controls (signals to the loader PID):

- `SIGUSR1` → stage = `deny`
- `SIGUSR2` → stage = `flip`
- `SIGHUP`  → stage = `off`
- `SIGTERM` → shutdown

## Host prereqs

- Kernel built with `CONFIG_BPF_LSM=y`.
- Boot cmdline: `lsm=…bpf…`. Verify
  `cat /sys/kernel/security/lsm` contains `bpf`.
- `bpftool feature probe | grep lsm_fmod_ret` must show `ok`.
- CAP_SYS_ADMIN on the loader process.

## Build

```
make
```

## Run

```
./build/ch07-devcgroup-houdini-lsm -h
./build/ch07-devcgroup-houdini-lsm -t 0 -p /tmp/ch07.pid -s deny
# then in another shell:
kill -USR2 "$(cat /tmp/ch07.pid)"   # flip

# end-to-end driver:
bash trigger.sh
```

## Evidence

Loader stderr on linuxkit 6.12 aarch64:

```
[ch07] BPF LSM is active — proceeding
[ch07] keep hook=inode_mknod (BTF FUNC bpf_lsm_inode_mknod present)
[ch07] keep hook=file_open   (BTF FUNC bpf_lsm_file_open present)
[ch07] prune hook=dev_open reason="no BTF FUNC bpf_lsm_dev_open"
[ch07] attached lsm.s/inode_mknod
[ch07] attached lsm.s/file_open
[ch07] active — 2 LSM hook(s) attached; target_tgid=0 stage=off pid=1234
```

Loader stdout on a proof run:

```
[ch07] DENY hook=inode_mknod pid=5123 tgid=5123 comm=mknod  major=8 minor=0 verdict=-1 stage=deny
[ch07] FLIP hook=inode_mknod pid=5124 tgid=5124 comm=mknod  major=8 minor=0 verdict=0  stage=flip
```

Trigger proof markers:

```
CH07_PROVEN flipped=<M>
=== CH07_CONCEPT_PROVEN before_rc=<N> after_rc=0 flips=<M> ===
```

## Proof status

**PROVEN** on Ubuntu 6.17.0-29-generic aarch64 (Lima VM). Both variants
(`ch07-devcgroup-houdini` and `ch07-devcgroup-houdini-lsm`) proved.

## Detection

- `bpftool prog list type lsm` shows the attached sleepable programs.
- Audit of `bpf()` syscalls records each program load.
- Unexpected `-EPERM` bursts on char/block mknod while the in-kernel
  cap/cgroup state says operations should succeed.

## Limitations

- The synthesized denial is a property of *our* BPF program, not of a
  real cgroup constraint. Proving the flipper against a real cgroup
  deny requires `bpf_lsm_dev_open` (not present on this kernel) and an
  LSM chain ordering that puts `bpf` ahead of `capability` (not the
  default on any mainstream distro).
- fmod_ret-style LSM attach requires `CAP_SYS_ADMIN` on the loader.
- No audit-record spoofing: a host that monitors per-process mknod
  outcomes will notice the anomaly.
