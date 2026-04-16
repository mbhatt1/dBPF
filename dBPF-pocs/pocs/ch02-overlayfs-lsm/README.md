# ch02 OverlayFS Trojan — LSM variant

Sibling POC to `ch02-overlayfs/`. The chapter's full claim is "inject
payload during copy-up" — a true inject requires a userspace racer that
tampers with the upper-layer file in the narrow window between
`inode_copy_up` and the next `vfs_read`. This POC delivers the **first
exploit primitive**: selective **DENY** of copy-up for sensitive
basenames, combined with an observer on `inode_permission` so the
attacker knows which processes to race.

## Primitive
- `SEC("lsm.s/inode_copy_up")` — sleepable `fmod_ret` on the overlay
  copy-up LSM hook. Returning `-EPERM` prevents the upper layer from
  ever receiving a writable copy, so readers keep hitting the lower
  layer (which an attacker with write access to the lower backing
  store controls).
- `SEC("lsm.s/inode_permission")` — observer, records access attempts
  on targeted basenames.

Basename matching (not full-path) is used because LSM inode hooks see
`struct dentry` / `struct inode`, and a reliable full-path walk from a
BPF program is not practical. Basenames are the cheapest filter that
still produces useful exploit semantics for this primitive.

## Host prereqs
- `CONFIG_BPF_LSM=y`.
- `cat /sys/kernel/security/lsm` must include `bpf` (boot cmdline
  `lsm=...,bpf,...`).
- `CONFIG_OVERLAY_FS=y`.
- `security_inode_copy_up` LSM hook — present since **Linux 4.10**
  (introduced alongside overlay cred switching).
- `CAP_SYS_ADMIN` to attach fmod_ret LSM programs.

## Build
```
docker run --rm -v "$PWD/../..":/work -w /work dbpf-selinux \
  bash -c 'cd pocs/ch02-overlayfs-lsm && make'
```

## Run
```
sudo ./build/ch02-overlayfs-lsm -p secret.txt
sudo bash trigger.sh
```

## Evidence (expected on BPF-LSM host)
```
[ch02-lsm] BPF LSM is active — proceeding
[ch02-lsm] protecting basename=secret.txt
[ch02-lsm] active — copy-up for targeted basenames will be denied
[ch02-lsm] PERMISSION pid=1234 comm=bash   name=secret.txt   observed
[ch02-lsm] COPY_UP    pid=1234 comm=bash   name=secret.txt   -> DENIED (-EPERM)
```
From `trigger.sh`: baseline copy-up succeeds and the upper dir ends up
with a `secret.txt`; with the BPF program loaded the write returns
`EPERM` and the upper dir stays empty.

## Limitations
- Basename filter — a policy that demands full-path matching must do
  dentry-walk in a loop bounded by the verifier, or offload to a
  userspace helper via ringbuf.
- Full "inject payload" requires a userspace racer; this POC is the
  gating primitive, not the complete exploit.
- `lsm.s/inode_copy_up` fires only on overlay copy-up; other forms of
  writable-access escalation (e.g. direct writes to upperdir) are not
  intercepted here.

## Blog post

See the chapter write-up: [`2025-02-01-the-overlayfs-trojan-horse`](../../../_posts/2025-02-01-the-overlayfs-trojan-horse.md) in the Diabolical eBPF Field Manual.
