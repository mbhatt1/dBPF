# ch01 LSM variant — REAL capability override

Sibling POC to `ch01-mirror-controls/`. The original uses kprobe/kretprobe
on `cap_capable` and calls `bpf_override_return` — **blocked** by the
error_injection allowlist on most kernels (including Docker Desktop
linuxkit 6.12). This variant uses the first-class primitive: BPF LSM
`fmod_ret` on `security_capable`.

## Primitive
`SEC("lsm.s/capable")` — the `.s` suffix means sleepable; `fmod_ret`
semantics let the program's return value replace the LSM hook's.

## Host prereqs
- `CONFIG_BPF_LSM=y` in the kernel config.
- Boot cmdline contains `bpf` in `lsm=...` (check
  `cat /sys/kernel/security/lsm`).
- Typically satisfied by: Fedora 38+ default, or any distro after adding
  `lsm=landlock,lockdown,yama,bpf,integrity,apparmor,selinux` to GRUB.
- **Docker Desktop linuxkit** lacks this; use `dbpf-selinux` image on a
  proper Linux VM or bare host.

## Build
```
docker run --rm -v "$PWD/../..":/work -w /work dbpf-selinux \
  bash -c 'cd pocs/ch01-mirror-controls-lsm && make'
```

## Run
```
sudo ./build/ch01-mirror-controls-lsm --help
sudo ./build/ch01-mirror-controls-lsm -a             # flip every deny
sudo ./build/ch01-mirror-controls-lsm -t 12345       # targeted tgid
sudo bash trigger.sh                                 # end-to-end demo
```

## Evidence (expected on BPF-LSM host)
```
[ch01-lsm] BPF LSM is active — proceeding
[ch01-lsm] mode=wildcard
[ch01-lsm] active — cap denials for targeted tgids will be flipped
[ch01-lsm] FLIP pid=1234 comm=cat             cap=2 orig=-1 -> 0 (allowed)
```
And from the trigger: `cat /etc/shadow` as the unprivileged user
**succeeds** with BPF loaded (vs `Permission denied` baseline).

## Limitations
- Fails attach on kernels without BPF LSM — loader exits with code 3
  and a clear diagnostic.
- fmod_ret on LSM hooks requires `CAP_SYS_ADMIN` (not just CAP_BPF).

## Blog post

See the chapter write-up: [`2025-01-31-the-mirror-controls`](../../../_posts/2025-01-31-the-mirror-controls.md) in the Diabolical eBPF Field Manual.
