# ch08 LSM variant — REAL keyring-permission override

Sibling POC to `ch08-keyring-heist/` (pure observer: kprobe
`key_task_permission` + `lookup_user_key`, emits type/desc/serial events).
This variant **weaponizes** the observation: on a kernel with
`CONFIG_BPF_LSM=y` and `lsm=bpf,...` in the boot cmdline, it uses
fmod_ret on `security_key_permission` to flip deny -> allow for targeted
tgids. LSM fmod_ret is a first-class override primitive — no
error_injection allowlist, no tracefs tricks.

## Primitive
`SEC("lsm.s/key_permission")` — the `.s` suffix marks the program
sleepable; fmod_ret semantics let the program's return value replace the
LSM hook's.

Signature (matches `security_key_permission`):
```c
int BPF_PROG(lsm_key_permission,
             key_ref_t key_ref,
             const struct cred *cred,
             unsigned int need_perm,
             int ret)
```
`key_ref_t` packs a `struct key *` with the low 2 bits reserved for
"possession" flags — we mask those off and BPF_CORE_READ `serial` and
`type->name` for the event.

## Host prereqs
- `CONFIG_BPF_LSM=y` in the kernel config.
- Boot cmdline contains `bpf` in `lsm=...` (check
  `cat /sys/kernel/security/lsm`).
- `keyctl(1)` from `keyutils` (the trigger uses it).
- Typically satisfied by Fedora 38+ default, or any distro after adding
  `lsm=landlock,lockdown,yama,bpf,integrity,apparmor,selinux` to GRUB.
- **Docker Desktop linuxkit** lacks this; the loader prints
  `CH08_SKIP reason="..."` and exits 3.

## Build
```
docker run --rm -v "$PWD/../..":/work -w /work dbpf-selinux \
  bash -c 'cd pocs/ch08-keyring-heist-lsm && make'
```

## Run
```
sudo ./build/ch08-keyring-heist-lsm -h
sudo ./build/ch08-keyring-heist-lsm -a              # flip every deny
sudo ./build/ch08-keyring-heist-lsm -t 12345        # targeted tgid
sudo bash trigger.sh                                # end-to-end demo
```

## Evidence (expected on BPF-LSM host)
```
[ch08] BPF LSM is active - proceeding
[ch08] mode=wildcard
[ch08] active - key_permission denials for targeted tgids will be flipped
[ch08] FLIP pid=1234 serial=0x2bd1a0e3 type=user            orig=-13 -> 0 (granted)
```
And from the trigger: the unprivileged `dut08` user's
`keyctl print $KEY_ID` **succeeds** with BPF loaded (vs `Permission
denied` / `EACCES` baseline).

The trigger prints one of:
- `CH08_PROVEN flipped=N` on success (N ≥ 1),
- `CH08_SKIP reason="..."` when preconditions are unmet.

These markers are what `harness/proof.py` scans for (regex
`CH08_PROVEN|CH08_WEAPON_PROVEN|FLIP\s+pid=`).

## Proof status

**PROVEN** on Ubuntu 6.17.0-29-generic aarch64 (Lima VM). Uses
`bpf_probe_read_kernel` to exfiltrate keyring data via the raw-context
workaround (bypasses BPF_PROG macro to avoid the BTF FWD issue on
`key_ref_t` at ctx[0]). All three variants proved.

## Limitations
- Fails attach on kernels without BPF LSM — loader emits
  `CH08_SKIP reason="..."` and exits 3.
- fmod_ret on LSM hooks requires `CAP_SYS_ADMIN` (not just CAP_BPF).
- Some hardened kernels short-circuit `key_permission` inside
  `key_task_permission` before the LSM hook is reached for revoked or
  uninstantiated keys — those paths won't flip.
