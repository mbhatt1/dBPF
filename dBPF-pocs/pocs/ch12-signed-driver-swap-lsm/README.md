# ch12 LSM variant — REAL module-signature gate override

Sibling POC to `ch12-signed-driver-swap/` (observer: kprobes on
`load_module`, `module_sig_check`, `mod_verify_sig`). This variant
**weaponizes** the observation: on a kernel with `CONFIG_BPF_LSM=y` and
`lsm=bpf,...` in the boot cmdline, it uses fmod_ret on three LSM hooks in
the module-load path:

| Hook | Gates |
|------|-------|
| `security_kernel_read_file` | file-backed kernel reads (modules, firmware, kexec) |
| `security_kernel_load_data` | buffer-backed kernel loads |
| `security_locked_down`      | features disabled by `kernel_lockdown` |

Each returns 0 for targeted tgids whenever the underlying LSM would
have denied — the signature / lockdown gate collapses.

## Primitive
`SEC("lsm.s/kernel_read_file")`, `SEC("lsm.s/kernel_load_data")`,
`SEC("lsm.s/locked_down")` — `.s` = sleepable; fmod_ret replaces the
hook's return value.

## Host prereqs
- `CONFIG_BPF_LSM=y` in the kernel config.
- Boot cmdline contains `bpf` in `lsm=...` (check
  `cat /sys/kernel/security/lsm`).
- `insmod(8)` (from `kmod`); the trigger uses it to feed a fabricated
  fake module through the signature path.
- Typically satisfied by Fedora 38+ default, or any distro after adding
  `lsm=landlock,lockdown,yama,bpf,integrity,apparmor,selinux` to GRUB.
- **Docker Desktop linuxkit** lacks this; the loader prints
  `CH12_SKIP reason="..."` and exits 3.

## Build
```
docker run --rm -v "$PWD/../..":/work -w /work dbpf-selinux \
  bash -c 'cd pocs/ch12-signed-driver-swap-lsm && make'
```

## Run
```
sudo ./build/ch12-signed-driver-swap-lsm -h
sudo ./build/ch12-signed-driver-swap-lsm -a              # flip every deny
sudo ./build/ch12-signed-driver-swap-lsm -t 12345        # targeted tgid
sudo bash trigger.sh                                     # end-to-end demo
```

## Evidence (expected on BPF-LSM host)
```
[ch12] BPF LSM is active - proceeding
[ch12] mode=wildcard
[ch12] active - kernel_read_file/kernel_load_data/locked_down denials will be flipped
[ch12] FLIP hook=kernel_read_file pid=5678 comm=insmod          orig=-74 -> 0
```

### Evidence distinguishes errno shift EBADMSG -> ENOEXEC
The trigger fabricates `/tmp/ch12-fake.ko` with valid ELF magic but a
bogus signature / payload. Two distinct failure modes prove the override
fired:

1. **Baseline** (no BPF): `insmod` returns `EBADMSG` ("Bad message") —
   the kernel's `module_sig_check` / `security_kernel_read_file` gate
   rejected the signature *before* the ELF payload was even consumed.
2. **With BPF**: the same `insmod` call now returns `ENOEXEC` ("Exec
   format error") — the signature gate was bypassed (LSM said "allow"),
   so the kernel progressed into the ELF validator, which then rejected
   the fake payload on its own. The **errno shift EBADMSG -> ENOEXEC** is
   the evidence that the LSM override changed the control flow.

The trigger prints one of:
- `CH12_PROVEN flipped=N hook=kernel_read_file baseline=EBADMSG override=ENOEXEC`
- `CH12_PROVEN flipped=N hook=<name>` (flip fired, errno unchanged)
- `CH12_SKIP reason="..."` when preconditions are unmet.

These markers are what `harness/proof.py` scans for (regex
`CH12_PROVEN|CH12_WEAPON_PROVEN|FLIP\s+hook=`).

## Limitations
- Fails attach on kernels without BPF LSM — loader emits
  `CH12_SKIP reason="..."` and exits 3.
- fmod_ret on LSM hooks requires `CAP_SYS_ADMIN` (not just CAP_BPF).
- The errno shift depends on in-tree modules and post-gate validators.
  On kernels with `CONFIG_MODULE_SIG_FORCE=y` and stricter downstream
  checks, the final errno may remain the same even though the LSM flip
  fired — the FLIP event in the ringbuf is still the primary evidence.
- `kernel_load_data` and `locked_down` hooks only fire on paths that
  reach them (e.g. `request_firmware`, `kexec_file_load`, lockdown-gated
  features). A plain `insmod` typically only triggers
  `kernel_read_file`.

## Blog post

See the chapter write-up: [`2025-03-01-ebpf-signed-driver-swap`](../../../_posts/2025-03-01-ebpf-signed-driver-swap.md) in the Diabolical eBPF Field Manual.
