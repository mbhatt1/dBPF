# Restore-POCs spec — proof markers, honest skips, harness contract

## Reference templates (already working, mimic exactly)
- Observer (non-LSM) 5-file template:
    pocs/ch01-mirror-controls/{ch01-mirror-controls.bpf.c,ch01-mirror-controls.c,Makefile,trigger.sh,README.md}
  Key features: getopt (-a/-t/-h), kallsyms preflight with `set_autoload(false)`,
  sigaction cleanup, `[ch01] tag=... field=...` tab-separated log format,
  events=stdout / status=stderr, -Wall -Wextra -Werror clean.
- LSM-variant 5-file template:
    pocs/ch01-mirror-controls-lsm/{ch01-mirror-controls-lsm.bpf.c,ch01-mirror-controls-lsm.c,Makefile,trigger.sh,README.md}
  Uses SEC("lsm.s/<hook>") fmod_ret. Loader checks /sys/kernel/security/lsm
  contains "bpf"; exits 3 with clear error if not.

## Harness contract — proof markers

Harness is at `harness/proof.py`. Each POC's loader/trigger MUST emit one of:
- `CHxx_PROVEN <details>`  when the weaponization succeeds (at least once).
- `CHxx_SKIP reason="..."`  when honest-skip conditions are detected at runtime
   (missing kernel feature, arch mismatch, SELinux not loaded, etc.).

The harness scans ALL streams (loader stdout/stderr + trigger stdout/stderr)
for these regexes, so prints can come from either.

## POCs to restore (10)

### Observer variants (non-LSM)
#### ch06-silence-selinux
- Hooks: kprobe `avc_has_perm`, `avc_has_perm_noaudit`, `selinux_file_permission`
- Linuxkit aarch64 HAS NONE — loader prints `CH06_SKIP reason="SELinux not loaded (/sys/kernel/security/lsm lacks selinux)"` and exits.
- On a SELinux host, each decision → ringbuf event; document the override path is BPF LSM (point to ch06-silence-selinux-lsm).

#### ch07-devcgroup-houdini
- Hooks: kprobe `devcgroup_check_permission` and inner `__devcgroup_check_permission`.
- Streams {pid, comm, type, major, minor, access, verdict}.
- trigger.sh: creates temp mknod, reads /dev/null/zero/mem. Print `CH07_PROVEN type=char/block count=N` when ≥1 deny observed; else `CH07_SKIP reason="no deny observed"`.

#### ch08-keyring-heist
- Hooks: kprobe `key_task_permission`, `lookup_user_key`.
- trigger.sh: keyctl add user → read → revoke; ringbuf emits type/desc/serial.
- Print `CH08_PROVEN events=N` on ≥3 captured checks.

#### ch12-signed-driver-swap
- Hooks: kprobe `mod_verify_sig`, `module_sig_check`, `load_module` (at least one).
- trigger.sh: modprobe non-existent, insmod a fake .ko (8B ELF header); expect EBADMSG.
- Print `CH12_PROVEN hook=<name>` on first hit.

#### ch13-powercap-override
- Hooks: `powercap_register_control_type`, `powercap_set_max_power_uw`, `powercap_get_max_power_uw`, `thermal_zone_device_update`.
- linuxkit aarch64 has NONE — print `CH13_SKIP reason="no powercap/RAPL symbols (x86-only subsystem)"` and exit 2.
- Harness already has `skip_reason` set; POC needs to match.

#### ch17-acpi-wsmi
- Hooks: acpi_* (mostly x86) + firmware_request/_request_firmware/firmware_request_nowarn (aarch64 fallback).
- Loader prints symbol availability. If ONLY firmware-* present, attach those and print `ACPI_PROBE_PROVEN arch=aarch64 substituted=firmware_loader` (honest substitution).
- If none present, `CH17_SKIP reason="no acpi nor firmware symbols"`.

### LSM-variant POCs (mutate via fmod_ret)
#### ch06-silence-selinux-lsm
- `SEC("lsm.s/file_permission")`, `SEC("lsm.s/inode_permission")`, `SEC("lsm.s/bprm_check_security")` fmod_ret → 0 for target_tgids.
- trigger.sh: requires /sys/kernel/security/lsm to contain both "bpf" AND "selinux"; prints `CH06_SKIP reason="..."` if either missing. On a BPF-LSM+SELinux host: baseline denial of labeled access, BPF-assisted success, print `CH06_PROVEN flipped=N`.

#### ch07-devcgroup-houdini-lsm
- `SEC("lsm.s/inode_mknod")` + `SEC("lsm.s/file_open")` + `SEC("lsm.s/dev_open")` fmod_ret → 0.
- trigger.sh: create restricted devcgroup; inside try mknod/open /dev/mem; baseline EPERM, with BPF allow. Print `CH07_PROVEN flipped=N`. Skip with reason if LSM missing.

#### ch08-keyring-heist-lsm
- `SEC("lsm.s/key_permission")` fmod_ret → 0.
- trigger.sh: root creates key with `setperm 0x3f010000`; unpriv user `keyctl print $ID` fails baseline; with BPF succeeds. Print `CH08_PROVEN flipped=N`. Skip with reason if LSM missing.

#### ch12-signed-driver-swap-lsm
- `SEC("lsm.s/kernel_read_file")` + `SEC("lsm.s/kernel_load_data")` + `SEC("lsm.s/locked_down")` fmod_ret → 0.
- trigger.sh: insmod fake.ko; baseline EBADMSG; with BPF override fires (full insmod still fails with ENOEXEC but the signature gate is bypassed — demonstrate ret code shift). Print `CH12_PROVEN flipped=N hook=...`.

## Build command
    docker run --rm -v "$PWD":/work -w /work dbpf-base \
      bash -c 'cd pocs/<dir> && make'
For LSM variants, use `dbpf-selinux` image.

## Harness run command
    bash harness/run.sh                         # full TUI
    bash harness/run.sh --only ch06,ch07,...    # subset (if supported)
