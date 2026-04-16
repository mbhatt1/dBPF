# ch08 Keyring Heist — KPROBE variant

Sibling POC to `ch08-keyring-heist/` (observer) and `ch08-keyring-heist-lsm/`
(real LSM override). This variant exists to sidestep a BTF-specific
loader failure: on some kernels (observed on linuxkit 6.12 aarch64) the
BTF metadata for `security_key_permission` forward-declares `struct key`
(BTF FWD kind) instead of defining it, so the verifier refuses the LSM
`fmod_ret` program with:

```
arg0 type FWD is not a struct
```

even though `struct key` is fully defined in `vmlinux.h`.

This variant attaches as kprobes at `key_task_permission` and
`lookup_user_key` instead. Kprobe programs take `struct pt_regs *`; we
pull the first argument out via `PT_REGS_PARM1` as an opaque pointer and
let CO-RE resolve `struct key` fields against `vmlinux.h`, which is
unaffected by the LSM hook's FWD-typed BTF.

Clearly marked as a variant: this is READ-ONLY observation from the
access-denied syscall path. It does not mutate the syscall return, does
not alter the kernel's access decision, and does not touch credentials.
For actual override, use `ch08-keyring-heist-lsm/` on a kernel whose BTF
doesn't forward-declare `struct key`.

## Mechanism

Kprobe both call sites that carry a `struct key *` at their first
argument. From each, CO-RE reads
`{serial, type->name, description}` and emits a ringbuf event. The
kernel keeps executing the access check normally; the BPF program just
observes the pointer the kernel is already about to use.

## Hook(s)

- `kprobe/key_task_permission`
- `kprobe/lookup_user_key`

## Host prereqs

- Both symbols present in `/proc/kallsyms` (true on linuxkit 6.12 aarch64).
- CO-RE BTF available (vmlinux BTF shipped with the kernel).
- `keyctl(1)` from `keyutils` (the trigger uses it).

## Build / Run

```
cd pocs/ch08-keyring-heist-kprobe && make
sudo ./build/ch08-keyring-heist-kprobe
sudo bash trigger.sh
```

## Evidence

Per-event loader lines:
```
[ch08k] hook=key_task_permission pid=12345 comm=keyctl serial=0x2bd1a0e3 type=user desc='ch08-research-entry'
```

Trigger verdict line (note: syscall rc unchanged; only the side-stream
reveals metadata):
```
=== CH08_CONCEPT_PROVEN syscall_rc_unchanged=yes description_in_ringbuf=yes ===
```

On missing prereqs, both loader and trigger emit
`CH08K_SKIP reason="..."` and exit 0.

## Limitations

- Observer-only. The unprivileged `keyctl print` still returns EACCES
  before and after attach — the kernel's access decision is preserved.
- Does not read `key->payload` (that would require invoking the key's
  `type->read` method, which isn't safe from BPF).
- Kprobe attachment is kernel-version sensitive on function signatures;
  argument position is currently fixed at PARM1 for both hooks.

## Blog post

See the chapter write-up: [`2025-02-08-keyring-heist`](../../../_posts/2025-02-08-keyring-heist.md) in the Diabolical eBPF Field Manual.
