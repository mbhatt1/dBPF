# Ch23 — TPM Unseal Heist

**Status**: PROVEN (full plaintext byte-capture — 32 real key bytes read at `tpm2_unseal_trusted` from a genuine TPM2 unseal)
**Category**: REAL
**Primitive**: `kretprobe/tpm2_unseal_trusted` reads `struct trusted_key_payload->key[0..key_len]` via CO-RE `bpf_core_read` during the window between TPM unseal and consumer use.
**Hook(s)**: `kprobe/tpm2_unseal_trusted` + `kretprobe/tpm2_unseal_trusted`
**Architecture**: aarch64 + x86_64
**Verified on**: Ubuntu 25.10, kernel 6.17.0-19-generic aarch64 — Lima **qemu** VM (`dbpf-tpm`) on Apple Silicon, with an swtpm TPM2 attached at boot via QEMU `-device tpm-tis-device` (HVF-accelerated `qemu-system-aarch64`).

## Verification notes (Ubuntu 25.10 qemu Lima VM with boot-attached swtpm)

Unlike a `vmType: vz` VM (which cannot attach a TPM at boot, so the trusted-key
type binds to no TPM and `keyctl add trusted` fails), this VM boots with a
swtpm-backed `tpm-tis-device`. The kernel detects it at boot
(`tpm_tis MSFT0101:00: 2.0 TPM`) and the trusted-key type binds to it
(`Key type trusted registered`), so trusted keys can be created and unsealed.

Real capture (via `trigger.sh`):

```
[ch23] INTERCEPT pid=20979 comm=keyctl kind=entry
[ch23] CAPTURE pid=20979 comm=keyctl captured=32 key_bytes=814712ab534a5138c6322e5c00d69fdae2768dfd51e1d1a1c76f6f6c9e3fdef2
=== CH23_PROVEN key_bytes_captured=32 captures=1 kind=trusted-plaintext ===
```

Genuineness cross-check: loading the *same* sealed blob three times produced
byte-identical plaintext each time (a deterministic `TPM2_CC_Unseal` of a fixed
blob), confirming the captured bytes are the true unsealed key, not garbage.

Proof marker: `CH23_PROVEN key_bytes_captured=32 captures=1 kind=trusted-plaintext`

### Two real bugs fixed to make the capture fire

1. **Wrong struct offsets in the BPF program.** `struct trusted_key_payload`
   begins with a 16-byte `struct callback_head rcu`, so `key_len` is at offset
   16 and `key[]` at offset 26 — not 0 and 4 as the original hard-coded reads
   assumed. Reading offset 0 pulled the rcu `next` pointer as `key_len`, which
   failed the `key_len > MAX_KEY_LEN` sanity check, so no event was emitted. Now
   read via CO-RE (`bpf_core_read(&p->key_len)` / `&p->key`), version-independent.
2. **`trigger.sh` never fired the unseal.** It created a key with `new 32` then
   ran `keyctl print`, which only returns the *already-sealed* blob and does not
   call `tpm2_unseal_trusted`. The unseal fires on the **load** path: export the
   sealed blob and `keyctl add trusted ... "load <blob>"`, which runs
   `TPM2_CC_Unseal` and lands the plaintext in `payload->key[]`. The trigger now
   does seal→export→load.

On modern kernels (~6.10+) TPM2 trusted-key seal also needs a persistent parent
(SRK). If systemd-tpm2-setup has not persisted one, the bare `new 32` seal
returns EINVAL (`trusted_key: key_seal failed (-22)`); the trigger provisions a
persistent SRK at `0x81000001` and references it via `keyhandle=`.

## What this demonstrates

The Linux kernel's trusted-key type wraps a payload in a TPM-sealed blob. When a consumer needs the plaintext — LUKS master-key seeds (`systemd-cryptenroll`), IMA-EVM HMAC keys, systemd credentials with `--with-key=tpm2` — the kernel calls `tpm2_unseal_trusted`, which issues `TPM2_CC_Unseal`, copies the plaintext into `struct trusted_key_payload->key[]`, and returns. A BPF retrobe on that function captures the plaintext from kernel memory the moment it lands, before any consumer uses it.

The primitive is a retargeting of the Chapter 8 keyring-heist pattern at a different payload-bearing struct. Same class of read; different kind of key. The TPM is not bypassed — it correctly performed the unseal the authorized caller asked for — but once the plaintext is in kernel memory, `CAP_BPF` reaches it.

## What this does NOT do

- Does not bypass the TPM's sealing policy. If the PCRs/authorization do not match, the unseal fails upstream and no plaintext ever lands in the payload.
- Does not reach keys held in TPM slots for in-hardware signing/decryption (`TPM2_CC_Sign`, `TPM2_CC_RSA_Decrypt`). Those keys never enter kernel memory.
- Does not fire on kernels without `CONFIG_TRUSTED_KEYS=y` or without a TPM2 backend. The loader skips cleanly on linuxkit 6.12 aarch64.

## Prerequisites

- Kernel with `CONFIG_TRUSTED_KEYS=y` (or =m and loaded) and `CONFIG_TCG_TPM2=y`
- `/dev/tpm0` or `/dev/tpmrm0` present (hardware TPM or software emulator via `swtpm`)
- `CAP_BPF` + `CAP_PERFMON` (or `CAP_SYS_ADMIN`)
- `keyctl` (from keyutils) available in the trigger environment

Typical environments: Fedora 38+, RHEL 9+, Ubuntu 22.04+ with TPM2 hardware or `swtpm` emulation. The book's secondary Fedora 42 aarch64 QEMU VM (`dBPF-pocs/run-qemu-tests.sh`) has all of these.

## Files

| File | Purpose |
|------|---------|
| `ch23-tpm-unseal-heist.bpf.c` | Kernel-side BPF program (kprobe+kretprobe on `tpm2_unseal_trusted`) |
| `ch23-tpm-unseal-heist.c`     | Userspace loader with kallsyms preflight + ringbuf drain |
| `trigger.sh`                   | Activity generator — creates a trusted key, triggers unseal, checks markers |
| `Makefile`                     | Build (uses `shared/common.mk`) |

## Build & Run

```bash
# Inside the harness container (or Fedora QEMU):
make
sudo ./build/ch23-tpm-unseal-heist &
# In another terminal:
bash trigger.sh
```

`trigger.sh` runs the loader itself, provisions a persistent SRK if needed,
seals a trusted key, then loads the sealed blob back (the unseal). On a kernel
with TPM2 + trusted keys and a **boot-attached** TPM backend: expect
`[ch23] CAPTURE ... captured=32 key_bytes=<hex>` and the marker
`CH23_PROVEN key_bytes_captured=32 captures=1 kind=trusted-plaintext`.

Reproducing the boot-attached TPM on Apple Silicon (this repo): a `vmType: vz`
Lima VM cannot attach a TPM at boot. Use a `vmType: qemu` VM with the native
HVF-accelerated `qemu-system-aarch64` and inject an swtpm TPM at boot. Lima has
no config field for arbitrary QEMU args, so a PATH-shim wrapper around
`qemu-system-aarch64` appends `-chardev socket,id=chrtpm,path=<swtpm-sock>
-tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis-device,tpmdev=tpm0`,
with `swtpm socket --tpm2 --ctrl type=unixio,path=<sock>` started before boot.

On a kernel without `tpm2_unseal_trusted` in kallsyms: expect `CH23_SKIP` with the reason text identifying which precondition failed.

## Detection

- `bpftool prog list type kprobe` shows `kret_tpm2_unseal` attached to `tpm2_unseal_trusted`. No legitimate observability tool hooks this symbol.
- `/sys/kernel/debug/kprobes/list` — grep for `tpm2_unseal_trusted` returns non-empty iff a program like this is attached.
- `bpf(2)` auditd records for `BPF_PROG_LOAD` (command id `5`) show the loading PID/UID. Chapter 22's inventory step enumerates which processes are allowed to load BPF programs; trusted-key consumers should not be in that set.

The capture (the `bpf_probe_read_kernel` of `p->key[]`) leaves no audit trace. Detection must happen at load time, not run time.

## Mitigation

- Do not colocate `CAP_BPF` holders (observability agents, CI runners) with trusted-key consumers (`cryptsetup` on TPM-enrolled LUKS volumes, IMA-EVM, systemd-credentials).
- Prefer per-operation HSM signing (`TPM2_CC_Sign`, `TPM2_CC_RSA_Decrypt`) to unseal-plus-use where the workload can afford the latency. The unseal path is where this primitive lives; per-op signing never touches kernel memory with plaintext.
- Track the LKML "trusted keys in encrypted memory" proposal. When it merges, the `bpf_probe_read_kernel` of `p->key[]` will return ciphertext.
