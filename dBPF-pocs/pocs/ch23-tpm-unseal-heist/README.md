# Ch23 — TPM Unseal Heist

**Category**: REAL
**Primitive**: `kretprobe/tpm2_unseal_trusted` reads `struct trusted_key_payload->key[0..key_len]` via `bpf_probe_read_kernel` during the window between TPM unseal and consumer use.
**Hook(s)**: `kprobe/tpm2_unseal_trusted` + `kretprobe/tpm2_unseal_trusted`
**Architecture**: aarch64 + x86_64

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

On a kernel with TPM2 + trusted keys: expect `[ch23] CAPTURE ... captured=32 key_bytes=<hex>` and the marker `CH23_PROVEN key_bytes_captured=32`.

On a kernel without: expect `CH23_SKIP` with the reason text identifying which precondition failed.

## Detection

- `bpftool prog list type kprobe` shows `kret_tpm2_unseal` attached to `tpm2_unseal_trusted`. No legitimate observability tool hooks this symbol.
- `/sys/kernel/debug/kprobes/list` — grep for `tpm2_unseal_trusted` returns non-empty iff a program like this is attached.
- `bpf(2)` auditd records for `BPF_PROG_LOAD` (command id `5`) show the loading PID/UID. Chapter 22's inventory step enumerates which processes are allowed to load BPF programs; trusted-key consumers should not be in that set.

The capture (the `bpf_probe_read_kernel` of `p->key[]`) leaves no audit trace. Detection must happen at load time, not run time.

## Mitigation

- Do not colocate `CAP_BPF` holders (observability agents, CI runners) with trusted-key consumers (`cryptsetup` on TPM-enrolled LUKS volumes, IMA-EVM, systemd-credentials).
- Prefer per-operation HSM signing (`TPM2_CC_Sign`, `TPM2_CC_RSA_Decrypt`) to unseal-plus-use where the workload can afford the latency. The unseal path is where this primitive lives; per-op signing never touches kernel memory with plaintext.
- Track the LKML "trusted keys in encrypted memory" proposal. When it merges, the `bpf_probe_read_kernel` of `p->key[]` will return ciphertext.
