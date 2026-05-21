// ch06 Silence SELinux — SYNTHETIC variant.
//
// Purpose: prove the primitive "a BPF LSM program can flip a denial to an
// allow" on kernels that lack SELinux (e.g. Docker Desktop's linuxkit 6.12
// aarch64). On such kernels the natural SELinux avc_has_perm path never
// fires, so there is no organic deny for a classic `fmod_ret` to flip.
// Instead we synthesize the deny ourselves, inside BPF, and then also
// demonstrate the flip — both primitives, end to end, in-kernel.
//
// Design: a single sleepable `lsm.s/file_open` program that reads a
// control map to select its current stage:
//
//   stage == STAGE_OFF     → pass through (return 0)
//   stage == STAGE_DENY    → DENIER: return -EACCES for (target_uid, sentinel)
//   stage == STAGE_FLIP    → FLIPPER: match the same (target_uid, sentinel)
//                            but return 0, proving the primitive that turns
//                            a would-be deny into an allow.
//
// We deliberately use a single program with a map-driven toggle because
// LSM fmod_ret hooks short-circuit at the first non-zero return: a
// standalone "denier" program returning -EACCES would prevent a
// subsequent "flipper" program on the same hook from ever running. The
// map toggle models the same attacker capability (deny-then-flip)
// without running into LSM chaining semantics.
//
// The sentinel match uses bpf_d_path() on file->f_path, which requires a
// sleepable LSM program (lsm.s/...). file_open is a clean attachment
// point because it exposes a struct file* and fires on every open(2).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define EACCES 13

#define STAGE_OFF  0
#define STAGE_DENY 1
#define STAGE_FLIP 2

#define SENTINEL_MAX 128

struct ctrl {
    unsigned int stage;
    unsigned int target_uid;
    unsigned int sentinel_len;
    char sentinel[SENTINEL_MAX];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, unsigned int);
    __type(value, struct ctrl);
    __uint(max_entries, 1);
} ctrl_map SEC(".maps");

struct evt {
    unsigned int pid, tgid, uid;
    char comm[16];
    int stage;
    int verdict;       // 0 = allow, -EACCES = deny
    int matched;       // 1 if sentinel/uid matched
    char path[SENTINEL_MAX];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

// Scratch buffer for bpf_d_path output — too big for the BPF stack.
struct path_scratch {
    char buf[SENTINEL_MAX];
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, unsigned int);
    __type(value, struct path_scratch);
    __uint(max_entries, 1);
} scratch SEC(".maps");

static __always_inline int str_eq_n(const char *a, const char *b, int n)
{
    #pragma unroll
    for (int i = 0; i < SENTINEL_MAX; i++) {
        if (i >= n)
            return 1;
        if (a[i] != b[i])
            return 0;
        if (a[i] == 0)
            return 1;
    }
    return 1;
}

SEC("lsm.s/file_open")
int BPF_PROG(ch06_synth_file_open, struct file *file)
{
    unsigned int k = 0;
    struct ctrl *c = bpf_map_lookup_elem(&ctrl_map, &k);
    if (!c)
        return 0;
    if (c->stage == STAGE_OFF)
        return 0;

    unsigned long long ut = bpf_get_current_uid_gid();
    unsigned int uid = (unsigned int)(ut & 0xffffffff);

    // Fast reject: wrong uid → don't bother resolving the path.
    if (uid != c->target_uid)
        return 0;

    struct path_scratch *ps = bpf_map_lookup_elem(&scratch, &k);
    if (!ps)
        return 0;

    long n = bpf_d_path(&file->f_path, ps->buf, sizeof(ps->buf));
    if (n <= 0)
        return 0;

    unsigned int slen = c->sentinel_len;
    if (slen == 0 || slen > SENTINEL_MAX)
        return 0;

    // bpf_d_path returns the number of bytes written including the NUL.
    // We require an exact match on the NUL-terminated full path so the
    // probe only triggers on the sentinel file.
    int matched = str_eq_n(ps->buf, c->sentinel, slen);
    if (!matched)
        return 0;

    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    int verdict = 0;
    if (e) {
        unsigned long long id = bpf_get_current_pid_tgid();
        e->pid = (unsigned int)(id & 0xffffffff);
        e->tgid = (unsigned int)(id >> 32);
        e->uid = uid;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        e->stage = c->stage;
        e->matched = 1;

        #pragma unroll
        for (int i = 0; i < SENTINEL_MAX; i++)
            e->path[i] = ps->buf[i];
    }

    if (c->stage == STAGE_DENY) {
        verdict = -EACCES;
    } else if (c->stage == STAGE_FLIP) {
        // Flipper: the denier would have returned -EACCES here; we
        // return 0 instead. This is the primitive: a BPF LSM program
        // turning a would-be deny into an allow.
        verdict = 0;
    }

    if (e) {
        e->verdict = verdict;
        bpf_ringbuf_submit(e, 0);
    }
    return verdict;
}
