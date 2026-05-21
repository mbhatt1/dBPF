// ch01 Mirror Controls — REAL mutation variant using BPF LSM fmod_ret.
//
// On a kernel built with CONFIG_BPF_LSM=y and booted with `lsm=bpf,...` in
// the cmdline, this program overrides `security_capable` to return 0 (cap
// granted) for tgids in the target_tgids map. Unlike the kprobe-based
// variant, fmod_ret on LSM hooks is NOT gated by the error_injection
// allowlist — LSM is the first-class override primitive.
//
// Verify prerequisites on the host before running:
//   cat /sys/kernel/security/lsm      # must contain "bpf"
//   bpftool feature probe | grep lsm  # must show "lsm_fmod_ret ok"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct evt {
    unsigned int pid, tgid;
    char comm[16];
    int cap;
    int orig_ret;
    int flipped;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned int);
    __type(value, unsigned int);
    __uint(max_entries, 1024);
} target_tgids SEC(".maps");

// lsm/capable fmod_ret: signature must match
//   int security_capable(const struct cred *cred, struct user_namespace *ns,
//                        int cap, unsigned int opts)
// Return value: 0 = allow, -EPERM = deny. We intercept the ret arg and rewrite.
SEC("lsm.s/capable")
int BPF_PROG(lsm_capable,
             const struct cred *cred,
             struct user_namespace *ns,
             int cap,
             unsigned int opts,
             int ret)
{
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
        e->cap = cap;
        e->orig_ret = ret;
        e->flipped = flipped;
        bpf_ringbuf_submit(e, 0);
    }
    return new_ret;
}
