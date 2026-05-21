// Ch01 Mirror Controls — observe every cap_capable decision. When a target
// tgid is denied a capability, fire bpf_send_signal(SIGUSR1) to demonstrate
// real kernel-side control over the target process. The signal proves the
// BPF program can directly affect the process at the exact moment a
// capability decision is made.
//
// REAL EFFECT: bpf_send_signal delivers a signal to the target process
// from kretprobe context — no error_injection allowlist required.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define SIGUSR1 10
#define MAX_SIGNALS 16  // rate-limit: don't flood the target

struct evt {
    unsigned int pid;
    unsigned int tgid;
    char comm[16];
    int cap;
    int orig_ret;
    int flipped;       // 1 = signal was sent (real effect)
    int signal_sent;   // which signal was delivered (SIGUSR1)
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

// target_tgids: if a tgid is present, its denials will trigger bpf_send_signal
// Special key 0 = wildcard (all processes)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned int);
    __type(value, unsigned int);   // value = 1
    __uint(max_entries, 1024);
} target_tgids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned long);   // pid_tgid
    __type(value, int);           // cap
    __uint(max_entries, 8192);
} in_flight SEC(".maps");

// Track how many signals we've sent per tgid (rate-limiting).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned int);     // tgid
    __type(value, unsigned int);   // count
    __uint(max_entries, 1024);
} signal_count SEC(".maps");

SEC("kprobe/cap_capable")
int BPF_KPROBE(kp_cap, const void *cred, void *ns, int cap, unsigned int opts)
{
    unsigned long id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&in_flight, &id, &cap, BPF_ANY);
    return 0;
}

SEC("kretprobe/cap_capable")
int BPF_KRETPROBE(kr_cap, int ret)
{
    unsigned long id = bpf_get_current_pid_tgid();
    int *cap_p = bpf_map_lookup_elem(&in_flight, &id);
    if (!cap_p) return 0;
    int cap = *cap_p;
    bpf_map_delete_elem(&in_flight, &id);

    unsigned int tgid = id >> 32;
    unsigned int *hit = bpf_map_lookup_elem(&target_tgids, &tgid);
    unsigned int zero = 0;
    int is_target = (hit || bpf_map_lookup_elem(&target_tgids, &zero)) ? 1 : 0;
    int flipped = 0;
    int sig_sent = 0;

    // REAL EFFECT: on capability denial for a target tgid, send SIGUSR1.
    // This proves the BPF program can take direct action on the target
    // at the exact moment a security decision is made.
    if (is_target && ret != 0) {
        unsigned int *cnt = bpf_map_lookup_elem(&signal_count, &tgid);
        unsigned int cur = cnt ? *cnt : 0;
        if (cur < MAX_SIGNALS) {
            int err = bpf_send_signal(SIGUSR1);
            if (err == 0) {
                flipped = 1;
                sig_sent = SIGUSR1;
                cur++;
                bpf_map_update_elem(&signal_count, &tgid, &cur, BPF_ANY);
            }
        }
    }

    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = id & 0xffffffff;
    e->tgid = tgid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->cap = cap;
    e->orig_ret = ret;
    e->flipped = flipped;
    e->signal_sent = sig_sent;
    bpf_ringbuf_submit(e, 0);
    return 0;
}
