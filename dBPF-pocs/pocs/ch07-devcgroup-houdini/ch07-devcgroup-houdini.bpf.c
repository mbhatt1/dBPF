// ch07 devcgroup-houdini: kprobe devcgroup_check_permission + kretprobe
// that delivers bpf_send_signal(SIGUSR2) on every DENIAL for a target tgid.
//
// REAL EFFECT: when a device cgroup denies access (returns -EPERM), the
// BPF program sends SIGUSR2 to the calling process. The trigger catches
// the signal as proof that BPF can intercept and react to device-cgroup
// decisions in real time. Additionally, the BPF program reads and exfils
// the full device major:minor + access mode from kernel context.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define SIGUSR2 12
#define MAX_SIGNALS 32

struct evt {
    unsigned int pid;
    unsigned int tgid;
    char comm[16];
    int hook;           // 1=devcgroup_check_permission 2=__devcgroup_check_permission
    short type;         // S_IFCHR==2 S_IFBLK==6
    unsigned int major;
    unsigned int minor;
    int access;
    int verdict;        // populated by kretprobe
    int signal_sent;    // 1 if SIGUSR2 was delivered
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned long);
    __type(value, struct evt);
    __uint(max_entries, 8192);
} inflight SEC(".maps");

// target_tgids: tgids whose denials trigger bpf_send_signal.
// Key=0 means wildcard (signal on all denials).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned int);
    __type(value, unsigned int);
    __uint(max_entries, 1024);
} target_tgids SEC(".maps");

// Rate-limit signals per tgid.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned int);
    __type(value, unsigned int);
    __uint(max_entries, 1024);
} signal_count SEC(".maps");

SEC("kprobe/devcgroup_check_permission")
int BPF_KPROBE(kp_dcp, short type, unsigned int major, unsigned int minor, int access)
{
    struct evt e = {};
    unsigned long id = bpf_get_current_pid_tgid();
    e.pid = id & 0xffffffff;
    e.tgid = id >> 32;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    e.hook = 1;
    e.type = type;
    e.major = major;
    e.minor = minor;
    e.access = access;
    e.verdict = 0;
    e.signal_sent = 0;
    bpf_map_update_elem(&inflight, &id, &e, BPF_ANY);
    return 0;
}

SEC("kretprobe/devcgroup_check_permission")
int BPF_KRETPROBE(kr_dcp, int ret)
{
    unsigned long id = bpf_get_current_pid_tgid();
    struct evt *p = bpf_map_lookup_elem(&inflight, &id);
    if (!p) return 0;
    p->verdict = ret;
    p->signal_sent = 0;

    // REAL EFFECT: on denial (ret != 0) for target tgids, send SIGUSR2.
    if (ret != 0) {
        unsigned int tgid = p->tgid;
        unsigned int zero = 0;
        int is_target = (bpf_map_lookup_elem(&target_tgids, &tgid) ||
                         bpf_map_lookup_elem(&target_tgids, &zero)) ? 1 : 0;
        if (is_target) {
            unsigned int *cnt = bpf_map_lookup_elem(&signal_count, &tgid);
            unsigned int cur = cnt ? *cnt : 0;
            if (cur < MAX_SIGNALS) {
                int err = bpf_send_signal(SIGUSR2);
                if (err == 0) {
                    p->signal_sent = 1;
                    cur++;
                    bpf_map_update_elem(&signal_count, &tgid, &cur, BPF_ANY);
                }
            }
        }
    }

    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        __builtin_memcpy(e, p, sizeof(*e));
        bpf_ringbuf_submit(e, 0);
    }
    bpf_map_delete_elem(&inflight, &id);
    return 0;
}
