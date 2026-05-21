// Ch13 Powercap Override — observer variant.
//
// Kprobes the powercap framework (x86 RAPL and Intel PowerClamp live
// under it) and thermal zone updates. Every call streams a ringbuf event
// so userspace can see when the kernel registers a control type,
// queries/sets the max TDP envelope, or fires a thermal zone update.
//
// On arches where powercap is absent (aarch64 linuxkit in particular)
// none of these symbols exist; the loader skips cleanly.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct evt {
    unsigned long long ts_ns;
    unsigned int pid;
    unsigned int tgid;
    char comm[16];
    int hook;              // 1=register 2=set_max 3=get_max 4=thermal_update
    unsigned long long arg0;
    unsigned long long arg1;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

static __always_inline void emit(int hook,
                                 unsigned long long a0,
                                 unsigned long long a1)
{
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return;
    unsigned long long id = bpf_get_current_pid_tgid();
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = (unsigned int)(id & 0xffffffff);
    e->tgid = (unsigned int)(id >> 32);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->hook = hook;
    e->arg0 = a0;
    e->arg1 = a1;
    bpf_ringbuf_submit(e, 0);
}

// struct powercap_control_type *powercap_register_control_type(
//     struct powercap_control_type *, const char *name,
//     const struct powercap_control_type_ops *ops)
// We only need to prove it fired; we stash the name pointer in arg0 (user
// triage reads the string via bpf_probe_read_kernel_str in future revs —
// for now we just record that it fired so the proof marker lands).
SEC("kprobe/powercap_register_control_type")
int BPF_KPROBE(kp_register, void *ptype, const char *name)
{
    (void)ptype;
    emit(1, (unsigned long long)(unsigned long)name, 0);
    return 0;
}

// int powercap_set_max_power_uw(struct powercap_zone *z, int cid, u64 max_power)
SEC("kprobe/powercap_set_max_power_uw")
int BPF_KPROBE(kp_set_max, void *z, int cid, unsigned long long max_power)
{
    (void)z;
    emit(2, (unsigned long long)cid, max_power);
    return 0;
}

// int powercap_get_max_power_uw(struct powercap_zone *z, int cid, u64 *max_power)
SEC("kprobe/powercap_get_max_power_uw")
int BPF_KPROBE(kp_get_max, void *z, int cid, void *max_power_ptr)
{
    (void)z;
    emit(3, (unsigned long long)cid,
         (unsigned long long)(unsigned long)max_power_ptr);
    return 0;
}

// void thermal_zone_device_update(struct thermal_zone_device *tz,
//                                 enum thermal_notify_event event)
SEC("kprobe/thermal_zone_device_update")
int BPF_KPROBE(kp_therm, void *tz, int event)
{
    (void)tz;
    emit(4, (unsigned long long)event, 0);
    return 0;
}
