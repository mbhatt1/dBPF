// ch08-keyring-heist-kprobe: CO-RE field extraction of kernel struct key
// from the access-denied syscall path.
//
// Why this sibling to ch08-keyring-heist-lsm exists:
//   The LSM variant cannot load on this kernel because the BTF function
//   signature of `security_key_permission` forward-declares `struct key`
//   (BTF FWD kind) rather than defining it, and the verifier refuses an
//   `fmod_ret` program whose arg0 type is FWD with:
//
//       arg0 type FWD is not a struct
//
//   Even though struct key IS fully defined inside vmlinux.h, the BTF
//   metadata for the LSM hook's parameter is a forward declaration, so
//   fmod_ret type-match fails.
//
// This variant sidesteps that entirely by attaching as a kprobe at
// `key_task_permission` and `lookup_user_key` (both present in
// /proc/kallsyms on linuxkit 6.12 aarch64). Kprobe programs take
// `struct pt_regs *` and we pull the first argument out via
// PT_REGS_PARM1 as an opaque pointer. CO-RE field access is then
// resolved against vmlinux.h's full definition of `struct key`, which is
// unaffected by the LSM hook's FWD-typed BTF metadata.
//
// This program is READ-ONLY observation of an access-denied path. It
// does not mutate the syscall return, does not alter permission checks,
// and does not touch credentials. The kernel's access decision is
// preserved in full; the program only reads structure-level metadata
// (serial, key type name, description) at the decision site.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define HOOK_KEY_TASK_PERMISSION 1
#define HOOK_LOOKUP_USER_KEY     2

#define TYPE_NAME_LEN 16
#define DESC_LEN      64

struct evt {
    unsigned int pid;
    unsigned int tgid;
    char comm[16];
    int serial;
    int hook;
    char type_name[TYPE_NAME_LEN];
    char description[DESC_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

static __always_inline void emit_key(struct key *k, int hook)
{
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;
    __builtin_memset(e, 0, sizeof(*e));

    unsigned long long id = bpf_get_current_pid_tgid();
    e->pid  = (unsigned int)(id & 0xffffffff);
    e->tgid = (unsigned int)(id >> 32);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->hook = hook;

    if (k) {
        // CO-RE read against vmlinux.h's complete struct key definition.
        e->serial = BPF_CORE_READ(k, serial);

        struct key_type *kt = BPF_CORE_READ(k, type);
        if (kt) {
            const char *tn = BPF_CORE_READ(kt, name);
            if (tn)
                bpf_probe_read_kernel_str(&e->type_name,
                                          sizeof(e->type_name), tn);
        }

        const char *desc = BPF_CORE_READ(k, description);
        if (desc)
            bpf_probe_read_kernel_str(&e->description,
                                      sizeof(e->description), desc);
    }

    bpf_ringbuf_submit(e, 0);
}

// key_task_permission(const key_ref_t key_ref, const struct cred *cred,
//                     enum key_need_perm need_perm)
//
// PARM1 is key_ref_t, an opaque pointer whose low 2 bits are possession
// flags. Mask them off to obtain the backing `struct key *`.
SEC("kprobe/key_task_permission")
int BPF_KPROBE(kp_key_task_permission)
{
    unsigned long raw = (unsigned long)PT_REGS_PARM1(ctx);
    struct key *k = (struct key *)(raw & ~3UL);
    emit_key(k, HOOK_KEY_TASK_PERMISSION);
    return 0;
}

// lookup_user_key(key_serial_t id, unsigned long lflags, enum key_need_perm)
//
// Here PARM1 is a key_serial_t (int), not a pointer. We emit just the
// caller identity + serial-id-as-observed. The subsequent
// key_task_permission hook gives us the structure-level view.
SEC("kprobe/lookup_user_key")
int BPF_KPROBE(kp_lookup_user_key)
{
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    __builtin_memset(e, 0, sizeof(*e));

    unsigned long long id = bpf_get_current_pid_tgid();
    e->pid  = (unsigned int)(id & 0xffffffff);
    e->tgid = (unsigned int)(id >> 32);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->hook = HOOK_LOOKUP_USER_KEY;
    e->serial = (int)PT_REGS_PARM1(ctx);
    __builtin_memcpy(e->type_name, "lookup", 7);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
