// Ch17 ACPI / WSMI Ping — observer for ACPI method evaluation and the
// aarch64 firmware-loader fallback.
//
// Primary hooks (x86 typical):
//   - acpi_evaluate_object
//   - acpi_ns_evaluate
//   - acpi_ex_execute_method
//
// Fallback hooks (present on aarch64 linuxkit, where the ACPI interpreter
// is absent but the firmware-request path is the nearest moral equivalent
// for "kernel reaches out to ask firmware to do something"):
//   - request_firmware
//   - _request_firmware
//   - firmware_request_nowarn
//
// Each hook emits a ringbuf event {pid, comm, hook, arg_string} where
// arg_string is the pathname (ACPI object path or firmware filename).
// The userspace loader decides which class of hook(s) attached and emits
// the appropriate proof marker.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define HOOK_ACPI_EVAL_OBJECT  1
#define HOOK_ACPI_NS_EVALUATE  2
#define HOOK_ACPI_EX_EXEC      3
#define HOOK_REQUEST_FIRMWARE  4
#define HOOK_UNDERSCORE_RF     5
#define HOOK_FW_REQ_NOWARN     6

#define ARG_MAX_LEN 64

struct evt {
    unsigned int pid;
    unsigned int tgid;
    char         comm[16];
    int          hook;
    char         arg_string[ARG_MAX_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

// Per-CPU scratch: ARG_MAX_LEN=64 pushes us close to the BPF stack budget.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, unsigned int);
    __type(value, struct evt);
    __uint(max_entries, 1);
} scratch SEC(".maps");

static __always_inline struct evt *scratch_get(int hook)
{
    unsigned int zero = 0;
    struct evt *e = bpf_map_lookup_elem(&scratch, &zero);
    if (!e)
        return NULL;
    unsigned long long id = bpf_get_current_pid_tgid();
    e->pid  = (unsigned int)(id & 0xffffffff);
    e->tgid = (unsigned int)(id >> 32);
    e->hook = hook;
    e->arg_string[0] = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    return e;
}

static __always_inline void submit(struct evt *src)
{
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;
    __builtin_memcpy(e, src, sizeof(*e));
    bpf_ringbuf_submit(e, 0);
}

// acpi_evaluate_object(acpi_handle handle, acpi_string pathname,
//                      struct acpi_object_list *external_params,
//                      struct acpi_buffer *return_buffer)
// pathname is a NUL-terminated kernel string (e.g. "\\_SB.PCI0._STA").
SEC("kprobe/acpi_evaluate_object")
int BPF_KPROBE(kp_acpi_evaluate_object, void *handle, const char *pathname)
{
    (void)handle;
    struct evt *e = scratch_get(HOOK_ACPI_EVAL_OBJECT);
    if (!e)
        return 0;
    if (pathname)
        bpf_probe_read_kernel_str(&e->arg_string, sizeof(e->arg_string),
                                  pathname);
    submit(e);
    return 0;
}

// acpi_ns_evaluate(struct acpi_evaluate_info *info)
// We can't reliably deref info->relative_pathname across kernels without a
// tight CO-RE struct definition, so just mark that the path fired.
SEC("kprobe/acpi_ns_evaluate")
int BPF_KPROBE(kp_acpi_ns_evaluate)
{
    struct evt *e = scratch_get(HOOK_ACPI_NS_EVALUATE);
    if (!e)
        return 0;
    submit(e);
    return 0;
}

// acpi_ex_execute_method(struct acpi_walk_state *walk_state)
SEC("kprobe/acpi_ex_execute_method")
int BPF_KPROBE(kp_acpi_ex_execute_method)
{
    struct evt *e = scratch_get(HOOK_ACPI_EX_EXEC);
    if (!e)
        return 0;
    submit(e);
    return 0;
}

// request_firmware(const struct firmware **fw, const char *name,
//                  struct device *device)
SEC("kprobe/request_firmware")
int BPF_KPROBE(kp_request_firmware, void *fw, const char *name)
{
    (void)fw;
    struct evt *e = scratch_get(HOOK_REQUEST_FIRMWARE);
    if (!e)
        return 0;
    if (name)
        bpf_probe_read_kernel_str(&e->arg_string, sizeof(e->arg_string),
                                  name);
    submit(e);
    return 0;
}

// _request_firmware(const struct firmware **firmware_p, const char *name,
//                   struct device *device, void *buf, size_t size,
//                   size_t offset, u32 opt_flags)
SEC("kprobe/_request_firmware")
int BPF_KPROBE(kp_underscore_request_firmware, void *firmware_p,
               const char *name)
{
    (void)firmware_p;
    struct evt *e = scratch_get(HOOK_UNDERSCORE_RF);
    if (!e)
        return 0;
    if (name)
        bpf_probe_read_kernel_str(&e->arg_string, sizeof(e->arg_string),
                                  name);
    submit(e);
    return 0;
}

// firmware_request_nowarn(const struct firmware **fw, const char *name,
//                         struct device *device)
SEC("kprobe/firmware_request_nowarn")
int BPF_KPROBE(kp_firmware_request_nowarn, void *fw, const char *name)
{
    (void)fw;
    struct evt *e = scratch_get(HOOK_FW_REQ_NOWARN);
    if (!e)
        return 0;
    if (name)
        bpf_probe_read_kernel_str(&e->arg_string, sizeof(e->arg_string),
                                  name);
    submit(e);
    return 0;
}
