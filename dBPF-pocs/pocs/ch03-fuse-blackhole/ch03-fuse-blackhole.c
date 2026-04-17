// Ch03 FUSE Audit Black-Hole — userspace loader.
// Observer-only: streams every audit_log_start/end/format call on the host
// kernel. See README.md for why this is "observer" not "mutator" in this
// environment.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "ch03-fuse-blackhole.skel.h"

#define MSG_MAX 96

struct evt {
    unsigned int pid;
    unsigned int tgid;
    int          hook;
    int          audit_type;
    int          has_ctx;
    char         comm[16];
    char         fmt_preview[MSG_MAX];
};

static volatile sig_atomic_t stop;
static void sig(int _) { (void)_; stop = 1; }

static const char *hook_name(int h) {
    switch (h) {
    case 1: return "audit_log_start";
    case 2: return "audit_log_end  ";
    case 3: return "audit_log_format";
    }
    return "?";
}

// Common AUDIT_* types — a partial decoder.
static const char *audit_type_name(int t) {
    switch (t) {
    case 1000: return "AUDIT_GET";
    case 1100: return "AUDIT_USER_AUTH";
    case 1101: return "AUDIT_USER_ACCT";
    case 1300: return "AUDIT_SYSCALL";
    case 1302: return "AUDIT_PATH";
    case 1305: return "AUDIT_CONFIG_CHANGE";
    case 1306: return "AUDIT_SOCKADDR";
    case 1307: return "AUDIT_CWD";
    case 1309: return "AUDIT_EXECVE";
    case 1320: return "AUDIT_EOE";
    case 1327: return "AUDIT_PROCTITLE";
    case 1400: return "AUDIT_AVC";
    case 1401: return "AUDIT_SELINUX_ERR";
    case 1402: return "AUDIT_AVC_PATH";
    case 1701: return "AUDIT_ANOM_ABEND";
    }
    return "AUDIT_*";
}

static int handle(void *ctx, void *data, size_t sz) {
    (void)ctx; (void)sz;
    struct evt *e = data;
    // Cap fmt preview to printable ASCII for terminal safety.
    char buf[MSG_MAX];
    size_t i;
    for (i = 0; i < sizeof(e->fmt_preview) && e->fmt_preview[i]; i++) {
        unsigned char c = (unsigned char)e->fmt_preview[i];
        buf[i] = (c >= 0x20 && c < 0x7f) ? c : '.';
    }
    buf[i] = 0;

    if (e->hook == 1) {
        printf("[audit] %-16s pid=%u comm=%-15s type=%d(%s) ctx=%d\n",
               hook_name(e->hook), e->tgid, e->comm,
               e->audit_type, audit_type_name(e->audit_type), e->has_ctx);
    } else if (e->hook == 3) {
        printf("[audit] %-16s pid=%u comm=%-15s fmt='%s'\n",
               hook_name(e->hook), e->tgid, e->comm, buf);
    } else {
        printf("[audit] %-16s pid=%u comm=%-15s ab=%d\n",
               hook_name(e->hook), e->tgid, e->comm, e->has_ctx);
    }
    return 0;
}

int main(int argc, char **argv) {
    libbpf_set_print(NULL);

    struct ch03_fuse_blackhole_bpf *s = ch03_fuse_blackhole_bpf__open_and_load();
    if (!s) {
        fprintf(stderr, "[ch03] CH03_SKIP reason=\"open_and_load failed: %s\"\n",
                strerror(errno));
        return 1;
    }
    if (ch03_fuse_blackhole_bpf__attach(s)) {
        fprintf(stderr, "[ch03] CH03_SKIP reason=\"attach failed: %s "
                        "(audit_log_* symbols not attachable on this kernel)\"\n",
                strerror(errno));
        ch03_fuse_blackhole_bpf__destroy(s);
        return 1;
    }

    if (argc > 1 && !strcmp(argv[1], "--pretend-drop")) {
        unsigned int z = 0, v = 1;
        bpf_map__update_elem(s->maps.ctrl, &z, sizeof(z), &v, sizeof(v), BPF_ANY);
        fprintf(stderr, "[audit] advertising drop intent (observer-only; "
                        "bpf_override_return not permitted on audit_log_* here)\n");
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(s->maps.events),
                                              handle, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ch03] ring_buffer__new failed: %s\n", strerror(errno));
        ch03_fuse_blackhole_bpf__destroy(s);
        return 1;
    }

    struct sigaction sa = { .sa_handler = sig };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    fprintf(stderr, "[audit] attached — streaming audit_log_start/end/format\n");
    while (!stop) {
        int n = ring_buffer__poll(rb, 200);
        if (n < 0 && n != -EINTR) break;
    }
    ring_buffer__free(rb);
    ch03_fuse_blackhole_bpf__destroy(s);
    return 0;
}
