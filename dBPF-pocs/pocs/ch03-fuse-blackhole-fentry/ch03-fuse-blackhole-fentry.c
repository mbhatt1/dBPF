// ch03 FUSE Audit Black-Hole loader.
//
// Strategy:
//   1. Open+load the skeleton (autoload ON for both programs).
//   2. Use BTF introspection to decide whether fmod_ret/audit_log_start
//      is viable on this kernel. Criterion: the function exists in
//      vmlinux BTF AND a test attach succeeds. (The canonical allowlist
//      is BTF_SET_START(bpf_modify_return_targets); libbpf surfaces
//      allowlist-miss as an -EINVAL on attach.)
//   3. Disable whichever program isn't viable, attach the rest.
//   4. Enable the suppression via the `enabled` array map.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include "ch03-fuse-blackhole-fentry.skel.h"

struct evt {
    unsigned int pid, tgid;
    char comm[16];
    int hook;
    int suppressed;
    int type;
};

static volatile sig_atomic_t stop;
static void on_sig(int s){ (void)s; stop = 1; }

static int handle(void *ctx, void *data, size_t sz)
{
    (void)ctx;
    if (sz < sizeof(struct evt)) return 0;
    const struct evt *e = data;
    const char *what = (e->hook == 1) ? "audit_log_start" : "security_syslog";
    printf("[ch03-fe] %s\tpid=%u\tcomm=%-16s\ttype=%d\t%s\n",
           what, e->pid, e->comm, e->type,
           e->suppressed ? "-> SUPPRESSED" : "observed");
    return 0;
}

static int check_lsm_bpf_enabled(void)
{
    FILE *f = fopen("/sys/kernel/security/lsm", "r");
    if (!f) return 0;
    char buf[512] = {0};
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return 0; }
    fclose(f);
    return strstr(buf, "bpf") != NULL;
}

// Returns 1 if the symbol is present in vmlinux BTF as a FUNC.
// Presence alone is NOT proof the modify-return allowlist covers it: BTF
// carries every traceable function, but fmod_ret is gated separately.
static int btf_has_func(const char *name)
{
    struct btf *btf = btf__load_vmlinux_btf();
    if (!btf) return 0;
    int id = btf__find_by_name_kind(btf, name, BTF_KIND_FUNC);
    btf__free(btf);
    return id > 0;
}

// Ground truth for fmod_ret viability. A BPF_MODIFY_RETURN program can only
// attach to a function the kernel deems "modifiable": either annotated with
// ALLOW_ERROR_INJECTION (surfaced in the error_injection list) or a BPF-LSM
// hook. If the target is absent from that set, the *load* — not the attach —
// fails at verification time with "<func>() is not modifiable" (-EINVAL),
// which tears down the whole skeleton. So we must gate autoload on this, not
// on mere BTF presence; otherwise the fmod_ret program crashes the load
// before the lsm/syslog fallback ever gets a chance.
static int func_error_injectable(const char *name)
{
    static const char *paths[] = {
        "/sys/kernel/debug/error_injection/list",
        "/sys/kernel/tracing/error_injection/list",
    };
    for (unsigned i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        FILE *f = fopen(paths[i], "r");
        if (!f) continue;
        char line[256];
        int found = 0;
        while (fgets(line, sizeof(line), f)) {
            // format: "<func>\t<TYPE>" (one entry per line, symbol first).
            char sym[128];
            if (sscanf(line, "%127s", sym) == 1 &&
                strcmp(sym, name) == 0) {
                found = 1;
                break;
            }
        }
        fclose(f);
        return found; // first readable list is authoritative
    }
    return 0; // list unreadable (not mounted / no privilege) -> assume no
}

int main(int argc, char **argv)
{
    int opt;
    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
        case 'h':
        default:
            fprintf(stderr,
                "Usage: %s\n"
                "  No arguments. Loader auto-selects between\n"
                "  fmod_ret/audit_log_start (preferred) and\n"
                "  lsm.s/syslog (fallback) based on kernel support.\n",
                argv[0]);
            return opt == 'h' ? 0 : 2;
        }
    }

    struct ch03_fuse_blackhole_fentry_bpf *s = ch03_fuse_blackhole_fentry_bpf__open();
    if (!s) { fprintf(stderr, "[ch03-fe] open: %s\n", strerror(errno)); return 1; }

    // fmod_ret/audit_log_start is viable only if the symbol is BOTH in BTF
    // (so the trampoline can be built) AND in the kernel's modify-return
    // allowlist (error_injection list). audit_log_start is in BTF on every
    // recent kernel but is NOT error-injectable on mainline — so this gate
    // is normally false and we fall back. (Gating on BTF alone made the
    // fmod_ret program fail the *load* with "not modifiable", crashing the
    // whole skeleton before the fallback could attach.)
    int have_mr = btf_has_func("audit_log_start") &&
                  func_error_injectable("audit_log_start");
    int have_lsm = check_lsm_bpf_enabled();

    if (!have_mr)
        bpf_program__set_autoload(s->progs.mr_audit_log_start, false);
    if (!have_lsm)
        bpf_program__set_autoload(s->progs.lsm_syslog, false);

    if (!have_mr && !have_lsm) {
        fprintf(stderr,
            "[ch03-fe] ERROR: neither suppression path available on this kernel.\n"
            "  - fmod_ret/audit_log_start: symbol %s vmlinux BTF, %s the\n"
            "    modify-return allowlist (error_injection list). fmod_ret needs\n"
            "    BOTH; audit_log_start is not error-injectable on mainline, so\n"
            "    the verifier rejects it with \"not modifiable\".\n"
            "  - lsm.s/syslog: 'bpf' is not in the active LSM stack\n"
            "    (/sys/kernel/security/lsm). Needs lsm=...,bpf on the kernel\n"
            "    cmdline (CONFIG_BPF_LSM=y alone is not enough).\n"
            "  NOTE: fentry/fexit could OBSERVE audit_log_start but cannot change\n"
            "  its return value, so it cannot suppress records (that is fmod_ret\n"
            "  only). See primary ch03 (kprobe) for the observer primitive.\n",
            btf_has_func("audit_log_start") ? "IS in" : "is NOT in",
            func_error_injectable("audit_log_start") ? "IS in" : "is NOT in");
        ch03_fuse_blackhole_fentry_bpf__destroy(s);
        return 3;
    }

    if (ch03_fuse_blackhole_fentry_bpf__load(s) != 0) {
        fprintf(stderr, "[ch03-fe] load: %s\n", strerror(errno));
        ch03_fuse_blackhole_fentry_bpf__destroy(s);
        return 1;
    }

    // Try audit_log_start first. have_mr already required the symbol to be
    // in the modify-return allowlist (error_injection list); if we reach here
    // with have_mr set the load succeeded, so attach should too.
    int used_mr = 0;
    if (have_mr) {
        struct bpf_link *l = bpf_program__attach(s->progs.mr_audit_log_start);
        if (l) {
            fprintf(stderr, "[ch03-fe] attached fmod_ret/audit_log_start (preferred)\n");
            used_mr = 1;
        } else {
            fprintf(stderr, "[ch03-fe] fmod_ret/audit_log_start not in allowlist "
                            "(attach=%s) — falling back to lsm/syslog\n",
                    strerror(errno));
        }
    }

    int used_lsm = 0;
    if (!used_mr && have_lsm) {
        struct bpf_link *l = bpf_program__attach(s->progs.lsm_syslog);
        if (l) {
            fprintf(stderr, "[ch03-fe] attached lsm.s/syslog (fallback)\n");
            used_lsm = 1;
        } else {
            fprintf(stderr, "[ch03-fe] lsm.s/syslog attach failed: %s\n",
                    strerror(errno));
        }
    }

    if (!used_mr && !used_lsm) {
        fprintf(stderr, "[ch03-fe] ERROR: no suppression path attached\n");
        ch03_fuse_blackhole_fentry_bpf__destroy(s);
        return 4;
    }

    unsigned int k = 0, v = 1;
    bpf_map__update_elem(s->maps.enabled, &k, sizeof(k), &v, sizeof(v), BPF_ANY);

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(s->maps.events),
                                              handle, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ch03-fe] ring_buffer__new: %s\n", strerror(errno));
        ch03_fuse_blackhole_fentry_bpf__destroy(s);
        return 1;
    }
    signal(SIGINT, on_sig); signal(SIGTERM, on_sig);
    fprintf(stderr, "[ch03-fe] active — audit suppression engaged (%s)\n",
            used_mr ? "fmod_ret" : "lsm");

    while (!stop) {
        int n = ring_buffer__poll(rb, 200);
        if (n < 0 && n != -EINTR) break;
    }
    ring_buffer__free(rb);
    ch03_fuse_blackhole_fentry_bpf__destroy(s);
    return 0;
}
