// ch12 signed-driver-swap (syscall variant) — userspace loader.
//
// Forges the return value of module-load syscalls to 0 by attaching
// kretprobes to __arm64_sys_finit_module / __arm64_sys_init_module and
// calling bpf_override_return(ctx, 0). Both symbols are on the kernel's
// error-injection allowlist on 6.12 aarch64 linuxkit.
//
// Modes:
//   --all              forge every module-load syscall return (wildcard)
//   --tgid <pid>       forge only calls from <pid> (may be repeated)
//   -v                 verbose libbpf output
//   -h                 usage
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "ch12-signed-driver-swap-syscall.skel.h"

#define HOOK_FINIT_MODULE 1
#define HOOK_INIT_MODULE  2

struct evt {
    unsigned int pid;
    unsigned int tgid;
    char         comm[16];
    long         orig_ret;
    int          hook;
    int          flipped;
};

static volatile sig_atomic_t stop;
static void on_signal(int sig)
{
    (void)sig;
    stop = 1;
}

static const char *hook_str(int h)
{
    switch (h) {
    case HOOK_FINIT_MODULE: return "finit_module";
    case HOOK_INIT_MODULE:  return "init_module";
    default:                return "?";
    }
}

static int handle(void *ctx, void *data, size_t sz)
{
    (void)ctx;
    if (sz < sizeof(struct evt))
        return 0;
    const struct evt *e = data;
    const char *sc = hook_str(e->hook);
    if (e->flipped) {
        printf("[ch12s] FORGE pid=%u comm=%s syscall=%s orig_ret=%ld -> 0 "
               "(module NOT actually loaded)\n",
               e->pid, e->comm, sc, e->orig_ret);
    } else {
        printf("[ch12s] OBSERVE pid=%u comm=%s syscall=%s ret=%ld\n",
               e->pid, e->comm, sc, e->orig_ret);
    }
    fflush(stdout);
    return 0;
}

static int libbpf_print(enum libbpf_print_level lvl, const char *fmt, va_list ap)
{
    if (lvl == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, fmt, ap);
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [--all] [--tgid <pid>]... [-v] [-h]\n"
            "  --all          forge every module-load syscall return (wildcard)\n"
            "  --tgid <pid>   forge only calls from <pid> (may be repeated,\n"
            "                 up to 1024 entries)\n"
            "  -v             verbose libbpf output\n"
            "  -h             show this help\n"
            "Events are written to stdout; status to stderr.\n",
            prog);
}

// Returns 1 if symbol present in /proc/kallsyms, 0 absent, -1 on I/O error.
static int kallsyms_has(const char *sym)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) {
        fprintf(stderr, "[ch12s] open /proc/kallsyms: %s\n", strerror(errno));
        return -1;
    }
    char line[512];
    size_t slen = strlen(sym);
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        char *p = strchr(line, ' ');
        if (!p)
            continue;
        char type = p[1];
        char *name = p + 3;
        if (type != 'T' && type != 't' && type != 'W' && type != 'w')
            continue;
        size_t nlen = strcspn(name, " \t\n");
        if (nlen == slen && memcmp(name, sym, slen) == 0) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

// Returns 1 if symbol present in the error_injection allowlist.
static int err_inj_has(const char *sym)
{
    FILE *f = fopen("/sys/kernel/debug/error_injection/list", "r");
    if (!f)
        return -1;
    char line[512];
    size_t slen = strlen(sym);
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        size_t nlen = strcspn(line, " \t\n");
        if (nlen == slen && memcmp(line, sym, slen) == 0) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

#define MAX_TARGETS 1024

int main(int argc, char **argv)
{
    int verbose = 0;
    int wildcard = 0;
    unsigned int targets[MAX_TARGETS];
    size_t n_targets = 0;

    static const struct option longopts[] = {
        { "all",  no_argument,       NULL, 'A' },
        { "tgid", required_argument, NULL, 'T' },
        { "help", no_argument,       NULL, 'h' },
        { 0, 0, 0, 0 },
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "vh", longopts, NULL)) != -1) {
        switch (opt) {
        case 'A':
            wildcard = 1;
            break;
        case 'T': {
            if (n_targets >= MAX_TARGETS) {
                fprintf(stderr, "[ch12s] too many --tgid entries (max %d)\n",
                        MAX_TARGETS);
                return 2;
            }
            char *end = NULL;
            unsigned long v = strtoul(optarg, &end, 10);
            if (!end || *end || v == 0 || v > 0x7fffffffUL) {
                fprintf(stderr, "[ch12s] invalid tgid: %s\n", optarg);
                return 2;
            }
            targets[n_targets++] = (unsigned int)v;
            break;
        }
        case 'v':
            verbose = 1;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 2;
        }
    }
    if (optind != argc) {
        fprintf(stderr, "[ch12s] unexpected argument: %s\n", argv[optind]);
        usage(argv[0]);
        return 2;
    }
    if (!wildcard && n_targets == 0) {
        fprintf(stderr, "[ch12s] no targets specified; pass --all or --tgid <pid>\n");
        usage(argv[0]);
        return 2;
    }

    if (verbose)
        libbpf_set_print(libbpf_print);

    // Preflight: symbols in kallsyms + error_injection allowlist.
    const char *fsym = "__arm64_sys_finit_module";
    const char *isym = "__arm64_sys_init_module";
    int has_f  = kallsyms_has(fsym);
    int has_i  = kallsyms_has(isym);
    int inj_f  = err_inj_has(fsym);
    int inj_i  = err_inj_has(isym);
    fprintf(stderr, "[ch12s] symbol=%s\tkallsyms=%s\terror_injection=%s\n",
            fsym,
            has_f == 1 ? "present" : (has_f == 0 ? "ABSENT" : "err"),
            inj_f == 1 ? "present" : (inj_f == 0 ? "ABSENT" : "err"));
    fprintf(stderr, "[ch12s] symbol=%s\tkallsyms=%s\terror_injection=%s\n",
            isym,
            has_i == 1 ? "present" : (has_i == 0 ? "ABSENT" : "err"),
            inj_i == 1 ? "present" : (inj_i == 0 ? "ABSENT" : "err"));

    if (has_f != 1 && has_i != 1) {
        fprintf(stderr, "[ch12s] CH12S_SKIP reason=\"module-load syscalls absent\"\n");
        return 2;
    }
    if (inj_f != 1 && inj_i != 1) {
        fprintf(stderr,
                "[ch12s] CH12S_SKIP reason=\"module-load syscalls NOT in "
                "error_injection allowlist; bpf_override_return would be rejected\"\n");
        return 2;
    }

    int rc = 1;
    struct ring_buffer *rb = NULL;
    struct ch12_signed_driver_swap_syscall_bpf *s =
        ch12_signed_driver_swap_syscall_bpf__open();
    if (!s) {
        fprintf(stderr, "[ch12s] skeleton open failed: %s\n", strerror(errno));
        return 1;
    }

    if (has_f != 1 || inj_f != 1) {
        fprintf(stderr, "[ch12s] disabling kr_finit_module (symbol or inject missing)\n");
        bpf_program__set_autoload(s->progs.kr_finit_module, false);
    }
    if (has_i != 1 || inj_i != 1) {
        fprintf(stderr, "[ch12s] disabling kr_init_module (symbol or inject missing)\n");
        bpf_program__set_autoload(s->progs.kr_init_module, false);
    }

    int err = ch12_signed_driver_swap_syscall_bpf__load(s);
    if (err) {
        fprintf(stderr, "[ch12s] load failed: %s\n", strerror(-err));
        goto out;
    }

    int n_attached = 0, n_skipped = 0;
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, s->obj) {
        if (!bpf_program__autoload(prog)) {
            n_skipped++;
            continue;
        }
        struct bpf_link *link = bpf_program__attach(prog);
        long e = libbpf_get_error(link);
        if (e) {
            fprintf(stderr, "[ch12s] attach prog=%s failed: %s\n",
                    bpf_program__name(prog), strerror(-(int)e));
            continue;
        }
        fprintf(stderr, "[ch12s] attached prog=%s\n", bpf_program__name(prog));
        n_attached++;
    }
    fprintf(stderr, "[ch12s] attached=%d\tskipped=%d\n", n_attached, n_skipped);
    if (n_attached == 0) {
        fprintf(stderr, "[ch12s] no programs attached — nothing to do\n");
        goto out;
    }

    if (wildcard) {
        unsigned int z = 0, one = 1;
        err = bpf_map__update_elem(s->maps.target_tgids,
                                   &z, sizeof(z),
                                   &one, sizeof(one), BPF_ANY);
        if (err) {
            fprintf(stderr, "[ch12s] wildcard install failed: %s\n",
                    strerror(-err));
        } else {
            fprintf(stderr, "[ch12s] tag=target\tmode=wildcard\n");
        }
    }
    for (size_t i = 0; i < n_targets; i++) {
        unsigned int tgid = targets[i];
        unsigned int one = 1;
        err = bpf_map__update_elem(s->maps.target_tgids,
                                   &tgid, sizeof(tgid),
                                   &one, sizeof(one), BPF_ANY);
        if (err) {
            fprintf(stderr, "[ch12s] target tgid=%u update failed: %s\n",
                    tgid, strerror(-err));
        } else {
            fprintf(stderr, "[ch12s] tag=target\ttgid=%u\n", tgid);
        }
    }

    rb = ring_buffer__new(bpf_map__fd(s->maps.events), handle, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ch12s] ring_buffer__new failed: %s\n",
                strerror(errno));
        goto out;
    }

    struct sigaction sa = { .sa_handler = on_signal };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    fprintf(stderr, "[ch12s] status=ready\tmsg=syscall-return override active\n");
    while (!stop) {
        int n = ring_buffer__poll(rb, 200);
        if (n < 0 && n != -EINTR) {
            fprintf(stderr, "[ch12s] ring_buffer__poll: %s\n", strerror(-n));
            break;
        }
    }
    rc = 0;

out:
    if (rb)
        ring_buffer__free(rb);
    if (s)
        ch12_signed_driver_swap_syscall_bpf__destroy(s);
    return rc;
}
