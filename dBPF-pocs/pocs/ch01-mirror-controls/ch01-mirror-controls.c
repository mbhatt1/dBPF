// ch01 mirror-controls — userspace loader
//
// Observes every cap_capable() decision; when a targeted tgid is denied
// a capability, fires bpf_send_signal(SIGUSR1) to prove real kernel control.
// Use -t <tgid> to target a specific process, or -a to target all processes.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "ch01-mirror-controls.skel.h"

struct evt {
    unsigned int pid;
    unsigned int tgid;
    char comm[16];
    int cap;
    int orig_ret;
    int flipped;
    int signal_sent;
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
    if (e->flipped)
        printf("[ch01] tag=FLIP\tpid=%u\tcomm=%-16s\tcap=%d\torig=%d\tsignal=%d\n",
               e->pid, e->comm, e->cap, e->orig_ret, e->signal_sent);
    else if (e->orig_ret != 0)
        printf("[ch01] tag=deny\tpid=%u\tcomm=%-16s\tcap=%d\tret=%d\n",
               e->pid, e->comm, e->cap, e->orig_ret);
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
            "Usage: %s [-t tgid]... [-a] [-v] [-h]\n"
            "  -t tgid   target tgid; its denials trigger SIGUSR1\n"
            "            (may be repeated, up to 1024 entries)\n"
            "  -a        wildcard: signal ALL cap denials\n"
            "  -v        verbose libbpf output\n"
            "  -h        show this help\n"
            "Events are written to stdout; status to stderr.\n",
            prog);
}

// Returns 1 if symbol found in /proc/kallsyms, 0 if absent, -1 on I/O error.
static int kallsyms_has(const char *sym)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) {
        fprintf(stderr, "[ch01] open /proc/kallsyms: %s\n", strerror(errno));
        return -1;
    }
    char line[512];
    size_t slen = strlen(sym);
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        // format: "<addr> <type> <name>[ \tmodule]\n"
        char *name = strchr(line, ' ');
        if (!name) continue;
        name = strchr(name + 1, ' ');
        if (!name) continue;
        name++;
        size_t n = strlen(name);
        while (n && (name[n-1] == '\n' || name[n-1] == '\t' || name[n-1] == ' '))
            name[--n] = 0;
        // strip module suffix " [mod]"
        char *br = strchr(name, '\t');
        if (br) *br = 0;
        if (n >= slen && strcmp(name, sym) == 0) {
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
    int verbose = 0, wildcard = 0;
    unsigned int targets[MAX_TARGETS];
    size_t n_targets = 0;

    int opt;
    while ((opt = getopt(argc, argv, "t:avh")) != -1) {
        switch (opt) {
        case 'a':
            wildcard = 1;
            break;
        case 't': {
            if (n_targets >= MAX_TARGETS) {
                fprintf(stderr, "[ch01] too many -t entries (max %d)\n", MAX_TARGETS);
                return 2;
            }
            char *end = NULL;
            unsigned long v = strtoul(optarg, &end, 10);
            if (!end || *end || v == 0 || v > 0x7fffffffUL) {
                fprintf(stderr, "[ch01] invalid tgid: %s\n", optarg);
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
        fprintf(stderr, "[ch01] unexpected argument: %s\n", argv[optind]);
        usage(argv[0]);
        return 2;
    }

    if (verbose)
        libbpf_set_print(libbpf_print);

    int rc = 1;
    struct ring_buffer *rb = NULL;
    struct ch01_mirror_controls_bpf *s = ch01_mirror_controls_bpf__open();
    if (!s) {
        fprintf(stderr, "[ch01] CH01_SKIP reason=\"skeleton open failed: %s\"\n",
                strerror(errno));
        return 1;
    }

    // Symbol preflight — disable autoload of probes whose targets are absent.
    int has_cap = kallsyms_has("cap_capable");
    if (has_cap == 0) {
        fprintf(stderr, "[ch01] symbol cap_capable not in /proc/kallsyms; "
                        "disabling kp_cap and kr_cap\n");
        if (bpf_program__set_autoload(s->progs.kp_cap, false))
            fprintf(stderr, "[ch01] set_autoload(kp_cap,false) failed\n");
        if (bpf_program__set_autoload(s->progs.kr_cap, false))
            fprintf(stderr, "[ch01] set_autoload(kr_cap,false) failed\n");
    } else if (has_cap < 0) {
        fprintf(stderr, "[ch01] kallsyms unreadable — proceeding optimistically\n");
    } else {
        fprintf(stderr, "[ch01] symbol=cap_capable\tstatus=present\n");
    }

    int err = ch01_mirror_controls_bpf__load(s);
    if (err) {
        fprintf(stderr, "[ch01] CH01_SKIP reason=\"load failed: %s\"\n",
                strerror(-err));
        goto out;
    }

    // Per-program attach with individual error reporting.
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
            fprintf(stderr, "[ch01] attach prog=%s failed: %s\n",
                    bpf_program__name(prog), strerror(-(int)e));
            continue;
        }
        n_attached++;
    }
    fprintf(stderr, "[ch01] attached=%d\tskipped=%d\n", n_attached, n_skipped);
    if (n_attached == 0) {
        fprintf(stderr, "[ch01] no programs attached — nothing to do\n");
        goto out;
    }

    if (wildcard) {
        unsigned int zero = 0, one = 1;
        err = bpf_map__update_elem(s->maps.target_tgids,
                                   &zero, sizeof(zero),
                                   &one, sizeof(one), BPF_ANY);
        if (err)
            fprintf(stderr, "[ch01] wildcard update failed: %s\n", strerror(-err));
        else
            fprintf(stderr, "[ch01] tag=target\tmode=wildcard\n");
    }
    for (size_t i = 0; i < n_targets; i++) {
        unsigned int tgid = targets[i];
        unsigned int one = 1;
        err = bpf_map__update_elem(s->maps.target_tgids,
                                   &tgid, sizeof(tgid),
                                   &one, sizeof(one), BPF_ANY);
        if (err) {
            fprintf(stderr, "[ch01] target tgid=%u update failed: %s\n",
                    tgid, strerror(-err));
        } else {
            fprintf(stderr, "[ch01] tag=target\ttgid=%u\n", tgid);
        }
    }

    rb = ring_buffer__new(bpf_map__fd(s->maps.events), handle, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ch01] ring_buffer__new failed: %s\n", strerror(errno));
        goto out;
    }

    struct sigaction sa = { .sa_handler = on_signal };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    fprintf(stderr, "[ch01] status=ready\tmsg=mirror active\n");
    while (!stop) {
        int n = ring_buffer__poll(rb, 200);
        if (n < 0 && n != -EINTR) {
            fprintf(stderr, "[ch01] ring_buffer__poll: %s\n", strerror(-n));
            break;
        }
    }
    rc = 0;

out:
    if (rb)
        ring_buffer__free(rb);
    if (s)
        ch01_mirror_controls_bpf__destroy(s);
    return rc;
}
