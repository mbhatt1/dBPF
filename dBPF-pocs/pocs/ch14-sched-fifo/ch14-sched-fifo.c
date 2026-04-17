// ch14-sched-fifo: SCHED_FIFO impersonator loader.
//
// Attaches kprobe + kretprobe on __arm64_sys_sched_setscheduler. The
// kretprobe calls bpf_override_return(0) for matching tgids. The
// targeted entrypoint IS in /sys/kernel/debug/error_injection/list on
// linuxkit 6.12, so the override actually fires.
//
// Status messages go to stderr; ringbuf events go to stdout (one line
// per event) so `./ch14-sched-fifo > events.log` keeps a clean stream.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "ch14-sched-fifo.skel.h"

struct evt {
    unsigned int pid;
    unsigned int tgid;
    char         comm[16];
    int          policy;   /* reused as orig_ret */
    int          prio;
    int          flipped;
};

static volatile sig_atomic_t stop;
static void on_sig(int _s) { (void)_s; stop = 1; }

static const char *KPROBE_TARGET = "__arm64_sys_sched_setscheduler";

static void usage(const char *argv0)
{
    fprintf(stderr,
        "Usage: %s [options] [tgid ...]\n"
        "  -a, --all          flip every caller (wildcard)\n"
        "  -t, --tgid <N>     register tgid N (repeatable)\n"
        "  -h, --help         show this help and exit\n"
        "  -v, --verbose      noisier libbpf logging on stderr\n"
        "\n"
        "Positional integer args are treated as tgids (back-compat).\n"
        "Events are emitted on stdout, status on stderr.\n",
        argv0);
}

/* libbpf_print_fn: gate debug noise behind --verbose */
static int g_verbose;
static int libbpf_print(enum libbpf_print_level lvl, const char *fmt, va_list ap)
{
    if (!g_verbose && lvl == LIBBPF_DEBUG) return 0;
    return vfprintf(stderr, fmt, ap);
}

/* Preflight: confirm KPROBE_TARGET exists in /proc/kallsyms.
 * Returns 1 if found, 0 if not, -1 on error reading kallsyms. */
static int kallsyms_has(const char *sym)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) return -1;
    char line[512];
    size_t slen = strlen(sym);
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        /* format: "addr type name [module]" */
        char *p = strchr(line, ' ');
        if (!p) continue;
        p = strchr(p + 1, ' ');
        if (!p) continue;
        p++;
        size_t n = strlen(p);
        while (n && (p[n-1] == '\n' || p[n-1] == '\t' || p[n-1] == ' ')) p[--n] = '\0';
        /* exact match or "name\t[module]" prefix */
        if (strncmp(p, sym, slen) == 0 &&
            (p[slen] == '\0' || p[slen] == '\t' || p[slen] == ' ')) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

static int register_tgid(struct ch14_sched_fifo_bpf *s, unsigned int tgid)
{
    unsigned int one = 1;
    int err = bpf_map__update_elem(s->maps.target_tgids,
                                   &tgid, sizeof(tgid),
                                   &one,  sizeof(one), BPF_ANY);
    if (err) {
        fprintf(stderr, "[ch14] map update tgid=%u failed: %s\n",
                tgid, strerror(-err));
    } else {
        fprintf(stderr, "[ch14] tag=register tgid=%u\n", tgid);
    }
    return err;
}

static int handle_event(void *ctx, void *data, size_t sz)
{
    (void)ctx;
    if (sz < sizeof(struct evt)) return 0;
    struct evt *e = data;
    /* events to stdout */
    printf("[sched] pid=%u tgid=%u comm=%-16s orig_ret=%d flipped=%d\n",
           e->pid, e->tgid, e->comm, e->policy, e->flipped);
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv)
{
    bool wildcard = false;
    unsigned int pending_tgids[256];
    int n_pending = 0;

    static const struct option long_opts[] = {
        { "all",     no_argument,       NULL, 'a' },
        { "tgid",    required_argument, NULL, 't' },
        { "help",    no_argument,       NULL, 'h' },
        { "verbose", no_argument,       NULL, 'v' },
        { NULL, 0, NULL, 0 },
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "at:hv", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'a': wildcard = true; break;
        case 't': {
            if (n_pending >= (int)(sizeof(pending_tgids)/sizeof(pending_tgids[0]))) {
                fprintf(stderr, "too many --tgid arguments\n");
                return 2;
            }
            char *end = NULL;
            unsigned long v = strtoul(optarg, &end, 10);
            if (!end || *end != '\0' || v == 0 || v > 0xffffffffUL) {
                fprintf(stderr, "invalid tgid '%s'\n", optarg);
                return 2;
            }
            pending_tgids[n_pending++] = (unsigned int)v;
            break;
        }
        case 'h': usage(argv[0]); return 0;
        case 'v': g_verbose = 1; break;
        default:  usage(argv[0]); return 2;
        }
    }

    /* back-compat: positional tgids and bare "--all" already consumed */
    for (int i = optind; i < argc; i++) {
        if (!strcmp(argv[i], "all")) { wildcard = true; continue; }
        char *end = NULL;
        unsigned long v = strtoul(argv[i], &end, 10);
        if (!end || *end != '\0' || v == 0 || v > 0xffffffffUL) {
            fprintf(stderr, "invalid positional tgid '%s'\n", argv[i]);
            usage(argv[0]);
            return 2;
        }
        if (n_pending >= (int)(sizeof(pending_tgids)/sizeof(pending_tgids[0]))) {
            fprintf(stderr, "too many tgid arguments\n");
            return 2;
        }
        pending_tgids[n_pending++] = (unsigned int)v;
    }

    if (!wildcard && n_pending == 0) {
        fprintf(stderr, "[ch14] note: no targets registered; loader will idle. "
                        "Use --all or --tgid <N>.\n");
    }

    libbpf_set_print(libbpf_print);

    /* Symbol preflight */
    int have = kallsyms_has(KPROBE_TARGET);
    if (have < 0) {
        fprintf(stderr, "[ch14] warning: cannot read /proc/kallsyms (%s); "
                        "proceeding optimistically\n", strerror(errno));
    } else if (have == 0) {
        fprintf(stderr, "[ch14] CH14_SKIP reason=\"kprobe target %s missing "
                        "from kallsyms (wrong arch or kernel)\"\n", KPROBE_TARGET);
        return 3;
    } else {
        fprintf(stderr, "[ch14] tag=preflight target=%s status=present\n", KPROBE_TARGET);
    }

    int rc = 1;
    struct ring_buffer *rb = NULL;
    struct ch14_sched_fifo_bpf *s = ch14_sched_fifo_bpf__open_and_load();
    if (!s) {
        fprintf(stderr, "[ch14] CH14_SKIP reason=\"open_and_load failed: %s\"\n",
                strerror(errno));
        return 1;
    }

    int err = ch14_sched_fifo_bpf__attach(s);
    if (err) {
        fprintf(stderr, "[ch14] CH14_SKIP reason=\"attach failed: %s\"\n",
                strerror(-err));
        goto out;
    }

    if (wildcard) {
        unsigned int z = 0;
        if (register_tgid(s, z) != 0) goto out;
        fprintf(stderr, "[ch14] tag=mode wildcard=1\n");
    }
    for (int i = 0; i < n_pending; i++) {
        if (register_tgid(s, pending_tgids[i]) != 0) goto out;
    }

    rb = ring_buffer__new(bpf_map__fd(s->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ch14] ring_buffer__new failed: %s\n", strerror(errno));
        goto out;
    }

    if (signal(SIGINT,  on_sig) == SIG_ERR ||
        signal(SIGTERM, on_sig) == SIG_ERR) {
        fprintf(stderr, "[ch14] signal() failed: %s\n", strerror(errno));
        goto out;
    }

    fprintf(stderr, "[ch14] tag=ready hook=%s\n", KPROBE_TARGET);

    while (!stop) {
        int n = ring_buffer__poll(rb, 200);
        if (n < 0 && n != -EINTR) {
            fprintf(stderr, "[ch14] ring_buffer__poll: %s\n", strerror(-n));
            break;
        }
    }

    rc = 0;
    fprintf(stderr, "[ch14] tag=shutdown\n");

out:
    if (rb) ring_buffer__free(rb);
    if (s)  ch14_sched_fifo_bpf__destroy(s);
    return rc;
}
