// Ch16 Seccomp TID Hop — userspace loader.
//
// Attaches a kprobe + kretprobe pair on __secure_computing and streams every
// seccomp evaluation as a ringbuf event. Targeting is by tgid:
//
//   --tgid <pid>   add a single tgid to the target_tgids map (repeatable)
//   --all          install the wildcard (key 0) so every seccomp check is
//                  flagged as "targeted"
//
// Tradeoff: --all is the loud option; it tags every seccomp evaluation system-
// wide as a hijack candidate (still observer-only on this kernel, see README).
// Prefer --tgid <pid> in production demos to keep the noise floor sane.
//
// Status messages go to stderr; ringbuf events go to stdout so the stream
// pipes cleanly:  ./ch16-seccomp-tid-hop --all > seccomp.jsonl 2> status.log

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "ch16-seccomp-tid-hop.skel.h"

#define MAX_TGIDS 64

struct evt {
    unsigned int pid;
    unsigned int tgid;
    int syscall_nr;
    int seccomp_mode;
    int override_attempted;
    int override_ok;
    unsigned long long ts_ns;
    char comm[16];
};

static volatile sig_atomic_t stop;
static void sig(int _sig){ (void)_sig; stop = 1; }

static const char *modestr(int m){
    switch(m){
        case 0: return "DISABLED";
        case 1: return "STRICT";
        case 2: return "FILTER";
        default: return "UNKNOWN";
    }
}

static void usage(const char *argv0)
{
    fprintf(stderr,
        "Usage: %s [options]\n"
        "\n"
        "Observe every __secure_computing() invocation and flag those whose\n"
        "tgid is in the target set. The chapter's TID-hop write primitive\n"
        "degrades to observation on stock 6.12 (see README). \n"
        "\n"
        "Options:\n"
        "  -p, --tgid <pid>   Add tgid to target_tgids (repeatable, max %d)\n"
        "  -a, --all          Wildcard: flag every seccomp check as targeted\n"
        "  -h, --help         Show this help and exit\n"
        "\n"
        "Tradeoffs:\n"
        "  --all is loud — every seccomp-filtered task in the system is\n"
        "  marked target=1. Prefer --tgid for surgical demos.\n",
        argv0, MAX_TGIDS);
}

// Return 1 iff `sym` appears as a T/t/W symbol in /proc/kallsyms.
static int sym_exists(const char *sym)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) return -1;
    char line[512];
    size_t slen = strlen(sym);
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        char *p = strchr(line, ' ');
        if (!p) continue;
        char type = p[1];
        char *name = p + 3;
        if (type != 'T' && type != 't' && type != 'W' && type != 'w')
            continue;
        size_t nlen = strcspn(name, " \t\n");
        if (nlen == slen && memcmp(name, sym, slen) == 0) { found = 1; break; }
    }
    fclose(f);
    return found;
}

static int handle(void *ctx, void *data, size_t sz){
    (void)ctx; (void)sz;
    struct evt *e = data;
    printf("[seccomp] ts=%llu pid=%u tgid=%u comm=%-16s mode=%-8s "
           "target=%d nr/ret=%d allow=%d\n",
           e->ts_ns, e->pid, e->tgid, e->comm, modestr(e->seccomp_mode),
           e->override_attempted, e->syscall_nr, e->override_ok);
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv)
{
    static const struct option longopts[] = {
        { "tgid", required_argument, NULL, 'p' },
        { "all",  no_argument,       NULL, 'a' },
        { "help", no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 },
    };

    unsigned int queue[MAX_TGIDS];
    int nqueue = 0;
    int wildcard = 0;
    int c;
    while ((c = getopt_long(argc, argv, "p:ah", longopts, NULL)) != -1) {
        switch (c) {
        case 'p': {
            if (nqueue >= MAX_TGIDS) {
                fprintf(stderr, "[ch16] too many --tgid entries (max %d)\n",
                        MAX_TGIDS);
                return 2;
            }
            char *end = NULL;
            long v = strtol(optarg, &end, 10);
            if (!end || *end != '\0' || v <= 0 || v > 0x7fffffff) {
                fprintf(stderr, "[ch16] invalid --tgid value: %s\n", optarg);
                return 2;
            }
            queue[nqueue++] = (unsigned int)v;
            break;
        }
        case 'a':
            wildcard = 1;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 2;
        }
    }
    if (optind < argc) {
        fprintf(stderr, "[ch16] unexpected positional arg: %s\n", argv[optind]);
        usage(argv[0]);
        return 2;
    }

    // Symbol preflight — refuse to load if the only kprobe target is missing.
    fprintf(stderr, "=== symbol availability ===\n");
    int sc_ok = sym_exists("__secure_computing");
    fprintf(stderr, "  %-28s : %s\n", "__secure_computing",
            sc_ok == 1 ? "present" : (sc_ok == 0 ? "ABSENT" : "kallsyms-err"));
    if (sc_ok != 1) {
        fprintf(stderr, "[ch16] __secure_computing not in kallsyms — "
                        "cannot attach. Bailing.\n");
        return 3;
    }

    struct ch16_seccomp_tid_hop_bpf *s = ch16_seccomp_tid_hop_bpf__open_and_load();
    if (!s) {
        fprintf(stderr, "[ch16] open_and_load failed: %s\n", strerror(errno));
        return 1;
    }
    if (ch16_seccomp_tid_hop_bpf__attach(s)) {
        fprintf(stderr, "[ch16] attach failed: %s\n", strerror(errno));
        ch16_seccomp_tid_hop_bpf__destroy(s);
        return 1;
    }

    unsigned int one = 1;
    if (wildcard) {
        unsigned int z = 0;
        if (bpf_map__update_elem(s->maps.target_tgids, &z, sizeof(z),
                                 &one, sizeof(one), BPF_ANY) != 0) {
            fprintf(stderr, "[ch16] map_update wildcard failed: %s\n",
                    strerror(errno));
        } else {
            fprintf(stderr, "[ch16] targeting: ALL (wildcard)\n");
        }
    }
    for (int i = 0; i < nqueue; i++) {
        if (bpf_map__update_elem(s->maps.target_tgids,
                                 &queue[i], sizeof(queue[i]),
                                 &one, sizeof(one), BPF_ANY) != 0) {
            fprintf(stderr, "[ch16] map_update tgid=%u failed: %s\n",
                    queue[i], strerror(errno));
        } else {
            fprintf(stderr, "[ch16] targeting tgid=%u\n", queue[i]);
        }
    }
    if (!wildcard && nqueue == 0) {
        fprintf(stderr, "[ch16] no targets given — observation only "
                        "(target=0 on every event). Use --tgid or --all.\n");
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(s->maps.events),
                                              handle, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ch16] ringbuf new failed: %s\n", strerror(errno));
        ch16_seccomp_tid_hop_bpf__destroy(s);
        return 1;
    }

    struct sigaction sa = { .sa_handler = sig };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    fprintf(stderr, "[ch16] attached — observing __secure_computing "
                    "(Ctrl-C to stop)\n");
    while (!stop) {
        int err = ring_buffer__poll(rb, 200);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "[ch16] ringbuf poll: %s\n", strerror(-err));
            break;
        }
    }

    fprintf(stderr, "[ch16] shutting down\n");
    ring_buffer__free(rb);
    ch16_seccomp_tid_hop_bpf__destroy(s);
    return 0;
}
