// ch09 pid-doppel — userspace loader
//
// Tracks every fresh PID-namespace entry by hooking sched_process_fork
// (raw tracepoint) and copy_namespaces (kprobe). On SIGINT/SIGTERM, dumps
// every recorded host<->ns PID pair from the mapping HASH map as a summary.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "ch09-pid-doppel.skel.h"

struct evt {
    unsigned int host_pid;
    unsigned int host_tgid;
    unsigned int ns_pid;
    unsigned int ns_level;
    unsigned long ns_inum;
    char comm[16];
    int src;
};

static volatile sig_atomic_t stop;
static void on_signal(int sig)
{
    (void)sig;
    stop = 1;
}

static const char *src_str(int s)
{
    switch (s) {
    case 1: return "fork";
    case 2: return "copy";
    default: return "?";
    }
}

static int handle(void *ctx, void *data, size_t sz)
{
    (void)ctx;
    if (sz < sizeof(struct evt))
        return 0;
    const struct evt *e = data;
    printf("[ch09] src=%-4s\thost_pid=%u\thost_tgid=%u\tns_pid=%u\tlevel=%u\tns_inum=%lu\tcomm=%s\n",
           src_str(e->src), e->host_pid, e->host_tgid,
           e->ns_pid, e->ns_level, e->ns_inum, e->comm);
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
        "Usage: %s [-v] [-h]\n"
        "  -v        verbose libbpf output\n"
        "  -h, --help show this help\n"
        "Events to stdout; status to stderr. On SIGINT/SIGTERM a summary\n"
        "of the host<->ns PID mapping table is printed to stderr.\n",
        prog);
}

// Returns 1 if symbol found in /proc/kallsyms, 0 if absent, -1 on I/O error.
static int kallsyms_has(const char *sym)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) {
        fprintf(stderr, "[ch09] open /proc/kallsyms: %s\n", strerror(errno));
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

static void dump_mapping(struct bpf_map *m)
{
    int fd = bpf_map__fd(m);
    if (fd < 0) {
        fprintf(stderr, "[ch09] mapping fd unavailable\n");
        return;
    }
    fprintf(stderr, "\n[ch09] === post-run mapping table ===\n");
    fprintf(stderr, "[ch09] %-10s %-10s %-10s %-6s %-12s %s\n",
            "host_pid", "host_tgid", "ns_pid", "level", "ns_inum", "comm");
    unsigned int key = 0, next_key = 0;
    struct evt v;
    int n = 0;
    while (bpf_map_get_next_key(fd, n == 0 ? NULL : &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(fd, &next_key, &v) == 0) {
            fprintf(stderr, "[ch09] %-10u %-10u %-10u %-6u %-12lu %s\n",
                    v.host_pid, v.host_tgid, v.ns_pid,
                    v.ns_level, v.ns_inum, v.comm);
            n++;
        }
        key = next_key;
    }
    fprintf(stderr, "[ch09] === %d entries ===\n", n);
}

int main(int argc, char **argv)
{
    int verbose = 0;
    static struct option longopts[] = {
        { "help", no_argument, NULL, 'h' },
        { 0, 0, 0, 0 }
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "vh", longopts, NULL)) != -1) {
        switch (opt) {
        case 'v': verbose = 1; break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 2;
        }
    }
    if (optind != argc) {
        fprintf(stderr, "[ch09] unexpected argument: %s\n", argv[optind]);
        usage(argv[0]);
        return 2;
    }

    if (verbose)
        libbpf_set_print(libbpf_print);

    int rc = 1;
    struct ring_buffer *rb = NULL;
    struct ch09_pid_doppel_bpf *s = ch09_pid_doppel_bpf__open();
    if (!s) {
        fprintf(stderr, "[ch09] skeleton open failed: %s\n", strerror(errno));
        return 1;
    }

    // Symbol preflight — copy_namespaces may be inlined / absent on some kernels.
    int has_copy = kallsyms_has("copy_namespaces");
    if (has_copy == 0) {
        fprintf(stderr, "[ch09] symbol copy_namespaces absent — disabling kp_copy\n");
        if (bpf_program__set_autoload(s->progs.kp_copy, false))
            fprintf(stderr, "[ch09] set_autoload(kp_copy,false) failed\n");
    } else if (has_copy > 0) {
        fprintf(stderr, "[ch09] symbol=copy_namespaces\tstatus=present\n");
    }
    // raw_tp/sched_process_fork is a tracepoint — always present when CONFIG_SCHED_TRACEPOINTS=y.

    int err = ch09_pid_doppel_bpf__load(s);
    if (err) {
        fprintf(stderr, "[ch09] load failed: %s\n", strerror(-err));
        goto out;
    }

    int n_attached = 0, n_skipped = 0, n_failed = 0;
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, s->obj) {
        if (!bpf_program__autoload(prog)) {
            n_skipped++;
            continue;
        }
        struct bpf_link *link = bpf_program__attach(prog);
        long e = libbpf_get_error(link);
        if (e) {
            fprintf(stderr, "[ch09] attach prog=%s failed: %s\n",
                    bpf_program__name(prog), strerror(-(int)e));
            n_failed++;
            continue;
        }
        n_attached++;
    }
    fprintf(stderr, "[ch09] attached=%d\tskipped=%d\tfailed=%d\n",
            n_attached, n_skipped, n_failed);
    if (n_attached == 0) {
        fprintf(stderr, "[ch09] no programs attached — nothing to do\n");
        goto out;
    }

    rb = ring_buffer__new(bpf_map__fd(s->maps.events), handle, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ch09] ring_buffer__new failed: %s\n", strerror(errno));
        goto out;
    }

    struct sigaction sa = { .sa_handler = on_signal };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    fprintf(stderr, "[ch09] status=ready\tmsg=doppelganger tracker active\n");
    while (!stop) {
        int n = ring_buffer__poll(rb, 200);
        if (n < 0 && n != -EINTR) {
            fprintf(stderr, "[ch09] ring_buffer__poll: %s\n", strerror(-n));
            break;
        }
    }
    rc = 0;

    // Post-run mapping table — walk the HASH map and print every recorded
    // host<->ns pid pair as a summary.
    dump_mapping(s->maps.mapping);

out:
    if (rb)
        ring_buffer__free(rb);
    if (s)
        ch09_pid_doppel_bpf__destroy(s);
    fprintf(stderr, "[ch09] status=exit\tcode=%d\n", rc);
    return rc;
}
