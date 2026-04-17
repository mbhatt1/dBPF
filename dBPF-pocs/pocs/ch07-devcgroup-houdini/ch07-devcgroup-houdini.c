// ch07 devcgroup-houdini — userspace loader with SIGUSR2 injection.
//
// Hooks devcgroup_check_permission kprobe+kretprobe. On denials for
// targeted tgids, the BPF program sends SIGUSR2 proving real kernel-side
// control. Supports -t <tgid> targeting and -a (wildcard).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "ch07-devcgroup-houdini.skel.h"

struct evt {
    unsigned int pid, tgid;
    char comm[16];
    int hook;
    short type;
    unsigned int major, minor;
    int access;
    int verdict;
    int signal_sent;
};

static volatile sig_atomic_t stop;
static unsigned long long total_events;
static unsigned long long denies;
static unsigned long long signals_sent;

static void on_sig(int s){ (void)s; stop = 1; }

static const char *type_name(short t)
{
    switch (t) {
    case 1:  return "blk";
    case 2:  return "chr";
    case 6:  return "blk";
    default: return "?";
    }
}

static const char *access_str(int a)
{
    static char buf[8];
    int i = 0;
    if (a & 1) buf[i++] = 'r';
    if (a & 2) buf[i++] = 'w';
    if (a & 4) buf[i++] = 'm';
    buf[i] = 0;
    return buf;
}

static int handle(void *ctx, void *data, size_t sz)
{
    (void)ctx;
    if (sz < sizeof(struct evt)) return 0;
    const struct evt *e = data;
    total_events++;
    if (e->verdict != 0) denies++;
    if (e->signal_sent) signals_sent++;

    const char *verdict = e->verdict == 0 ? "ALLOW" : "DENY";
    printf("[ch07] hook=devcgroup_check_permission   pid=%-5u comm=%-16s type=%s %u:%u access=%s verdict=%s",
           e->pid, e->comm, type_name(e->type), e->major, e->minor,
           access_str(e->access), verdict);
    if (e->signal_sent)
        printf("  SIGUSR2_SENT");
    printf("\n");
    fflush(stdout);
    return 0;
}

static int kallsyms_has(const char *sym)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) return -1;
    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        char *p = strchr(line, ' '); if (!p) continue;
        char type = p[1];
        if (type != 'T' && type != 't' && type != 'W' && type != 'w')
            continue;
        p = strchr(p + 1, ' '); if (!p) continue;
        p++;
        size_t n = strlen(p);
        while (n && (p[n-1]=='\n'||p[n-1]==' '||p[n-1]=='\t')) p[--n]=0;
        char *t = strchr(p, '\t'); if (t) *t = 0;
        if (!strcmp(p, sym)) { found = 1; break; }
    }
    fclose(f);
    return found;
}

static void usage(const char *a)
{
    fprintf(stderr,
        "Usage: %s [-t tgid]... [-a] [-v] [-h]\n"
        "  -t tgid  target tgid for SIGUSR2 on denial\n"
        "  -a       wildcard: signal ALL denials\n"
        "  -v       verbose libbpf output\n"
        "  -h       show this help\n"
        "\n"
        "Hooks devcgroup_check_permission. On device-cgroup denials for\n"
        "targeted tgids, sends SIGUSR2 to prove kernel-side control.\n",
        a);
}

#define MAX_TARGETS 1024

int main(int argc, char **argv)
{
    int verbose = 0, wildcard = 0;
    unsigned int targets[MAX_TARGETS];
    size_t n_targets = 0;
    int c;

    while ((c = getopt(argc, argv, "t:avh")) != -1) {
        switch (c) {
        case 't': {
            if (n_targets >= MAX_TARGETS) {
                fprintf(stderr, "[ch07] too many -t entries\n");
                return 2;
            }
            char *end;
            unsigned long v = strtoul(optarg, &end, 10);
            if (!end || *end || v == 0) {
                fprintf(stderr, "[ch07] invalid tgid: %s\n", optarg);
                return 2;
            }
            targets[n_targets++] = (unsigned int)v;
            break;
        }
        case 'a': wildcard = 1; break;
        case 'v': verbose = 1; break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 2;
        }
    }
    (void)verbose;

    int has = kallsyms_has("devcgroup_check_permission");
    if (has == 0) {
        fprintf(stderr, "[ch07] CH07_SKIP reason=\"devcgroup_check_permission absent\"\n");
        return 2;
    }
    fprintf(stderr, "[ch07] symbol=devcgroup_check_permission\tstatus=present\n");

    int rc = 1;
    struct ring_buffer *rb = NULL;
    struct ch07_devcgroup_houdini_bpf *s = ch07_devcgroup_houdini_bpf__open_and_load();
    if (!s) {
        fprintf(stderr, "[ch07] CH07_SKIP reason=\"open_and_load: %s\"\n", strerror(errno));
        return 1;
    }

    // Populate target_tgids map.
    if (wildcard) {
        unsigned int zero = 0, one = 1;
        bpf_map__update_elem(s->maps.target_tgids,
                             &zero, sizeof(zero), &one, sizeof(one), BPF_ANY);
        fprintf(stderr, "[ch07] tag=target\tmode=wildcard\n");
    }
    for (size_t i = 0; i < n_targets; i++) {
        unsigned int t = targets[i], one = 1;
        bpf_map__update_elem(s->maps.target_tgids,
                             &t, sizeof(t), &one, sizeof(one), BPF_ANY);
        fprintf(stderr, "[ch07] tag=target\ttgid=%u\n", t);
    }

    int err = ch07_devcgroup_houdini_bpf__attach(s);
    if (err) {
        fprintf(stderr, "[ch07] CH07_SKIP reason=\"attach: %s\"\n", strerror(-err));
        goto out;
    }

    rb = ring_buffer__new(bpf_map__fd(s->maps.events), handle, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ch07] ring_buffer__new: %s\n", strerror(errno));
        goto out;
    }

    struct sigaction sa = { .sa_handler = on_sig };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    fprintf(stderr, "[ch07] attached — devcgroup houdini active (SIGUSR2 on denial)\n");

    while (!stop) {
        int n = ring_buffer__poll(rb, 200);
        if (n < 0 && n != -EINTR) break;
    }
    rc = 0;

    fprintf(stderr, "[ch07] total=%llu denies=%llu signals=%llu\n",
            total_events, denies, signals_sent);
    if (signals_sent > 0)
        printf("[ch07] CH07_WEAPON_PROVEN signals=%llu denies=%llu events=%llu\n",
               signals_sent, denies, total_events);
    else if (total_events > 0)
        printf("[ch07] CH07_PROVEN events=%llu denies=%llu\n",
               total_events, denies);

out:
    if (rb) ring_buffer__free(rb);
    if (s) ch07_devcgroup_houdini_bpf__destroy(s);
    return rc;
}
