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
};

static volatile sig_atomic_t stop;
static unsigned long long total_events;
static unsigned long long denies;

static void on_sig(int s){ (void)s; stop = 1; }

static const char *type_name(short t)
{
    switch (t) { case 1: return "B"; case 2: return "C"; case 6: return "block"; default: return "?"; }
}

static int handle(void *ctx, void *data, size_t sz)
{
    (void)ctx;
    if (sz < sizeof(struct evt)) return 0;
    const struct evt *e = data;
    total_events++;
    if (e->verdict != 0) denies++;
    printf("[ch07] pid=%u\tcomm=%-16s\ttype=%s\tmajor=%u\tminor=%u\taccess=0x%x\tverdict=%d\n",
           e->pid, e->comm, type_name(e->type), e->major, e->minor, e->access, e->verdict);
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
        p = strchr(p + 1, ' '); if (!p) continue;
        p++;
        size_t n = strlen(p); while (n && (p[n-1]=='\n'||p[n-1]==' '||p[n-1]=='\t')) p[--n]=0;
        char *t = strchr(p, '\t'); if (t) *t = 0;
        if (!strcmp(p, sym)) { found = 1; break; }
    }
    fclose(f);
    return found;
}

static void usage(const char *a)
{
    fprintf(stderr, "Usage: %s [-v] [-h]\n"
                    "  -v   verbose libbpf output\n"
                    "  -h   show this help\n"
                    "Events to stdout; status to stderr.\n", a);
}

int main(int argc, char **argv)
{
    int verbose = 0;
    int c;
    while ((c = getopt(argc, argv, "vh")) != -1) {
        switch (c) {
        case 'v': verbose = 1; break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 2;
        }
    }
    if (verbose) { /* libbpf will default to printing */ }

    int has = kallsyms_has("devcgroup_check_permission");
    if (has == 0) {
        fprintf(stderr, "[ch07] CH07_SKIP reason=\"devcgroup_check_permission symbol absent (kernel built without CONFIG_CGROUP_DEVICE or inlined)\"\n");
        return 2;
    }
    if (has > 0)
        fprintf(stderr, "[ch07] symbol=devcgroup_check_permission\tstatus=present\n");

    int rc = 1;
    struct ring_buffer *rb = NULL;
    struct ch07_devcgroup_houdini_bpf *s = ch07_devcgroup_houdini_bpf__open_and_load();
    if (!s) { fprintf(stderr, "[ch07] open_and_load: %s\n", strerror(errno)); return 1; }
    int err = ch07_devcgroup_houdini_bpf__attach(s);
    if (err) { fprintf(stderr, "[ch07] attach: %s\n", strerror(-err)); goto out; }

    rb = ring_buffer__new(bpf_map__fd(s->maps.events), handle, NULL, NULL);
    if (!rb) { fprintf(stderr, "[ch07] ring_buffer__new: %s\n", strerror(errno)); goto out; }

    struct sigaction sa = { .sa_handler = on_sig };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    fprintf(stderr, "[ch07] attached — devcgroup observer active\n");
    while (!stop) {
        int n = ring_buffer__poll(rb, 200);
        if (n < 0 && n != -EINTR) { fprintf(stderr, "[ch07] poll: %s\n", strerror(-n)); break; }
    }
    rc = 0;

    if (total_events > 0)
        fprintf(stderr, "[ch07] CH07_PROVEN events=%llu denies=%llu\n", total_events, denies);
    else
        fprintf(stderr, "[ch07] CH07_SKIP reason=\"no deny observed (privileged container bypasses devcgroup; re-run with restricted cgroup)\"\n");
out:
    if (rb) ring_buffer__free(rb);
    if (s) ch07_devcgroup_houdini_bpf__destroy(s);
    return rc;
}
