// ch01-mirror-controls-lsm loader — hooks lsm/file_permission.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "ch01-mirror-controls-lsm.skel.h"

struct evt {
    unsigned int pid, tgid;
    char comm[16];
    int hook, orig_ret, flipped, mask;
    char fname[32];
};

static volatile sig_atomic_t stop;
static unsigned long long flips;
static void on_sig(int s){ (void)s; stop = 1; }

static int handle(void *ctx, void *data, size_t sz)
{
    (void)ctx;
    if (sz < sizeof(struct evt)) return 0;
    const struct evt *e = data;
    if (e->flipped) {
        flips++;
        printf("[ch01-lsm] FLIP\tpid=%u\tcomm=%-16s\tfile=%s\tmask=%d\torig=%d\n",
               e->pid, e->comm, e->fname, e->mask, e->orig_ret);
        fflush(stdout);
    }
    return 0;
}

static void usage(const char *a)
{
    fprintf(stderr, "Usage: %s [-t tgid]... [-a] [-h]\n"
        "  -t tgid  target tgid for override\n"
        "  -a       wildcard (all tgids)\n", a);
}

int main(int argc, char **argv)
{
    int wildcard = 0;
    unsigned int targets[1024];
    int ntargets = 0;
    int c;
    while ((c = getopt(argc, argv, "t:ah")) != -1) {
        switch (c) {
        case 't':
            if (ntargets < 1024) targets[ntargets++] = atoi(optarg);
            break;
        case 'a': wildcard = 1; break;
        default: usage(argv[0]); return c == 'h' ? 0 : 2;
        }
    }

    if (!fopen("/sys/kernel/security/lsm", "r") ||
        !strstr(({
            static char buf[256];
            FILE *f = fopen("/sys/kernel/security/lsm", "r");
            if (f) { fgets(buf, sizeof(buf), f); fclose(f); }
            buf;
        }), "bpf")) {
        fprintf(stderr, "[ch01-lsm] CH01_SKIP reason=\"BPF LSM not active\"\n");
        return 2;
    }

    struct ch01_mirror_controls_lsm_bpf *s = ch01_mirror_controls_lsm_bpf__open_and_load();
    if (!s) {
        fprintf(stderr, "[ch01-lsm] CH01_SKIP reason=\"load: %s\"\n", strerror(errno));
        return 1;
    }

    if (wildcard) {
        unsigned int z = 0, one = 1;
        bpf_map__update_elem(s->maps.target_tgids, &z, sizeof(z), &one, sizeof(one), BPF_ANY);
        fprintf(stderr, "[ch01-lsm] mode=wildcard\n");
    }
    for (int i = 0; i < ntargets; i++) {
        unsigned int t = targets[i], one = 1;
        bpf_map__update_elem(s->maps.target_tgids, &t, sizeof(t), &one, sizeof(one), BPF_ANY);
    }

    int err = ch01_mirror_controls_lsm_bpf__attach(s);
    if (err) {
        fprintf(stderr, "[ch01-lsm] CH01_SKIP reason=\"attach: %s\"\n", strerror(-err));
        ch01_mirror_controls_lsm_bpf__destroy(s);
        return 1;
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(s->maps.events), handle, NULL, NULL);
    if (!rb) { ch01_mirror_controls_lsm_bpf__destroy(s); return 1; }

    fprintf(stderr, "[ch01-lsm] BPF LSM is active — proceeding\n");
    fprintf(stderr, "[ch01-lsm] active — file_permission denials will be flipped\n");

    struct sigaction sa = { .sa_handler = on_sig };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    while (!stop) {
        int n = ring_buffer__poll(rb, 200);
        if (n < 0 && n != -EINTR) break;
    }

    fprintf(stderr, "[ch01-lsm] flips=%llu\n", flips);
    ring_buffer__free(rb);
    ch01_mirror_controls_lsm_bpf__destroy(s);
    return 0;
}
