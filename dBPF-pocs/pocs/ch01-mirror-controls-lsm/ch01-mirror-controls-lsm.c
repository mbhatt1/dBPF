// ch01 LSM-variant loader: attaches SEC("lsm.s/capable") fmod_ret program.
// Fails fast with a clear error if the host kernel doesn't expose BPF LSM.
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
    int cap, orig_ret, flipped;
};

static volatile sig_atomic_t stop;
static void on_sig(int s){ (void)s; stop = 1; }

static int handle(void *ctx, void *data, size_t sz)
{
    (void)ctx;
    if (sz < sizeof(struct evt)) return 0;
    const struct evt *e = data;
    if (e->flipped)
        printf("[ch01-lsm] FLIP\tpid=%u\tcomm=%-16s\tcap=%d\torig=%d\t-> 0 (allowed)\n",
               e->pid, e->comm, e->cap, e->orig_ret);
    return 0;
}

static int check_lsm_bpf_enabled(void)
{
    FILE *f = fopen("/sys/kernel/security/lsm", "r");
    if (!f) { fprintf(stderr, "[ch01-lsm] /sys/kernel/security/lsm unreadable\n"); return 0; }
    char buf[512] = {0};
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return 0; }
    fclose(f);
    return strstr(buf, "bpf") != NULL;
}

int main(int argc, char **argv)
{
    unsigned int tgid_args[1024];
    int n_tgid = 0;
    int all = 0;
    int opt;
    while ((opt = getopt(argc, argv, "at:h")) != -1) {
        switch (opt) {
        case 'a': all = 1; break;
        case 't': tgid_args[n_tgid++] = (unsigned int)atoi(optarg); break;
        case 'h':
        default:
            fprintf(stderr, "Usage: %s [-a] [-t tgid]...\n"
                            "  -a     wildcard: flip every capability deny\n"
                            "  -t N   flip denials originating from tgid N\n", argv[0]);
            return opt == 'h' ? 0 : 2;
        }
    }

    if (!check_lsm_bpf_enabled()) {
        fprintf(stderr, "[ch01-lsm] ERROR: kernel does not have 'bpf' in "
                        "/sys/kernel/security/lsm. Boot with lsm=bpf,...\n");
        return 3;
    }
    fprintf(stderr, "[ch01-lsm] BPF LSM is active — proceeding\n");

    struct ch01_mirror_controls_lsm_bpf *s = ch01_mirror_controls_lsm_bpf__open_and_load();
    if (!s) { fprintf(stderr, "[ch01-lsm] open_and_load: %s\n", strerror(errno)); return 1; }

    int err = ch01_mirror_controls_lsm_bpf__attach(s);
    if (err) {
        fprintf(stderr, "[ch01-lsm] attach: %s\n", strerror(-err));
        ch01_mirror_controls_lsm_bpf__destroy(s);
        return 1;
    }

    if (all) {
        unsigned int z = 0, v = 1;
        bpf_map__update_elem(s->maps.target_tgids, &z, sizeof(z), &v, sizeof(v), BPF_ANY);
        fprintf(stderr, "[ch01-lsm] mode=wildcard\n");
    }
    for (int i = 0; i < n_tgid; i++) {
        unsigned int v = 1;
        bpf_map__update_elem(s->maps.target_tgids, &tgid_args[i], sizeof(tgid_args[i]),
                             &v, sizeof(v), BPF_ANY);
        fprintf(stderr, "[ch01-lsm] target=%u\n", tgid_args[i]);
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(s->maps.events), handle, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ch01-lsm] ring_buffer__new: %s\n", strerror(errno));
        ch01_mirror_controls_lsm_bpf__destroy(s);
        return 1;
    }
    signal(SIGINT, on_sig); signal(SIGTERM, on_sig);
    fprintf(stderr, "[ch01-lsm] active — cap denials for targeted tgids will be flipped\n");

    while (!stop) {
        int n = ring_buffer__poll(rb, 200);
        if (n < 0 && n != -EINTR) break;
    }
    ring_buffer__free(rb);
    ch01_mirror_controls_lsm_bpf__destroy(s);
    return 0;
}
