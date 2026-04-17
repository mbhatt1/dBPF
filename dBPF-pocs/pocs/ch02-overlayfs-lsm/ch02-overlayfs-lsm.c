// ch02 OverlayFS Trojan LSM loader: attaches lsm.s/inode_copy_up fmod_ret
// (DENY targeted copy-ups) and lsm.s/inode_permission (observer).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "ch02-overlayfs-lsm.skel.h"

#define PATH_MAX_COMP 64

struct evt {
    unsigned int pid, tgid;
    char comm[16];
    char name[PATH_MAX_COMP];
    int hook;
    int denied;
};

static volatile sig_atomic_t stop;
static void on_sig(int s){ (void)s; stop = 1; }

static int handle(void *ctx, void *data, size_t sz)
{
    (void)ctx;
    if (sz < sizeof(struct evt)) return 0;
    const struct evt *e = data;
    const char *what = (e->hook == 1) ? "COPY_UP" : "PERMISSION";
    printf("[ch02-lsm] %s\tpid=%u\tcomm=%-16s\tname=%-32s\t%s\n",
           what, e->pid, e->comm, e->name,
           e->denied ? "-> DENIED (-EPERM)" : "observed");
    return 0;
}

static int check_lsm_bpf_enabled(void)
{
    FILE *f = fopen("/sys/kernel/security/lsm", "r");
    if (!f) { fprintf(stderr, "[ch02-lsm] /sys/kernel/security/lsm unreadable\n"); return 0; }
    char buf[512] = {0};
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return 0; }
    fclose(f);
    return strstr(buf, "bpf") != NULL;
}

int main(int argc, char **argv)
{
    const char *targets[64];
    int n_targets = 0;
    int opt;
    while ((opt = getopt(argc, argv, "p:h")) != -1) {
        switch (opt) {
        case 'p':
            if (n_targets < 64) targets[n_targets++] = optarg;
            break;
        case 'h':
        default:
            fprintf(stderr, "Usage: %s -p <basename> [-p <basename>]...\n"
                            "  -p NAME   basename (not full path) to protect from copy-up\n",
                    argv[0]);
            return opt == 'h' ? 0 : 2;
        }
    }

    if (n_targets == 0) {
        fprintf(stderr, "[ch02-lsm] ERROR: at least one -p target required\n");
        return 2;
    }

    if (!check_lsm_bpf_enabled()) {
        fprintf(stderr, "[ch02-lsm] CH02_LSM_SKIP reason=\"BPF LSM not enabled "
                        "(boot with lsm=bpf,...)\"\n");
        return 3;
    }
    fprintf(stderr, "[ch02-lsm] BPF LSM is active — proceeding\n");

    struct ch02_overlayfs_lsm_bpf *s = ch02_overlayfs_lsm_bpf__open_and_load();
    if (!s) {
        fprintf(stderr, "[ch02-lsm] CH02_LSM_SKIP reason=\"open_and_load: %s\"\n",
                strerror(errno));
        return 1;
    }

    int err = ch02_overlayfs_lsm_bpf__attach(s);
    if (err) {
        fprintf(stderr, "[ch02-lsm] CH02_LSM_SKIP reason=\"attach: %s\"\n",
                strerror(-err));
        ch02_overlayfs_lsm_bpf__destroy(s);
        return 1;
    }

    for (int i = 0; i < n_targets; i++) {
        char key[PATH_MAX_COMP] = {0};
        strncpy(key, targets[i], PATH_MAX_COMP - 1);
        unsigned int v = 1;
        if (bpf_map__update_elem(s->maps.target_paths, key, sizeof(key),
                                 &v, sizeof(v), BPF_ANY) != 0) {
            fprintf(stderr, "[ch02-lsm] map update for %s failed: %s\n",
                    targets[i], strerror(errno));
        } else {
            fprintf(stderr, "[ch02-lsm] protecting basename=%s\n", targets[i]);
        }
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(s->maps.events), handle, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ch02-lsm] ring_buffer__new: %s\n", strerror(errno));
        ch02_overlayfs_lsm_bpf__destroy(s);
        return 1;
    }
    signal(SIGINT, on_sig); signal(SIGTERM, on_sig);
    fprintf(stderr, "[ch02-lsm] active — copy-up for targeted basenames will be denied\n");

    while (!stop) {
        int n = ring_buffer__poll(rb, 200);
        if (n < 0 && n != -EINTR) break;
    }
    ring_buffer__free(rb);
    ch02_overlayfs_lsm_bpf__destroy(s);
    return 0;
}
