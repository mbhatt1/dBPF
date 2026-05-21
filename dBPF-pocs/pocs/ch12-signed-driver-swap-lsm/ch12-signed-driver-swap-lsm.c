// ch12 LSM-variant loader: attaches three SEC("lsm.s/*") fmod_ret programs:
//   - kernel_read_file
//   - kernel_load_data
//   - locked_down
// Fails fast with CH12_SKIP if the host kernel doesn't expose BPF LSM.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "ch12-signed-driver-swap-lsm.skel.h"

#define HOOK_NAME_LEN 24

struct evt {
    unsigned int pid, tgid;
    char comm[16];
    int hook;
    int orig_ret;
    int flipped;
    char hook_name[HOOK_NAME_LEN];
};

static volatile sig_atomic_t stop;
static void on_sig(int s){ (void)s; stop = 1; }

static int handle(void *ctx, void *data, size_t sz)
{
    (void)ctx;
    if (sz < sizeof(struct evt)) return 0;
    const struct evt *e = data;
    if (e->flipped) {
        printf("[ch12] FLIP\thook=%-.*s\tpid=%u\tcomm=%-16s\torig=%d\t-> 0\n",
               HOOK_NAME_LEN, e->hook_name[0] ? e->hook_name : "?",
               e->pid, e->comm, e->orig_ret);
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
        "  -a     wildcard: flip every kernel_read_file / kernel_load_data / locked_down denial\n"
        "  -t N   flip denials originating from tgid N\n"
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
        fprintf(stderr, "CH12_SKIP reason=\"%s\"\n", skip_reason);
        return 3;
    }
    fprintf(stderr, "[ch12] BPF LSM is active - proceeding\n");

    struct ch12_signed_driver_swap_lsm_bpf *s =
        ch12_signed_driver_swap_lsm_bpf__open_and_load();
    if (!s) {
        fprintf(stderr, "[ch12] open_and_load: %s\n", strerror(errno));
        return 1;
    }

    int err = ch12_signed_driver_swap_lsm_bpf__attach(s);
    if (err) {
        fprintf(stderr, "[ch12] attach: %s\n", strerror(-err));
        ch12_signed_driver_swap_lsm_bpf__destroy(s);
        return 1;
    }

    if (all) {
        unsigned int z = 0, v = 1;
        bpf_map__update_elem(s->maps.target_tgids, &z, sizeof(z),
                             &v, sizeof(v), BPF_ANY);
        fprintf(stderr, "[ch12] mode=wildcard\n");
    }
    for (int i = 0; i < n_tgid; i++) {
        unsigned int v = 1;
        bpf_map__update_elem(s->maps.target_tgids,
                             &tgid_args[i], sizeof(tgid_args[i]),
                             &v, sizeof(v), BPF_ANY);
        fprintf(stderr, "[ch12] target=%u\n", tgid_args[i]);
    }

    struct ring_buffer *rb =
        ring_buffer__new(bpf_map__fd(s->maps.events), handle, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ch12] ring_buffer__new: %s\n", strerror(errno));
        ch12_signed_driver_swap_lsm_bpf__destroy(s);
        return 1;
    }

    struct sigaction sa = { .sa_handler = on_sig };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    fprintf(stderr,
        "[ch12] active - kernel_read_file/kernel_load_data/locked_down denials will be flipped\n");

    while (!stop) {
        int n = ring_buffer__poll(rb, 200);
        if (n < 0 && n != -EINTR) break;
    }
    ring_buffer__free(rb);
    ch12_signed_driver_swap_lsm_bpf__destroy(s);
    return 0;
}
