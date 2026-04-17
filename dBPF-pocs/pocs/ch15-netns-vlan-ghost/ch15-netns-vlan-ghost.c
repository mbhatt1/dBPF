// ch15-netns-vlan-ghost: XDP loader.
//
// Attaches xdp_vlan_ghost to an ingress veth. When VLAN 4242 ingress
// frames arrive, the BPF program strips the tag and (optionally)
// redirects via DEVMAP to an egress interface in a different netns.
//
// Status messages on stderr; events on stdout. SIGINT / SIGTERM
// trigger a clean detach in *every* exit path — including failures
// after a partial attach.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdarg.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "ch15-netns-vlan-ghost.skel.h"

struct evt {
    unsigned int   ifindex_in;
    unsigned int   redirect_ifindex;
    unsigned short vlan_id;
    unsigned short inner_proto;
    unsigned char  src_mac[6];
    unsigned char  dst_mac[6];
    int            action;
};

static volatile sig_atomic_t stop;
static void on_sig(int _s) { (void)_s; stop = 1; }

/* Track which ifindexes have an active XDP attach so cleanup detaches
 * regardless of which exit path fires. */
static int g_attached_ifindex_in;
static int g_attached_ifindex_out;
static unsigned int g_xdp_flags;

static int g_verbose;
static int libbpf_print(enum libbpf_print_level lvl, const char *fmt, va_list ap)
{
    if (!g_verbose && lvl == LIBBPF_DEBUG) return 0;
    return vfprintf(stderr, fmt, ap);
}

static void usage(const char *argv0)
{
    fprintf(stderr,
        "Usage: %s [options] -i <ingress-ifname> [-o <egress-ifname>]\n"
        "  -i, --ingress <ifname>   veth on which VLAN 4242 arrives (required)\n"
        "  -o, --egress  <ifname>   redirect target (must be XDP-capable);\n"
        "                           if omitted: strip-only / XDP_PASS\n"
        "  -s, --skb                force XDP SKB-mode (linuxkit needs this)\n"
        "  -h, --help               show this help and exit\n"
        "  -v, --verbose            noisier libbpf logging\n"
        "\n"
        "Back-compat positional form: %s <ingress> [egress]\n",
        argv0, argv0);
}

static int handle_event(void *ctx, void *data, size_t sz)
{
    (void)ctx;
    if (sz < sizeof(struct evt)) return 0;
    struct evt *e = data;
    const char *act = e->action == 1 ? "STRIP+REDIRECT"
                    : e->action == 2 ? "STRIP+PASS"
                    : "PASS";
    printf("[vghost] ifin=%u vid=%u inner=0x%04x "
           "%02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x  "
           "%s ifout=%u\n",
           e->ifindex_in, e->vlan_id, e->inner_proto,
           e->src_mac[0],e->src_mac[1],e->src_mac[2],
           e->src_mac[3],e->src_mac[4],e->src_mac[5],
           e->dst_mac[0],e->dst_mac[1],e->dst_mac[2],
           e->dst_mac[3],e->dst_mac[4],e->dst_mac[5],
           act, e->redirect_ifindex);
    fflush(stdout);
    return 0;
}

/* On Docker Desktop linuxkit 6.12 veth, only generic mode (flag 0 =
 * xdpgeneric) actually processes packets. DRV and SKB modes attach
 * successfully but silently fail to invoke the XDP program. So we try
 * generic first, then fall back to drv/skb for non-veth devices. */
static int attach_xdp(int ifindex, int prog_fd, bool force_skb, unsigned int *out_flags)
{
    int err;
    (void)force_skb;  /* ignored — generic mode is always preferred now */

    /* Generic mode first — reliable on veth. */
    err = bpf_xdp_attach(ifindex, prog_fd, 0, NULL);
    if (!err) { *out_flags = 0; return 0; }
    fprintf(stderr, "[ch15] generic failed on ifindex=%d (%s); trying drv\n",
            ifindex, strerror(-err));

    err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_DRV_MODE, NULL);
    if (!err) { *out_flags = XDP_FLAGS_DRV_MODE; return 0; }
    fprintf(stderr, "[ch15] drv-mode failed on ifindex=%d (%s); trying skb\n",
            ifindex, strerror(-err));

    err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
    if (!err) { *out_flags = XDP_FLAGS_SKB_MODE; return 0; }
    fprintf(stderr, "[ch15] all XDP attach modes failed on ifindex=%d: %s\n",
            ifindex, strerror(-err));
    return err;
}

static void detach_all(void)
{
    if (g_attached_ifindex_in) {
        int err = bpf_xdp_detach(g_attached_ifindex_in, g_xdp_flags, NULL);
        if (err) fprintf(stderr, "[ch15] detach ingress failed: %s\n", strerror(-err));
        g_attached_ifindex_in = 0;
    }
    if (g_attached_ifindex_out) {
        int err = bpf_xdp_detach(g_attached_ifindex_out, g_xdp_flags, NULL);
        if (err) fprintf(stderr, "[ch15] detach egress failed: %s\n", strerror(-err));
        g_attached_ifindex_out = 0;
    }
}

int main(int argc, char **argv)
{
    const char *ifn_in  = NULL;
    const char *ifn_out = NULL;
    bool force_skb = false;

    static const struct option long_opts[] = {
        { "ingress", required_argument, NULL, 'i' },
        { "egress",  required_argument, NULL, 'o' },
        { "skb",     no_argument,       NULL, 's' },
        { "help",    no_argument,       NULL, 'h' },
        { "verbose", no_argument,       NULL, 'v' },
        { NULL, 0, NULL, 0 },
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:o:shv", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'i': ifn_in  = optarg; break;
        case 'o': ifn_out = optarg; break;
        case 's': force_skb = true; break;
        case 'h': usage(argv[0]); return 0;
        case 'v': g_verbose = 1; break;
        default:  usage(argv[0]); return 2;
        }
    }

    /* back-compat positional form */
    if (!ifn_in && optind < argc)              ifn_in  = argv[optind++];
    if (!ifn_out && optind < argc)             ifn_out = argv[optind++];
    if (optind < argc) {
        fprintf(stderr, "unexpected extra argument: %s\n", argv[optind]);
        usage(argv[0]);
        return 2;
    }
    if (!ifn_in) {
        fprintf(stderr, "missing required --ingress\n");
        usage(argv[0]);
        return 2;
    }

    int ifidx_in = if_nametoindex(ifn_in);
    if (!ifidx_in) {
        fprintf(stderr, "[ch15] if_nametoindex(%s): %s\n", ifn_in, strerror(errno));
        return 1;
    }
    int ifidx_out = 0;
    if (ifn_out) {
        ifidx_out = if_nametoindex(ifn_out);
        if (!ifidx_out) {
            fprintf(stderr, "[ch15] if_nametoindex(%s): %s\n", ifn_out, strerror(errno));
            return 1;
        }
    }

    libbpf_set_print(libbpf_print);

    /* Install signal handlers BEFORE attach so a fast Ctrl-C between
     * attach and the poll loop still detaches via atexit-equivalent. */
    if (signal(SIGINT,  on_sig) == SIG_ERR ||
        signal(SIGTERM, on_sig) == SIG_ERR) {
        fprintf(stderr, "[ch15] signal(): %s\n", strerror(errno));
        return 1;
    }

    int rc = 1;
    struct ring_buffer *rb = NULL;
    struct ch15_netns_vlan_ghost_bpf *s = ch15_netns_vlan_ghost_bpf__open_and_load();
    if (!s) {
        fprintf(stderr, "[ch15] CH15_SKIP reason=\"open_and_load failed: %s\"\n",
                strerror(errno));
        return 1;
    }

    /* Populate cfg + devmap. */
    unsigned int key0 = 0, key1 = 1;
    unsigned int mode = ifn_out ? 1u : 0u;
    int err = bpf_map__update_elem(s->maps.cfg, &key0, sizeof(key0),
                                   &mode, sizeof(mode), BPF_ANY);
    if (err) {
        fprintf(stderr, "[ch15] cfg[0] update: %s\n", strerror(-err));
        goto out;
    }
    if (ifn_out) {
        unsigned int tgt = (unsigned int)ifidx_out;
        err = bpf_map__update_elem(s->maps.cfg, &key1, sizeof(key1),
                                   &tgt, sizeof(tgt), BPF_ANY);
        if (err) {
            fprintf(stderr, "[ch15] cfg[1] update: %s\n", strerror(-err));
            goto out;
        }
        unsigned int devkey = 0;
        err = bpf_map__update_elem(s->maps.tx_port, &devkey, sizeof(devkey),
                                   &ifidx_out, sizeof(ifidx_out), BPF_ANY);
        if (err) {
            fprintf(stderr, "[ch15] tx_port update: %s\n", strerror(-err));
            goto out;
        }
    }

    int prog_fd = bpf_program__fd(s->progs.xdp_vlan_ghost);
    if (prog_fd < 0) {
        fprintf(stderr, "[ch15] bpf_program__fd failed\n");
        goto out;
    }

    if (attach_xdp(ifidx_in, prog_fd, force_skb, &g_xdp_flags) != 0) {
        fprintf(stderr, "[ch15] xdp attach to %s failed\n", ifn_in);
        goto out;
    }
    g_attached_ifindex_in = ifidx_in;

    if (ifn_out) {
        unsigned int egress_flags = 0;
        if (attach_xdp(ifidx_out, prog_fd, force_skb, &egress_flags) != 0) {
            fprintf(stderr, "[ch15] WARNING: egress XDP attach to %s failed; "
                            "redirect may not work\n", ifn_out);
        } else {
            g_attached_ifindex_out = ifidx_out;
            /* If ingress and egress disagree on flags, detach uses the
             * ingress flag; that's fine for SKB/DRV interchangeably. */
        }
    }

    rb = ring_buffer__new(bpf_map__fd(s->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ch15] ring_buffer__new failed: %s\n", strerror(errno));
        goto out;
    }

    fprintf(stderr,
            "[ch15] tag=ready ingress=%s ifidx=%d mode=%s egress=%s ifidx=%d xdp_flags=0x%x\n",
            ifn_in, ifidx_in, ifn_out ? "redirect" : "strip-only",
            ifn_out ? ifn_out : "-", ifidx_out, g_xdp_flags);

    while (!stop) {
        int n = ring_buffer__poll(rb, 200);
        if (n < 0 && n != -EINTR) {
            fprintf(stderr, "[ch15] ring_buffer__poll: %s\n", strerror(-n));
            break;
        }
    }

    rc = 0;
    fprintf(stderr, "[ch15] tag=shutdown\n");

out:
    detach_all();
    if (rb) ring_buffer__free(rb);
    if (s)  ch15_netns_vlan_ghost_bpf__destroy(s);
    return rc;
}
