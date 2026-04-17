// ch13 powercap-override analog — userspace loader.
//
// See ch13-powercap-override-analog.bpf.c for the DISCLAIMER. This analog
// demonstrates the primitive ("rewrite read() buffer in flight") against a
// userspace sensor daemon, not against real RAPL (which is x86-only and
// absent on aarch64 linuxkit).
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "ch13-powercap-override-analog.skel.h"

struct evt {
    unsigned int pid;
    unsigned int tgid;
    char         comm[16];
    long         orig_bytes;
    int          patched;
};

static volatile sig_atomic_t stop;
static unsigned long patched_count;

static void on_signal(int signo) { (void)signo; stop = 1; }

static int handle_event(void *ctx, void *data, size_t sz)
{
    (void)ctx;
    if (sz < sizeof(struct evt)) return 0;
    const struct evt *e = data;
    if (e->patched) patched_count++;
    printf("[ch13-analog] pid=%-7u comm=%-16s sensor_read_bytes=%-4ld patched=%d\n",
           e->pid, e->comm, e->orig_bytes, e->patched);
    fflush(stdout);
    return 0;
}

static int libbpf_silence(enum libbpf_print_level lvl, const char *fmt, va_list ap)
{
    if (lvl == LIBBPF_DEBUG) return 0;
    return vfprintf(stderr, fmt, ap);
}

static void usage(const char *p)
{
    fprintf(stderr,
        "Usage: %s [-v] [-h]\n"
        "  -v  verbose libbpf output\n"
        "  -h  this help\n"
        "\n"
        "Attaches sys_enter_read/sys_exit_read. Reads of files whose\n"
        "basename is 'ch13_sensor_energy_uj' get their user buffer\n"
        "rewritten to '0\\n'. DISCLAIMER: this is a userspace analog —\n"
        "real RAPL/powercap is x86-only and does not exist on this host.\n",
        p);
}

int main(int argc, char **argv)
{
    int verbose = 0;
    static const struct option longopts[] = {
        {"verbose", no_argument, NULL, 'v'},
        {"help",    no_argument, NULL, 'h'},
        {0, 0, 0, 0},
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "vh", longopts, NULL)) != -1) {
        switch (opt) {
        case 'v': verbose = 1; break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 2;
        }
    }
    if (optind < argc) {
        fprintf(stderr, "[ch13-analog] unexpected arg: %s\n", argv[optind]);
        usage(argv[0]);
        return 2;
    }

    if (!verbose) libbpf_set_print(libbpf_silence);

    int rc = 1;
    struct ch13_powercap_override_analog_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;

    skel = ch13_powercap_override_analog_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "[ch13-analog] CH13_ANALOG_SKIP reason=\"open_and_load failed: %s\"\n",
                strerror(errno));
        goto out;
    }

    int err = ch13_powercap_override_analog_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "[ch13-analog] CH13_ANALOG_SKIP reason=\"attach failed: %s\"\n",
                strerror(-err));
        goto out;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ch13-analog] ring_buffer__new failed: %s\n", strerror(errno));
        goto out;
    }

    struct sigaction sa = { .sa_handler = on_signal };
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, NULL) < 0 || sigaction(SIGTERM, &sa, NULL) < 0) {
        fprintf(stderr, "[ch13-analog] sigaction failed: %s\n", strerror(errno));
        goto out;
    }

    fprintf(stderr, "[ch13-analog] attached — sensor override active (Ctrl-C to exit)\n");

    while (!stop) {
        int n = ring_buffer__poll(rb, 200);
        if (n < 0 && n != -EINTR) {
            fprintf(stderr, "[ch13-analog] ring_buffer__poll: %s\n", strerror(-n));
            break;
        }
    }

    rc = 0;
out:
    fprintf(stderr, "[ch13-analog] shutdown patched=%lu\n", patched_count);
    if (rb) ring_buffer__free(rb);
    if (skel) ch13_powercap_override_analog_bpf__destroy(skel);
    return rc;
}
