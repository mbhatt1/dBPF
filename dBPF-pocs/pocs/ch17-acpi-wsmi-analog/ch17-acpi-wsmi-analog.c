// ch17 ACPI/WSMI analog — userspace loader.
//
// See ch17-acpi-wsmi-analog.bpf.c for the DISCLAIMER. This analog rewrites
// the openat path argument of a userspace "firmware requester" process
// before the kernel's getname() copies it — demonstrating the same
// "kernel-mediated string substituted in flight" primitive that a real
// request_firmware rewrite would use, without needing an ACPI interpreter
// or a driver that calls request_firmware (neither exists on this host).
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "ch17-acpi-wsmi-analog.skel.h"

#define PATH_SCAN_LEN 96

struct evt {
    unsigned int pid;
    unsigned int tgid;
    char         comm[16];
    int          swapped;
    int          matched;
    char         orig[PATH_SCAN_LEN];
};

#define REPL_PATH "/tmp/CH17_REQ_attacker_replacement.bin"

static volatile sig_atomic_t stop;
static unsigned long         swapped_count;

static void on_signal(int s) { (void)s; stop = 1; }

static int handle(void *ctx, void *data, size_t sz)
{
    (void)ctx;
    if (sz < sizeof(struct evt)) return 0;
    const struct evt *e = data;
    if (e->swapped) swapped_count++;
    printf("[ch17-analog] pid=%u comm=%s matched=%d swapped=%d orig=\"%s\" replacement=\"%s\"\n",
           e->pid, e->comm, e->matched, e->swapped, e->orig, REPL_PATH);
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
        "Attaches sys_enter_openat. Opens by comm='fw_requester' whose path\n"
        "contains 'CH17_REQ_real_firmware.bin' get rewritten to\n"
        "'CH17_REQ_attacker_replacement.bin' before the kernel resolves\n"
        "the path. DISCLAIMER: userspace analog only — real\n"
        "request_firmware/acpi_evaluate_object don't fire on this host.\n",
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
        fprintf(stderr, "[ch17-analog] unexpected arg: %s\n", argv[optind]);
        usage(argv[0]);
        return 2;
    }

    if (!verbose) libbpf_set_print(libbpf_silence);

    int rc = 1;
    struct ch17_acpi_wsmi_analog_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;

    skel = ch17_acpi_wsmi_analog_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "[ch17-analog] open_and_load failed: %s\n", strerror(errno));
        goto out;
    }

    int err = ch17_acpi_wsmi_analog_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "[ch17-analog] attach failed: %s\n", strerror(-err));
        goto out;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ch17-analog] ring_buffer__new failed: %s\n", strerror(errno));
        goto out;
    }

    struct sigaction sa = { .sa_handler = on_signal };
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, NULL) < 0 || sigaction(SIGTERM, &sa, NULL) < 0) {
        fprintf(stderr, "[ch17-analog] sigaction failed: %s\n", strerror(errno));
        goto out;
    }

    fprintf(stderr, "[ch17-analog] attached — path-swap active (Ctrl-C to exit)\n");

    while (!stop) {
        int n = ring_buffer__poll(rb, 200);
        if (n < 0 && n != -EINTR) {
            fprintf(stderr, "[ch17-analog] ring_buffer__poll: %s\n", strerror(-n));
            break;
        }
    }

    rc = 0;
out:
    fprintf(stderr, "[ch17-analog] shutdown swapped=%lu\n", swapped_count);
    if (rb) ring_buffer__free(rb);
    if (skel) ch17_acpi_wsmi_analog_bpf__destroy(skel);
    return rc;
}
