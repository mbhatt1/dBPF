// ch05-cgroup-leash userspace loader.
//
// Attaches sys_enter_read / sys_exit_read tracepoints. The BPF program
// rewrites cpu.stat reads in-place so observers see zero CPU usage.
//
// Production hardening:
//   - getopt argument parsing with -h/--help
//   - SIGINT/SIGTERM clean shutdown, cleanup on every exit path
//   - every libbpf return value checked with strerror() messages
//   - events to stdout, status to stderr
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "ch05-cgroup-leash.skel.h"

struct evt {
    unsigned int pid;
    unsigned int tgid;
    char comm[16];
    long orig_bytes;
    int patched;
};

static volatile sig_atomic_t stop;

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
    printf("[ch05] pid=%-7u tgid=%-7u comm=%-16s cpu.stat_bytes=%-5ld patched=%d\n",
           e->pid, e->tgid, e->comm, e->orig_bytes, e->patched);
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
        "Usage: %s [-v] [-h]\n"
        "  -v, --verbose   Enable libbpf debug logs\n"
        "  -h, --help      Show this help and exit\n"
        "\n"
        "Attaches sys_enter_read/sys_exit_read tracepoints. Reads of files\n"
        "named 'cpu.stat' are rewritten in-place to report zero usage.\n"
        "Status messages go to stderr; events go to stdout.\n",
        prog);
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
        fprintf(stderr, "[ch05] unexpected argument: %s\n", argv[optind]);
        usage(argv[0]);
        return 2;
    }

    if (!verbose)
        libbpf_set_print(libbpf_silence);

    int rc = 1;
    struct ch05_cgroup_leash_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;

    skel = ch05_cgroup_leash_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "[ch05] CH05_SKIP reason=\"open_and_load failed: %s\"\n",
                strerror(errno));
        goto out;
    }

    int err = ch05_cgroup_leash_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "[ch05] CH05_SKIP reason=\"attach failed: %s\"\n",
                strerror(-err));
        goto out;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ch05] ring_buffer__new failed: %s\n", strerror(errno));
        goto out;
    }

    struct sigaction sa = { .sa_handler = on_signal };
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; /* allow ring_buffer__poll to return -EINTR */
    if (sigaction(SIGINT, &sa, NULL) < 0 || sigaction(SIGTERM, &sa, NULL) < 0) {
        fprintf(stderr, "[ch05] sigaction failed: %s\n", strerror(errno));
        goto out;
    }

    fprintf(stderr, "[ch05] attached — cgroup leash active (Ctrl-C to exit)\n");

    while (!stop) {
        int n = ring_buffer__poll(rb, 200);
        if (n < 0 && n != -EINTR) {
            fprintf(stderr, "[ch05] ring_buffer__poll: %s\n", strerror(-n));
            break;
        }
    }

    rc = 0;
out:
    if (rb)
        ring_buffer__free(rb);
    if (skel)
        ch05_cgroup_leash_bpf__destroy(skel);
    fprintf(stderr, "[ch05] shutdown (rc=%d)\n", rc);
    return rc;
}
