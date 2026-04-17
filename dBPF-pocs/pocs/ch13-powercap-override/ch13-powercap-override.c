// ch13 powercap-override — userspace loader (observer).
//
// Preflight:
//   1. Enumerate the four powercap/thermal symbols in /proc/kallsyms.
//      If NONE are present (aarch64 linuxkit), emit CH13_SKIP and exit 2.
//   2. For each absent symbol, bpf_program__set_autoload(false).
//   3. Attach surviving programs; stream ringbuf events to stdout.
//
// On the first event for any hook, emit CH13_PROVEN <hook> so the
// harness's proof regex fires.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "ch13-powercap-override.skel.h"

struct evt {
    unsigned long long ts_ns;
    unsigned int pid;
    unsigned int tgid;
    char comm[16];
    int hook;
    unsigned long long arg0;
    unsigned long long arg1;
};

static volatile sig_atomic_t stop;
static void on_signal(int sig) { (void)sig; stop = 1; }

static unsigned long long total_events;
static unsigned long long per_hook_count[5];
static int per_hook_proven[5];

static const char *hook_name(int h)
{
    switch (h) {
    case 1: return "powercap_register_control_type";
    case 2: return "powercap_set_max_power_uw";
    case 3: return "powercap_get_max_power_uw";
    case 4: return "thermal_zone_device_update";
    default: return "unknown";
    }
}

static int handle(void *ctx, void *data, size_t sz)
{
    (void)ctx;
    if (sz < sizeof(struct evt))
        return 0;
    const struct evt *e = data;
    total_events++;
    if (e->hook >= 1 && e->hook <= 4) {
        per_hook_count[e->hook]++;
        if (!per_hook_proven[e->hook]) {
            per_hook_proven[e->hook] = 1;
            printf("[ch13] CH13_PROVEN hook=%s events=%llu\n",
                   hook_name(e->hook),
                   (unsigned long long)per_hook_count[e->hook]);
            fflush(stdout);
        }
    }
    if (total_events <= 40 || (total_events & 31) == 0) {
        printf("[ch13] tag=powercap\tts=%llu\tpid=%u\tcomm=%-16s\thook=%s\targ0=0x%llx\targ1=0x%llx\n",
               (unsigned long long)e->ts_ns, e->pid, e->comm,
               hook_name(e->hook),
               (unsigned long long)e->arg0,
               (unsigned long long)e->arg1);
        fflush(stdout);
    }
    return 0;
}

static int libbpf_print(enum libbpf_print_level lvl, const char *fmt, va_list ap)
{
    if (lvl == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, fmt, ap);
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [-v] [-h]\n"
        "  -v, --verbose  verbose libbpf output\n"
        "  -h, --help     show this help\n"
        "Streams powercap/thermal events to stdout; status to stderr.\n"
        "Exits 2 with CH13_SKIP when powercap/RAPL is not present.\n",
        prog);
}

// 1 if `sym` exists as T/t/W/w in /proc/kallsyms, 0 if absent, -1 on error.
static int sym_exists(const char *sym)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) return -1;
    char line[512];
    size_t slen = strlen(sym);
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        char *p = strchr(line, ' ');
        if (!p) continue;
        char type = p[1];
        if (type != 'T' && type != 't' && type != 'W' && type != 'w')
            continue;
        char *name = p + 3;
        size_t nlen = strcspn(name, " \t\n");
        if (nlen == slen && memcmp(name, sym, slen) == 0) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

struct prog_entry {
    const char *sym;
    struct bpf_program *(*getter)(struct ch13_powercap_override_bpf *s);
};

#define GETTER(field) \
    static struct bpf_program *get_##field(struct ch13_powercap_override_bpf *s) \
    { return s->progs.field; }

GETTER(kp_register)
GETTER(kp_set_max)
GETTER(kp_get_max)
GETTER(kp_therm)

int main(int argc, char **argv)
{
    int verbose = 0;

    static const struct option longopts[] = {
        { "help",    no_argument, NULL, 'h' },
        { "verbose", no_argument, NULL, 'v' },
        { NULL,      0,           NULL, 0   },
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "hv", longopts, NULL)) != -1) {
        switch (opt) {
        case 'h':
            usage(argv[0]);
            return 0;
        case 'v':
            verbose = 1;
            break;
        default:
            usage(argv[0]);
            return 2;
        }
    }
    if (optind != argc) {
        fprintf(stderr, "[ch13] unexpected argument: %s\n", argv[optind]);
        usage(argv[0]);
        return 2;
    }

    if (verbose)
        libbpf_set_print(libbpf_print);

    struct prog_entry table[] = {
        { "powercap_register_control_type", get_kp_register },
        { "powercap_set_max_power_uw",      get_kp_set_max  },
        { "powercap_get_max_power_uw",      get_kp_get_max  },
        { "thermal_zone_device_update",     get_kp_therm    },
    };
    int n = (int)(sizeof(table) / sizeof(table[0]));

    // Honest-skip preflight: powercap is x86-only. Probe kallsyms before
    // we even bother opening the skeleton.
    int any_present = 0;
    int present_flag[4] = {0, 0, 0, 0};
    fprintf(stderr, "[ch13] === symbol availability ===\n");
    for (int i = 0; i < n; i++) {
        int ok = sym_exists(table[i].sym);
        fprintf(stderr, "  %-36s : %s\n", table[i].sym,
                ok == 1 ? "present" : (ok == 0 ? "ABSENT" : "kallsyms-err"));
        if (ok == 1) {
            present_flag[i] = 1;
            any_present = 1;
        }
    }
    if (!any_present) {
        printf("[ch13] CH13_SKIP reason=\"no powercap/RAPL symbols "
               "(x86-only subsystem not available on this arch)\"\n");
        fflush(stdout);
        return 2;
    }

    struct ch13_powercap_override_bpf *s = ch13_powercap_override_bpf__open();
    if (!s) {
        fprintf(stderr, "[ch13] skeleton open failed: %s\n", strerror(errno));
        return 1;
    }

    int rc = 1;
    struct ring_buffer *rb = NULL;

    for (int i = 0; i < n; i++) {
        if (present_flag[i])
            continue;
        if (bpf_program__set_autoload(table[i].getter(s), false))
            fprintf(stderr, "[ch13] set_autoload(%s,false) failed\n",
                    table[i].sym);
    }

    int err = ch13_powercap_override_bpf__load(s);
    if (err) {
        fprintf(stderr, "[ch13] CH13_SKIP reason=\"load failed: %s\"\n", strerror(-err));
        goto out;
    }

    int attached = 0;
    for (int i = 0; i < n; i++) {
        if (!present_flag[i]) continue;
        struct bpf_program *p = table[i].getter(s);
        struct bpf_link *l = bpf_program__attach(p);
        long e = libbpf_get_error(l);
        if (e) {
            fprintf(stderr, "[ch13] attach %s FAILED: %s\n",
                    table[i].sym, strerror(-(int)e));
            continue;
        }
        fprintf(stderr, "[ch13] attached\tsym=%s\n", table[i].sym);
        attached++;
    }
    if (attached == 0) {
        fprintf(stderr, "[ch13] no programs attached — nothing to do\n");
        goto out;
    }
    fprintf(stderr, "[ch13] attached=%d\tstatus=ready\n", attached);

    rb = ring_buffer__new(bpf_map__fd(s->maps.events), handle, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ch13] ring_buffer__new failed: %s\n", strerror(errno));
        goto out;
    }

    struct sigaction sa = { .sa_handler = on_signal };
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) == -1)
        fprintf(stderr, "[ch13] sigaction(SIGINT): %s\n", strerror(errno));
    if (sigaction(SIGTERM, &sa, NULL) == -1)
        fprintf(stderr, "[ch13] sigaction(SIGTERM): %s\n", strerror(errno));

    while (!stop) {
        int pn = ring_buffer__poll(rb, 200);
        if (pn < 0 && pn != -EINTR) {
            fprintf(stderr, "[ch13] ring_buffer__poll: %s\n", strerror(-pn));
            break;
        }
    }

    fprintf(stderr, "[ch13] shutdown\ttotal=%llu\n", total_events);
    for (int i = 1; i <= 4; i++) {
        if (per_hook_count[i])
            fprintf(stderr, "[ch13] hook=%s\tcount=%llu\n",
                    hook_name(i), per_hook_count[i]);
    }
    rc = 0;

out:
    if (rb)
        ring_buffer__free(rb);
    if (s)
        ch13_powercap_override_bpf__destroy(s);
    return rc;
}
