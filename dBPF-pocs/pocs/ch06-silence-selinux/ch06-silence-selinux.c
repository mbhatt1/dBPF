// ch06 silence-selinux — userspace loader (observer).
//
// Preflight:
//   1. /sys/kernel/security/lsm must contain "selinux". If not, emit
//      CH06_SKIP and exit 2.
//   2. Each kprobe target is checked against /proc/kallsyms; absent
//      symbols are disabled via bpf_program__set_autoload(false).
//
// On the first captured event for a given hook, print a
// CH06_PROVEN <hook> events=N line on stdout so the harness's proof
// regex fires.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "ch06-silence-selinux.skel.h"

struct evt {
    unsigned int pid;
    unsigned int tgid;
    char comm[16];
    int hook;
    unsigned int ssid;
    unsigned int tsid;
    unsigned int tclass;
    int requested;
};

static volatile sig_atomic_t stop;
static void on_signal(int sig) { (void)sig; stop = 1; }

static unsigned long long total_events;
static unsigned long long per_hook_count[4]; // indexed by hook id 1..3
static int per_hook_proven[4];

static const char *hook_name(int h)
{
    switch (h) {
    case 1: return "avc_has_perm";
    case 2: return "avc_has_perm_noaudit";
    case 3: return "selinux_file_permission";
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
    if (e->hook >= 1 && e->hook <= 3) {
        per_hook_count[e->hook]++;
        if (!per_hook_proven[e->hook]) {
            per_hook_proven[e->hook] = 1;
            printf("[ch06] CH06_PROVEN hook=%s events=%llu\n",
                   hook_name(e->hook),
                   (unsigned long long)per_hook_count[e->hook]);
            fflush(stdout);
        }
    }
    if (total_events <= 40 || (total_events & 63) == 0) {
        printf("[ch06] tag=avc\tpid=%u\tcomm=%-16s\thook=%s\tssid=%u\ttsid=%u\ttclass=%u\treq=0x%x\n",
               e->pid, e->comm, hook_name(e->hook),
               e->ssid, e->tsid, e->tclass, (unsigned int)e->requested);
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
        "Streams SELinux AVC decisions to stdout; status to stderr.\n"
        "Exits 2 with CH06_SKIP when SELinux is not loaded.\n",
        prog);
}

// Return 1 if `sym` is a T/t/W/w kallsym, 0 if absent, -1 on error.
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

// Read /sys/kernel/security/lsm and search for "selinux" token.
// Returns 1 if selinux is in the list, 0 if file exists but lacks it,
// -1 if the file is absent/unreadable (securityfs not mounted).
static int selinux_loaded(void)
{
    int fd = open("/sys/kernel/security/lsm", O_RDONLY);
    if (fd < 0) return -1;
    char buf[1024];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = 0;
    // strtok modifies; use a manual scan since tokens are comma-separated.
    const char *p = buf;
    while (*p) {
        const char *q = p;
        while (*q && *q != ',' && *q != '\n') q++;
        size_t len = (size_t)(q - p);
        if (len == 7 && memcmp(p, "selinux", 7) == 0)
            return 1;
        if (!*q) break;
        p = q + 1;
    }
    return 0;
}

struct prog_entry {
    const char *sym;
    struct bpf_program *(*getter)(struct ch06_silence_selinux_bpf *s);
};

#define GETTER(field) \
    static struct bpf_program *get_##field(struct ch06_silence_selinux_bpf *s) \
    { return s->progs.field; }

GETTER(kp_avc_has_perm)
GETTER(kp_avc_has_perm_noaudit)
GETTER(kp_selinux_file_permission)

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
        fprintf(stderr, "[ch06] unexpected argument: %s\n", argv[optind]);
        usage(argv[0]);
        return 2;
    }

    // Honest-skip: no SELinux LSM loaded.
    int se = selinux_loaded();
    if (se <= 0) {
        printf("[ch06] CH06_SKIP reason=\"SELinux not loaded\"\n");
        fflush(stdout);
        fprintf(stderr, "[ch06] /sys/kernel/security/lsm: %s\n",
                se == 0 ? "selinux token absent"
                        : "unreadable (securityfs not mounted?)");
        return 2;
    }

    if (verbose)
        libbpf_set_print(libbpf_print);

    struct prog_entry table[] = {
        { "avc_has_perm",           get_kp_avc_has_perm           },
        { "avc_has_perm_noaudit",   get_kp_avc_has_perm_noaudit   },
        { "selinux_file_permission",get_kp_selinux_file_permission},
    };
    int n = (int)(sizeof(table) / sizeof(table[0]));

    struct ch06_silence_selinux_bpf *s = ch06_silence_selinux_bpf__open();
    if (!s) {
        fprintf(stderr, "[ch06] skeleton open failed: %s\n", strerror(errno));
        return 1;
    }

    int rc = 1;
    struct ring_buffer *rb = NULL;

    fprintf(stderr, "[ch06] === symbol availability ===\n");
    int present_mask = 0;
    for (int i = 0; i < n; i++) {
        int ok = sym_exists(table[i].sym);
        fprintf(stderr, "  %-28s : %s\n", table[i].sym,
                ok == 1 ? "present" : (ok == 0 ? "ABSENT" : "kallsyms-err"));
        if (ok != 1) {
            if (bpf_program__set_autoload(table[i].getter(s), false))
                fprintf(stderr, "[ch06] set_autoload(%s,false) failed\n",
                        table[i].sym);
        } else {
            present_mask |= (1 << i);
        }
    }
    if (!present_mask) {
        printf("[ch06] CH06_SKIP reason=\"no SELinux AVC symbols in kallsyms\"\n");
        fflush(stdout);
        goto out;
    }

    int err = ch06_silence_selinux_bpf__load(s);
    if (err) {
        fprintf(stderr, "[ch06] CH06_SKIP reason=\"load failed: %s\"\n", strerror(-err));
        goto out;
    }

    int attached = 0;
    for (int i = 0; i < n; i++) {
        if (!(present_mask & (1 << i))) continue;
        struct bpf_program *p = table[i].getter(s);
        struct bpf_link *l = bpf_program__attach(p);
        long e = libbpf_get_error(l);
        if (e) {
            fprintf(stderr, "[ch06] attach %s FAILED: %s\n",
                    table[i].sym, strerror(-(int)e));
            continue;
        }
        fprintf(stderr, "[ch06] attached\tsym=%s\n", table[i].sym);
        attached++;
    }
    if (attached == 0) {
        fprintf(stderr, "[ch06] no programs attached — nothing to do\n");
        goto out;
    }
    fprintf(stderr, "[ch06] attached=%d\tstatus=ready\n", attached);

    rb = ring_buffer__new(bpf_map__fd(s->maps.events), handle, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ch06] ring_buffer__new failed: %s\n", strerror(errno));
        goto out;
    }

    struct sigaction sa = { .sa_handler = on_signal };
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) == -1)
        fprintf(stderr, "[ch06] sigaction(SIGINT): %s\n", strerror(errno));
    if (sigaction(SIGTERM, &sa, NULL) == -1)
        fprintf(stderr, "[ch06] sigaction(SIGTERM): %s\n", strerror(errno));

    while (!stop) {
        int pn = ring_buffer__poll(rb, 200);
        if (pn < 0 && pn != -EINTR) {
            fprintf(stderr, "[ch06] ring_buffer__poll: %s\n", strerror(-pn));
            break;
        }
    }

    fprintf(stderr, "[ch06] shutdown\ttotal=%llu\n", total_events);
    for (int i = 1; i <= 3; i++) {
        if (per_hook_count[i])
            fprintf(stderr, "[ch06] hook=%s\tcount=%llu\n",
                    hook_name(i), per_hook_count[i]);
    }
    rc = 0;

out:
    if (rb)
        ring_buffer__free(rb);
    if (s)
        ch06_silence_selinux_bpf__destroy(s);
    return rc;
}
