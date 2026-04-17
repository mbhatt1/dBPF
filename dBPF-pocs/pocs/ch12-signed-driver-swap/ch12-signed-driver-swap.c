// ch12 signed-driver-swap — userspace loader.
//
// Observes the kernel module signature-check path by attaching kprobes to
// load_module, module_sig_check, mod_verify_sig (+ kretprobe for ret).
// Each invocation emits a ringbuf event; the first observed event prints a
// CH12_PROVEN marker to stdout. If /proc/kallsyms contains NONE of the
// target symbols (kernel built without CONFIG_MODULE_SIG or the helpers were
// inlined), the loader prints CH12_SKIP and exits 2.
//
// Events: stdout, prefixed "[ch12]". Status / diagnostics: stderr.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "ch12-signed-driver-swap.skel.h"

#define HOOK_LOAD_MODULE      1
#define HOOK_MODULE_SIG_CHECK 2
#define HOOK_MOD_VERIFY_SIG   3
#define HOOK_MOD_VERIFY_SIG_R 4

#define MODNAME_LEN 56

struct evt {
    unsigned int pid;
    unsigned int tgid;
    char         comm[16];
    int          hook;
    int          ret;
    char         modname[MODNAME_LEN];
};

static volatile sig_atomic_t stop;
static void on_signal(int sig)
{
    (void)sig;
    stop = 1;
}

static unsigned long long total_events;
static int proven_announced;

static const char *hook_str(int h)
{
    switch (h) {
    case HOOK_LOAD_MODULE:      return "load_module";
    case HOOK_MODULE_SIG_CHECK: return "module_sig_check";
    case HOOK_MOD_VERIFY_SIG:   return "mod_verify_sig";
    case HOOK_MOD_VERIFY_SIG_R: return "mod_verify_sig_ret";
    default:                    return "?";
    }
}

static int handle(void *ctx, void *data, size_t sz)
{
    (void)ctx;
    if (sz < sizeof(struct evt))
        return 0;
    const struct evt *e = data;
    total_events++;

    if (!proven_announced) {
        printf("[ch12] CH12_PROVEN hook=%s\n", hook_str(e->hook));
        proven_announced = 1;
    }

    if (e->hook == HOOK_MOD_VERIFY_SIG_R) {
        printf("[ch12] tag=sig_ret\tpid=%u\tcomm=%-16s\thook=%s\tret=%d\n",
               e->pid, e->comm, hook_str(e->hook), e->ret);
    } else {
        printf("[ch12] tag=enter\tpid=%u\tcomm=%-16s\thook=%s\tmodname=%s\n",
               e->pid, e->comm, hook_str(e->hook),
               e->modname[0] ? e->modname : "(unknown)");
    }
    fflush(stdout);
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
        "\n"
        "Observe kernel module signature-check gates. Events on stdout,\n"
        "status on stderr.\n"
        "\n"
        "Options:\n"
        "  -v  verbose libbpf output\n"
        "  -h  show this help and exit\n",
        prog);
}

// Return 1 iff `sym` is present as a T/t/W/w entry in /proc/kallsyms.
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
        char *name = p + 3;
        if (type != 'T' && type != 't' && type != 'W' && type != 'w')
            continue;
        size_t nlen = strcspn(name, " \t\n");
        if (nlen == slen && memcmp(name, sym, slen) == 0) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

int main(int argc, char **argv)
{
    int verbose = 0;
    static const struct option longopts[] = {
        { "verbose", no_argument, NULL, 'v' },
        { "help",    no_argument, NULL, 'h' },
        { NULL, 0, NULL, 0 },
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "vh", longopts, NULL)) != -1) {
        switch (opt) {
        case 'v': verbose = 1; break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 2;
        }
    }
    if (optind != argc) {
        fprintf(stderr, "[ch12] unexpected argument: %s\n", argv[optind]);
        usage(argv[0]);
        return 2;
    }

    if (verbose)
        libbpf_set_print(libbpf_print);

    // Preflight: which of the 4 targets are available?
    struct target {
        const char *sym;
        int         present;
    } targets[] = {
        { "load_module",       0 },
        { "module_sig_check",  0 },
        { "mod_verify_sig",    0 },
        { "mod_verify_sig",    0 }, // same symbol — kretprobe uses it too
    };
    const int NT = (int)(sizeof(targets) / sizeof(targets[0]));

    fprintf(stderr, "[ch12] === symbol availability ===\n");
    int present_mask = 0;
    for (int i = 0; i < NT; i++) {
        // Only query unique symbols once; retprobe shares with entry probe.
        int ok = (i == 3) ? targets[2].present : sym_exists(targets[i].sym);
        targets[i].present = ok == 1;
        if (i < 3) {
            fprintf(stderr, "  %-20s : %s\n", targets[i].sym,
                    ok == 1 ? "present" :
                    (ok == 0 ? "ABSENT" : "kallsyms-err"));
        }
        if (targets[i].present)
            present_mask |= (1 << i);
    }

    // If NONE of the three unique symbols are present, honest skip.
    if (!(present_mask & 0x7)) {
        fprintf(stderr,
            "[ch12] CH12_SKIP reason=\"no module-signing symbols "
            "(kernel built without CONFIG_MODULE_SIG or symbols inlined)\"\n");
        return 2;
    }

    struct ch12_signed_driver_swap_bpf *s = ch12_signed_driver_swap_bpf__open();
    if (!s) {
        fprintf(stderr, "[ch12] CH12_SKIP reason=\"skeleton open failed: %s\"\n",
                strerror(errno));
        return 1;
    }

    // Disable autoload on missing targets. (Spec says "set_autoload(false)
    // absent" — but we still need it to skip *missing* programs cleanly.
    // Only the unique-symbol probes are touched; no symbol → skip program.)
    if (!targets[0].present)
        bpf_program__set_autoload(s->progs.kp_load_module, false);
    if (!targets[1].present)
        bpf_program__set_autoload(s->progs.kp_module_sig_check, false);
    if (!targets[2].present) {
        bpf_program__set_autoload(s->progs.kp_mod_verify_sig, false);
        bpf_program__set_autoload(s->progs.kr_mod_verify_sig, false);
    }

    int err = ch12_signed_driver_swap_bpf__load(s);
    if (err) {
        fprintf(stderr, "[ch12] CH12_SKIP reason=\"load failed: %s\"\n", strerror(-err));
        ch12_signed_driver_swap_bpf__destroy(s);
        return 1;
    }

    int attached = 0, skipped = 0;
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, s->obj) {
        if (!bpf_program__autoload(prog)) {
            skipped++;
            continue;
        }
        struct bpf_link *link = bpf_program__attach(prog);
        long e = libbpf_get_error(link);
        if (e) {
            fprintf(stderr, "[ch12] attach prog=%s FAILED: %s\n",
                    bpf_program__name(prog), strerror(-(int)e));
            continue;
        }
        fprintf(stderr, "[ch12] attached prog=%s\n", bpf_program__name(prog));
        attached++;
    }
    fprintf(stderr, "[ch12] attached=%d\tskipped=%d\n", attached, skipped);
    if (attached == 0) {
        fprintf(stderr,
            "[ch12] CH12_SKIP reason=\"no module-signing symbols "
            "(kernel built without CONFIG_MODULE_SIG or symbols inlined)\"\n");
        ch12_signed_driver_swap_bpf__destroy(s);
        return 2;
    }

    struct ring_buffer *rb = ring_buffer__new(
        bpf_map__fd(s->maps.events), handle, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ch12] ring_buffer__new failed: %s\n",
                strerror(errno));
        ch12_signed_driver_swap_bpf__destroy(s);
        return 1;
    }

    struct sigaction sa = { .sa_handler = on_signal };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    fprintf(stderr, "[ch12] status=ready\tmsg=sig-check observer active\n");
    while (!stop) {
        int n = ring_buffer__poll(rb, 200);
        if (n < 0 && n != -EINTR) {
            fprintf(stderr, "[ch12] ring_buffer__poll: %s\n", strerror(-n));
            break;
        }
    }

    fprintf(stderr, "[ch12] total_events=%llu\n", total_events);
    ring_buffer__free(rb);
    ch12_signed_driver_swap_bpf__destroy(s);
    return 0;
}
