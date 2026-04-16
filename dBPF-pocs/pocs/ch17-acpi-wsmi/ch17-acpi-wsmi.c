// ch17 ACPI / WSMI Ping — userspace loader.
//
// Preflights all 6 candidate symbols in /proc/kallsyms:
//   ACPI path     : acpi_evaluate_object, acpi_ns_evaluate,
//                   acpi_ex_execute_method
//   Firmware path : request_firmware, _request_firmware,
//                   firmware_request_nowarn
//
// Emits:
//   - [acpi] attached=acpi_path          (if any ACPI symbol is present)
//   - [acpi] attached=firmware_fallback  (if only firmware symbols present)
//   - CH17_SKIP reason="no acpi nor firmware symbols"  (if neither)
//
// On ≥1 firmware-fallback event while only-firmware hooks are attached,
// prints ACPI_PROBE_PROVEN arch=aarch64 substituted=firmware_loader.
// Events on stdout, status on stderr.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/utsname.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "ch17-acpi-wsmi.skel.h"

#define HOOK_ACPI_EVAL_OBJECT  1
#define HOOK_ACPI_NS_EVALUATE  2
#define HOOK_ACPI_EX_EXEC      3
#define HOOK_REQUEST_FIRMWARE  4
#define HOOK_UNDERSCORE_RF     5
#define HOOK_FW_REQ_NOWARN     6

#define ARG_MAX_LEN 64

struct evt {
    unsigned int pid;
    unsigned int tgid;
    char         comm[16];
    int          hook;
    char         arg_string[ARG_MAX_LEN];
};

static volatile sig_atomic_t stop;
static void on_signal(int sig)
{
    (void)sig;
    stop = 1;
}

// Which class(es) of hook(s) actually attached.
static int acpi_attached;
static int firmware_attached;
static int proven_announced;
static unsigned long long total_events;

static const char *hook_str(int h)
{
    switch (h) {
    case HOOK_ACPI_EVAL_OBJECT: return "acpi_evaluate_object";
    case HOOK_ACPI_NS_EVALUATE: return "acpi_ns_evaluate";
    case HOOK_ACPI_EX_EXEC:     return "acpi_ex_execute_method";
    case HOOK_REQUEST_FIRMWARE: return "request_firmware";
    case HOOK_UNDERSCORE_RF:    return "_request_firmware";
    case HOOK_FW_REQ_NOWARN:    return "firmware_request_nowarn";
    default:                    return "?";
    }
}

static const char *current_arch(void)
{
    static struct utsname u;
    if (uname(&u) != 0)
        return "unknown";
    return u.machine;
}

static int handle(void *ctx, void *data, size_t sz)
{
    (void)ctx;
    if (sz < sizeof(struct evt))
        return 0;
    const struct evt *e = data;
    total_events++;

    if (!proven_announced) {
        if (acpi_attached) {
            printf("[acpi] ACPI_PROBE_PROVEN arch=%s substituted=none\n",
                   current_arch());
        } else if (firmware_attached) {
            printf("[acpi] ACPI_PROBE_PROVEN arch=%s substituted=firmware_loader\n",
                   current_arch());
        }
        proven_announced = 1;
    }

    printf("[acpi] tag=call\tpid=%u\tcomm=%-16s\thook=%s\targ=%s\n",
           e->pid, e->comm, hook_str(e->hook),
           e->arg_string[0] ? e->arg_string : "(none)");
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
        "Observe ACPI method evaluation; fall back to firmware-loader hooks\n"
        "on kernels without the ACPI interpreter (e.g. aarch64 linuxkit).\n"
        "Events on stdout, status on stderr.\n"
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
        fprintf(stderr, "[acpi] unexpected argument: %s\n", argv[optind]);
        usage(argv[0]);
        return 2;
    }

    if (verbose)
        libbpf_set_print(libbpf_print);

    struct { const char *sym; int present; int is_acpi; } targets[] = {
        { "acpi_evaluate_object",   0, 1 },
        { "acpi_ns_evaluate",       0, 1 },
        { "acpi_ex_execute_method", 0, 1 },
        { "request_firmware",       0, 0 },
        { "_request_firmware",      0, 0 },
        { "firmware_request_nowarn",0, 0 },
    };
    const int NT = (int)(sizeof(targets) / sizeof(targets[0]));

    fprintf(stderr, "[acpi] === symbol availability ===\n");
    int acpi_mask = 0, fw_mask = 0;
    for (int i = 0; i < NT; i++) {
        int ok = sym_exists(targets[i].sym);
        targets[i].present = (ok == 1);
        fprintf(stderr, "  %-26s : %s\n", targets[i].sym,
                ok == 1 ? "present" :
                (ok == 0 ? "ABSENT" : "kallsyms-err"));
        if (targets[i].present) {
            if (targets[i].is_acpi) acpi_mask |= (1 << i);
            else                    fw_mask   |= (1 << i);
        }
    }

    if (!acpi_mask && !fw_mask) {
        fprintf(stderr,
            "[acpi] CH17_SKIP reason=\"no acpi nor firmware symbols\"\n");
        return 2;
    }

    struct ch17_acpi_wsmi_bpf *s = ch17_acpi_wsmi_bpf__open();
    if (!s) {
        fprintf(stderr, "[acpi] skeleton open failed: %s\n", strerror(errno));
        return 1;
    }

    // Disable autoload for absent symbols.
    if (!targets[0].present)
        bpf_program__set_autoload(s->progs.kp_acpi_evaluate_object, false);
    if (!targets[1].present)
        bpf_program__set_autoload(s->progs.kp_acpi_ns_evaluate, false);
    if (!targets[2].present)
        bpf_program__set_autoload(s->progs.kp_acpi_ex_execute_method, false);
    if (!targets[3].present)
        bpf_program__set_autoload(s->progs.kp_request_firmware, false);
    if (!targets[4].present)
        bpf_program__set_autoload(s->progs.kp_underscore_request_firmware,
                                  false);
    if (!targets[5].present)
        bpf_program__set_autoload(s->progs.kp_firmware_request_nowarn, false);

    int err = ch17_acpi_wsmi_bpf__load(s);
    if (err) {
        fprintf(stderr, "[acpi] load failed: %s\n", strerror(-err));
        ch17_acpi_wsmi_bpf__destroy(s);
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
            fprintf(stderr, "[acpi] attach prog=%s FAILED: %s\n",
                    bpf_program__name(prog), strerror(-(int)e));
            continue;
        }
        fprintf(stderr, "[acpi] attached prog=%s\n", bpf_program__name(prog));
        attached++;
    }

    if (attached == 0) {
        fprintf(stderr,
            "[acpi] CH17_SKIP reason=\"no acpi nor firmware symbols\"\n");
        ch17_acpi_wsmi_bpf__destroy(s);
        return 2;
    }

    acpi_attached     = (acpi_mask != 0);
    firmware_attached = (acpi_mask == 0) && (fw_mask != 0);

    if (acpi_attached)
        fprintf(stderr, "[acpi] attached=acpi_path\n");
    else if (firmware_attached)
        fprintf(stderr, "[acpi] attached=firmware_fallback\n");
    fprintf(stderr, "[acpi] attached=%d\tskipped=%d\n", attached, skipped);

    struct ring_buffer *rb = ring_buffer__new(
        bpf_map__fd(s->maps.events), handle, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[acpi] ring_buffer__new failed: %s\n",
                strerror(errno));
        ch17_acpi_wsmi_bpf__destroy(s);
        return 1;
    }

    struct sigaction sa = { .sa_handler = on_signal };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    fprintf(stderr, "[acpi] status=ready\tmsg=acpi/firmware observer active\n");
    while (!stop) {
        int n = ring_buffer__poll(rb, 200);
        if (n < 0 && n != -EINTR) {
            fprintf(stderr, "[acpi] ring_buffer__poll: %s\n", strerror(-n));
            break;
        }
    }

    fprintf(stderr, "[acpi] total_events=%llu\n", total_events);
    ring_buffer__free(rb);
    ch17_acpi_wsmi_bpf__destroy(s);
    return 0;
}
