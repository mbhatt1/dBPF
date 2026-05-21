// ch07 Device-cgroup Houdini — LSM-variant loader (synthetic deny+flip).
//
// Attaches sleepable fmod_ret programs on inode_mknod, file_open, and
// (if the kernel exposes it) dev_open. A runtime stage toggle in
// ctrl_map selects:
//   SIGHUP  -> stage=off   (pass-through)
//   SIGUSR1 -> stage=deny  (synthesize -EPERM for target tgid on char/blk)
//   SIGUSR2 -> stage=flip  (match, but return 0 — "houdini escape")
//
// Both the deny and the flip primitives are proven inside the kernel:
// deny shows that a BPF LSM program CAN return -EPERM from these hooks;
// flip shows the same program returning 0 on a matching path makes the
// syscall succeed. This does not require a natural capability denial to
// be reachable (which, on a standard LSM chain with `capability` ahead
// of `bpf`, it is not — vfs_mknod also direct-calls capable(CAP_MKNOD)
// before the LSM chain, so cap_mknod drops never reach our fmod_ret).
//
// BTF-driven prune: before load we consult vmlinux BTF for each
// `bpf_lsm_<hook>` FUNC. Missing hooks get
// bpf_program__set_autoload(false) so libbpf does not fail the whole
// skeleton load with "failed to find kernel BTF type ID". On linuxkit
// 6.12 aarch64 `bpf_lsm_dev_open` is not in BTF.
//
// Proof markers (stdout):
//   [ch07] DENY hook=<name> tgid=<n> major=<m> minor=<n> verdict=-1
//   [ch07] FLIP hook=<name> tgid=<n> major=<m> minor=<n> verdict=0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include "ch07-devcgroup-houdini-lsm.skel.h"

#define STAGE_OFF  0
#define STAGE_DENY 1
#define STAGE_FLIP 2

struct ctrl {
    unsigned int stage;
    unsigned int target_tgid;
};

struct evt {
    unsigned int pid, tgid;
    char comm[16];
    int hook;
    int stage;
    int verdict;
    int matched;
    unsigned int major;
    unsigned int minor;
};

static volatile sig_atomic_t stop;
static volatile sig_atomic_t want_stage = -1;
static unsigned long long total_flips;
static unsigned long long total_denies;

static void on_sig(int s)
{
    switch (s) {
    case SIGINT:
    case SIGTERM:
        stop = 1;
        break;
    case SIGUSR1:
        want_stage = STAGE_DENY;
        break;
    case SIGUSR2:
        want_stage = STAGE_FLIP;
        break;
    case SIGHUP:
        want_stage = STAGE_OFF;
        break;
    default:
        break;
    }
}

static const char *hook_name(int h)
{
    switch (h) {
    case 1: return "inode_mknod";
    case 2: return "file_open";
    case 3: return "dev_open";
    default: return "unknown";
    }
}

static const char *stage_name(int s)
{
    switch (s) {
    case STAGE_OFF:  return "off";
    case STAGE_DENY: return "deny";
    case STAGE_FLIP: return "flip";
    default:         return "unknown";
    }
}

static int handle_event(void *ctx, void *data, size_t sz)
{
    (void)ctx;
    if (sz < sizeof(struct evt))
        return 0;
    const struct evt *e = data;
    if (!e->matched)
        return 0;

    const char *tag = (e->stage == STAGE_FLIP) ? "FLIP" :
                      (e->stage == STAGE_DENY) ? "DENY" : "HIT";
    if (e->stage == STAGE_FLIP)
        total_flips++;
    else if (e->stage == STAGE_DENY)
        total_denies++;

    printf("[ch07] %s hook=%s pid=%u tgid=%u comm=%s "
           "major=%u minor=%u verdict=%d stage=%s\n",
           tag, hook_name(e->hook), e->pid, e->tgid, e->comm,
           e->major, e->minor, e->verdict, stage_name(e->stage));
    fflush(stdout);
    return 0;
}

static int check_lsm_bpf_enabled(char *reason, size_t rlen)
{
    FILE *f = fopen("/sys/kernel/security/lsm", "r");
    if (!f) {
        snprintf(reason, rlen, "/sys/kernel/security/lsm unreadable");
        return 0;
    }
    char buf[512] = {0};
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        snprintf(reason, rlen, "/sys/kernel/security/lsm empty");
        return 0;
    }
    fclose(f);
    if (!strstr(buf, "bpf")) {
        snprintf(reason, rlen,
                 "kernel lacks 'bpf' in /sys/kernel/security/lsm "
                 "(boot with lsm=bpf,...)");
        return 0;
    }
    return 1;
}

// 1 if the named FUNC is present in vmlinux BTF. LSM attach targets
// appear as `bpf_lsm_<hook>`; that name is what libbpf looks up at
// load time. Missing here means load will fail with
// "failed to find kernel BTF type ID", so we disable autoload.
static int btf_has_func(struct btf *btf, const char *name)
{
    if (!btf)
        return 0;
    int id = btf__find_by_name_kind(btf, name, BTF_KIND_FUNC);
    return id > 0;
}

static int push_ctrl(struct ch07_devcgroup_houdini_lsm_bpf *s,
                     const struct ctrl *c)
{
    unsigned int k = 0;
    int err = bpf_map__update_elem(s->maps.ctrl_map,
                                   &k, sizeof(k),
                                   c, sizeof(*c),
                                   BPF_ANY);
    if (err) {
        fprintf(stderr, "[ch07] ctrl_map update: %s\n", strerror(-err));
        return -1;
    }
    return 0;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
        "Usage: %s [-t tgid] [-p pidfile] [-s stage] [-h]\n"
        "  -t N   target tgid (0 or omitted => wildcard: match every tgid)\n"
        "  -p F   write loader pid to F after attach (signal control)\n"
        "  -s S   initial stage: off (default) | deny | flip\n"
        "  -h     this help\n"
        "\n"
        "Runtime stage control (signals to loader pid):\n"
        "  SIGUSR1 -> stage=deny  (synthesize -EPERM on char/blk ops)\n"
        "  SIGUSR2 -> stage=flip  (match, return 0 — the houdini escape)\n"
        "  SIGHUP  -> stage=off   (pass-through)\n",
        argv0);
}

static int parse_stage(const char *s)
{
    if (!s) return -1;
    if (!strcmp(s, "off"))  return STAGE_OFF;
    if (!strcmp(s, "deny")) return STAGE_DENY;
    if (!strcmp(s, "flip")) return STAGE_FLIP;
    return -1;
}

int main(int argc, char **argv)
{
    unsigned int target_tgid = 0;
    const char *pidfile = NULL;
    int initial_stage = STAGE_OFF;
    int opt;

    while ((opt = getopt(argc, argv, "t:p:s:h")) != -1) {
        switch (opt) {
        case 't':
            target_tgid = (unsigned int)atoi(optarg);
            break;
        case 'p':
            pidfile = optarg;
            break;
        case 's': {
            int st = parse_stage(optarg);
            if (st < 0) {
                fprintf(stderr, "[ch07] bad -s value '%s' "
                                "(expected off|deny|flip)\n", optarg);
                return 2;
            }
            initial_stage = st;
            break;
        }
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 2;
        }
    }

    char skip_reason[256] = {0};
    if (!check_lsm_bpf_enabled(skip_reason, sizeof(skip_reason))) {
        fprintf(stderr, "CH07_SKIP reason=\"%s\"\n", skip_reason);
        return 3;
    }
    fprintf(stderr, "[ch07] BPF LSM is active — proceeding\n");

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    struct ch07_devcgroup_houdini_lsm_bpf *s =
        ch07_devcgroup_houdini_lsm_bpf__open();
    if (!s) {
        fprintf(stderr, "[ch07] open: %s\n", strerror(errno));
        return 1;
    }

    // BTF-driven hook prune.
    struct btf *btf = btf__load_vmlinux_btf();
    if (!btf) {
        fprintf(stderr, "[ch07] warning: btf__load_vmlinux_btf failed (%s) — "
                        "no prune; load may fail on kernels missing a hook\n",
                strerror(errno));
    }

    struct hook_entry {
        const char *btf_func;      // bpf_lsm_<hook> in vmlinux BTF
        const char *pretty;        // log-friendly name
        struct bpf_program *prog;  // libbpf handle
        int available;             // BTF says yes
    } hooks[] = {
        { "bpf_lsm_inode_mknod", "inode_mknod", s->progs.lsm_inode_mknod, 0 },
        { "bpf_lsm_file_open",   "file_open",   s->progs.lsm_file_open,   0 },
        { "bpf_lsm_dev_open",    "dev_open",    s->progs.lsm_dev_open,    0 },
    };
    int n_hooks = (int)(sizeof(hooks) / sizeof(hooks[0]));
    int available_count = 0;

    for (int i = 0; i < n_hooks; i++) {
        hooks[i].available = btf ? btf_has_func(btf, hooks[i].btf_func) : 1;
        if (!hooks[i].available) {
            if (bpf_program__set_autoload(hooks[i].prog, false) != 0)
                fprintf(stderr,
                        "[ch07] set_autoload(false) for %s failed: %s\n",
                        hooks[i].pretty, strerror(errno));
            else
                fprintf(stderr,
                        "[ch07] prune hook=%s reason=\"no BTF FUNC %s\"\n",
                        hooks[i].pretty, hooks[i].btf_func);
        } else {
            fprintf(stderr, "[ch07] keep hook=%s (BTF FUNC %s present)\n",
                    hooks[i].pretty, hooks[i].btf_func);
            available_count++;
        }
    }
    if (btf)
        btf__free(btf);

    if (available_count == 0) {
        fprintf(stderr,
            "CH07_SKIP reason=\"no LSM hook target present in BTF; "
            "cannot attach\"\n");
        ch07_devcgroup_houdini_lsm_bpf__destroy(s);
        return 3;
    }

    int err = ch07_devcgroup_houdini_lsm_bpf__load(s);
    if (err) {
        fprintf(stderr, "[ch07] load: %s\n", strerror(-err));
        ch07_devcgroup_houdini_lsm_bpf__destroy(s);
        return 1;
    }

    // Seed ctrl map with the requested initial stage before attach.
    struct ctrl c = {0};
    c.stage = (unsigned int)initial_stage;
    c.target_tgid = target_tgid;
    if (push_ctrl(s, &c) != 0) {
        ch07_devcgroup_houdini_lsm_bpf__destroy(s);
        return 1;
    }

    int attached = 0;
    for (int i = 0; i < n_hooks; i++) {
        if (!hooks[i].available)
            continue;
        struct bpf_link *l = bpf_program__attach(hooks[i].prog);
        if (!l) {
            fprintf(stderr, "[ch07] attach lsm.s/%s failed: %s\n",
                    hooks[i].pretty, strerror(errno));
            continue;
        }
        fprintf(stderr, "[ch07] attached lsm.s/%s\n", hooks[i].pretty);
        attached++;
    }

    if (attached == 0) {
        fprintf(stderr, "CH07_SKIP reason=\"no LSM hook successfully "
                        "attached\"\n");
        ch07_devcgroup_houdini_lsm_bpf__destroy(s);
        return 3;
    }

    struct ring_buffer *rb =
        ring_buffer__new(bpf_map__fd(s->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ch07] ring_buffer__new: %s\n", strerror(errno));
        ch07_devcgroup_houdini_lsm_bpf__destroy(s);
        return 1;
    }

    struct sigaction sa = {0};
    sa.sa_handler = on_sig;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT,  &sa, NULL) != 0 ||
        sigaction(SIGTERM, &sa, NULL) != 0 ||
        sigaction(SIGHUP,  &sa, NULL) != 0 ||
        sigaction(SIGUSR1, &sa, NULL) != 0 ||
        sigaction(SIGUSR2, &sa, NULL) != 0) {
        fprintf(stderr, "[ch07] sigaction: %s\n", strerror(errno));
        ring_buffer__free(rb);
        ch07_devcgroup_houdini_lsm_bpf__destroy(s);
        return 1;
    }

    if (pidfile) {
        FILE *pf = fopen(pidfile, "w");
        if (pf) {
            fprintf(pf, "%d\n", (int)getpid());
            fclose(pf);
        } else {
            fprintf(stderr, "[ch07] pidfile %s: %s\n",
                    pidfile, strerror(errno));
        }
    }

    fprintf(stderr,
            "[ch07] active — %d LSM hook(s) attached; "
            "target_tgid=%u stage=%s pid=%d\n",
            attached, target_tgid, stage_name((int)c.stage), (int)getpid());

    while (!stop) {
        int n = ring_buffer__poll(rb, 200);
        if (n < 0 && n != -EINTR)
            break;
        if (want_stage != -1) {
            c.stage = (unsigned int)want_stage;
            want_stage = -1;
            if (push_ctrl(s, &c) == 0) {
                fprintf(stderr, "[ch07] stage -> %s\n",
                        stage_name((int)c.stage));
            }
        }
    }

    fprintf(stderr, "[ch07] shutdown — denies=%llu flips=%llu\n",
            total_denies, total_flips);
    ring_buffer__free(rb);
    ch07_devcgroup_houdini_lsm_bpf__destroy(s);
    return 0;
}
