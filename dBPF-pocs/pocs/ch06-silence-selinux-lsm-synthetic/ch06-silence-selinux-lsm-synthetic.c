// ch06 Silence SELinux — SYNTHETIC loader.
//
// Loads a single sleepable BPF LSM program attached to file_open. A
// control map selects its stage at runtime:
//
//   SIGUSR1 → stage = DENY  (synthesize -EACCES for target_uid+sentinel)
//   SIGUSR2 → stage = FLIP  (same match, but return 0 — the "flipper")
//   SIGHUP  → stage = OFF
//
// Prints proof-marker lines to stdout on every matched event:
//
//   [ch06-synth] stage=deny pid=... uid=... verdict=-13 path=...
//   [ch06-synth] stage=flip pid=... uid=... verdict=0  path=...
//
// CLI:
//   ch06-silence-selinux-lsm-synthetic -u <target_uid> -s <sentinel_path>
//
// The loader starts in stage=OFF, so an untriggered run is a no-op.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "ch06-silence-selinux-lsm-synthetic.skel.h"

#define SENTINEL_MAX 128

#define STAGE_OFF  0
#define STAGE_DENY 1
#define STAGE_FLIP 2

struct ctrl {
    unsigned int stage;
    unsigned int target_uid;
    unsigned int sentinel_len;
    char sentinel[SENTINEL_MAX];
};

struct evt {
    unsigned int pid, tgid, uid;
    char comm[16];
    int stage;
    int verdict;
    int matched;
    char path[SENTINEL_MAX];
};

static volatile sig_atomic_t stop;
static volatile sig_atomic_t want_stage = -1;

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

static const char *stage_name(int s)
{
    switch (s) {
    case STAGE_OFF:  return "off";
    case STAGE_DENY: return "deny";
    case STAGE_FLIP: return "flip";
    default:         return "unknown";
    }
}

static int handle_event(void *cctx, void *data, size_t sz)
{
    (void)cctx;
    if (sz < sizeof(struct evt))
        return 0;
    const struct evt *e = data;
    // The path buffer from bpf_d_path is NUL-terminated already; cap it
    // defensively anyway.
    char path[SENTINEL_MAX + 1];
    memcpy(path, e->path, SENTINEL_MAX);
    path[SENTINEL_MAX] = 0;
    printf("[ch06-synth] stage=%s pid=%u uid=%u comm=%s verdict=%d path=%s\n",
           stage_name(e->stage), e->pid, e->uid, e->comm, e->verdict, path);
    fflush(stdout);
    return 0;
}

static int check_bpf_lsm(void)
{
    FILE *f = fopen("/sys/kernel/security/lsm", "r");
    if (!f) {
        fprintf(stderr, "[ch06-synth] /sys/kernel/security/lsm unreadable\n");
        return 0;
    }
    char buf[512] = {0};
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        return 0;
    }
    fclose(f);
    return strstr(buf, "bpf") != NULL;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "Usage: %s -u <uid> -s <sentinel_abs_path> [-p <pidfile>]\n"
            "  -u N   target uid (only events from this uid match)\n"
            "  -s P   sentinel absolute file path (exact bpf_d_path match)\n"
            "  -p F   write loader pid to F after attach\n"
            "\n"
            "Runtime controls (send signals to the loader pid):\n"
            "  SIGUSR1  → stage = deny  (synthesize -EACCES)\n"
            "  SIGUSR2  → stage = flip  (match but return 0)\n"
            "  SIGHUP   → stage = off\n"
            "  SIGTERM  → shutdown\n",
            argv0);
}

static int push_ctrl(struct ch06_silence_selinux_lsm_synthetic_bpf *s,
                     struct ctrl *c)
{
    unsigned int k = 0;
    int err = bpf_map__update_elem(s->maps.ctrl_map,
                                   &k, sizeof(k),
                                   c, sizeof(*c),
                                   BPF_ANY);
    if (err) {
        fprintf(stderr, "[ch06-synth] ctrl_map update: %s\n",
                strerror(-err));
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    int opt;
    unsigned int target_uid = 0;
    int have_uid = 0;
    const char *sentinel = NULL;
    const char *pidfile = NULL;

    while ((opt = getopt(argc, argv, "u:s:p:h")) != -1) {
        switch (opt) {
        case 'u':
            target_uid = (unsigned int)atoi(optarg);
            have_uid = 1;
            break;
        case 's':
            sentinel = optarg;
            break;
        case 'p':
            pidfile = optarg;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 2;
        }
    }

    if (!have_uid || !sentinel) {
        usage(argv[0]);
        return 2;
    }

    size_t slen = strlen(sentinel) + 1; // include NUL
    if (slen > SENTINEL_MAX) {
        fprintf(stderr, "[ch06-synth] sentinel path too long (>%d)\n",
                SENTINEL_MAX - 1);
        return 2;
    }

    if (!check_bpf_lsm()) {
        fprintf(stderr,
                "[ch06-synth] CH06_SYNTH_SKIP reason=\"BPF LSM not enabled "
                "(need 'bpf' in /sys/kernel/security/lsm)\"\n");
        return 3;
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    struct ch06_silence_selinux_lsm_synthetic_bpf *s =
        ch06_silence_selinux_lsm_synthetic_bpf__open_and_load();
    if (!s) {
        fprintf(stderr, "[ch06-synth] CH06_SYNTH_SKIP reason=\"open_and_load failed: %s\"\n",
                strerror(errno));
        return 1;
    }

    // Seed control map with stage=OFF before attach so the hook is a
    // no-op until we explicitly switch it on.
    struct ctrl c = {0};
    c.stage = STAGE_OFF;
    c.target_uid = target_uid;
    c.sentinel_len = (unsigned int)slen;
    memcpy(c.sentinel, sentinel, slen);
    if (push_ctrl(s, &c) != 0) {
        ch06_silence_selinux_lsm_synthetic_bpf__destroy(s);
        return 1;
    }

    int err = ch06_silence_selinux_lsm_synthetic_bpf__attach(s);
    if (err) {
        fprintf(stderr, "[ch06-synth] CH06_SYNTH_SKIP reason=\"attach failed: %s\"\n",
                strerror(-err));
        ch06_silence_selinux_lsm_synthetic_bpf__destroy(s);
        return 1;
    }

    struct ring_buffer *rb =
        ring_buffer__new(bpf_map__fd(s->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ch06-synth] ring_buffer__new: %s\n",
                strerror(errno));
        ch06_silence_selinux_lsm_synthetic_bpf__destroy(s);
        return 1;
    }

    struct sigaction sa = {0};
    sa.sa_handler = on_sig;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);

    if (pidfile) {
        FILE *pf = fopen(pidfile, "w");
        if (pf) {
            fprintf(pf, "%d\n", (int)getpid());
            fclose(pf);
        } else {
            fprintf(stderr, "[ch06-synth] pidfile %s: %s\n",
                    pidfile, strerror(errno));
        }
    }

    fprintf(stderr,
            "[ch06-synth] attached lsm.s/file_open "
            "target_uid=%u sentinel=%s stage=off pid=%d\n",
            target_uid, sentinel, (int)getpid());

    while (!stop) {
        int n = ring_buffer__poll(rb, 200);
        if (n < 0 && n != -EINTR)
            break;
        if (want_stage != -1) {
            c.stage = (unsigned int)want_stage;
            want_stage = -1;
            if (push_ctrl(s, &c) == 0) {
                fprintf(stderr, "[ch06-synth] stage -> %s\n",
                        stage_name((int)c.stage));
            }
        }
    }

    ring_buffer__free(rb);
    ch06_silence_selinux_lsm_synthetic_bpf__destroy(s);
    return 0;
}
