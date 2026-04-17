#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "ch04-phantom-syscall.skel.h"

struct evt {
    unsigned int pid, tgid, uid, euid;
    char comm[16];
    char parent_comm[16];
    char payload[32];
};

static volatile sig_atomic_t stop;
static void on_sig(int s){ (void)s; stop = 1; }

static int handle(void *ctx, void *data, size_t sz)
{
    (void)ctx;
    if (sz < sizeof(struct evt))
        return 0;
    const struct evt *e = data;
    /* Defensive: ensure strings are NUL-terminated before %s */
    char comm[17] = {0}, pcomm[17] = {0}, payload[33] = {0};
    memcpy(comm, e->comm, 16);
    memcpy(pcomm, e->parent_comm, 16);
    memcpy(payload, e->payload, 32);
    printf("[phantom] pid=%u tgid=%u uid=%u euid=%u comm=%s parent=%s payload='%s'\n",
           e->pid, e->tgid, e->uid, e->euid, comm, pcomm, payload);
    fflush(stdout);
    return 0;
}

int main(void)
{
    int rc = 1;
    struct ring_buffer *rb = NULL;
    struct ch04_phantom_syscall_bpf *s = ch04_phantom_syscall_bpf__open_and_load();
    if (!s) {
        fprintf(stderr, "[ch04] CH04_SKIP reason=\"open_and_load failed: %s\"\n",
                strerror(errno));
        return 1;
    }
    /* Prevent stage2 from auto-attaching to sys_enter_write directly. */
    bpf_program__set_autoattach(s->progs.phantom_stage2, false);
    int stage2_fd = bpf_program__fd(s->progs.phantom_stage2);
    unsigned int k = 0;
    bpf_map__update_elem(s->maps.jumps, &k, sizeof(k), &stage2_fd, sizeof(stage2_fd), BPF_ANY);

    int err = ch04_phantom_syscall_bpf__attach(s);
    if (err) {
        fprintf(stderr, "[ch04] CH04_SKIP reason=\"attach failed: %s\"\n",
                strerror(-err));
        goto out;
    }

    rb = ring_buffer__new(bpf_map__fd(s->maps.events), handle, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ch04] ring_buffer__new failed: %s\n", strerror(errno));
        goto out;
    }

    struct sigaction sa = { .sa_handler = on_sig };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    fprintf(stderr, "[ch04] attached — phantom active (magic: 'PHANTOM\\0')\n");
    while (!stop) {
        int n = ring_buffer__poll(rb, 200);
        if (n < 0 && n != -EINTR) {
            fprintf(stderr, "[ch04] ring_buffer__poll: %s\n", strerror(-n));
            break;
        }
    }
    rc = 0;

out:
    if (rb)
        ring_buffer__free(rb);
    if (s)
        ch04_phantom_syscall_bpf__destroy(s);
    return rc;
}
