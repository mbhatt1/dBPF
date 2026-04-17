#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "ch08-keyring-heist.skel.h"

struct evt {
    unsigned int pid;
    char comm[16];
    int serial;
    unsigned int datalen;
    char type[16];
    char desc[64];
    int hook;
};

static volatile sig_atomic_t stop;
static unsigned long long total_events;

static void on_sig(int s){ (void)s; stop = 1; }

static const char *hname(int h)
{
    switch (h) { case 1: return "key_task_perm"; case 2: return "lookup_user_key"; default: return "?"; }
}

static int handle(void *ctx, void *data, size_t sz)
{
    (void)ctx;
    if (sz < sizeof(struct evt)) return 0;
    const struct evt *e = data;
    total_events++;
    printf("[ch08] hook=%-15s\tpid=%u\tcomm=%-16s\tserial=0x%x\ttype=%s\tdesc='%s'\tlen=%u\n",
           hname(e->hook), e->pid, e->comm, e->serial, e->type, e->desc, e->datalen);
    fflush(stdout);
    return 0;
}

static int kallsyms_has(const char *sym)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) return -1;
    char line[512]; int found = 0;
    while (fgets(line, sizeof(line), f)) {
        char *p = strchr(line, ' '); if (!p) continue;
        p = strchr(p+1, ' '); if (!p) continue; p++;
        size_t n = strlen(p); while (n && (p[n-1]=='\n'||p[n-1]=='\t'||p[n-1]==' ')) p[--n]=0;
        char *t = strchr(p, '\t'); if (t) *t = 0;
        if (!strcmp(p, sym)) { found = 1; break; }
    }
    fclose(f); return found;
}

static void usage(const char *a)
{
    fprintf(stderr, "Usage: %s [-v] [-h]\n  -v verbose  -h help\n", a);
}

int main(int argc, char **argv)
{
    int c;
    while ((c = getopt(argc, argv, "vh")) != -1) {
        switch (c) { case 'v': break; case 'h': usage(argv[0]); return 0;
                     default: usage(argv[0]); return 2; }
    }

    int has_ktp = kallsyms_has("key_task_permission");
    int has_luk = kallsyms_has("lookup_user_key");
    if (has_ktp == 0 && has_luk == 0) {
        fprintf(stderr, "[ch08] CH08_SKIP reason=\"keyring symbols absent (CONFIG_KEYS=n?)\"\n");
        return 2;
    }

    int rc = 1;
    struct ring_buffer *rb = NULL;
    struct ch08_keyring_heist_bpf *s = ch08_keyring_heist_bpf__open();
    if (!s) {
        fprintf(stderr, "[ch08] CH08_SKIP reason=\"open: %s\"\n", strerror(errno));
        return 1;
    }
    if (has_ktp == 0) bpf_program__set_autoload(s->progs.kp_ktp, false);
    if (has_luk == 0) bpf_program__set_autoload(s->progs.kp_luk, false);
    int err = ch08_keyring_heist_bpf__load(s);
    if (err) {
        fprintf(stderr, "[ch08] CH08_SKIP reason=\"load: %s\"\n", strerror(-err));
        goto out;
    }
    err = ch08_keyring_heist_bpf__attach(s);
    if (err) {
        fprintf(stderr, "[ch08] CH08_SKIP reason=\"attach: %s\"\n", strerror(-err));
        goto out;
    }

    rb = ring_buffer__new(bpf_map__fd(s->maps.events), handle, NULL, NULL);
    if (!rb) { fprintf(stderr, "[ch08] ring_buffer__new: %s\n", strerror(errno)); goto out; }

    struct sigaction sa = { .sa_handler = on_sig };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL); sigaction(SIGTERM, &sa, NULL);
    fprintf(stderr, "[ch08] status=ready\tmsg=keyring observer active\n");
    while (!stop) {
        int n = ring_buffer__poll(rb, 200);
        if (n < 0 && n != -EINTR) break;
    }
    rc = 0;

    if (total_events >= 3)
        fprintf(stderr, "[ch08] CH08_PROVEN events=%llu\n", total_events);
    else
        fprintf(stderr, "[ch08] CH08_SKIP reason=\"only %llu keyring events (need >=3)\"\n", total_events);
out:
    if (rb) ring_buffer__free(rb);
    if (s) ch08_keyring_heist_bpf__destroy(s);
    return rc;
}
