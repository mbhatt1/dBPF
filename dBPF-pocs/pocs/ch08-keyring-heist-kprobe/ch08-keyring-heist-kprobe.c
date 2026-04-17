// ch08-keyring-heist-kprobe loader.
//
// Attaches two kprobes (key_task_permission, lookup_user_key) that
// perform CO-RE field extraction of `struct key` during the
// access-denied syscall path. The syscall return value is not modified;
// only structure metadata is observed at the decision point.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "ch08-keyring-heist-kprobe.skel.h"

#define TYPE_NAME_LEN 16
#define DESC_LEN      64

struct evt {
    unsigned int pid;
    unsigned int tgid;
    char comm[16];
    int serial;
    int hook;
    char type_name[TYPE_NAME_LEN];
    char description[DESC_LEN];
};

static volatile sig_atomic_t stop;
static unsigned long long total_events;

static void on_sig(int s) { (void)s; stop = 1; }

static const char *hook_name(int h)
{
    switch (h) {
    case 1: return "key_task_permission";
    case 2: return "lookup_user_key";
    default: return "?";
    }
}

static int handle(void *ctx, void *data, size_t sz)
{
    (void)ctx;
    if (sz < sizeof(struct evt))
        return 0;
    const struct evt *e = data;
    total_events++;
    printf("[ch08k] hook=%-20s pid=%u comm=%s serial=%d type=%s desc='%s'\n",
           hook_name(e->hook), e->pid, e->comm, e->serial,
           e->type_name[0] ? e->type_name : "?",
           e->description);
    fflush(stdout);
    return 0;
}

static int kallsyms_has(const char *sym)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f)
        return -1;
    char line[512];
    int found = 0;
    size_t slen = strlen(sym);
    while (fgets(line, sizeof(line), f)) {
        // format: "<addr> <type> <name>[\tmodule]"
        char *p = strchr(line, ' ');
        if (!p) continue;
        p = strchr(p + 1, ' ');
        if (!p) continue;
        p++;
        // trim newline/tab
        size_t n = strlen(p);
        while (n && (p[n-1] == '\n' || p[n-1] == '\t' || p[n-1] == ' '))
            p[--n] = 0;
        char *t = strchr(p, '\t');
        if (t) *t = 0;
        if (strlen(p) == slen && !strcmp(p, sym)) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    int has_ktp = kallsyms_has("key_task_permission");
    int has_luk = kallsyms_has("lookup_user_key");
    if (has_ktp <= 0 && has_luk <= 0) {
        fprintf(stderr, "[ch08k] CH08K_SKIP reason=\"keyring symbols absent in kallsyms\"\n");
        return 2;
    }
    fprintf(stderr, "[ch08k] kallsyms key_task_permission=%d lookup_user_key=%d\n",
            has_ktp, has_luk);

    struct ch08_keyring_heist_kprobe_bpf *s =
        ch08_keyring_heist_kprobe_bpf__open();
    if (!s) {
        fprintf(stderr, "[ch08k] CH08K_SKIP reason=\"open: %s\"\n", strerror(errno));
        return 1;
    }

    if (has_ktp <= 0)
        bpf_program__set_autoload(s->progs.kp_key_task_permission, false);
    if (has_luk <= 0)
        bpf_program__set_autoload(s->progs.kp_lookup_user_key, false);

    int err = ch08_keyring_heist_kprobe_bpf__load(s);
    if (err) {
        fprintf(stderr, "[ch08k] CH08K_SKIP reason=\"load: %s\"\n", strerror(-err));
        ch08_keyring_heist_kprobe_bpf__destroy(s);
        return 1;
    }

    err = ch08_keyring_heist_kprobe_bpf__attach(s);
    if (err) {
        fprintf(stderr, "[ch08k] CH08K_SKIP reason=\"attach: %s\"\n", strerror(-err));
        ch08_keyring_heist_kprobe_bpf__destroy(s);
        return 1;
    }

    struct ring_buffer *rb =
        ring_buffer__new(bpf_map__fd(s->maps.events), handle, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ch08k] ring_buffer__new: %s\n", strerror(errno));
        ch08_keyring_heist_kprobe_bpf__destroy(s);
        return 1;
    }

    struct sigaction sa = { .sa_handler = on_sig };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    fprintf(stderr, "[ch08k] attached\n");
    fflush(stderr);

    while (!stop) {
        int n = ring_buffer__poll(rb, 200);
        if (n < 0 && n != -EINTR)
            break;
    }

    ring_buffer__free(rb);
    ch08_keyring_heist_kprobe_bpf__destroy(s);
    fprintf(stderr, "[ch08k] total_events=%llu\n", total_events);
    return 0;
}
