// Ch11 IRQ Affinity Chaos — userspace loader.
//
// Opens the skeleton without auto-attaching, preflights every kprobe target
// against /proc/kallsyms, disables autoload on missing symbols, then
// manually attaches each surviving program with individual error reporting.
// Streams ringbuf events to stdout, status to stderr, and on SIGINT prints
// a tabular summary built from the per-CPU BPF hash map:
//
//     CPU | IRQ# | count
//
// drained across all possible CPUs.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "ch11-irq-chaos.skel.h"

#define MAX_CPUS 256

struct evt {
    unsigned long long ts_ns;
    unsigned int cpu;
    unsigned int irq;
    unsigned int pid;
    char comm[16];
    char name[32];
    int hook;
};

static volatile int stop;
static void sig(int _sig){ (void)_sig; stop = 1; }

static unsigned long long total_events;
static unsigned long long per_cpu_events[MAX_CPUS];

static void usage(const char *argv0)
{
    fprintf(stderr,
        "Usage: %s [-h]\n"
        "\n"
        "Hook IRQ dispatch and stream {cpu,irq,name,pid,comm} events.\n"
        "On SIGINT prints a CPU x IRQ count table assembled from the\n"
        "BPF per-CPU hash map.\n"
        "\n"
        "Options:\n"
        "  -h, --help   Show this help and exit\n",
        argv0);
}

static const char *hook_str(int h)
{
    switch (h) {
    case 1:  return "handle_irq_event";
    case 2:  return "__handle_irq_event_percpu";
    default: return "?";
    }
}

static int handle(void *ctx, void *data, size_t sz)
{
    (void)ctx; (void)sz;
    struct evt *e = data;
    total_events++;
    if (e->cpu < MAX_CPUS) per_cpu_events[e->cpu]++;

    if (total_events <= 20 || (total_events & 63) == 0) {
        printf("[irq] cpu=%u\tirq=%-3u\tname=%-16s\tpid=%u\tcomm=%-16s\thook=%s\n",
               e->cpu, e->irq, e->name[0] ? e->name : "(none)",
               e->pid, e->comm, hook_str(e->hook));
        fflush(stdout);
    }
    return 0;
}

// Return 1 iff `sym` is present as a T/t/W/w symbol in /proc/kallsyms.
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

struct prog_entry {
    const char *sym;
    struct bpf_program *(*getter)(struct ch11_irq_chaos_bpf *s);
};

#define GETTER(field) \
    static struct bpf_program *get_##field(struct ch11_irq_chaos_bpf *s) \
    { return s->progs.field; }

GETTER(kp_hie)
GETTER(kp_hiep)
GETTER(kp_hiep2)

static void summary(struct ch11_irq_chaos_bpf *s)
{
    fprintf(stderr, "\n==== IRQ dispatch summary ====\n");
    fprintf(stderr, "total ringbuf events seen: %llu\n", total_events);

    int ncpu = libbpf_num_possible_cpus();
    if (ncpu <= 0) ncpu = 1;
    if (ncpu > MAX_CPUS) ncpu = MAX_CPUS;

    int fd = bpf_map__fd(s->maps.per_cpu_counts);
    if (fd < 0) {
        fprintf(stderr, "per_cpu_counts: bad fd\n");
        return;
    }

    fprintf(stderr, "\n%-5s | %-5s | %s\n", "CPU", "IRQ#", "count");
    fprintf(stderr, "------+-------+----------\n");

    unsigned int key = 0, next;
    int has_prev = 0;
    unsigned long long vals[MAX_CPUS];
    int rows = 0;

    while (bpf_map_get_next_key(fd, has_prev ? &key : NULL, &next) == 0) {
        key = next;
        has_prev = 1;
        memset(vals, 0, sizeof(vals));
        if (bpf_map_lookup_elem(fd, &key, vals) != 0) continue;
        for (int c = 0; c < ncpu; c++) {
            if (vals[c]) {
                fprintf(stderr, "%-5d | %-5u | %llu\n", c, key, vals[c]);
                rows++;
            }
        }
    }
    if (!rows)
        fprintf(stderr, "(no IRQs recorded)\n");

    fprintf(stderr, "\nper-CPU ringbuf totals:\n");
    for (int c = 0; c < MAX_CPUS; c++) {
        if (per_cpu_events[c])
            fprintf(stderr, "  cpu%-3d  %llu\n", c, per_cpu_events[c]);
    }
}

int main(int argc, char **argv)
{
    static const struct option longopts[] = {
        { "help", no_argument, NULL, 'h' },
        { NULL, 0, NULL, 0 },
    };
    int c;
    while ((c = getopt_long(argc, argv, "h", longopts, NULL)) != -1) {
        switch (c) {
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 2;
        }
    }

    struct prog_entry table[] = {
        { "handle_irq_event",          get_kp_hie   },
        { "__handle_irq_event_percpu", get_kp_hiep  },
        { "handle_irq_event_percpu",   get_kp_hiep2 },
    };
    int n = (int)(sizeof(table) / sizeof(table[0]));

    struct ch11_irq_chaos_bpf *s = ch11_irq_chaos_bpf__open();
    if (!s) {
        fprintf(stderr, "[ch11] open failed: %s\n", strerror(errno));
        return 1;
    }

    fprintf(stderr, "[ch11] === symbol availability ===\n");
    int present_mask = 0;
    for (int i = 0; i < n; i++) {
        int ok = sym_exists(table[i].sym);
        fprintf(stderr, "  %-30s : %s\n", table[i].sym,
                ok == 1 ? "present" : (ok == 0 ? "ABSENT" : "kallsyms-err"));
        if (ok != 1) {
            bpf_program__set_autoload(table[i].getter(s), false);
        } else {
            present_mask |= (1 << i);
        }
    }
    if (!present_mask) {
        fprintf(stderr, "[ch11] no IRQ kprobe targets present on this kernel\n");
        ch11_irq_chaos_bpf__destroy(s);
        return 2;
    }

    if (ch11_irq_chaos_bpf__load(s)) {
        fprintf(stderr, "[ch11] load failed: %s\n", strerror(errno));
        ch11_irq_chaos_bpf__destroy(s);
        return 1;
    }

    int attached = 0;
    for (int i = 0; i < n; i++) {
        if (!(present_mask & (1 << i))) continue;
        struct bpf_program *p = table[i].getter(s);
        struct bpf_link *l = bpf_program__attach(p);
        long err = libbpf_get_error(l);
        if (err) {
            fprintf(stderr, "[ch11] attach %s FAILED: %s\n",
                    table[i].sym, strerror(-err));
            continue;
        }
        fprintf(stderr, "[ch11] attached %s\n", table[i].sym);
        attached++;
    }
    if (attached == 0) {
        fprintf(stderr, "[ch11] no programs attached\n");
        ch11_irq_chaos_bpf__destroy(s);
        return 1;
    }
    fprintf(stderr, "[ch11] attached %d program(s) — IRQ observer active\n",
            attached);

    struct ring_buffer *rb = ring_buffer__new(
        bpf_map__fd(s->maps.events), handle, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ch11] ringbuf new failed: %s\n", strerror(errno));
        ch11_irq_chaos_bpf__destroy(s);
        return 1;
    }

    signal(SIGINT,  sig);
    signal(SIGTERM, sig);

    while (!stop) {
        int err = ring_buffer__poll(rb, 200);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "[ch11] ringbuf poll: %s\n", strerror(-err));
            break;
        }
    }

    summary(s);
    ring_buffer__free(rb);
    ch11_irq_chaos_bpf__destroy(s);
    return 0;
}
