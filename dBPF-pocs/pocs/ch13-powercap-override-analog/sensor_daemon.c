// ch13 analog sensor daemon — simulates what
// /sys/class/powercap/intel-rapl:*/energy_uj does on an x86 host.
//
// Writes a monotonically increasing "energy" value (as text) to
// /tmp/ch13_sensor_energy_uj every 100ms. The path is atomically
// replaced using rename(2) so readers never see a torn write.
//
// DISCLAIMER: This is a userspace analog. Real RAPL energy_uj is a
// kernel-owned sysfs attribute exposed by intel_rapl_common on x86 —
// it does not exist on aarch64 linuxkit.
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stop;
static void on_signal(int s) { (void)s; stop = 1; }

#define TARGET "/tmp/ch13_sensor_energy_uj"
#define TMPTGT "/tmp/ch13_sensor_energy_uj.tmp"

int main(int argc, char **argv)
{
    unsigned long long step = 100;  // energy units per tick
    unsigned long long base = 100;  // start value
    unsigned int       interval_ms = 100;
    int                iterations  = -1;  // -1 = forever

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--step") && i + 1 < argc)
            step = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--base") && i + 1 < argc)
            base = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--interval-ms") && i + 1 < argc)
            interval_ms = (unsigned int)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--iterations") && i + 1 < argc)
            iterations = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            fprintf(stderr,
                "Usage: %s [--base N] [--step N] [--interval-ms N] [--iterations N]\n"
                "  Writes %s with a monotonically increasing energy value.\n",
                argv[0], TARGET);
            return 0;
        } else {
            fprintf(stderr, "sensor: unknown arg %s\n", argv[i]);
            return 2;
        }
    }

    struct sigaction sa = { .sa_handler = on_signal };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    // Seed the target once so readers don't race the first tick.
    unsigned long long energy = base;
    int fd = open(TMPTGT, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("sensor: open tmp"); return 1; }
    char line[64];
    int  nlen = snprintf(line, sizeof(line), "%llu\n", energy);
    if (write(fd, line, (size_t)nlen) != nlen) {
        perror("sensor: write seed"); close(fd); return 1;
    }
    close(fd);
    if (rename(TMPTGT, TARGET) < 0) { perror("sensor: rename"); return 1; }

    struct timespec ts = {
        .tv_sec  = interval_ms / 1000,
        .tv_nsec = (long)(interval_ms % 1000) * 1000000L,
    };

    int count = 0;
    while (!stop && (iterations < 0 || count < iterations)) {
        nanosleep(&ts, NULL);
        if (stop) break;
        energy += step;

        fd = open(TMPTGT, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) { perror("sensor: open tmp"); return 1; }
        nlen = snprintf(line, sizeof(line), "%llu\n", energy);
        if (write(fd, line, (size_t)nlen) != nlen) {
            perror("sensor: write"); close(fd); return 1;
        }
        close(fd);
        if (rename(TMPTGT, TARGET) < 0) { perror("sensor: rename"); return 1; }
        count++;
    }

    fprintf(stderr, "sensor: exit (wrote %d ticks, last=%llu)\n", count, energy);
    return 0;
}
