// ch13 analog sensor reader — reads /tmp/ch13_sensor_energy_uj via open+read
// into a heap buffer (mutable in this process's address space, so
// bpf_probe_write_user can rewrite it from sys_exit_read).
//
// Prints one "<value>" per iteration. DISCLAIMER: userspace analog only;
// real RAPL counters live in sysfs on x86.
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

int main(int argc, char **argv)
{
    int iterations = 3;
    unsigned int interval_ms = 1000;
    const char *tag = "reader";

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--iterations") && i + 1 < argc)
            iterations = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--interval-ms") && i + 1 < argc)
            interval_ms = (unsigned int)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--tag") && i + 1 < argc)
            tag = argv[++i];
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            fprintf(stderr,
                "Usage: %s [--iterations N] [--interval-ms N] [--tag LABEL]\n",
                argv[0]);
            return 0;
        } else {
            fprintf(stderr, "reader: unknown arg %s\n", argv[i]);
            return 2;
        }
    }

    struct sigaction sa = { .sa_handler = on_signal };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    struct timespec ts = {
        .tv_sec  = interval_ms / 1000,
        .tv_nsec = (long)(interval_ms % 1000) * 1000000L,
    };

    // Heap-allocated mutable buffer — bpf_probe_write_user targets this.
    size_t cap = 128;
    char  *buf = malloc(cap);
    if (!buf) { perror("reader: malloc"); return 1; }

    for (int i = 0; i < iterations && !stop; i++) {
        int fd = open(TARGET, O_RDONLY);
        if (fd < 0) {
            fprintf(stdout, "[%s] iter=%d open_err=%s\n", tag, i, strerror(errno));
            fflush(stdout);
            nanosleep(&ts, NULL);
            continue;
        }
        memset(buf, 0, cap);
        ssize_t n = read(fd, buf, cap - 1);
        close(fd);
        if (n < 0) {
            fprintf(stdout, "[%s] iter=%d read_err=%s\n", tag, i, strerror(errno));
            fflush(stdout);
        } else {
            // Trim the trailing newline for a clean single-line log.
            if (n > 0 && buf[n - 1] == '\n') buf[n - 1] = 0;
            buf[n] = 0;
            fprintf(stdout, "[%s] iter=%d value=%s\n", tag, i, buf);
            fflush(stdout);
        }
        if (i + 1 < iterations) nanosleep(&ts, NULL);
    }

    free(buf);
    return 0;
}
