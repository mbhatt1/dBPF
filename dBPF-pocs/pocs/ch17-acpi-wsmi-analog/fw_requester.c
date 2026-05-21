// ch17 analog — userspace "firmware requester".
//
// Reads a basename from stdin, composes /tmp/<basename> into a mutable
// heap buffer, opens that path, reads the file and prints the contents.
// It also reports the filename it *thought* it was opening (captured
// BEFORE the open call, so if an in-flight BPF rewrite swapped the path,
// the printed name still matches what the user asked for).
//
// DISCLAIMER: stands in for a kernel code path that looks up firmware or
// ACPI tables by a trusted string (request_firmware, acpi_evaluate_object).
// Real subsystems aren't available on this host.
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>

#define PATH_CAP 256
#define TMPDIR   "/tmp/"

int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    // Force comm = "fw_requester" regardless of how we were invoked.
    // (argv[0] may be any path; the BPF program filters on this comm.)
    prctl(PR_SET_NAME, (unsigned long)"fw_requester", 0, 0, 0);

    // Mutable heap-allocated path buffer — BPF's bpf_probe_write_user
    // targets this memory on sys_enter_openat.
    char *path = malloc(PATH_CAP);
    if (!path) { perror("requester: malloc"); return 1; }
    memset(path, 0, PATH_CAP);

    // Read basename from stdin (single line).
    char basename[128] = {};
    if (!fgets(basename, sizeof(basename), stdin)) {
        fprintf(stderr, "requester: stdin empty\n");
        free(path);
        return 2;
    }
    // Strip trailing newline.
    size_t bl = strlen(basename);
    while (bl > 0 && (basename[bl-1] == '\n' || basename[bl-1] == '\r'))
        basename[--bl] = 0;

    // Compose "/tmp/<basename>" into the mutable buffer.
    int n = snprintf(path, PATH_CAP, "%s%s", TMPDIR, basename);
    if (n < 0 || n >= PATH_CAP) {
        fprintf(stderr, "requester: path too long\n");
        free(path);
        return 2;
    }

    // Save a snapshot of what we THINK we're opening, BEFORE any rewrite.
    char requested[PATH_CAP];
    memcpy(requested, path, PATH_CAP);

    // Hand the mutable buffer to open(). If BPF rewrote it on sys_enter,
    // the kernel sees the new bytes; the user sees them too once we read
    // them back below.
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stdout, "requester: requested=\"%s\" open_err=%s\n",
                requested, strerror(errno));
        free(path);
        return 1;
    }

    char content[256] = {};
    ssize_t r = read(fd, content, sizeof(content) - 1);
    close(fd);
    if (r < 0) {
        fprintf(stdout, "requester: requested=\"%s\" read_err=%s\n",
                requested, strerror(errno));
        free(path);
        return 1;
    }
    content[r] = 0;
    if (r > 0 && content[r-1] == '\n') content[r-1] = 0;

    // Report: what we asked for, what the buffer currently holds (may have
    // been rewritten by BPF), and what we read from the fd.
    fprintf(stdout, "requester: requested=\"%s\" buffer_after=\"%s\" content=\"%s\"\n",
            requested, path, content);

    free(path);
    return 0;
}
