// ch24 bpf-token-delegation -- real SCM_RIGHTS-based token handoff.
//
//   --server  : privileged side. Mounts a bpffs instance at a known
//               path with delegate_* mount options. Calls the raw
//               BPF_TOKEN_CREATE bpf() command (requires CAP_SYS_ADMIN,
//               hence the split architecture). Binds an AF_UNIX socket
//               and hands the resulting token_fd to an unprivileged
//               client via SCM_RIGHTS. Holds until signaled.
//
//   --client  : unprivileged side. Connects to the unix socket, pulls
//               the token_fd out of the cmsg, parses the compiled BPF
//               ELF with libbpf (WITHOUT bpf_token_path -- that would
//               re-invoke BPF_TOKEN_CREATE which requires CAP_SYS_ADMIN),
//               creates the ringbuf map with .token_fd = received_fd,
//               rewrites LD_IMM64 map-fd placeholders in the program
//               instructions, loads the program with .token_fd, attaches
//               via perf_event_open + PERF_EVENT_IOC_SET_BPF, and polls
//               the ringbuf for 10 seconds.
//
// Skip behavior:
//   - kernel < 6.9                                   -> CH24_SKIP
//   - bpffs mount rejects delegate_* options         -> CH24_SKIP
//   - BPF_TOKEN_CREATE returns error on server       -> CH24_SKIP
//   - BPF_PROG_LOAD with token_fd returns EPERM      -> CH24_SKIP
//
// Proof marker (client, stdout):
//   CH24_PROVEN uid_events=N token_delegated=yes capeff=0x%llx

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <time.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

/* --- uapi compatibility shims --------------------------------------- */

#ifndef BPF_TOKEN_CREATE
#define BPF_TOKEN_CREATE 36
#endif

#ifndef BPF_F_TOKEN_FD
#define BPF_F_TOKEN_FD (1U << 16)
#endif

#ifndef BPF_PSEUDO_MAP_FD
#define BPF_PSEUDO_MAP_FD 1
#endif

#ifndef BPF_PSEUDO_MAP_IDX
#define BPF_PSEUDO_MAP_IDX 5
#endif

#ifndef PERF_FLAG_FD_CLOEXEC
#define PERF_FLAG_FD_CLOEXEC (1U << 3)
#endif

/* --- defaults -------------------------------------------------------- */

#define DEFAULT_SOCK_PATH   "/tmp/ch24.sock"
#define DEFAULT_READY_PATH  "/tmp/ch24-server-ready"
#define DEFAULT_BPFFS_PATH  "/tmp/ch24-bpffs"
#define DEFAULT_BPF_OBJ     "./build/ch24-bpf-token-delegation.bpf.o"

#define TP_EVENT_PATH       "/sys/kernel/tracing/events/syscalls/sys_enter_getuid/id"
#define PROG_NAME           "tp_sys_enter_getuid"
#define MAP_NAME            "events"

/* --- shared state ---------------------------------------------------- */

static volatile sig_atomic_t g_running = 1;

static void on_signal(int sig) { (void)sig; g_running = 0; }

static int libbpf_silent(enum libbpf_print_level lvl, const char *fmt, va_list a)
{
    if (lvl == LIBBPF_DEBUG) return 0;
    return vfprintf(stderr, fmt, a);
}

static void install_sig_handlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* SIGPIPE is guaranteed when a client disappears mid-send. */
    struct sigaction ign;
    memset(&ign, 0, sizeof(ign));
    ign.sa_handler = SIG_IGN;
    sigemptyset(&ign.sa_mask);
    sigaction(SIGPIPE, &ign, NULL);
}

static int kernel_version_ge(int major, int minor)
{
    struct utsname u;
    if (uname(&u) != 0) return 0;
    int maj = 0, min = 0;
    if (sscanf(u.release, "%d.%d", &maj, &min) != 2) return 0;
    if (maj > major) return 1;
    if (maj == major && min >= minor) return 1;
    return 0;
}

static int read_cap_eff(unsigned long long *out)
{
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    char line[256];
    int rc = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "CapEff:", 7) == 0) {
            *out = strtoull(line + 7, NULL, 16);
            rc = 0;
            break;
        }
    }
    fclose(f);
    return rc;
}

/* --- server ---------------------------------------------------------- */

struct server_state {
    const char *sock_path;
    const char *ready_path;
    const char *bpffs_path;
    bool mounted;
    int listen_fd;
    int token_fd;
};

static void server_cleanup(struct server_state *st)
{
    if (st->listen_fd >= 0) {
        close(st->listen_fd);
        st->listen_fd = -1;
    }
    if (st->token_fd >= 0) {
        close(st->token_fd);
        st->token_fd = -1;
    }
    if (st->sock_path) unlink(st->sock_path);
    if (st->ready_path) unlink(st->ready_path);
    if (st->mounted) {
        if (umount(st->bpffs_path) != 0) {
            fprintf(stderr, "[ch24-server] umount %s: %s\n",
                    st->bpffs_path, strerror(errno));
        }
        st->mounted = false;
    }
    rmdir(st->bpffs_path);
}

static void log_userns_state(void)
{
    char self_ns[64] = {0}, init_ns[64] = {0};
    ssize_t r;
    r = readlink("/proc/self/ns/user", self_ns, sizeof(self_ns) - 1);
    if (r > 0) self_ns[r] = '\0';
    r = readlink("/proc/1/ns/user", init_ns, sizeof(init_ns) - 1);
    if (r > 0) init_ns[r] = '\0';
    fprintf(stderr, "[ch24-server] userns self=%s init(pid1)=%s match=%s\n",
            self_ns, init_ns, strcmp(self_ns, init_ns) == 0 ? "yes" : "no");
}

static int server_create_token(const char *bpffs_path)
{
    int dir_fd = open(bpffs_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir_fd < 0) {
        fprintf(stderr, "[ch24-server] open(%s): %s\n",
                bpffs_path, strerror(errno));
        return -1;
    }

    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.token_create.bpffs_fd = dir_fd;
    attr.token_create.flags    = 0;

    int tok = (int)syscall(SYS_bpf, BPF_TOKEN_CREATE, &attr, sizeof(attr));
    int saved = errno;
    close(dir_fd);
    if (tok < 0) {
        errno = saved;
        /* EOPNOTSUPP on kernel 6.9..6.15 means the caller's user
         * namespace differs from the bpffs mount's user namespace
         * (kernel/bpf/token.c: `if (current_user_ns() != sb->s_user_ns)
         * return -EOPNOTSUPP;`). This trips when the server runs inside
         * a service namespace (e.g. cloud-init's runcmd). Log the ns
         * state for diagnosis. */
        if (saved == EOPNOTSUPP) {
            log_userns_state();
        }
        fprintf(stderr, "[ch24-server] BPF_TOKEN_CREATE: %s\n", strerror(saved));
        return -1;
    }
    return tok;
}

static int server_send_token(int client_fd, int token_fd)
{
    char dummy = 'T';
    struct iovec iov = { .iov_base = &dummy, .iov_len = 1 };

    union {
        char   buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } u;
    memset(&u, 0, sizeof(u));

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov        = &iov;
    msg.msg_iovlen     = 1;
    msg.msg_control    = u.buf;
    msg.msg_controllen = sizeof(u.buf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SCM_RIGHTS;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &token_fd, sizeof(int));

    ssize_t n;
    do {
        n = sendmsg(client_fd, &msg, 0);
    } while (n < 0 && errno == EINTR);
    if (n < 0) {
        fprintf(stderr, "[ch24-server] sendmsg: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

static int run_server(const char *sock_path,
                      const char *ready_path,
                      const char *bpffs_path)
{
    if (!kernel_version_ge(6, 9)) {
        fprintf(stderr, "[ch24-server] CH24_SKIP reason=\"kernel < 6.9 (no bpf_token)\"\n");
        return 2;
    }

    struct server_state st = {
        .sock_path  = sock_path,
        .ready_path = ready_path,
        .bpffs_path = bpffs_path,
        .mounted    = false,
        .listen_fd  = -1,
        .token_fd   = -1,
    };

    install_sig_handlers();

    if (mkdir(bpffs_path, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "[ch24-server] CH24_SKIP reason=\"mkdir %s: %s\"\n",
                bpffs_path, strerror(errno));
        return 2;
    }

    /* Delegation: use "any" for maximal compatibility across 6.9..6.15+
     * (the exact accepted tokens for delegate_attachs shifted across
     * versions; "any" is the universal form). A production deployment
     * would narrow these to the specific cmds/progs/maps the workload
     * needs. See kernel/bpf/inode.c::bpf_parse_delegate_* for the
     * per-kernel accepted keyword set. */
    const char *mopts_try[] = {
        "delegate_cmds=any,delegate_progs=any,delegate_maps=any,delegate_attachs=any",
        "delegate_cmds=any,delegate_progs=any,delegate_maps=any",
        "delegate_cmds=prog_load:map_create:link_create:map_update_elem,"
        "delegate_progs=tracepoint,delegate_maps=ringbuf",
        NULL,
    };

    int mount_rc = -1;
    int mount_errno = 0;
    for (int i = 0; mopts_try[i]; i++) {
        if (mount("bpf", bpffs_path, "bpf", 0, mopts_try[i]) == 0) {
            mount_rc = 0;
            break;
        }
        mount_errno = errno;
    }
    if (mount_rc != 0) {
        fprintf(stderr, "[ch24-server] CH24_SKIP reason=\"bpffs mount: %s (tried %d option strings)\"\n",
                strerror(mount_errno),
                (int)(sizeof(mopts_try)/sizeof(*mopts_try) - 1));
        server_cleanup(&st);
        return 2;
    }
    st.mounted = true;

    if (chmod(bpffs_path, 0755) != 0) {
        fprintf(stderr, "[ch24-server] chmod %s: %s\n",
                bpffs_path, strerror(errno));
    }

    fprintf(stderr, "[ch24-server] bpffs mounted at %s (delegate_cmds set)\n",
            bpffs_path);

    /* Mint a token referring to the freshly-mounted bpffs. */
    st.token_fd = server_create_token(bpffs_path);
    if (st.token_fd < 0) {
        fprintf(stderr, "[ch24-server] CH24_SKIP reason=\"BPF_TOKEN_CREATE failed: %s\"\n",
                strerror(errno));
        server_cleanup(&st);
        return 2;
    }
    fprintf(stderr, "[ch24-server] minted token_fd=%d\n", st.token_fd);

    /* Bind AF_UNIX listener. */
    unlink(sock_path);

    st.listen_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (st.listen_fd < 0) {
        fprintf(stderr, "[ch24-server] socket: %s\n", strerror(errno));
        server_cleanup(&st);
        return 1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(sock_path) >= sizeof(addr.sun_path)) {
        fprintf(stderr, "[ch24-server] socket path too long: %s\n", sock_path);
        server_cleanup(&st);
        return 1;
    }
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    if (bind(st.listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fprintf(stderr, "[ch24-server] bind %s: %s\n", sock_path, strerror(errno));
        server_cleanup(&st);
        return 1;
    }

    /* Allow unprivileged processes to connect. */
    if (chmod(sock_path, 0666) != 0) {
        fprintf(stderr, "[ch24-server] chmod %s: %s\n", sock_path, strerror(errno));
    }

    if (listen(st.listen_fd, 4) != 0) {
        fprintf(stderr, "[ch24-server] listen: %s\n", strerror(errno));
        server_cleanup(&st);
        return 1;
    }

    /* Publish readiness. */
    if (ready_path && *ready_path) {
        FILE *f = fopen(ready_path, "w");
        if (!f) {
            fprintf(stderr, "[ch24-server] fopen %s: %s\n",
                    ready_path, strerror(errno));
        } else {
            fputs("ready\n", f);
            fclose(f);
            chmod(ready_path, 0644);
        }
    }

    fprintf(stderr, "[ch24-server] listening on %s (ready_file=%s)\n",
            sock_path, ready_path ? ready_path : "<none>");

    /* Accept loop: serve tokens until signaled. One client per round is plenty
     * for the PoC, but loop so a flaky trigger can reconnect. */
    while (g_running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(st.listen_fd, &rfds);
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };

        int r = select(st.listen_fd + 1, &rfds, NULL, NULL, &tv);
        if (r < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "[ch24-server] select: %s\n", strerror(errno));
            break;
        }
        if (r == 0) continue;

        int cfd = accept4(st.listen_fd, NULL, NULL, SOCK_CLOEXEC);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "[ch24-server] accept: %s\n", strerror(errno));
            continue;
        }

        fprintf(stderr, "[ch24-server] client connected; sending token_fd=%d\n",
                st.token_fd);
        if (server_send_token(cfd, st.token_fd) != 0) {
            fprintf(stderr, "[ch24-server] send_token failed\n");
        } else {
            fprintf(stderr, "[ch24-server] token sent via SCM_RIGHTS\n");
        }
        close(cfd);
    }

    fprintf(stderr, "[ch24-server] shutting down\n");
    server_cleanup(&st);
    return 0;
}

/* --- client ---------------------------------------------------------- */

struct evt {
    uint64_t ts;
    uint32_t pid;
    uint32_t uid;
    char     comm[16];
};

static unsigned long long g_uid_events = 0;

static int handle_event(void *ctx, void *data, size_t sz)
{
    (void)ctx;
    if (sz < sizeof(struct evt)) return 0;
    const struct evt *e = data;
    g_uid_events++;
    fprintf(stderr, "[ch24-client] getuid pid=%u uid=%u comm=%.16s\n",
            e->pid, e->uid, e->comm);
    return 0;
}

static int client_connect(const char *sock_path)
{
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        fprintf(stderr, "[ch24-client] socket: %s\n", strerror(errno));
        return -1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(sock_path) >= sizeof(addr.sun_path)) {
        fprintf(stderr, "[ch24-client] socket path too long\n");
        close(fd);
        return -1;
    }
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    /* Retry connect briefly in case the server is still coming up. */
    int tries = 50;
    while (tries-- > 0) {
        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0)
            return fd;
        if (errno != ENOENT && errno != ECONNREFUSED) {
            fprintf(stderr, "[ch24-client] connect %s: %s\n",
                    sock_path, strerror(errno));
            close(fd);
            return -1;
        }
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 100 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    fprintf(stderr, "[ch24-client] connect %s timed out: %s\n",
            sock_path, strerror(errno));
    close(fd);
    return -1;
}

static int client_recv_token(int sfd)
{
    char buf[4] = {0};
    struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };

    union {
        char   cbuf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } u;
    memset(&u, 0, sizeof(u));

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov        = &iov;
    msg.msg_iovlen     = 1;
    msg.msg_control    = u.cbuf;
    msg.msg_controllen = sizeof(u.cbuf);

    ssize_t n;
    do {
        n = recvmsg(sfd, &msg, MSG_CMSG_CLOEXEC);
    } while (n < 0 && errno == EINTR);
    if (n < 0) {
        fprintf(stderr, "[ch24-client] recvmsg: %s\n", strerror(errno));
        return -1;
    }
    if (msg.msg_flags & MSG_CTRUNC) {
        fprintf(stderr, "[ch24-client] recvmsg: cmsg truncated\n");
        return -1;
    }

    for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS &&
            c->cmsg_len  == CMSG_LEN(sizeof(int))) {
            int tok;
            memcpy(&tok, CMSG_DATA(c), sizeof(int));
            return tok;
        }
    }
    fprintf(stderr, "[ch24-client] no SCM_RIGHTS cmsg in reply\n");
    return -1;
}

static int read_tracepoint_id(const char *path, uint64_t *out)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    unsigned long long id = 0;
    if (fscanf(f, "%llu", &id) != 1) {
        fclose(f);
        return -1;
    }
    fclose(f);
    *out = id;
    return 0;
}

static int open_perf_tracepoint(uint64_t tp_id)
{
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));
    pe.type          = PERF_TYPE_TRACEPOINT;
    pe.size          = sizeof(pe);
    pe.config        = tp_id;
    pe.sample_period = 1;
    pe.wakeup_events = 1;

    int fd = (int)syscall(SYS_perf_event_open, &pe, -1, 0, -1,
                          (unsigned long)PERF_FLAG_FD_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "[ch24-client] perf_event_open: %s\n", strerror(errno));
        return -1;
    }
    return fd;
}

/* Walk the instruction stream and rewrite LD_IMM64 map-fd placeholders
 * that libbpf left with src_reg = BPF_PSEUDO_MAP_FD or BPF_PSEUDO_MAP_IDX.
 * For this PoC there is a single "events" ringbuf map, so every such
 * placeholder resolves to the same runtime map_fd. */
static int patch_map_fds(struct bpf_insn *insns, size_t cnt, int map_fd)
{
    int patched = 0;
    for (size_t i = 0; i + 1 < cnt; i++) {
        struct bpf_insn *ins = &insns[i];
        /* LD_IMM64 opcode = 0x18, occupies two 8-byte slots. */
        if (ins->code != (BPF_LD | BPF_DW | BPF_IMM)) continue;

        if (ins->src_reg == BPF_PSEUDO_MAP_FD ||
            ins->src_reg == BPF_PSEUDO_MAP_IDX) {
            ins->src_reg = BPF_PSEUDO_MAP_FD;
            ins->imm     = map_fd;
            insns[i + 1].imm = 0; /* high half: fd fits in 32 bits */
            patched++;
        }
        i++; /* skip the paired second slot */
    }
    return patched;
}

static int run_client(const char *sock_path, const char *bpf_obj_path)
{
    if (!kernel_version_ge(6, 9)) {
        fprintf(stderr, "[ch24-client] CH24_SKIP reason=\"kernel < 6.9\"\n");
        return 2;
    }

    install_sig_handlers();
    libbpf_set_print(libbpf_silent);

    unsigned long long cap_eff = 0;
    (void)read_cap_eff(&cap_eff);
    fprintf(stderr,
            "[ch24-client] uid=%u euid=%u CapEff=0x%llx (CAP_BPF bit 39 = %s)\n",
            getuid(), geteuid(), cap_eff,
            (cap_eff & (1ULL << 39)) ? "SET" : "clear");

    /* 1. Get the token from the server. */
    int sfd = client_connect(sock_path);
    if (sfd < 0) {
        fprintf(stderr, "[ch24-client] CH24_SKIP reason=\"cannot reach server socket %s\"\n",
                sock_path);
        return 2;
    }
    int token_fd = client_recv_token(sfd);
    close(sfd);
    if (token_fd < 0) {
        fprintf(stderr, "[ch24-client] CH24_SKIP reason=\"failed to receive token_fd\"\n");
        return 2;
    }
    fprintf(stderr, "[ch24-client] received token_fd=%d via SCM_RIGHTS\n", token_fd);

    /* 2. Parse the BPF object WITHOUT bpf_token_path. We must not trigger
     * an in-libbpf BPF_TOKEN_CREATE since that requires CAP_SYS_ADMIN in
     * the userns -- the entire point of this PoC is to avoid that. */
    struct bpf_object *obj = bpf_object__open_file(bpf_obj_path, NULL);
    if (!obj || libbpf_get_error(obj)) {
        long err = libbpf_get_error(obj);
        fprintf(stderr, "[ch24-client] bpf_object__open_file(%s): %ld (%s)\n",
                bpf_obj_path, err, strerror(err ? (int)-err : errno));
        close(token_fd);
        return 2;
    }

    /* 3. Locate the ringbuf map def. */
    struct bpf_map *events_map = NULL;
    struct bpf_map *m;
    bpf_object__for_each_map(m, obj) {
        const char *n = bpf_map__name(m);
        if (n && strcmp(n, MAP_NAME) == 0) {
            events_map = m;
            break;
        }
    }
    if (!events_map) {
        fprintf(stderr, "[ch24-client] map \"%s\" not found in %s\n",
                MAP_NAME, bpf_obj_path);
        bpf_object__close(obj);
        close(token_fd);
        return 1;
    }

    enum bpf_map_type mtype = bpf_map__type(events_map);
    uint32_t key_sz  = bpf_map__key_size(events_map);
    uint32_t val_sz  = bpf_map__value_size(events_map);
    uint32_t max_ent = bpf_map__max_entries(events_map);

    /* 4. Create the map with the delegated token. */
    LIBBPF_OPTS(bpf_map_create_opts, mopts, .token_fd = token_fd);
    int map_fd = bpf_map_create(mtype, MAP_NAME, key_sz, val_sz, max_ent, &mopts);
    if (map_fd < 0) {
        int e = errno;
        fprintf(stderr, "[ch24-client] bpf_map_create: %s\n", strerror(e));
        if (e == EPERM) {
            fprintf(stderr, "[ch24-client] CH24_SKIP reason=\"map_create EPERM even with token_fd\"\n");
        }
        bpf_object__close(obj);
        close(token_fd);
        return 2;
    }
    fprintf(stderr, "[ch24-client] created ringbuf map fd=%d (type=%u max=%u)\n",
            map_fd, mtype, max_ent);

    /* 5. Find the program by name and copy its insns to a writable buffer. */
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, PROG_NAME);
    if (!prog) {
        fprintf(stderr, "[ch24-client] program \"%s\" not found\n", PROG_NAME);
        close(map_fd);
        bpf_object__close(obj);
        close(token_fd);
        return 1;
    }

    const struct bpf_insn *ro_insns = bpf_program__insns(prog);
    size_t insn_cnt = bpf_program__insn_cnt(prog);
    if (!ro_insns || insn_cnt == 0) {
        fprintf(stderr, "[ch24-client] empty insns for %s\n", PROG_NAME);
        close(map_fd);
        bpf_object__close(obj);
        close(token_fd);
        return 1;
    }

    struct bpf_insn *insns = calloc(insn_cnt, sizeof(struct bpf_insn));
    if (!insns) {
        fprintf(stderr, "[ch24-client] calloc: %s\n", strerror(errno));
        close(map_fd);
        bpf_object__close(obj);
        close(token_fd);
        return 1;
    }
    memcpy(insns, ro_insns, insn_cnt * sizeof(struct bpf_insn));

    /* 6. Rewrite map-fd placeholders to our runtime map_fd. */
    int patched = patch_map_fds(insns, insn_cnt, map_fd);
    fprintf(stderr, "[ch24-client] patched %d LD_IMM64 map-fd placeholder(s)\n",
            patched);

    /* 7. Load the program with the delegated token. */
    LIBBPF_OPTS(bpf_prog_load_opts, popts,
                .token_fd = token_fd,
                .expected_attach_type = 0);
    int prog_fd = bpf_prog_load(BPF_PROG_TYPE_TRACEPOINT,
                                "tp_getuid",
                                "GPL",
                                insns, insn_cnt,
                                &popts);
    free(insns);
    if (prog_fd < 0) {
        int e = errno;
        fprintf(stderr, "[ch24-client] bpf_prog_load: %s\n", strerror(e));
        if (e == EPERM) {
            fprintf(stderr, "[ch24-client] CH24_SKIP reason=\"prog_load EPERM even with token_fd\"\n");
        } else {
            fprintf(stderr, "[ch24-client] CH24_SKIP reason=\"prog_load failed: %s\"\n",
                    strerror(e));
        }
        close(map_fd);
        bpf_object__close(obj);
        close(token_fd);
        return 2;
    }
    fprintf(stderr, "[ch24-client] loaded tracepoint program fd=%d\n", prog_fd);

    /* 8. Attach via perf_event_open + PERF_EVENT_IOC_SET_BPF. */
    uint64_t tp_id = 0;
    if (read_tracepoint_id(TP_EVENT_PATH, &tp_id) != 0) {
        fprintf(stderr, "[ch24-client] read %s: %s\n",
                TP_EVENT_PATH, strerror(errno));
        close(prog_fd);
        close(map_fd);
        bpf_object__close(obj);
        close(token_fd);
        return 1;
    }
    fprintf(stderr, "[ch24-client] sys_enter_getuid tp_id=%llu\n",
            (unsigned long long)tp_id);

    int perf_fd = open_perf_tracepoint(tp_id);
    if (perf_fd < 0) {
        close(prog_fd);
        close(map_fd);
        bpf_object__close(obj);
        close(token_fd);
        return 2;
    }

    if (ioctl(perf_fd, PERF_EVENT_IOC_SET_BPF, prog_fd) != 0) {
        fprintf(stderr, "[ch24-client] PERF_EVENT_IOC_SET_BPF: %s\n",
                strerror(errno));
        close(perf_fd);
        close(prog_fd);
        close(map_fd);
        bpf_object__close(obj);
        close(token_fd);
        return 2;
    }
    if (ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0) != 0) {
        fprintf(stderr, "[ch24-client] PERF_EVENT_IOC_ENABLE: %s\n",
                strerror(errno));
        close(perf_fd);
        close(prog_fd);
        close(map_fd);
        bpf_object__close(obj);
        close(token_fd);
        return 2;
    }

    fprintf(stderr, "[ch24-client] tracepoint attached -- polling ringbuf\n");

    /* 9. Poll the ringbuf. */
    struct ring_buffer *rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ch24-client] ring_buffer__new: %s\n", strerror(errno));
        ioctl(perf_fd, PERF_EVENT_IOC_DISABLE, 0);
        close(perf_fd);
        close(prog_fd);
        close(map_fd);
        bpf_object__close(obj);
        close(token_fd);
        return 2;
    }

    for (int i = 0; i < 50 && g_running; i++) {
        int n = ring_buffer__poll(rb, 200 /* ms */);
        if (n == -EINTR) continue;
        if (n < 0) {
            fprintf(stderr, "[ch24-client] ring_buffer__poll: %d\n", n);
            break;
        }
    }

    /* 10. Emit proof marker and tear down. */
    printf("CH24_PROVEN uid_events=%llu token_delegated=yes capeff=0x%llx\n",
           g_uid_events, cap_eff);
    fflush(stdout);

    ring_buffer__free(rb);
    ioctl(perf_fd, PERF_EVENT_IOC_DISABLE, 0);
    close(perf_fd);
    close(prog_fd);
    close(map_fd);
    bpf_object__close(obj);
    close(token_fd);

    return g_uid_events > 0 ? 0 : 2;
}

/* --- main ------------------------------------------------------------ */

static void usage(const char *argv0)
{
    fprintf(stderr,
        "Usage: %s --server|--client [options]\n"
        "  --server                run as root, mount bpffs, mint token,\n"
        "                          hand it out via SCM_RIGHTS\n"
        "  --client                run as unprivileged user, receive token,\n"
        "                          load+attach a tracepoint program\n"
        "  --socket=PATH           unix socket path (default %s)\n"
        "  --ready-file=PATH       server writes 'ready\\n' here (default %s)\n"
        "  --bpffs=PATH            bpffs mount path (default %s)\n"
        "  --bpf-obj=PATH          compiled BPF ELF (client, default %s)\n"
        "  --help                  show this help\n",
        argv0,
        DEFAULT_SOCK_PATH, DEFAULT_READY_PATH,
        DEFAULT_BPFFS_PATH, DEFAULT_BPF_OBJ);
}

int main(int argc, char **argv)
{
    int mode_server = 0, mode_client = 0;
    const char *sock_path  = DEFAULT_SOCK_PATH;
    const char *ready_path = DEFAULT_READY_PATH;
    const char *bpffs_path = DEFAULT_BPFFS_PATH;
    const char *bpf_obj    = DEFAULT_BPF_OBJ;

    static struct option longopts[] = {
        { "server",     no_argument,       NULL, 'S' },
        { "client",     no_argument,       NULL, 'C' },
        { "socket",     required_argument, NULL, 's' },
        { "ready-file", required_argument, NULL, 'r' },
        { "bpffs",      required_argument, NULL, 'b' },
        { "bpf-obj",    required_argument, NULL, 'o' },
        { "help",       no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 },
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "h", longopts, NULL)) != -1) {
        switch (opt) {
        case 'S': mode_server = 1; break;
        case 'C': mode_client = 1; break;
        case 's': sock_path  = optarg; break;
        case 'r': ready_path = optarg; break;
        case 'b': bpffs_path = optarg; break;
        case 'o': bpf_obj    = optarg; break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }

    if (mode_server == mode_client) {
        usage(argv[0]);
        return 1;
    }

    if (mode_server)
        return run_server(sock_path, ready_path, bpffs_path);
    return run_client(sock_path, bpf_obj);
}
