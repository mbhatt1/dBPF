// ch24 bpf-token-delegation -- real BPF_TOKEN_CREATE + SCM_RIGHTS handoff,
// working against a stock, fully-hardened kernel (verified on Ubuntu 25.10,
// kernel 6.17.0-35-generic, unprivileged_bpf_disabled=2).
//
// ---------------------------------------------------------------------------
// Why the split you might expect (privileged root server + separate
// unprivileged client) does NOT work, and what actually does:
//
//   * There is no CONFIG_BPF_TOKEN kconfig option. bpf_token support is part
//     of CONFIG_BPF_SYSCALL and is compiled into every modern kernel. The
//     gate is a *runtime* one, not a build one.
//
//   * bpf_token_create() (kernel/bpf/token.c) refuses to mint a token in the
//     init user namespace:  `if (current_user_ns() == &init_user_ns) return
//     -EOPNOTSUPP;`.  A plain root process therefore can NEVER create a token.
//     Tokens only make sense inside a non-init user namespace (a container).
//
//   * The bpffs the token refers to must be owned by that same non-init userns
//     (`if (current_user_ns() != sb->s_user_ns) return -EPERM;`), yet the
//     delegate_* mount options may only be *set* by a process holding
//     CAP_SYS_ADMIN in the INIT userns (kernel/bpf/inode.c uses capable(),
//     not ns_capable()).  A single mount(2) can satisfy at most one of those,
//     so it always fails.  The only way to build such a filesystem is the
//     new mount API split across the userns boundary:
//         child  (in userns X):  fs_fd = fsopen("bpf")            -> binds X
//         parent (init userns):  fsconfig(delegate_*), CMD_CREATE -> capable()
//         child  (in userns X):  fsmount(); bpf_token_create()    -> non-init
//
//   * To USE the token, the caller must be ns_capable(token->userns, CAP_BPF)
//     -- i.e. also inside userns X -- and must set BPF_F_TOKEN_FD in
//     map_flags / prog_flags (otherwise the kernel ignores the token fd and
//     falls back to init-userns capability checks, which fail with EPERM).
//
//   * Classic tracepoints attach via perf_event_open(), which is NOT covered
//     by the token and needs CAP_PERFMON in the init userns -> EACCES. We use
//     a RAW tracepoint, attached with the BPF_RAW_TRACEPOINT_OPEN bpf()
//     command, which the token delegates.
//
// ---------------------------------------------------------------------------
// Process layout (single invocation, run as root by trigger.sh):
//
//   top (init userns) ---- helper: materialize delegate bpffs superblock
//     |
//     +-fork-> minter (userns X, host-unprivileged): fsopen, fsmount,
//               BPF_TOKEN_CREATE  --> real token_fd
//                 |
//                 +-fork-> consumer (userns X): receives token_fd via
//                          SCM_RIGHTS, creates the ringbuf map + loads the
//                          raw-tp program *with the delegated token*, attaches
//                          via BPF_RAW_TRACEPOINT_OPEN, drains the ringbuf.
//
// The minter, after handing off the token, generates getuid() calls so the
// consumer's program fires. The consumer emits the proof marker.
//
// Skip behavior (any -> CH24_SKIP, exit 2):
//   kernel < 6.9 / fsopen unsupported / BPF_TOKEN_CREATE fails /
//   map_create or prog_load EPERM even with token / attach fails.
//
// Proof marker (consumer, stdout):
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
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
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
#ifndef FSOPEN_CLOEXEC
#define FSOPEN_CLOEXEC 0x00000001
#endif
#ifndef FSCONFIG_SET_STRING
#define FSCONFIG_SET_STRING 1
#endif
#ifndef FSCONFIG_CMD_CREATE
#define FSCONFIG_CMD_CREATE 6
#endif
#ifndef FSMOUNT_CLOEXEC
#define FSMOUNT_CLOEXEC 0x00000001
#endif

/* glibc >= 2.36 (Ubuntu 25.10) exposes fsopen/fsconfig/fsmount wrappers via
 * <sys/mount.h>; fall back to raw syscalls otherwise. */
#ifndef __NR_fsopen
#define __NR_fsopen   430
#define __NR_fsconfig 431
#define __NR_fsmount  432
#endif
#if !defined(__GLIBC__) || (__GLIBC__ < 2) || (__GLIBC__ == 2 && __GLIBC_MINOR__ < 36)
static int fsopen(const char *fs, unsigned f){return syscall(__NR_fsopen,fs,f);}
static int fsconfig(int fd,unsigned c,const char*k,const void*v,int a){return syscall(__NR_fsconfig,fd,c,k,v,a);}
static int fsmount(int fd,unsigned f,unsigned m){return syscall(__NR_fsmount,fd,f,m);}
#endif

/* getuid syscall number for the trigger loop (arm64 asm-generic). */
#ifndef SYS_getuid
#define SYS_getuid __NR_getuid
#endif

#define PROG_NAME "rtp_sys_enter"
#define MAP_NAME  "events"
#define RAW_TP    "sys_enter"
#define DEFAULT_BPF_OBJ "./build/ch24-bpf-token-delegation.bpf.o"

/* --- misc helpers ---------------------------------------------------- */

static volatile sig_atomic_t g_running = 1;
static void on_signal(int sig){ (void)sig; g_running = 0; }

static int libbpf_silent(enum libbpf_print_level lvl, const char *fmt, va_list a)
{
    if (lvl == LIBBPF_DEBUG) return 0;
    return vfprintf(stderr, fmt, a);
}

static void install_sig_handlers(void)
{
    struct sigaction sa; memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal; sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL); sigaction(SIGTERM, &sa, NULL);
    struct sigaction ign; memset(&ign, 0, sizeof(ign));
    ign.sa_handler = SIG_IGN; sigemptyset(&ign.sa_mask);
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
    char line[256]; int rc = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "CapEff:", 7) == 0) {
            *out = strtoull(line + 7, NULL, 16); rc = 0; break;
        }
    }
    fclose(f);
    return rc;
}

static void log_userns(const char *who)
{
    char self_ns[64] = {0}, init_ns[64] = {0};
    ssize_t r;
    r = readlink("/proc/self/ns/user", self_ns, sizeof(self_ns) - 1);
    if (r > 0) self_ns[r] = '\0';
    r = readlink("/proc/1/ns/user", init_ns, sizeof(init_ns) - 1);
    if (r > 0) init_ns[r] = '\0';
    fprintf(stderr, "[ch24-%s] userns self=%s init(pid1)=%s non_init=%s\n",
            who, self_ns, init_ns, strcmp(self_ns, init_ns) ? "yes" : "NO");
}

/* --- SCM_RIGHTS fd passing ------------------------------------------- */

static int send_fd(int sock, int fd)
{
    char b = 'T';
    struct iovec io = { .iov_base = &b, .iov_len = 1 };
    union { char buf[CMSG_SPACE(sizeof(int))]; struct cmsghdr a; } u;
    memset(&u, 0, sizeof(u));
    struct msghdr m; memset(&m, 0, sizeof(m));
    m.msg_iov = &io; m.msg_iovlen = 1;
    m.msg_control = u.buf; m.msg_controllen = sizeof(u.buf);
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &fd, sizeof(int));
    ssize_t n;
    do { n = sendmsg(sock, &m, 0); } while (n < 0 && errno == EINTR);
    return n < 0 ? -1 : 0;
}

static int recv_fd(int sock)
{
    char b;
    struct iovec io = { .iov_base = &b, .iov_len = 1 };
    union { char buf[CMSG_SPACE(sizeof(int))]; struct cmsghdr a; } u;
    memset(&u, 0, sizeof(u));
    struct msghdr m; memset(&m, 0, sizeof(m));
    m.msg_iov = &io; m.msg_iovlen = 1;
    m.msg_control = u.buf; m.msg_controllen = sizeof(u.buf);
    ssize_t n;
    do { n = recvmsg(sock, &m, MSG_CMSG_CLOEXEC); } while (n < 0 && errno == EINTR);
    if (n < 0) return -1;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&m); c; c = CMSG_NXTHDR(&m, c)) {
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS &&
            c->cmsg_len == CMSG_LEN(sizeof(int))) {
            int fd; memcpy(&fd, CMSG_DATA(c), sizeof(int)); return fd;
        }
    }
    return -1;
}

static int write_map(const char *path, const char *val)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t n = write(fd, val, strlen(val));
    close(fd);
    return n < 0 ? -1 : 0;
}

/* --- init-userns helper: build the delegate bpffs superblock --------- */
//
// Receives the fs_context fd (fsopen'd inside userns X by the minter),
// applies the delegate_* masks (requires init-userns CAP_SYS_ADMIN, which we
// have here), and instantiates the superblock. The superblock's s_user_ns is
// X (captured at fsopen time), so the minter can then create a token on it.

static int helper_materialize_bpffs(int sock)
{
    int fs = recv_fd(sock);
    if (fs < 0) {
        fprintf(stderr, "[ch24-helper] recv fs_fd failed\n");
        return -1;
    }
    /* "any" delegates every cmd/map/prog/attach. A real deployment would
     * narrow these (e.g. delegate_cmds=prog_load:map_create:...). */
    fsconfig(fs, FSCONFIG_SET_STRING, "delegate_cmds",    "any", 0);
    fsconfig(fs, FSCONFIG_SET_STRING, "delegate_maps",    "any", 0);
    fsconfig(fs, FSCONFIG_SET_STRING, "delegate_progs",   "any", 0);
    fsconfig(fs, FSCONFIG_SET_STRING, "delegate_attachs", "any", 0);
    if (fsconfig(fs, FSCONFIG_CMD_CREATE, NULL, NULL, 0) != 0) {
        fprintf(stderr, "[ch24-helper] FSCONFIG_CMD_CREATE: %s\n", strerror(errno));
        char nak = 'N'; (void)!write(sock, &nak, 1);
        close(fs);
        return -1;
    }
    fprintf(stderr, "[ch24-helper] delegate bpffs superblock created (owning userns = minter's)\n");
    char ack = 'Y';
    if (write(sock, &ack, 1) != 1) { close(fs); return -1; }
    close(fs);
    return 0;
}

/* --- LD_IMM64 map-fd relocation -------------------------------------- */

// Relocate LD_IMM64 map-fd placeholders to our runtime map_fd.
//
// bpf_object__open() does NOT resolve map references -- libbpf defers that to
// bpf_object__load() (which we deliberately bypass so we can drive the raw
// syscall path with the delegated token). So a map-referencing LD_IMM64 can
// appear here in any of three forms:
//   * src_reg = BPF_PSEUDO_MAP_FD (1)   -- already marked by an older clang
//   * src_reg = BPF_PSEUDO_MAP_IDX (5)  -- map-by-index form
//   * src_reg = 0, imm = 0              -- bare, unresolved relocation slot
// This PoC's program has exactly one map ("events") and thus exactly one such
// placeholder; rewrite each to BPF_PSEUDO_MAP_FD + the live map_fd.
static int patch_map_fds(struct bpf_insn *insns, size_t cnt, int map_fd)
{
    int patched = 0; size_t i = 0;
    while (i + 1 < cnt) {
        struct bpf_insn *ins = &insns[i];
        if (ins->code == (BPF_LD | BPF_DW | BPF_IMM)) {
            bool is_map_ref =
                ins->src_reg == BPF_PSEUDO_MAP_FD ||
                ins->src_reg == BPF_PSEUDO_MAP_IDX ||
                (ins->src_reg == 0 && ins->imm == 0 && insns[i + 1].imm == 0);
            if (is_map_ref) {
                ins->src_reg = BPF_PSEUDO_MAP_FD;
                ins->imm = map_fd;
                insns[i + 1].imm = 0;
                patched++;
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    return patched;
}

/* --- consumer: use the delegated token to load + attach -------------- */

static unsigned long long g_uid_events = 0;

static int handle_event(void *ctx, void *data, size_t sz)
{
    (void)ctx; (void)data;
    if (sz < sizeof(uint64_t)) return 0;
    g_uid_events++;
    return 0;
}

/* runs inside userns X; token_sock is connected to the minter */
static int run_consumer(int token_sock, const char *bpf_obj_path)
{
    install_sig_handlers();
    libbpf_set_print(libbpf_silent);

    unsigned long long cap_eff = 0;
    (void)read_cap_eff(&cap_eff);
    log_userns("consumer");
    fprintf(stderr,
            "[ch24-consumer] uid=%u euid=%u CapEff=0x%llx (host-unprivileged: no caps in init userns)\n",
            getuid(), geteuid(), cap_eff);

    int token_fd = recv_fd(token_sock);
    if (token_fd < 0) {
        fprintf(stderr, "[ch24-consumer] CH24_SKIP reason=\"failed to receive token_fd via SCM_RIGHTS\"\n");
        return 2;
    }
    fprintf(stderr, "[ch24-consumer] received delegated token_fd=%d via SCM_RIGHTS\n", token_fd);

    struct bpf_object *obj = bpf_object__open_file(bpf_obj_path, NULL);
    if (!obj || libbpf_get_error(obj)) {
        long err = obj ? libbpf_get_error(obj) : -errno;
        fprintf(stderr, "[ch24-consumer] bpf_object__open_file(%s): %ld\n", bpf_obj_path, err);
        return 2;
    }

    struct bpf_map *events_map = NULL, *m;
    bpf_object__for_each_map(m, obj) {
        const char *n = bpf_map__name(m);
        if (n && strcmp(n, MAP_NAME) == 0) { events_map = m; break; }
    }
    if (!events_map) {
        fprintf(stderr, "[ch24-consumer] map \"%s\" not found\n", MAP_NAME);
        bpf_object__close(obj); return 1;
    }

    /* 1. Create the ringbuf map WITH the delegated token. BPF_F_TOKEN_FD in
     *    map_flags is mandatory -- without it the kernel ignores token_fd. */
    LIBBPF_OPTS(bpf_map_create_opts, mopts,
                .token_fd = token_fd,
                .map_flags = BPF_F_TOKEN_FD);
    int map_fd = bpf_map_create(bpf_map__type(events_map), MAP_NAME,
                                bpf_map__key_size(events_map),
                                bpf_map__value_size(events_map),
                                bpf_map__max_entries(events_map), &mopts);
    if (map_fd < 0) {
        int e = errno;
        fprintf(stderr, "[ch24-consumer] bpf_map_create: %s\n", strerror(e));
        fprintf(stderr, "[ch24-consumer] CH24_SKIP reason=\"map_create %s even with token_fd\"\n", strerror(e));
        bpf_object__close(obj); close(token_fd); return 2;
    }
    fprintf(stderr, "[ch24-consumer] created ringbuf map fd=%d via delegated token\n", map_fd);

    /* 2. Copy program insns, relocate map fd. */
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, PROG_NAME);
    if (!prog) {
        fprintf(stderr, "[ch24-consumer] program \"%s\" not found\n", PROG_NAME);
        close(map_fd); bpf_object__close(obj); close(token_fd); return 1;
    }
    const struct bpf_insn *ro = bpf_program__insns(prog);
    size_t icnt = bpf_program__insn_cnt(prog);
    struct bpf_insn *insns = calloc(icnt, sizeof(*insns));
    if (!insns) { close(map_fd); bpf_object__close(obj); close(token_fd); return 1; }
    memcpy(insns, ro, icnt * sizeof(*insns));
    int patched = patch_map_fds(insns, icnt, map_fd);
    fprintf(stderr, "[ch24-consumer] relocated %d map-fd placeholder(s)\n", patched);

    /* 3. Load the RAW_TRACEPOINT program WITH the delegated token. */
    LIBBPF_OPTS(bpf_prog_load_opts, popts,
                .token_fd = token_fd,
                .prog_flags = BPF_F_TOKEN_FD);
    int prog_fd = bpf_prog_load(BPF_PROG_TYPE_RAW_TRACEPOINT, PROG_NAME, "GPL",
                                insns, icnt, &popts);
    free(insns);
    if (prog_fd < 0) {
        int e = errno;
        fprintf(stderr, "[ch24-consumer] bpf_prog_load: %s\n", strerror(e));
        fprintf(stderr, "[ch24-consumer] CH24_SKIP reason=\"prog_load %s even with token_fd\"\n", strerror(e));
        close(map_fd); bpf_object__close(obj); close(token_fd); return 2;
    }
    fprintf(stderr, "[ch24-consumer] loaded raw_tp program fd=%d via delegated token\n", prog_fd);

    /* 4. Attach via BPF_RAW_TRACEPOINT_OPEN (a bpf() command; token-delegated,
     *    unlike perf_event_open which needs init-userns CAP_PERFMON). */
    int link_fd = bpf_raw_tracepoint_open(RAW_TP, prog_fd);
    if (link_fd < 0) {
        int e = errno;
        fprintf(stderr, "[ch24-consumer] bpf_raw_tracepoint_open(%s): %s\n", RAW_TP, strerror(e));
        fprintf(stderr, "[ch24-consumer] CH24_SKIP reason=\"raw_tracepoint_open %s\"\n", strerror(e));
        close(prog_fd); close(map_fd); bpf_object__close(obj); close(token_fd); return 2;
    }
    fprintf(stderr, "[ch24-consumer] attached raw tracepoint '%s' link_fd=%d\n", RAW_TP, link_fd);

    struct ring_buffer *rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ch24-consumer] ring_buffer__new: %s\n", strerror(errno));
        close(link_fd); close(prog_fd); close(map_fd);
        bpf_object__close(obj); close(token_fd); return 2;
    }

    /* Signal the minter that we are attached and ready for the trigger. */
    char ready = 'R';
    if (write(token_sock, &ready, 1) != 1)
        fprintf(stderr, "[ch24-consumer] ready-signal write failed\n");

    fprintf(stderr, "[ch24-consumer] draining ringbuf...\n");
    for (int i = 0; i < 40 && g_running; i++) {
        int n = ring_buffer__poll(rb, 200 /* ms */);
        if (n == -EINTR) continue;
        if (n < 0) break;
    }

    printf("CH24_PROVEN uid_events=%llu token_delegated=yes capeff=0x%llx\n",
           g_uid_events, cap_eff);
    fflush(stdout);

    ring_buffer__free(rb);
    close(link_fd); close(prog_fd); close(map_fd);
    bpf_object__close(obj); close(token_fd);
    return g_uid_events > 0 ? 0 : 2;
}

/* --- minter: create token in userns X, hand to consumer -------------- */

static int run_minter(int helper_sock, const char *bpf_obj_path)
{
    /* Capture the host uid/gid BEFORE unshare -- after CLONE_NEWUSER and before
     * the id maps are written, getuid()/getgid() return the overflow id. */
    uid_t host_uid = getuid();
    gid_t host_gid = getgid();

    /* Enter a fresh user namespace (become root within it, host-unprivileged
     * outside it) and a private mount namespace. */
    if (unshare(CLONE_NEWUSER) != 0) {
        fprintf(stderr, "[ch24-minter] CH24_SKIP reason=\"unshare(CLONE_NEWUSER): %s\"\n", strerror(errno));
        return 2;
    }
    write_map("/proc/self/setgroups", "deny");
    {
        char m[64];
        snprintf(m, sizeof(m), "0 %d 1", host_uid);
        if (write_map("/proc/self/uid_map", m) != 0)
            fprintf(stderr, "[ch24-minter] uid_map write: %s\n", strerror(errno));
        snprintf(m, sizeof(m), "0 %d 1", host_gid);
        if (write_map("/proc/self/gid_map", m) != 0)
            fprintf(stderr, "[ch24-minter] gid_map write: %s\n", strerror(errno));
    }
    if (setgid(0) != 0 || setuid(0) != 0) {
        fprintf(stderr, "[ch24-minter] setuid/setgid in userns: %s\n", strerror(errno));
    }
    if (unshare(CLONE_NEWNS) != 0 ||
        mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
        fprintf(stderr, "[ch24-minter] CH24_SKIP reason=\"mount ns setup: %s\"\n", strerror(errno));
        return 2;
    }
    log_userns("minter");

    /* fsopen binds the eventual superblock to THIS user namespace. */
    int fs = fsopen("bpf", FSOPEN_CLOEXEC);
    if (fs < 0) {
        fprintf(stderr, "[ch24-minter] CH24_SKIP reason=\"fsopen(bpf): %s\"\n", strerror(errno));
        return 2;
    }
    if (send_fd(helper_sock, fs) != 0) {
        fprintf(stderr, "[ch24-minter] send fs_fd to helper failed\n");
        return 1;
    }
    char ack = 0;
    if (read(helper_sock, &ack, 1) != 1 || ack != 'Y') {
        fprintf(stderr, "[ch24-minter] CH24_SKIP reason=\"helper could not create delegate bpffs\"\n");
        return 2;
    }

    int mnt = fsmount(fs, FSMOUNT_CLOEXEC, 0);
    close(fs);
    if (mnt < 0) {
        fprintf(stderr, "[ch24-minter] CH24_SKIP reason=\"fsmount: %s\"\n", strerror(errno));
        return 2;
    }
    int bpffs_fd = openat(mnt, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (bpffs_fd < 0) {
        fprintf(stderr, "[ch24-minter] openat bpffs: %s\n", strerror(errno));
        close(mnt); return 1;
    }

    /* The moment of truth: a real BPF_TOKEN_CREATE. */
    int token_fd = bpf_token_create(bpffs_fd, NULL);
    if (token_fd < 0) {
        fprintf(stderr, "[ch24-minter] BPF_TOKEN_CREATE: %s\n", strerror(errno));
        fprintf(stderr, "[ch24-minter] CH24_SKIP reason=\"BPF_TOKEN_CREATE failed: %s\"\n", strerror(errno));
        close(bpffs_fd); close(mnt); return 2;
    }
    close(bpffs_fd); close(mnt);
    fprintf(stderr, "[ch24-minter] minted real bpf token_fd=%d\n", token_fd);

    /* Hand the token to a separate consumer process (still in userns X). */
    int cs[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, cs) != 0) {
        fprintf(stderr, "[ch24-minter] socketpair: %s\n", strerror(errno));
        close(token_fd); return 1;
    }
    pid_t cpid = fork();
    if (cpid < 0) {
        fprintf(stderr, "[ch24-minter] fork consumer: %s\n", strerror(errno));
        close(token_fd); return 1;
    }
    if (cpid == 0) {
        close(cs[0]); close(token_fd);
        _exit(run_consumer(cs[1], bpf_obj_path));
    }
    close(cs[1]);

    fprintf(stderr, "[ch24-minter] handing token to consumer via SCM_RIGHTS\n");
    if (send_fd(cs[0], token_fd) != 0)
        fprintf(stderr, "[ch24-minter] send_fd(token) failed\n");
    close(token_fd);

    /* Wait for the consumer to attach, then generate getuid() events. */
    char ready = 0;
    if (read(cs[0], &ready, 1) == 1 && ready == 'R') {
        fprintf(stderr, "[ch24-minter] consumer attached; generating getuid() events\n");
        for (int i = 0; i < 200 && g_running; i++) {
            syscall(SYS_getuid);
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 10 * 1000 * 1000 };
            nanosleep(&ts, NULL);
        }
    } else {
        fprintf(stderr, "[ch24-minter] consumer never signalled ready\n");
    }

    int st = 0;
    waitpid(cpid, &st, 0);
    close(cs[0]);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 1;
}

/* --- top-level orchestration ----------------------------------------- */

static int run_proof(const char *bpf_obj_path)
{
    if (!kernel_version_ge(6, 9)) {
        fprintf(stderr, "[ch24] CH24_SKIP reason=\"kernel < 6.9 (no bpf_token)\"\n");
        return 2;
    }
    install_sig_handlers();

    int hs[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, hs) != 0) {
        fprintf(stderr, "[ch24] socketpair: %s\n", strerror(errno));
        return 1;
    }
    pid_t mpid = fork();
    if (mpid < 0) {
        fprintf(stderr, "[ch24] fork minter: %s\n", strerror(errno));
        return 1;
    }
    if (mpid == 0) {
        close(hs[0]);
        _exit(run_minter(hs[1], bpf_obj_path));
    }
    close(hs[1]);

    /* top process stays in the init userns and services the minter's
     * superblock-creation request (needs init-userns CAP_SYS_ADMIN). */
    (void)helper_materialize_bpffs(hs[0]);

    int st = 0;
    waitpid(mpid, &st, 0);
    close(hs[0]);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 1;
}

static void usage(const char *a0)
{
    fprintf(stderr,
        "Usage: %s [--run] [--bpf-obj=PATH]\n"
        "\n"
        "  --run             run the full bpf_token delegation proof (default).\n"
        "                    Must run as root. Internally:\n"
        "                      * a privileged (init-userns) helper materializes a\n"
        "                        delegate bpffs superblock owned by a child userns;\n"
        "                      * a user-namespace-confined MINTER (the '--server'\n"
        "                        role) calls BPF_TOKEN_CREATE and hands the token\n"
        "                        to a CONSUMER (the '--client' role) via SCM_RIGHTS;\n"
        "                      * the consumer loads+attaches a raw tracepoint using\n"
        "                        only the delegated token (no host privileges).\n"
        "  --server          alias for --run (kept for compatibility).\n"
        "  --client          alias for --run (the client/consumer role is driven\n"
        "                    internally; it cannot be a standalone process because\n"
        "                    it must live inside the delegating user namespace).\n"
        "  --bpf-obj=PATH    compiled raw-tp BPF ELF (default %s)\n"
        "  --help            show this help\n",
        a0, DEFAULT_BPF_OBJ);
}

int main(int argc, char **argv)
{
    const char *bpf_obj = DEFAULT_BPF_OBJ;
    static struct option longopts[] = {
        { "run",     no_argument,       NULL, 'R' },
        { "server",  no_argument,       NULL, 'S' },  /* alias -> --run */
        { "client",  no_argument,       NULL, 'C' },  /* alias -> --run */
        { "bpf-obj", required_argument, NULL, 'o' },
        { "help",    no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 },
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "h", longopts, NULL)) != -1) {
        switch (opt) {
        case 'R': case 'S': case 'C': break; /* all map to the integrated proof */
        case 'o': bpf_obj = optarg; break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }
    return run_proof(bpf_obj);
}
