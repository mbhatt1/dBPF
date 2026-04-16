---
layout: book
title: "Chapter 12: eBPF Signed-Driver Swap"
date: 2025-03-01
---

**Chapter 13: Forging the finit_module Return Value**

> **Note**: This primitive's natural hook did not fire on the test kernel. See [Chapter 21 — Skip Accounting]({{ site.baseurl }}/book/act-3/chapter-21-the-autopsy-what-refused-to-die.html) and the surviving workaround variant at [dBPF-pocs/pocs/ch12-signed-driver-swap-syscall/](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs).

## The Question and the Honest Answer

The question I started with was: can a BPF program flip a rejected kernel module load into a successful one, so that userspace believes the module is loaded when it isn't? Not actually load a malicious module — that is a different, much harder problem involving signed-module-loader internals and ELF-construction gymnastics that BPF does not help with — but defeat the class of orchestrators, monitors, and shell scripts that treat `insmod`'s return code as proof of load.

The answer is yes, with a very specific definition of "yes." The primitive I ended up with rewrites the syscall return value of `finit_module` and `init_module` to zero regardless of what the kernel's module loader did internally. Any userspace consumer that checks only the return code is fooled. Any consumer that checks kernel state — `lsmod`, `/proc/modules`, `/sys/module/<name>/`, `dmesg` — catches the forgery immediately. It is a userspace-illusion bypass, narrowly scoped to the syscall boundary.

Before I got to that working primitive, I spent a week on an approach that did not work. I want to describe that failed approach in detail, because the reason it failed is the same reason several chapters in this book are workaround variants rather than their original designs. The pattern matters more than the specific failure.

## The LSM Approach That Didn't Fire

My first cut was a BPF LSM program. On modern kernels with `CONFIG_BPF_LSM=y` — which the linuxkit Docker Desktop kernel and most Ubuntu/Debian distros enable — you can attach BPF programs to LSM hook points and use the `fmod_ret` return-override mechanism to change the hook's verdict. The plan was to target `mod_verify_sig`, the LSM hook that runs after the kernel has extracted the signature from an incoming module blob but before the loader decides whether to accept or reject based on it. If I could flip that hook's return from "signature invalid" to "signature valid," the loader would proceed to actually load the module.

The relevant hook surface in `security/security.c` includes `security_kernel_read_file`, `security_locked_down`, and a few others that sit in the module-load path. The plan was to fmod_ret on whichever of these the running kernel actually checks. On 6.12 aarch64 linuxkit, my BPF program attached fine to `kernel_read_file` and never fired.

Two independent problems killed the approach. They were not obvious from reading the kernel source alone; I had to run the POC and observe what happened to see them. That is the lesson I keep relearning in this work: you cannot reason a BPF primitive into working from the source code alone, because the running kernel's configuration and the specific code path your trigger exercises combine to determine which hooks actually run.

Problem one: the linuxkit kernel I am running does not enforce module signatures at all. `CONFIG_MODULE_SIG_FORCE` is off in the linuxkit config. That means even if a module has no signature, the loader accepts it (possibly logging a warning, but not failing). Without signature enforcement, there are no natural denials for `mod_verify_sig` to produce, and without denials, there is nothing for the LSM hook to be called about. The hook attaches fine; the code path it watches for never runs. I confirmed this by reading the linuxkit kernel config via `/proc/config.gz | gunzip | grep MODULE_SIG`, which showed `CONFIG_MODULE_SIG=y` (signing is supported) but `CONFIG_MODULE_SIG_FORCE` was unset (enforcement is off). The hook exists, the enforcement does not.

Same story on stock Debian cloud images, which I checked afterward. `CONFIG_MODULE_SIG_FORCE=n` is the default on a lot of distro kernels — signatures are checked and logged as warnings, not as fatal errors. If you want a kernel that fails-closed on unsigned modules, you either build it yourself with the flag set or you pass `module.sig_enforce=1` on the kernel command line. Most production systems do not. The attack surface I was trying to hit — signature enforcement rejecting a module that my BPF then flips to accept — simply does not exist on most kernels.

Problem two: even on a kernel with signature enforcement enabled, my test payload was not a valid ELF. I was writing a 1 KiB blob with an ELF header prefix but garbage bytes elsewhere, which the module loader rejects at ELF validation inside `load_module()` well before reaching the signature-verification hooks. The loader does ELF sanity checks first; if the section headers are malformed, the magic bytes are wrong, or the relocation tables do not make sense, the loader returns `-ENOEXEC` and never gets to the signature check. My LSM hook on `mod_verify_sig` would never see the call because the call never happens.

This is a specific, annoying detail about the kernel's module loader: the control flow is "parse ELF first, verify signature second, run init third." If you want to test the signature-verification hook, you need a validly-formed (but unsigned or wrongly-signed) ELF blob. Constructing one is not impossible — you take a real `.ko` and strip or corrupt the signature blob — but it is a meaningful engineering detour. I started down that path, got far enough to realize I was building a test harness more complex than the BPF primitive I was trying to prove, and backed out.

Both problems are the same category of mistake: I was trying to hook a check that was not happening on the code path my trigger was exercising. The chapter I started from described exactly this LSM-flipping plan and claimed it worked. It does not work on stock kernels, and without a deliberately-constructed test kernel plus a deliberately-constructed test ELF, you cannot even set up the conditions under which it would fire. The "working attack" described in the original draft was doing the same thing half the BPF exploitation write-ups on the internet do: describing a primitive under conditions that are not the real-world default, without saying so.

I am leaving the LSM attempt in the repository as `ch12-signed-driver-swap-lsm` for completeness, but the chapter is about what I moved on to.

## The Syscall-Entry Pivot

The approach that actually works is coarser and has a smaller claim. I read `/sys/kernel/debug/error_injection/list` to see what the kernel's error-injection allowlist contained. Two relevant entries:

```
__arm64_sys_finit_module
__arm64_sys_init_module
```

Both module-load syscall entry wrappers are ERRNO-injectable on 6.12 aarch64 linuxkit. The `__arm64_sys_` prefix is the architecture-specific syscall wrapper that Linux generates from the `SYSCALL_DEFINE*` macros; these wrappers are the actual kprobe targets. On x86_64 the equivalent names are `__x64_sys_finit_module` and `__x64_sys_init_module`.

ERRNO-injectable means a kretprobe attached to the symbol is permitted to call `bpf_override_return(ctx, 0)` — or any other value — and the verifier will accept the program at load. The override runs on syscall exit, after every internal rejection path inside the module loader has already produced an errno, after the ELF validation has failed or the signature check has failed or the init function has thrown an error. It works regardless of why the loader gave up, because it runs at the end of the syscall, after the decision has been made.

This is the same primitive class as ch14 (SCHED_FIFO impersonator, which flips `sched_setscheduler` return) and ch18 (token bypass, which flips `getuid` return). The pattern is: find a syscall entry point in the error-injection allowlist, attach a kretprobe, rewrite the return. It works wherever the kernel developers have chosen to allow fault injection, which for syscalls is a reasonably generous set.

The trade-off is scope. The kernel still rejects the module bytes; no code actually loads into kernel memory. `lsmod` still reports the true state of loaded modules; `/proc/modules` is unchanged; `dmesg` still logs the original rejection reason. Only the syscall's return value lies to userspace. Any consumer that does more than check the return value catches the forgery instantly.

What this is useful for: fooling anything that checks only the return value. Shell scripts that do `insmod x.ko && echo loaded`. Orchestrators that call `finit_module(fd, ...)` and treat rc=0 as load-confirmation. CI systems that assert "module loaded successfully" based on exit status. Any tool whose author assumed — reasonably, ordinarily — that a non-zero return from a module-load syscall means the module is actually loaded.

What this is not useful for: loading actual malicious code into the kernel. The module does not load. Kernel state is unchanged. The illusion is strictly userspace-visible.

I have to sit with this for a moment and be honest about the ROI. For an attacker, a userspace-illusion bypass is a narrow win: it defeats the specific class of weak verifiers that trust the syscall return. That class is large — because a lot of operations code was written assuming that when `insmod` says 0 the module is loaded — but it is not universal, and competent defenders easily defeat it with a post-check. The primitive has real value in adversarial workflows where an attacker wants to appear to have loaded their driver without actually loading it (because loading it would trip other detectors like auditd module-load events, or because they don't have the driver ready yet and just want to satisfy an orchestrator). It is not the "load an unsigned driver" primitive it might appear to be on first read.

The surviving variant is at `dBPF-pocs/pocs/ch12-signed-driver-swap-syscall/`. It is what the rest of this chapter describes.

## Source Walk: The BPF Program

The BPF object at `ch12-signed-driver-swap-syscall.bpf.c` is short. I will walk it in order.

License, constants, and the event struct:

```c
char LICENSE[] SEC("license") = "GPL";

#define HOOK_FINIT_MODULE 1
#define HOOK_INIT_MODULE  2

struct evt {
    unsigned int pid;
    unsigned int tgid;
    char         comm[16];
    long         orig_ret;
    int          hook;
    int          flipped;
};
```

GPL license for helper access. Two hook IDs so userspace can distinguish events from the two probes. The event carries: the PID (lightweight thread ID), the TGID (process ID in the userspace sense), the comm (16 bytes, standard), the original return value from the kernel's module loader, the hook identifier, and a boolean-ish `flipped` field saying whether we actually rewrote the return.

The `orig_ret` capture is the interesting field. It is the *pre-flip* return from the kernel — the kernel's actual verdict. On a non-ELF blob, it is `-ENOEXEC` (-8). On a valid ELF with a bad signature, it would be `-EKEYREJECTED` (-129). On a valid ELF whose init function failed, it is whatever the init returned. We record this before calling `bpf_override_return`, so userspace can see what the kernel actually decided and compare it to what we forged.

The maps:

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

// tgid -> 1.  Key 0 is the wildcard slot ("forge every caller").
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned int);
    __type(value, unsigned int);
    __uint(max_entries, 1024);
} target_tgids SEC(".maps");
```

Ringbuf for events — 256 KiB, plenty for a primitive that fires once per `insmod` call. The target map is interesting: it is a TGID-keyed hash mapping target process IDs to a presence flag. The key 0 is reserved as a wildcard slot. If 0 is present in the map, the program flips every caller's return; otherwise it only flips calls from TGIDs explicitly listed.

This target-selectivity is important for a primitive you would actually deploy. Wildcard mode is how you test the mechanism. Per-TGID mode is how you use it in real adversarial workflows — an attacker who wants to forge returns only for their own process, not for every privileged caller of `finit_module` on the system. Forging every caller's return would break systemd's module auto-loader, break driver initialization at boot, and otherwise cause chaos. Selective targeting keeps the blast radius limited.

The is_target helper:

```c
static __always_inline int is_target(void)
{
    unsigned int tgid = bpf_get_current_pid_tgid() >> 32;
    if (bpf_map_lookup_elem(&target_tgids, &tgid))
        return 1;
    unsigned int zero = 0;
    if (bpf_map_lookup_elem(&target_tgids, &zero))
        return 1;
    return 0;
}
```

Two lookups. First, check if the current TGID is explicitly listed. Second, if not, check if the wildcard slot (key 0) is set. Return 1 if either is true, 0 otherwise. The two-lookup pattern means wildcard mode is a single extra map lookup; the branch predictor handles the "not wildcard" case cheaply on any modern CPU.

The event emitter:

```c
static __always_inline void emit(long ret, int hook, int flipped)
{
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;
    unsigned long long id = bpf_get_current_pid_tgid();
    e->pid = (unsigned int)(id & 0xffffffff);
    e->tgid = (unsigned int)(id >> 32);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->orig_ret = ret;
    e->hook = hook;
    e->flipped = flipped;
    bpf_ringbuf_submit(e, 0);
}
```

Standard ringbuf reserve/fill/submit. The interesting ordering is: we capture the original ret *before* any potential override, we capture the flipped flag *after* deciding whether to override. The emit call comes last in the probe body so the event reflects the final state of the probe's decision.

The two probes:

```c
SEC("kretprobe/__arm64_sys_finit_module")
int BPF_KRETPROBE(kr_finit_module, long ret)
{
    int flip = 0;
    if (is_target() && ret != 0) {
        bpf_override_return(ctx, 0);
        flip = 1;
    }
    emit(ret, HOOK_FINIT_MODULE, flip);
    return 0;
}

SEC("kretprobe/__arm64_sys_init_module")
int BPF_KRETPROBE(kr_init_module, long ret)
{
    int flip = 0;
    if (is_target() && ret != 0) {
        bpf_override_return(ctx, 0);
        flip = 1;
    }
    emit(ret, HOOK_INIT_MODULE, flip);
    return 0;
}
```

Two kretprobes, one per syscall variant. The condition for flipping is "target process AND ret is non-zero." The second clause matters — if the kernel's loader actually succeeded (somehow, on a real module), we do not need to flip the return. Only failures get flipped. This makes the primitive idempotent against actual success cases and keeps the ringbuf events honest.

`BPF_KRETPROBE` is a libbpf macro that unpacks the kretprobe context so the `ret` parameter is directly accessible as a typed argument. Without the macro you would have to fetch the return via `PT_REGS_RC(ctx)` manually. The macro is cleaner and matches the pattern other retprobes in this book use.

`bpf_override_return(ctx, 0)` is the primitive that does the actual work. The `ctx` argument is the probe's pt_regs context; the second argument is the new return value. The verifier checks that the target symbol is in `ALLOW_ERROR_INJECTION` at program load — if it were not, the load would fail here with a specific error message. Because `__arm64_sys_finit_module` and `__arm64_sys_init_module` are both on the allowlist, load succeeds and the override takes effect at runtime.

The two-probe design covers both the legacy and modern module-load syscalls. `init_module` is the historical API; it takes a raw kernel-module image buffer and loads it. `finit_module` is the file-descriptor-based API that `insmod` and `modprobe` use on modern systems — it takes an fd to an already-opened `.ko` file. Both wind up in the same internal `load_module()` eventually, but at the syscall boundary they are distinct entry points. Attaching to both means we catch whichever one the caller actually used.

## Source Walk: The Userspace Loader

The loader at `ch12-signed-driver-swap-syscall.c` does three things: preflights the kallsyms and error-injection lists, loads and attaches the BPF programs, and pumps the ringbuf. The preflight is where the correctness work happens.

```c
const char *fsym = "__arm64_sys_finit_module";
const char *isym = "__arm64_sys_init_module";
int has_f  = kallsyms_has(fsym);
int has_i  = kallsyms_has(isym);
int inj_f  = err_inj_has(fsym);
int inj_i  = err_inj_has(isym);
fprintf(stderr, "[ch12s] symbol=%s\tkallsyms=%s\terror_injection=%s\n",
        fsym,
        has_f == 1 ? "present" : (has_f == 0 ? "ABSENT" : "err"),
        inj_f == 1 ? "present" : (inj_f == 0 ? "ABSENT" : "err"));
fprintf(stderr, "[ch12s] symbol=%s\tkallsyms=%s\terror_injection=%s\n",
        isym,
        has_i == 1 ? "present" : (has_i == 0 ? "ABSENT" : "err"),
        inj_i == 1 ? "present" : (inj_i == 0 ? "ABSENT" : "err"));

if (has_f != 1 && has_i != 1) {
    fprintf(stderr, "[ch12s] CH12S_SKIP reason=\"module-load syscalls absent\"\n");
    return 2;
}
if (inj_f != 1 && inj_i != 1) {
    fprintf(stderr,
            "[ch12s] CH12S_SKIP reason=\"module-load syscalls NOT in "
            "error_injection allowlist; bpf_override_return would be rejected\"\n");
    return 2;
}
```

Two preflights, both cheap. `kallsyms_has` looks for the function in `/proc/kallsyms`, same pattern ch11 uses. `err_inj_has` reads `/sys/kernel/debug/error_injection/list` looking for a matching name. That file is a plain text file with one function name per line — the set of functions the kernel will permit `bpf_override_return` on.

The loader then disables autoload for each program whose target is missing or not injectable:

```c
if (has_f != 1 || inj_f != 1) {
    fprintf(stderr, "[ch12s] disabling kr_finit_module (symbol or inject missing)\n");
    bpf_program__set_autoload(s->progs.kr_finit_module, false);
}
if (has_i != 1 || inj_i != 1) {
    fprintf(stderr, "[ch12s] disabling kr_init_module (symbol or inject missing)\n");
    bpf_program__set_autoload(s->progs.kr_init_module, false);
}
```

This is the same graceful-degradation pattern ch11 uses. If either one of the two syscalls is missing or not injectable, only the other gets loaded. If both are missing, the loader exits with a `CH12S_SKIP` marker explaining why.

Mode selection is via command-line flags:

```c
static const struct option longopts[] = {
    { "all",  no_argument,       NULL, 'A' },
    { "tgid", required_argument, NULL, 'T' },
    { "help", no_argument,       NULL, 'h' },
    { 0, 0, 0, 0 },
};
```

`--all` sets the wildcard bit in `target_tgids` (key 0 -> 1). `--tgid <pid>` adds a specific TGID to the map. Both can be combined, though there's no reason to; either mode is sufficient on its own.

The ringbuf handler is straightforward:

```c
static int handle(void *ctx, void *data, size_t sz)
{
    ...
    const struct evt *e = data;
    const char *sc = hook_str(e->hook);
    if (e->flipped) {
        printf("[ch12s] FORGE pid=%u comm=%s syscall=%s orig_ret=%ld -> 0 "
               "(module NOT actually loaded)\n",
               e->pid, e->comm, sc, e->orig_ret);
    } else {
        printf("[ch12s] OBSERVE pid=%u comm=%s syscall=%s ret=%ld\n",
               e->pid, e->comm, sc, e->orig_ret);
    }
    ...
}
```

Two formats: FORGE for flipped returns, OBSERVE for non-flipped (either not a target, or target with ret=0 already). The `orig_ret=%ld -> 0` output makes it obvious in the log what the kernel actually decided and what we lied about. The `(module NOT actually loaded)` parenthetical is there to head off the exact misreading this chapter is trying to prevent: people seeing "FORGE" and assuming the module loaded.

## The Trigger and the Proof Marker

The trigger at `trigger.sh` does a tight before/after comparison. Read it end-to-end:

```bash
# Build a 1 KiB non-ELF blob. insmod will fail with ENOEXEC ("Invalid module
# format") on any kernel — this is pre-signature-check rejection, so the LSM
# variant couldn't observe it, but the syscall return is still what userspace
# sees.
printf '\x7fELF\x02\x01\x01\x00' > "$FAKE_KO"
printf '\x00\x00\x00\x00\x00\x00\x00\x00' >> "$FAKE_KO"
dd if=/dev/zero bs=1 count=1016 >> "$FAKE_KO" 2>/dev/null
```

The fake module is an ELF header prefix followed by zeros. That is enough for the kernel to recognize "this is supposed to be an ELF" and then immediately reject it for being malformed. `\x7fELF\x02\x01\x01\x00` is the first 8 bytes of the ELF magic (class = 64-bit, data = little-endian, version = 1), followed by 8 zero bytes for the remainder of the ident, followed by 1016 zero bytes of "rest of the file." The total size is 1032 bytes. The loader will call it `-ENOEXEC` (invalid module format) because the section headers are garbage.

Then the baseline:

```bash
echo "=== BEFORE (no loader attached) ==="
BEFORE_OUT="$(insmod "$FAKE_KO" 2>&1)"
BEFORE_RC=$?
...
lsmod | grep -q "^${MODNAME}\b" && BEFORE_LSMOD=yes || BEFORE_LSMOD=no
echo "BEFORE: insmod_rc=${BEFORE_RC} lsmod_shows_module=${BEFORE_LSMOD}"
```

Without the BPF loader running, `insmod` returns non-zero (usually 1, representing ENOEXEC translated to userspace), and `lsmod` does not list the module. This is the baseline: kernel rejected, userspace saw the rejection.

Then the loader starts:

```bash
"$LOADER" --all >/tmp/ch12s.out 2>/tmp/ch12s.err &
LOADER_PID=$!

for i in $(seq 1 50); do
    if grep -q "status=ready" /tmp/ch12s.err 2>/dev/null; then
        break
    fi
    sleep 0.1
done
```

The `--all` flag sets wildcard mode so every caller's return is flipped. The trigger waits up to 5 seconds for the loader to print its `status=ready` marker, confirming the kretprobes are attached.

Then the AFTER run:

```bash
echo "=== AFTER (loader attached, override active) ==="
AFTER_OUT="$(insmod "$FAKE_KO" 2>&1)"
AFTER_RC=$?
...
lsmod | grep -q "^${MODNAME}\b" && AFTER_LSMOD=yes || AFTER_LSMOD=no
```

With the loader attached, `insmod` of the same non-ELF blob now returns 0. The syscall return was flipped from -ENOEXEC to 0. But `lsmod` still does not list any module called `ch12sfake` (the trigger's chosen modname), because no module was loaded. Kernel state is unchanged. The userspace-illusion is narrow: only the return code.

The proof marker:

```bash
if [[ "$BEFORE_RC" -ne 0 && "$AFTER_RC" -eq 0 && "$AFTER_LSMOD" == "no" ]]; then
    echo "=== CH12_CONCEPT_PROVEN syscall_override_landed=yes module_actually_loaded=no ==="
else
    echo "=== CH12_CONCEPT_UNPROVEN before_rc=${BEFORE_RC} after_rc=${AFTER_RC} lsmod=${AFTER_LSMOD} ==="
fi
```

The primitive is "proven" iff three conditions hold: BEFORE rc was non-zero (baseline: kernel rejects bad .ko), AFTER rc is zero (syscall return forged), AND lsmod still does not show the module (kernel state unchanged). The third condition is essential — without it, you could not distinguish "we lied about the rc" from "somehow the module actually loaded." All three conditions together prove exactly what the primitive claims: the syscall-return illusion is in effect, and it is strictly an illusion.

The ringbuf event confirms the override landed, with the original return visible:

```
[ch12s] FORGE pid=<N> comm=insmod syscall=finit_module orig_ret=-8 -> 0
```

`orig_ret=-8` is `-ENOEXEC` — the kernel's actual verdict, captured inside the probe before the override rewrites it. The `-> 0` is what userspace sees. The comm tells us insmod was the caller. The pid correlates with the test run.

## Scope: The Userspace Illusion and Its Limits

I keep circling back to the scope of this primitive because readers — and I, when I was writing the first draft of this chapter — want to believe it does more than it does.

What it does: rewrites the return value of `finit_module(2)` and `init_module(2)` from the kernel's actual verdict to zero, for processes that match the target map.

What it does not do:

- It does not load any code into the kernel.
- It does not change `lsmod` output.
- It does not change `/proc/modules`.
- It does not create an entry in `/sys/module/<name>/`.
- It does not suppress the kernel log message that records the original loader rejection.
- It does not change the kernel's runtime state in any way.

That is a strict scope. The value of the primitive depends entirely on whether the defender's checking logic is gated on the syscall return. If it is, the primitive fools them. If it is not, the primitive does nothing.

Orchestration code is a common target of this scope. Lots of system-provisioning tools call `modprobe` or `insmod` in a subprocess and check the exit code; if the exit code is zero, they proceed. That pattern is convenient, it matches how every other Unix tool works, and it is wrong against this primitive. A defender using such a tool sees "module loaded successfully" when the module in fact failed to load. The next step in the orchestration — configuring the module, using its sysfs entries, whatever — will fail with a different error (missing sysfs node, unknown syscall, etc.), but by that point the orchestrator may have already progressed past the point where it thought the module was available.

This is the specific attack surface: multi-step orchestrations where the module-load step's success is the gate for subsequent steps, and where a failure at a later step produces diagnostics different from the failure the primitive masked. An attacker who wants a defender's orchestrator to take some later action that assumes the module is present can use this primitive to make the module-load step "succeed" (lie) without having to actually supply a working module.

The narrower use is defender-fooling: any monitoring system that alerts on `insmod` failure but does not cross-check `/proc/modules` is blinded by this primitive. The loader call succeeds as far as the monitor can see. Only a post-check detects the forgery.

The even narrower use is anti-forensics: if a defender runs a script that logs the result of every `insmod` call to audit their system's module-load history, this primitive makes failed loads look like successes in the log. The `dmesg` record is untouched, so a forensic examiner who reads dmesg sees the truth, but the userspace log file is misleading.

None of these are "load an unsigned driver." The unsigned-driver attack requires either signature enforcement being off (in which case you don't need BPF at all, `insmod` works directly) or the LSM-level bypass of `mod_verify_sig` (which requires both signature enforcement and a real but unsigned .ko, conditions I could not set up on the test kernel). This primitive is for a different, narrower attack surface.

## Why the Error-Injection Allowlist Contains Syscall Entries

A digression on the kernel-source side of things, because it is useful to understand why the allowlist has what it has.

`/sys/kernel/debug/error_injection/list` is populated from source-code annotations. Functions that declare `ALLOW_ERROR_INJECTION(func_name, TYPE)` in their defining source file are added to this list at build time. The type — `ERRNO`, `NULL`, `TRUE`, `FALSE`, or `ANY` — tells the verifier what return values are permissible for the override. For syscall entry wrappers, the type is `ERRNO`, meaning override returns must be valid errno values (negative in the range -MAX_ERRNO to 0, or 0 itself).

The syscall wrappers get this annotation because fault injection testing of syscalls is a common kernel test technique. You want to be able to simulate "what happens if `finit_module` fails with ENOMEM right here" as part of the kernel's own self-test infrastructure, and the allowlist is the mechanism that enables that. BPF programs piggyback on this — the same gate that lets the kernel's fault-injection framework rewrite a return lets a BPF program do so.

This is why the allowlist contains a lot of syscall entries but very few mid-kernel functions. Syscall entries are natural points to inject faults at because the entire syscall is a single transactional unit from userspace's perspective; the kernel's behavior in response to one is a single point of observation. Mid-kernel functions are deeper in the call graph and rewriting their returns has effects on other functions up the stack that are harder to reason about. The kernel developers have been generous with syscall-entry annotations and stingy with anything below the syscall boundary.

The practical effect is that BPF programs that want to rewrite behavior have two clean attachment points: LSM hooks (explicit policy points with declared semantics for override) and syscall entries (explicit userspace-facing points with declared ERRNO semantics). Anywhere else — the IRQ dispatch path from chapter 11, the powercap functions from chapter 13, almost any filesystem or networking internal — is off-limits for `bpf_override_return` unless a kernel developer has specifically made that allowance.

For an attacker, this means the menu of possible primitives is bounded by the allowlist. You do not get to pick any function you like. You get to pick from a specific set. And for each function in the set, you get to decide what return value to rewrite to, within the ERRNO envelope.

This is the reason chapters 12, 14, and 18 look so structurally similar. Each one identifies a syscall in the allowlist, rewrites its return to fool a userspace consumer, and documents the scope. The pattern is the pattern because the allowlist is the allowlist.

## A Walk Through Why Non-ELF Triggers ENOEXEC

An aside to make the ELF-validation rejection concrete. When `insmod fake.ko` runs on a non-ELF blob, the kernel's path through `load_module()` is:

1. The syscall entry wrapper receives the file descriptor and flag arguments.
2. `kernel_read_file_from_fd` reads the .ko bytes into a kernel buffer.
3. `copy_module_from_user` copies the userspace image into a `struct load_info`.
4. `elf_header_check` validates the ELF header: magic bytes, class (32 vs 64), data encoding (LE/BE), version, machine type.

At step 4, the `\x7fELF\x02\x01\x01\x00` + zeros blob the trigger creates will make it past magic-byte check (the first four bytes are correct), past class check (`\x02` = ELFCLASS64), past data check (`\x01` = ELFDATA2LSB), past version check (`\x01` = EV_CURRENT). What it fails at is the subsequent sanity checks on section headers and program headers — the zero bytes make the header offsets nonsensical, e_shoff and e_phoff point into nowhere, and the loader rejects with `-ENOEXEC`.

The exact function that produces -ENOEXEC is `elf_validity_check` in `kernel/module/main.c`, called from the module-load path. This happens inside the syscall, before any LSM hooks that care about module contents run. My syscall-entry kretprobe fires on the way out of the syscall, after this rejection has been produced.

On a valid ELF with bad or missing signature, the path continues past elf_validity_check, through further section parsing, to `module_sig_check`. If signature enforcement is on and the signature is bad, that function returns `-EKEYREJECTED` (-129). If signature enforcement is off, it returns 0 (accept and continue, optionally with a warning). The LSM hooks that the original LSM variant was supposed to target run around this point — `kernel_read_file` runs during the read, `locked_down` runs during loader lockdown checks.

So the code path for "non-ELF blob" and "ELF with bad signature" diverge at the ELF validation step. The syscall-entry primitive catches both because it runs after everything; the LSM primitive catches only the second, and only on a kernel that enforces signatures.

## On bpf_override_return Semantics

The mechanics of `bpf_override_return` are worth pinning down because they are often described vaguely.

The function is a BPF helper that, when called from a kprobe or kretprobe on an allowlisted target, arranges for the probed function's return value to be the specified value instead of what the function would have returned. On kprobes, this preempts the function's execution — the function body does not run at all, and the return value is set to the override. On kretprobes, the function has already run; the override rewrites its return value before it propagates to the caller.

The kretprobe case is what this chapter uses. The module loader has already executed its full logic, decided to reject the bytes, and written a negative errno into the return register. The kretprobe fires on syscall exit, runs my BPF program, which calls `bpf_override_return(ctx, 0)`. That helper rewrites the kretprobe context's return-value slot, and when the probe returns, the kernel's return-path code uses the rewritten value to populate the userspace-visible return.

The override is not a "fake return from kernel space"; it is a literal rewrite of the pt_regs-backed return value at the moment of syscall exit. There is no way for any userspace-visible mechanism to distinguish a BPF-forged return from a kernel-native return, because from the CPU's point of view there is no distinction — they are the same value in the same register at the same point in execution.

Anything that reads the return in kernel space *before* the kretprobe runs sees the pre-flip value. That includes audit records, as noted in the detection section, and any other in-kernel consumer of the syscall's return. It also includes subsequent BPF programs attached to the same kretprobe if there are any — the order of kretprobe firing is not guaranteed to match the order of attachment.

Anything that reads the return in kernel space *after* the kretprobe runs sees the post-flip value. That includes the userspace delivery of the return via the syscall exit path.

The boundary between "before" and "after" is the specific placement of the kretprobe in the kernel's return-path code. This is a narrow window — single-digit instructions on modern kernels — and the behavior is consistent across 5.x and 6.x. The design choice here was made deliberately by the BPF developers: kretprobes need to be able to rewrite returns, the natural place to do that is at syscall exit after the function has run but before the value propagates.

For a primitive that wants to fool both userspace and audit, the kretprobe placement is not good enough. Audit catches the pre-flip value. For a primitive that wants to fool only userspace, the kretprobe placement is exactly right. Chapter 12 is in the second category.

## Cross-Kernel Behavior: When the LSM Path Actually Works

I want to describe the kernel configuration under which the original LSM approach does fire, because it is a real configuration and someone reading this chapter should know how to recognize it.

The LSM approach works against a kernel that has:

1. `CONFIG_BPF_LSM=y` (BPF LSM infrastructure).
2. `CONFIG_MODULE_SIG=y` (module signing compiled in).
3. `CONFIG_MODULE_SIG_FORCE=y` or `module.sig_enforce=1` on the command line (signature enforcement fail-closed).
4. A module loader that reaches `mod_verify_sig` — i.e., the caller supplies a validly-formed ELF (passes ELF validation) but with no signature or a bad signature.

On such a kernel, an unsigned `.ko` — or one signed with an untrusted key — gets past ELF validation, reaches `mod_verify_sig`, and the hook returns a signature-failure errno. A BPF LSM program attached via `fmod_ret` on that hook can flip the return to zero, and the loader proceeds to actually load the module into kernel memory. Unlike the syscall-entry primitive, this is a real bypass — the module actually loads, `lsmod` shows it, `/proc/modules` is updated, and the module's init function runs.

The ROI on that primitive is enormous: it is the "load an unsigned driver" attack people are thinking of when they read a chapter title like this one. It is also rare in practice, because the kernel config conditions above are specific and the test-case construction (a validly-formed ELF with bad or missing signature) is deliberate.

On a kernel with `CONFIG_MODULE_SIG_FORCE` off — which is most kernels — the LSM approach does not fire because there is no signature denial to flip. The kernel simply loads the unsigned module (possibly logging a warning). The LSM hook attaches, runs, returns success (because the signature was not enforced), and no flip is needed because nothing was going to deny anyway.

On a kernel with `CONFIG_MODULE_SIG_FORCE=y` but where my test payload is a non-ELF blob, the LSM approach also does not fire because the loader rejects at ELF validation before reaching the signature hook.

The two conditions combined — signature enforcement on, validly-formed ELF with bad signature — are the only configuration where the LSM bypass works. That configuration is what a serious production kernel with strict module signing looks like. It is also what this chapter does not have a test environment for.

The syscall-entry primitive works on any kernel where the module-load syscalls are in the error-injection allowlist, which is a much more permissive condition. Different conditions, different ROIs:

- **LSM approach** — actually loads unsigned modules on kernels that enforce signing. Rare kernel config; real bypass.
- **Syscall-entry approach** — forges return code for any reason of loader failure on any kernel with injectable module-load syscalls. Common kernel config; userspace illusion only.

Neither is strictly better; they do different things. The LSM approach is the one people imagine when they hear "signed-driver swap," and it is genuinely more powerful where it fires. The syscall-entry approach is the one I could prove on the test kernel and is what survives in the repository.

## Detection

The detection story is uncomfortably simple for the defender and embarrassing for the attacker: the forgery is visible to anyone who checks more than one thing.

`lsmod` / `/proc/modules`: the supposedly-loaded module is not listed. This is the canonical cross-check. Any workflow that does `insmod x.ko` followed by `lsmod | grep x` catches the forgery. The second command is maybe two seconds of extra script work; the defensive value is enormous.

`/sys/module/<name>/`: the module's sysfs directory does not exist. `stat("/sys/module/<name>")` returns ENOENT. Any orchestrator that consults the sysfs representation of loaded modules catches the forgery trivially.

`dmesg`: the kernel log still contains the module loader's original error message. "Invalid module format" for a bad ELF, "Key was rejected by service" for a signature failure, "Unknown symbol" for an unresolved init dependency. The log is not rewritten by the BPF primitive; only the syscall return is. A defender reading dmesg sees the truth.

`auditctl -a always,exit -S finit_module -S init_module`: audit watches on the module-load syscalls record every call, with the return code as the audit system sees it. The audit return is captured in the audit-exit stage of the syscall — which may be before or after the BPF kretprobe runs, depending on the kernel's audit-hook placement. On the 6.12 kernels I tested, the audit return captures the pre-flip value; the BPF override runs at the very end of syscall exit, after the audit record has been emitted. That means audit logs show the real return, not the forged one. Which is good news for defenders and bad news for the primitive's stealth.

`bpftool prog show type kprobe | grep -i finit_module`: the attached kretprobe is visible to anyone with `CAP_BPF`. This is the generic BPF-observability detection — same as ch11, same as every BPF primitive. If you can run `bpftool` you can see the probe.

`/sys/kernel/tracing/kprobe_events`: the kernel's tracing subsystem records every kprobe registration. The BPF loader does not typically go through this interface (it uses perf_event_open instead), but kprobes registered through either path show up here.

The defender's question, and this is what I ended the chapter section of the first draft with and I want to repeat it: "did this module actually load" is easy to verify. The real surface this primitive attacks is "which code path in my orchestration treats a syscall return as authoritative." That is a different question, and the answer varies by orchestrator.

## Prior Art and Related Primitives

Module-signature bypass has a long history in kernel-security research. Before BPF, the primary approaches were: modify the kernel's signing key in memory (requires arbitrary kernel write), load the module via `/proc/kallsyms` + `finit_module` with a kernel-resident trampoline (requires a privileged loader already in kernel), or directly modify `/sys/module/<name>/` entries via debugfs to mask the absence (requires debugfs write access, detectable).

The KSPP (Kernel Self-Protection Project) threads from 2018-2020 covered signature enforcement hardening fairly extensively. The consensus was that `CONFIG_MODULE_SIG_FORCE=y` plus a trusted keyring is sufficient to prevent unsigned module loads against an attacker who does not have kernel-code-execution already. Once they do, all bets are off; the kernel cannot defend against an attacker inside the kernel.

BPF-based extensions to module-signature bypass started appearing in public around 2022, on the back of the LSM fmod_ret mechanism. The threat model there is "attacker with CAP_BPF but not kernel-code-execution," which is a narrower and more interesting threat than the classical one. A lot of container escape research has hit this boundary: if the attacker has CAP_BPF in a container that shares the host kernel, the LSM bypass of `mod_verify_sig` is a plausible escalation step toward actually loading a kernel module from the container.

The syscall-entry variant I describe here is in a different class. It is not a privilege-escalation primitive — the attacker has to have CAP_BPF already to load the program, and the primitive doesn't get them anything extra in kernel memory. It is a workflow-manipulation primitive: fool the orchestration, not the kernel.

Ch14 (SCHED_FIFO impersonator), which forges `sched_setscheduler` returns, and ch18 (token bypass), which forges `getuid` returns, are the closest siblings. All three use the same pattern: ERRNO-injectable syscall entry, kretprobe, `bpf_override_return`, narrow userspace illusion. Different syscalls, different specific lies, same mechanism.

## Deployment Notes for the Defender

If you are a defender thinking about detection for this primitive, here is the practical playbook.

First, do not trust `insmod`'s exit code alone. If your ops scripts call `insmod` or `modprobe` and check the exit code, add a post-check on `/proc/modules` or `/sys/module/<name>/`. The two-line diff is:

```bash
# before
insmod x.ko || die "load failed"
# after
insmod x.ko || die "load failed"
lsmod | grep -q '^x\b' || die "load claimed success but module not present"
```

The cost is one extra shell-out per load. The defensive value is complete coverage of this primitive.

Second, deploy auditd rules on the module-load syscalls:

```
auditctl -a always,exit -S finit_module
auditctl -a always,exit -S init_module
```

The audit records capture the real return value (pre-flip, as discussed). A forensic analyst looking at audit logs sees every module-load attempt with the kernel's actual verdict, regardless of whether a BPF primitive has forged the syscall return for userspace.

Third, watch `bpftool prog show` output. Any kretprobe attached to `__arm64_sys_finit_module` or `__arm64_sys_init_module` (or the x86 equivalents) is high-signal. Legitimate observability tools do not kretprobe syscall entries by default. If you see one, ask who loaded it and why.

Fourth, consider `CONFIG_MODULE_SIG_FORCE=y` for your kernel build if you are not already doing this. Signature enforcement is the front-line defense against the LSM-variant attack; it also makes the syscall-entry variant less useful because most caller workflows that matter already post-check the module state. Enforcement is a requirement on serious production kernels and I'd argue should be the default everywhere except development.

Fifth, if you operate a cluster orchestration system that relies on module-load success as a gate, audit every call site to ensure it cross-checks `/proc/modules`. This is the kind of systemic review that does not scale to "read every script in every team's ops repo," but you can at least set the policy and write a lint rule.

## Deployment Notes for the Attacker

From the other side, if you are thinking about using this primitive adversarially, the things to know are:

First, this is a userspace-illusion primitive. Do not deploy it expecting to load code into the kernel; that is not what it does. The module does not load. If you need kernel code execution, you need a different primitive — typically one that requires conditions you do not have (kernel write, signature bypass on an enforcing kernel, and so on).

Second, the scope of the illusion is narrow. Any post-check against `/proc/modules` catches you. If your target workflow includes such a check, this primitive is useless. Audit the target workflow before deploying.

Third, the BPF load is visible. `bpftool prog show`, `/sys/kernel/tracing`, auditd BPF-load events — all of them reveal that a kretprobe is attached to the module-load syscalls. If your adversarial scenario requires stealth, the load itself is already detectable.

Fourth, the primitive interacts poorly with systems that do real module loading alongside the faked path. If you flip every caller's return with `--all`, you will forge the return of legitimate module loads too — turning a successful legitimate load into a ringbuf event with flipped=0 (not flipped, ret was already 0). But if a legitimate load fails for an ordinary reason (ENOMEM, missing dependency), the primitive flips that to success as well, which might cause the orchestrator to take unexpected actions. Use per-TGID targeting to constrain the blast radius.

Fifth, the primitive does not survive `rmmod` + `insmod` on a module that is already loaded. If the target module is loaded, `insmod` returns EEXIST; the primitive flips EEXIST to zero. That is probably the wrong behavior for most uses. Check the existence of the target module in userspace before relying on the primitive.

## A Digression on insmod vs modprobe

A small note on the userspace tooling. `insmod` is the low-level interface; it calls `finit_module` directly with a file descriptor. `modprobe` is the higher-level interface; it handles dependency resolution, loads dependent modules first, consults `/lib/modules/$(uname -r)/modules.dep`, and ultimately also calls `finit_module` (sometimes repeatedly for dependency chains).

The primitive catches both because it hooks the syscall, not the userspace tool. Whether the caller is `insmod x.ko`, `modprobe x`, or a custom program that calls `syscall(SYS_finit_module, ...)` directly, the kretprobe fires on syscall exit and the return is rewritten.

For modprobe specifically, this means: if modprobe is loading a module that depends on five other modules, and the primitive is in wildcard mode, then any of the six individual loads that fails has its return flipped. Modprobe's internal logic may be confused — it loaded what it thought was a success but the module is not actually present. The observable behavior from the outside depends on what modprobe does when a load "succeeds" but the expected post-conditions are not met. In my testing this varies by modprobe version; some versions notice and error out, some do not.

This is an area where the primitive's semantics become fuzzier the deeper you go into ecosystems that use module loading. The narrow claim — "the syscall return is flipped" — is stable; the impact on higher-level tooling depends on how that tooling reacts to "success without the expected state."

## Why This Is in the Book

I keep asking myself whether chapters like this one — where the primitive's scope is genuinely narrow and the victim class is specific — are worth including. The alternative would be to cut them and only feature the primitives that land big, with real kernel-state consequences.

The argument for including them is that they are representative of what BPF-based kernel adjacent primitives actually look like. Most primitives are narrow. Most primitives have a victim class that is specific to a particular engineering assumption (in this case, "syscall returns are authoritative for module load"). Most primitives need a post-check to be defeated.

A book that only featured the big-impact primitives would be misleading about the shape of the field. The field is small primitives, narrow scopes, and engineering work on the defender side to close the assumption gaps. Showing the small primitive clearly, with its scope, is more useful than showing an imagined big primitive that does not actually exist on real kernels.

The second argument for including this chapter is that the failure mode — the LSM approach that did not fire — is itself instructive. The setup conditions for "BPF LSM bypass of module signing" are specific enough that most readers who think they understand the attack have not thought through the conditions under which it fires. Walking through both the failure and the pivot teaches something about how to read kernel source for real exploitability, not just for the surface-level "is the hook there" question.

## Factual Note

The chapter I started from described intercepting `module_sig_check()`, swapping signature blobs in flight, and loading a malicious driver the kernel believed was legitimate. None of that is what this POC does, and none of it works on the kernels I tested.

The working attack is smaller. Its scope is strictly the syscall boundary. The kernel still rejects the bytes. Only userspace sees a forged return. That is a real primitive, it has a narrow but legitimate adversarial application, and it is what I can actually prove on the test kernel.

The original chapter's description conflated a working primitive (the LSM approach under specific kernel config) with a claimed outcome (loaded malicious driver) without distinguishing the setup conditions. That is the kind of over-claiming this book is trying to avoid. The honest version is: here is the approach that worked, here is the approach that did not, here is why, and here is what each one can and cannot do.
