---
layout: book
title: "Chapter 21: Skip Accounting — Primitives That Needed Another Kernel"
date: 2026-01-11
---

# Chapter 21: Skip Accounting — Primitives That Needed Another Kernel

> **See also**: [Blog post]({{ site.baseurl }}/skip-accounting.html) · [Harness](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

> **Navigation**: [Chapter 20 — Taxonomy]({{ site.baseurl }}/book/act-3/chapter-20-the-autopsy-what-we-proved.html) · [Chapter 21 — Skip Accounting]({{ site.baseurl }}/book/act-3/chapter-21-the-autopsy-what-refused-to-die.html) · [Chapter 22 — Defender Playbook]({{ site.baseurl }}/book/act-3/chapter-22-the-defender-playbook.html)

Six primitives did not produce effects on linuxkit 6.12 aarch64. Not because the BPF code was wrong; because the kernel environment did not host the surface the primitive needed to grip. There are three shapes of refusal in play: (a) no enforcement point was active at runtime, (b) BTF or the hook's target symbol was missing, (c) the target subsystem was absent from this kernel build. Each of the six is a cold case on this kernel and a live case on someone else's. The goal of this chapter is to make that distinction reproducible.

## Why honest negatives matter

A catalog that claims every primitive fires on every kernel it was tested against is either running against a kernel built to host the catalog, or it is hiding the cases that did not fire. Neither is useful to a reader trying to predict what will happen on their own kernel.

The test bed for this book is a single kernel image — `6.12.54-linuxkit` on aarch64, running inside Docker Desktop on Apple Silicon. That kernel has a specific set of `CONFIG_*` flags, a specific BTF contents, a specific LSM stack order, and a specific error-injection allowlist. Every decision the kernel's build system made about what to include or omit is visible as an attach success or failure when a BPF program tries to gain purchase on a particular hook.

Nineteen of twenty-five primitives in this book produced before/after markers on this kernel. Six did not. The six that did not are not bugs in the BPF code; the attach paths in question require environmental preconditions that this kernel does not meet. Describing those preconditions honestly is the credibility anchor for the other thirteen. The rule is: every primitive in this book has a named kernel it fires on and a named kernel it refuses on. Chapters 20 and 21 together enumerate both sides of that ledger.

Overclaiming 25/25 on a test kernel built to host the primitives would be a benchmark against the benchmark. It would tell a reader nothing about their own environment. The interesting question is not "does the primitive work?" — BPF is a computational substrate; of course a correctly-typed program can be loaded and attached on the kernel it was written for. The interesting question is "which surfaces of my kernel are live, and which are not?" The six cold cases in this chapter are six axes along which that question separates.

There is also a practical asymmetry. Red teams that encounter a cold case in the field often misdiagnose it as "the kernel is patched" or "the primitive doesn't work anymore," when in fact the surface is simply absent on this build. Blue teams that read only the proven-primitives list misjudge their own exposure, because they assume the attacker's catalog matches their kernel. Both misreads dissolve when the skip list is explicit about which axis silenced each primitive.

## The three shapes of refusal

Sorted by the axis that disarmed the attach:

**Shape A — no enforcement point active at runtime.** The BPF program compiles, loads, and attaches successfully. The hook is wired up. No traffic reaches the hook because the surrounding kernel policy never produces the decision the program was written to flip. Members: **ch06** (no SELinux policy loaded; BPF LSM `fmod_ret` has nothing to flip), **ch12-lsm** (no module signature enforcement; `mod_verify_sig` never returns a denial to override). Count: 2.

**Shape B — BTF or hook symbol missing at load time.** The attach fails before any traffic is considered. libbpf tries to resolve a kernel type or symbol the program references; the resolution returns `-ENOENT` or the verifier produces a type-match error. The program never gets to observe a single hook invocation. Members: **ch07-lsm** (`bpf_lsm_dev_open` FUNC absent from kernel BTF), **ch08-lsm** (`struct key` forward-declared in the LSM function signature's BTF; verifier refuses fmod_ret). Count: 2.

**Shape C — target subsystem absent from this kernel build.** The entire subsystem the primitive hooks is compiled out. No symbols, no sysfs interface, no call sites. The hook target is not findable in `/proc/kallsyms`; no attach is possible. Members: **ch13** (`CONFIG_POWERCAP=n` on aarch64 linuxkit; Intel RAPL is x86-only), **ch17** (no ACPI interpreter on aarch64; pivoted target `request_firmware` exists but no drivers call it at runtime). Count: 2.

The three shapes are orthogonal. A different kernel could move the same primitive between shapes — for instance, a full-BTF kernel moves ch07-lsm out of Shape B, and an enforcing-SELinux kernel moves ch06 out of Shape A. What stays fixed is that every primitive has a surface it needs, and every kernel makes its own choices about which surfaces to host. Pre-flight for BPF-based work is the practice of enumerating those choices before claiming a result.

## Skip 1 — Chapter 6 silencing SELinux

**Claim.** A BPF LSM `fmod_ret` program attached to `selinux_file_permission` (or any SELinux-bearing LSM hook) can flip a denial to an allow for a targeted process. The kernel's own AVC returns `-EACCES`; the BPF program replaces that with `0` and the caller proceeds as if the policy had granted access.

**What the kernel refused.** The linuxkit kernel does not load any SELinux policy. Inspection of the LSM stack on the test kernel:

```
$ cat /sys/kernel/security/lsm
capability,bpf
```

`selinux` is not present in the stack. There is no policy, no AVC, no natural `-EACCES` return to observe or flip. The BPF program loads correctly (the `fmod_ret` attach type is accepted and `bpf` is in the LSM line), but the hook it was written to intercept either does not execute in the chain at all (because SELinux is not registered) or executes as the kernel-default no-op returning `0`. Either way, there is nothing for the flipper to flip. The program attaches to a silent wire.

**Workaround variant (proven on this kernel).** `ch06-silence-selinux-lsm-synthetic/` establishes the primitive end-to-end using a single sleepable `lsm.s/file_open` program driven by a stage-control map. The program implements both halves of the attack on its own terms: in `STAGE_DENY` it synthesizes the `-EACCES` that SELinux would have returned; in `STAGE_FLIP` it matches the same sentinel and returns `0`. A single program is used rather than two because LSM `fmod_ret` hooks short-circuit at the first non-zero return — a standalone "denier" program would prevent a sibling "flipper" program from ever executing on the same hook. The map toggle models the same attacker capability (deny-then-flip) while respecting LSM chaining semantics.

The trigger procedure exercises three stages:

1. `STAGE_OFF` baseline: unprivileged `cat` of the sentinel file succeeds (`rc=0`).
2. `STAGE_DENY` after `SIGUSR1`: the synthetic denier returns `-EACCES` for (target_uid, sentinel path) — `cat` fails (`rc=1`, `EACCES`). This proves the primitive that a BPF LSM program can inject a denial where the kernel would have granted.
3. `STAGE_FLIP` after `SIGUSR2`: the flipper matches the same (uid, path) and returns `0` — `cat` succeeds. This proves the primitive that a BPF LSM program can override a denial that exists in the hook chain.

Marker on success: `CH06_CONCEPT_PROVEN denial_injected=yes flip_applied=yes`.

The synthetic variant does not claim the kernel's SELinux AVC was flipped — there is no AVC on this kernel. It claims that the fmod_ret mechanism itself works as designed, and that a sufficiently privileged BPF program holding `CAP_SYS_ADMIN` can both introduce and remove permission decisions at the LSM slot.

**What kernel would fire the full variant.** Any distro kernel with SELinux in enforcing mode and `bpf` present in the LSM stack: RHEL 9, Fedora 38+ with `lsm=...,bpf,...` added to GRUB, Amazon Linux 2023, hardened Android builds. On those kernels the natural AVC path produces organic denials for an unprivileged user attempting to read a file labeled outside its domain, and the fmod_ret program flips those denials directly without needing a synthetic denier. The marker on the full variant is `CH06_PROVEN flipped=N`.

## Skip 2 — Chapter 7 device-cgroup Houdini

**Claim.** A BPF LSM `fmod_ret` program attached to `dev_open` / `inode_mknod` / `file_open` can flip device-cgroup denials, letting a container that should not be able to open `/dev/sda` succeed. The hooks collectively cover the path by which the kernel's device-gate produces a `-EPERM`.

**What the kernel refused.** The first attempt targeted `dev_open` directly. libbpf refused to resolve the attach target in kernel BTF:

```
libbpf: failed to find kernel BTF type ID of 'dev_open': -3
```

The `bpf_lsm_dev_open` FUNC is absent from `/sys/kernel/btf/vmlinux` on linuxkit 6.12 aarch64. The linuxkit kernel's BTF includes `bpf_lsm_inode_mknod` and `bpf_lsm_file_open` but not `bpf_lsm_dev_open` — a direct consequence of which LSM hooks the kernel config chose to make BPF-attachable. `bpftool btf dump file /sys/kernel/btf/vmlinux format raw | grep bpf_lsm_` enumerates the set; the missing name is evidence, not a bug.

The loader (`ch07-devcgroup-houdini-lsm/ch07-devcgroup-houdini-lsm.c`) consults vmlinux BTF before attach and calls `bpf_program__set_autoload(prog, false)` on any program whose `bpf_lsm_<hook>` FUNC is absent. Without that prune step the entire skeleton load fails with the message above. With it, `inode_mknod` and `file_open` attach; `dev_open` is quietly skipped. Loader stderr on a proof run:

```
[ch07] BPF LSM is active — proceeding
[ch07] keep hook=inode_mknod (BTF FUNC bpf_lsm_inode_mknod present)
[ch07] keep hook=file_open   (BTF FUNC bpf_lsm_file_open present)
[ch07] prune hook=dev_open reason="no BTF FUNC bpf_lsm_dev_open"
[ch07] attached lsm.s/inode_mknod
[ch07] attached lsm.s/file_open
```

There is also a structural reason why a natural device-cgroup denial will not route through the BPF LSM slot on a mainstream distro even when all three hooks are present. `fs/namei.c::do_mknodat()` calls `capable(CAP_MKNOD)` before invoking the LSM chain via `security_inode_mknod()`. The `capability` module is registered first in the LSM chain on every mainstream distro; `bpf` is registered last. A capability-based denial returns `-EPERM` from the `capability` slot before the BPF LSM program is ever reached. The BPF program cannot flip a denial it never sees.

**Workaround variant (proven on this kernel).** `ch07-devcgroup-houdini-lsm/` uses the same synthetic deny-and-flip pattern as ch06: a single sleepable LSM program with a stage-control map that introduces its own denial in `STAGE_DENY` and then removes it in `STAGE_FLIP`. The primitive being proven is "a BPF LSM program can deny or allow a device operation at the outer `inode_mknod`/`file_open` hook" — the chain-ordering and missing-hook issues that disarm the natural path are sidestepped by synthesizing the denial inside BPF itself.

Marker on success: `CH07_CONCEPT_PROVEN before_rc=N after_rc=0 flips=M`.

**What kernel would fire the full variant.** A kernel compiled with full LSM BTF coverage (including `bpf_lsm_dev_open`) and an active cgroup-v2 devices BPF program providing a real `-EPERM` for the target device. On Fedora or RHEL with cgroup-v2 devices enforcement, an unprivileged container's attempt to `mknod /dev/sda b 8 0` or `open("/dev/sda")` produces a natural denial routed through the LSM chain. The flipper replaces that return value at the fmod_ret slot; the container proceeds as if the device-cgroup had permitted the operation.

## Skip 3 — Chapter 8 keyring heist (LSM variant)

**Claim.** A BPF LSM `fmod_ret` program attached to `security_key_permission` (via `SEC("lsm.s/key_permission")`) can flip a denied keyring access into a permitted one. The kernel's keyring subsystem computes the permission bits for a `key_ref_t`, rejects the access with `-EACCES`, and the BPF program replaces that with `0` before the caller regains control.

**What the kernel refused.** The verifier refuses the program at load time:

```
arg0 type FWD is not a struct
```

`key_ref_t` is a pointer to `struct key` with the low two bits reserved for possession flags. The BPF program's first argument is typed as `key_ref_t`, which decays to `struct key *` after masking. The verifier type-checks fmod_ret program arguments against the BTF of the LSM function signature — and on linuxkit 6.12 aarch64, the BTF for `security_key_permission` forward-declares `struct key` (BTF kind `FWD`) rather than defining it. The verifier cannot type-check field access against a forward declaration, so it refuses the program.

The underlying cause is a BTF-deduplication artifact. `struct key` is fully defined elsewhere in vmlinux (it lives in `security/keys/internal.h` and related headers) and `vmlinux.h` generated by `bpftool btf dump file /sys/kernel/btf/vmlinux format c` includes the full definition. But the BTF metadata for the specific LSM hook's parameter carries only the FWD reference, because the dedup pass collapsed the parameter's type to its forward declaration when the full definition was not needed by the hook's own call sites. Distro kernels that compile BTF with `pahole --btf_gen_all` or equivalent options resolve the FWDs; linuxkit does not.

**Workaround variant (proven on this kernel).** `ch08-keyring-heist-kprobe/` attaches as a kprobe on `key_task_permission` rather than as an LSM fmod_ret. Kprobe programs take `struct pt_regs *` as their context and pull the first argument out via `PT_REGS_PARM1` as an opaque `u64`. CO-RE field access (`BPF_CORE_READ(key, serial)`, `BPF_CORE_READ_STR_INTO(&type_name, key, type, name)`) is then resolved against `vmlinux.h`'s full definition of `struct key`, which is complete — the FWD typing only affected the LSM function signature's argument, not the struct itself.

The kprobe variant reads the same kernel state as the LSM variant would have — key serial, key type name, key description — and emits it via ringbuf. It is Class III (ringbuf exfiltration), not Class I (return-value override), because kprobes on `key_task_permission` cannot call `bpf_override_return` on this kernel (the symbol is not on the error-injection allowlist). The primitive demonstrated is observation at the decision site, not modification.

**The structural observation.** BTF type completeness is evaluated per program-type. LSM fmod_ret programs require the BTF argument to be a full struct definition for typed field access to verify. Kprobe programs take opaque registers and resolve types through CO-RE against the consuming program's own vmlinux.h copy. The same kernel state is reachable through both program types; the BTF requirements differ. On a kernel where the LSM hook's BTF carries a FWD, moving the attach from LSM to kprobe (or fentry on a different function that imports the full type) sidesteps the verifier's refusal. This is a verifier-invariant detail about how type-matching works per attach class, not a statement that the keyring subsystem is secure or insecure. The kernel's decision is unchanged; what changes is which slots a BPF program can attach to.

**What kernel would fire the full LSM variant.** Any kernel compiled with full-BTF and a complete `struct key` in the BTF of `security_key_permission`'s signature. Fedora 38+, Ubuntu 24.04, RHEL 9 with `lsm=...bpf...`, and any custom-built kernel where `pahole --btf_gen_all` was run during the BTF emit step. On those kernels the fmod_ret flipper produces `CH08_PROVEN flipped=N` markers against an unprivileged keyctl access baseline of `EACCES`.

## Skip 4 — Chapter 12 signed-driver swap (LSM variant)

**Claim.** A BPF LSM `fmod_ret` program attached to `mod_verify_sig`, `kernel_read_file`, or `security_locked_down` can let an unsigned kernel module load on a signature-enforcing kernel. The signature check produces `-EBADMSG` (or equivalent); the BPF program replaces that with `0` and the caller proceeds past the gate.

**What the kernel refused.** Two distinct issues, compounded:

1. The linuxkit kernel does not enforce module signatures. `module.sig_enforce=0` and `CONFIG_MODULE_SIG_FORCE=n` in the kernel config mean `mod_verify_sig` is effectively advisory — it does not return a denial the LSM chain would see. There is no natural `-EBADMSG` for the BPF program to flip.

2. The insmod test workflow feeds a fabricated module through `finit_module(2)`. Without a valid ELF header, the module loader rejects the bytes at ELF validation *before* the signature-related LSM hooks run. The failure mode is `-ENOEXEC` ("Exec format error") from the ELF validator, not `-EBADMSG` from the signature check. The fmod_ret program on `kernel_read_file` never executes against this input.

Additionally, the symbol `mod_verify_sig` is not on `/sys/kernel/debug/error_injection/list` on this kernel, which rules out a `bpf_override_return` approach even if one wanted to bypass the LSM path entirely.

**Workaround variant (proven on this kernel).** `ch12-signed-driver-swap-syscall/` moves the override to the syscall exit point — a `kretprobe` on `__arm64_sys_finit_module` (and `__arm64_sys_init_module` for the legacy path). Both syscalls are on the error-injection allowlist, so `bpf_override_return(ctx, 0)` is permitted. The kretprobe fires on exit regardless of *why* the loader failed internally — ELF validation, signature failure, symbol resolution, anything — and rewrites the syscall return value before userspace regains control.

This is an *illusion* bypass in the same class as ch14 (sched_setscheduler forge) and ch18 (token forge). The kernel's actual module loader still rejects the bytes. `lsmod` shows no new module. `/proc/modules` and `/sys/module/<name>/` do not reflect a load. Only a caller that trusts the `finit_module(2)` return value as authoritative proof is fooled. Marker on success: `CH12_CONCEPT_PROVEN syscall_override_landed=yes module_actually_loaded=no`. The honest framing is explicit in the marker: the primitive lied to userspace without achieving actual module load.

The syscall variant proves a different primitive than the LSM variant would have. The LSM variant, if it fired, would flip the in-kernel gate and cause the kernel to actually progress past signature verification — the module would be constructed in kernel memory and inserted. The syscall variant rewrites only the return value; the kernel never progressed past the gate and never constructed the module. Both primitives have utility against different monitoring stacks. The LSM variant defeats kernel-state observers that check `/sys/module/`. The syscall variant defeats only userspace consumers that trust the syscall return.

**What kernel would fire the full LSM variant.** A signature-enforcing kernel (`CONFIG_MODULE_SIG_FORCE=y`, boot-time lockdown in `confidentiality` or `integrity` mode) with a real but unsigned `.ko` blob fed through `finit_module`. On such a kernel `mod_verify_sig` returns `-EBADMSG`, the LSM chain sees it, and the fmod_ret program flips it to `0`. A subsequent detection signal — the errno shift from `EBADMSG` to `ENOEXEC` if the payload then fails downstream ELF or symbol validation — proves the LSM gate was bypassed. Marker on that kernel: `CH12_PROVEN flipped=N hook=kernel_read_file baseline=EBADMSG override=ENOEXEC`.

## Skip 5 — Chapter 13 powercap override

**Claim.** A `kretprobe + bpf_override_return` on `powercap_get_max_power_uw` returns a fixed low value, making power-monitoring tools see the CPU as idle forever. A sibling attach on `powercap_set_max_power_uw` observes privileged writes to the cap to confirm the primitive's context.

**What the kernel refused.** The powercap subsystem is not present on this kernel. Checking `/proc/kallsyms`:

```
$ grep powercap /proc/kallsyms
(empty)
```

None of the four target symbols — `powercap_register_control_type`, `powercap_set_max_power_uw`, `powercap_get_max_power_uw`, `thermal_zone_device_update` — are in the kernel's symbol table. `CONFIG_POWERCAP=n` on aarch64 linuxkit. Intel RAPL (`CONFIG_X86_INTEL_RAPL`) is x86-only; there is no ARM equivalent in mainline, and the linuxkit build does not enable any of the optional generic powercap providers. The kprobe attach fails at the symbol-resolution step: libbpf reports "no such function" and the loader exits with `CH13_SKIP reason="no powercap/RAPL symbols in /proc/kallsyms"`.

The refusal is architectural. Even if libbpf could somehow attach a kprobe to a symbol that does not exist, no call site would ever invoke it. The kernel's compile-time decision to exclude the subsystem removes both the target and the traffic in one motion.

**Workaround variant (proven on this kernel).** `ch13-powercap-override-analog/` substitutes a userspace sensor daemon that exposes a sysfs-like interface, and a userspace reader that samples it. A BPF program attaches at the reader's syscall path, observes the read returning real values, and rewrites the returned buffer using `bpf_probe_write_user` to clamp the reported value to a static low number. This is a Class II primitive (userspace buffer rewrite) that demonstrates the *same primitive shape* as the real RAPL override — a reader sees a kernel-mediated value that does not reflect ground truth — against a surface that exists on this architecture.

The analog explicitly records the substitution. Marker on success:

```
CH13_ANALOG_PROVEN before_climb=X->Y after=Z zero_reads=N patched_events=M \
  disclaimer="same primitive as RAPL override; real RAPL is x86-only"
```

The disclaimer in the marker is not decorative. It records that the RAPL-specific primitive was not exercised on this kernel; the reader should not interpret the marker as evidence against any aarch64 powercap implementation (there isn't one), nor as a successful x86 RAPL flip (this kernel is not x86).

**What kernel would fire the full variant.** Any x86_64 kernel with `CONFIG_X86_INTEL_RAPL=y` (default on Fedora, Ubuntu, RHEL, most server distros). The target host must also have Intel RAPL MSRs readable by the kernel — generally anything Sandy Bridge or later. On such a host the kretprobe attaches at `powercap_get_max_power_uw`, overrides the return with a low value, and sysfs readers of `/sys/class/powercap/intel-rapl:0/constraint_0_power_limit_uw` see the forged value. Telemetry stacks that query RAPL for power budget enforcement see the CPU as idle and make no throttling decisions.

## Skip 6 — Chapter 17 ACPI WSMI ping

**Claim.** A kprobe on `acpi_evaluate_object` observes ACPI method invocations and, with `bpf_override_return` on `acpi_ex_execute_method`, rewrites the path argument or the return value of an ACPI ping in flight. The primitive demonstrates kernel-mediated string substitution against WMI / WSMI firmware interfaces used by laptop platform drivers.

**What the kernel refused.** aarch64 linuxkit has no ACPI interpreter. None of the target symbols exist in `/proc/kallsyms`:

```
[acpi] === symbol availability ===
  acpi_evaluate_object       : ABSENT
  acpi_ns_evaluate           : ABSENT
  acpi_ex_execute_method     : ABSENT
```

`/sys/firmware/acpi/` does not exist. `CONFIG_ACPI=n` on this kernel. ACPI is an x86 (and increasingly arm64-server) firmware interface; the Apple Silicon Docker Desktop linuxkit image does not build it. No call sites invoke the interpreter. No kprobe attach is possible.

The POC attempts an arch-appropriate fallback: the firmware-request path (`request_firmware`, `_request_firmware`, `firmware_request_nowarn`), which is the closest moral equivalent (the kernel reaching out to firmware land). Those symbols *are* present in kallsyms on this kernel:

```
  request_firmware           : present
  _request_firmware          : present
  firmware_request_nowarn    : present
```

The kprobes attach successfully. But no traffic reaches them: linuxkit does not load any driver that calls `request_firmware` at runtime, and the `test_firmware` module is not present in the image. The observer prints `attached=firmware_fallback` and `ACPI_PROBE_PROVEN arch=aarch64 substituted=firmware_loader` (proving the probe is live) but records zero invocations because no caller exists.

**Workaround variant (proven on this kernel).** `ch17-acpi-wsmi-analog/` bundles a userspace firmware-requester process (`fw_requester`) that sets its comm to `fw_requester` via `PR_SET_NAME` and issues `openat()` calls for firmware-like paths. A BPF tracepoint program on `sys_enter_openat` filters by comm, reads the userspace path argument, and rewrites it in place using `bpf_probe_write_user`. This is a Class II primitive demonstrating the same primitive shape the ACPI variant would have — a kernel-mediated string substituted in flight — against a surface that exists on this architecture.

The analog is honest about its substitution. The userspace `fw_requester` is not the real firmware loader; it is a stand-in. The primitive being proven is string rewrite at the syscall boundary, not ACPI method rewrite. Both are instances of the same Class II shape; the ACPI version requires x86 and active ACPI traffic, which this kernel has neither.

**What kernel would fire the full variant.** Any x86 host with ACPI interpreter active — which is essentially every laptop, desktop, and x86 server in production use. Platform drivers on Dell, HP, Lenovo, and ThinkPad systems routinely evaluate ACPI methods for WMI pings (battery state, thermal sensors, lid state, keyboard backlight, fan control, firmware update triggers). On such a host the kprobe attaches at `acpi_evaluate_object`, observes the path strings, and can optionally override the return value to forge a ping response. The x86-specific marker is `ACPI_PROBE_PROVEN arch=x86_64 substituted=none`.

## The pattern, restated

Six skips, three shapes, two members each:

- **Shape A (no enforcement point active):** ch06, ch12-lsm. The hook loads and attaches; nothing produces the decision the program was written to flip.
- **Shape B (BTF or hook symbol missing):** ch07-lsm, ch08-lsm. The BPF program fails to load because the kernel's BTF does not expose the type or function the program references.
- **Shape C (target subsystem absent):** ch13, ch17. The entire subsystem is compiled out; no call sites, no traffic, no attach.

The honest takeaway: the test kernel's environment disarmed six primitives along three different axes. A different kernel would disarm different ones. Any sufficiently hardened kernel — one stripped of BTF, configured without BPF LSM, compiled without error-injection, and missing the subsystems each primitive targets — would disarm many more. Conversely, a maximally-permissive research kernel with full BTF, all LSMs stacked, every syscall allowlisted for error-injection, and every subsystem compiled in, would host more primitives than this book documents. There is no single kernel on which all twenty-five primitives fire, because the surfaces are not independent — enabling one sometimes precludes another (for example, some `CONFIG_DEBUG_*` options are incompatible with certain hardened builds).

The ledger for this book is therefore: nineteen primitives fire on 6.12 linuxkit aarch64, six do not. Each of the six has a named kernel it fires on, documented per-skip above. The distinction between "works" and "does not work" is not a property of the primitive alone — it is a relation between the primitive and a specific kernel build.

## For red-team readers

Environmental pre-flight is mandatory. Before claiming a primitive works on a target, scan four axes:

1. **`/proc/kallsyms`** for every function symbol the program attaches to. Missing symbols mean the subsystem is not compiled in. `grep -E '^[0-9a-f]+ [tT] (symbol_name)' /proc/kallsyms`. If the symbol is absent, no attach is possible regardless of BTF, LSM stack, or error-injection state.

2. **`/sys/kernel/security/lsm`** for the active LSM stack. If `bpf` is absent, no fmod_ret is possible. If `selinux` / `apparmor` / `lockdown` is absent, those LSMs' hooks never produce decisions for a BPF program to flip. The order of the stack matters too — `capability` first means capability-based denials short-circuit before the BPF slot.

3. **`/sys/kernel/debug/error_injection/list`** for `bpf_override_return` targets. If the target is not on this list, the override is rejected at verifier time. `__arm64_sys_finit_module` being on the list is what enables ch12's syscall variant on linuxkit; it would be absent on a kernel compiled without `CONFIG_FUNCTION_ERROR_INJECTION`.

4. **BTF visibility** for every struct the program dereferences. `bpftool btf dump file /sys/kernel/btf/vmlinux format raw | grep -w 'struct key'` tells you whether `struct key` is fully defined or forward-declared in the BTF the kernel exports. A FWD in the LSM hook's function signature disarms fmod_ret against that hook — switch to kprobe/fentry against a function that imports the full type.

Any of those four axes can silently disarm a primitive. The BPF program will load, the attach will succeed, and the trigger will print nothing interesting — which is worse than a loud failure, because it looks like the kernel is immune when it is only uncooperative to this specific attach path. Mistaking "no output" for "the primitive doesn't work anymore" is a common field misdiagnosis; the correct read is usually "this axis is cold here, pivot the attach."

## For blue-team readers

The attack surface for BPF-based primitives is the intersection of four axes:

- hook availability (is the attach target in kallsyms / BTF?)
- enforcement-point activity (does the hook produce decisions at runtime?)
- BTF completeness (can the verifier type-check the program's argument?)
- subsystem presence (is the target compiled into this kernel at all?)

Minimizing any axis shrinks the surface independently:

- **Hook availability.** Strip BTF for production kernels that do not need CO-RE tooling: `CONFIG_DEBUG_INFO_BTF=n`. Do not ship `/sys/kernel/btf/vmlinux`. BPF programs that depend on CO-RE type resolution cannot load without it.
- **Enforcement-point activity.** Audit which LSMs the workload actually needs. Disabling BPF LSM (`CONFIG_BPF_LSM=n`) removes the entire fmod_ret attack class. Booting without `bpf` in the `lsm=` cmdline removes it at boot without rebuilding.
- **BTF completeness.** Paradoxically, for kernels that *do* need BTF, deliberately incomplete BTF (FWD decls for types in LSM hook signatures) disarms fmod_ret against those hooks. This is not a recommended hardening path — it depends on a build artifact that is hard to audit — but it is worth knowing that linuxkit's minimalist BTF is part of why ch08-lsm does not fire there.
- **Subsystem presence.** Drop x86-specific subsystems on aarch64 builds (`CONFIG_X86_INTEL_RAPL`, `CONFIG_ACPI` where not needed). Drop `test_firmware` and similar debug hooks from production images. Drop `CONFIG_FUNCTION_ERROR_INJECTION=n` on non-test kernels — this removes `bpf_override_return` as a primitive entirely, disarming all Class I overrides that do not go through BPF LSM.

Additionally: monitor `bpf()` syscall enrollments for `BPF_PROG_TYPE_LSM` and `BPF_PROG_TYPE_TRACING` attach events. A privileged process attaching fmod_ret to `security_key_permission` or `kernel_read_file` is a high-signal event; log it, alert on it. The primitives in this book cannot be used without the attacker first loading a BPF program, and the load itself is an observable action on a kernel with audit configured for the `bpf()` syscall.

The four-axis model is useful beyond the six skips in this chapter. Any claim about BPF-based offensive capability should be evaluated against all four axes simultaneously. A primitive that "works" on a benchmark kernel may fail on every axis when tested against a hardened one, and vice versa.

## Onward

Chapter 22 is the full defender playbook, ordered from highest-leverage to lowest. It takes the four-axis model above and turns it into concrete `CONFIG_*` flags, boot-cmdline changes, and monitoring hooks. The skip list in this chapter is a diagnostic; Chapter 22 is the prescription.
