---
layout: book
title: "Chapter 21: Skip Accounting — Primitives That Needed Another Kernel"
date: 2026-01-11
---

# Chapter 21: Skip Accounting — Primitives That Needed Another Kernel

> **See also**: [Blog post]({{ site.baseurl }}/skip-accounting.html) · [Harness](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

> **Navigation**: [Chapter 20 — Taxonomy]({{ site.baseurl }}/book/act-3/chapter-20-the-autopsy-what-we-proved.html) · [Chapter 21 — Skip Accounting]({{ site.baseurl }}/book/act-3/chapter-21-the-autopsy-what-refused-to-die.html) · [Chapter 22 — Defender Playbook]({{ site.baseurl }}/book/act-3/chapter-22-the-defender-playbook.html)

Two primitives do not produce effects on the linuxkit 6.12 aarch64 primary environment. Not because the BPF code is wrong; because the linuxkit kernel environment does not host the surface the primitive needs to grip. The shape of refusal in both cases is the same: no enforcement point is active at runtime. ch06 (BPF LSM fmod_ret on SELinux hooks) needs a running SELinux policy that linuxkit does not load; ch12 (BPF LSM fmod_ret on `kernel_read_file`) needs module-signature enforcement that linuxkit is not built with. Each is a cold case on linuxkit and a live case on the Fedora 42 aarch64 QEMU VM secondary. The goal of this chapter is to make that distinction reproducible.

## The secondary environment

The secondary test environment is a Fedora 42 aarch64 QEMU VM with BPF LSM enabled, SELinux enforcing, and module signature enforcement active. It exists precisely so that the two PoCs that cannot fire on linuxkit can still be exercised end-to-end against a real enforcement substrate. The VM is driven by two scripts in the repo: `dBPF-pocs/run-qemu-tests.sh` (host-side orchestration — builds the cidata ISO, boots QEMU with a virtio-9p share rooted at `dBPF-pocs/pocs`, collects the guest's stdout) and `dBPF-pocs/qemu-runner.sh` (guest-side per-PoC driver — mounts the 9p share, registers `confined01` / `staff01` SELinux logins, runs each PoC's trigger and greps for `_PROVEN` / `_SKIP` markers). Across the two environments combined, all 20 registered PoCs demonstrate.

## Why honest negatives matter

A catalog that claims every primitive fires on every kernel it was tested against is either running against a kernel built to host the catalog, or it is hiding the cases that did not fire. Neither is useful to a reader trying to predict what will happen on their own kernel.

The test bed for this book is a single kernel image — `6.12.54-linuxkit` on aarch64, running inside Docker Desktop on Apple Silicon. That kernel has a specific set of `CONFIG_*` flags, a specific BTF contents, a specific LSM stack order, and a specific error-injection allowlist. Every decision the kernel's build system made about what to include or omit is visible as an attach success or failure when a BPF program tries to gain purchase on a particular hook. The kernel is not pathological — it is a shipping image used by a widely-deployed developer tool. But its build choices are not the same as a RHEL production kernel's, or a hardened embedded kernel's, or a research kernel compiled with every debug option. Each of those kernels would produce a different skip list for the same set of primitives.

Eighteen of twenty registered primitives produced before/after markers on linuxkit; the other two fire on the Fedora 42 aarch64 QEMU VM secondary environment. The two linuxkit-cold cases are not bugs in the BPF code; the attach paths in question require environmental preconditions that linuxkit does not meet (SELinux enforcing policy; module signature enforcement). Describing those preconditions honestly is the credibility anchor for the other eighteen. The rule is: every primitive in this book has a named environment it fires in and, where applicable, a named environment it refuses in. Chapters 20 and 21 together enumerate both sides of that ledger.

Overclaiming 20/20 on a single kernel would be a benchmark against the benchmark. It would tell a reader nothing about their own environment. The interesting question is not "does the primitive work?" — BPF is a computational substrate; of course a correctly-typed program can be loaded and attached on the kernel it was written for. The interesting question is "which surfaces of my kernel are live, and which are not?" The two cold cases in this chapter (and the kernel-configuration axes that disarm them) are points on that surface.

There is also a practical asymmetry. Red teams that encounter a cold case in the field often misdiagnose it as "the kernel is patched" or "the primitive doesn't work anymore," when in fact the surface is simply absent on this build. Blue teams that read only the proven-primitives list misjudge their own exposure, because they assume the attacker's catalog matches their kernel. Both misreads dissolve when the skip list is explicit about which axis silenced each primitive.

Academic literature on BPF-based offensive capability suffers particularly from the first misread. A paper demonstrates a primitive on a kernel where the author verified every precondition, publishes results, and readers transplant the assumption that the primitive generalizes. It does not. The author's kernel is a point in a high-dimensional configuration space; neighboring points disarm the primitive along one or more axes. This chapter's purpose is to make the configuration dependence legible: for each cold case, the exact environmental precondition that is absent and the exact Fedora QEMU environment in which it fires. Readers reproducing the book on their own kernels can then match their environment to the four-axis model (below) and predict, before running any code, which PoCs will warm up for them.

A parallel asymmetry exists in defensive posture. Stack ranking attacker capability by primitive count mistakes the relation between a primitive and a kernel. On linuxkit, two primitives are disarmed by the build itself — the defender does not need to do anything about them. On a Fedora distro kernel with BPF LSM active, SELinux enforcing, and module signing enforced, those two come online (ch06 and ch12 in their full forms), but the four Fedora-only enforcement points may also come with their own monitoring obligations. The defender's leverage is not in counting primitives but in shrinking the four-axis surface. Chapter 22 takes that prescription and makes it concrete; this chapter establishes the empirical basis for why the four axes are the ones that matter.

## The shape of refusal

Both linuxkit skips share the same shape:

**Shape A — no enforcement point active at runtime.** The BPF program compiles, loads, and attaches successfully. The hook is wired up. No traffic reaches the hook because the surrounding kernel policy never produces the decision the program was written to flip. Members: **ch06** (no SELinux policy loaded on linuxkit; BPF LSM `fmod_ret` has nothing to flip), **ch12** (no module signature enforcement on linuxkit; `mod_verify_sig` never returns a denial to override). Count: 2.

Two other shapes of refusal are worth naming for completeness, even though no currently-registered PoC is a member of them on linuxkit:

**Shape B — BTF or hook symbol missing at load time.** The attach fails before any traffic is considered. libbpf tries to resolve a kernel type or symbol the program references; the resolution returns `-ENOENT` or the verifier produces a type-match error. This shape historically affected ch08's LSM variant (forward-declared `struct key` in the LSM hook's BTF); the registered ch08 and ch08k PoCs now both use kprobe attachments against `key_task_permission` where the full `struct key` is available via vmlinux.h, so neither hits Shape B.

**Shape C — target subsystem absent from this kernel build.** The entire subsystem the primitive hooks is compiled out. No symbols, no sysfs interface, no call sites. Earlier drafts of this book registered aarch64-incompatible PoCs (powercap/RAPL, ACPI) that fell under this shape; those were retired from the harness in the cleanup that produced the current 20-PoC manifest, because a PoC that cannot fire on either the primary or the secondary environment was adding noise, not signal.

Shape A is orthogonal to Shapes B and C. A different kernel could move the same primitive between shapes, but on linuxkit versus Fedora QEMU the axis that matters is runtime enforcement-point activity, and both linuxkit skips live there.

**Diagnosing the shape.** The shape is determined by where in the pipeline the refusal occurs. Shape B refusals produce libbpf errors at `bpf_object__load()` time, before any program runs. Shape A refusals produce successful loads and successful attaches but silent ringbuf queues — no events arrive because no kernel decision routes through the hook. Shape C refusals produce errors at the attach step, when libbpf queries kallsyms for the target symbol and finds nothing. The error messages are distinguishable:

- Shape B: `libbpf: failed to find kernel BTF type ID of '<name>': -3`, or verifier messages like `arg0 type FWD is not a struct`.
- Shape A: no error; the program runs, ringbuf is empty, the trigger's BEFORE and AFTER look identical.
- Shape C: `libbpf: failed to determine kernel function '<name>' location: -ENOENT`, or kretprobe attach failures citing no matching symbol.

A researcher encountering a cold case on their own kernel should first match the observed error against these signatures, which determines the shape, which in turn determines the pivot. Shape B pivots are usually kprobe (if a non-FWD caller exists) or a different BTF target — as the ch08/ch08k kprobe-on-`key_task_permission` choice demonstrates. Shape A pivots are to move the PoC to an environment where the enforcement point is live — in this book, the Fedora 42 QEMU VM. Shape C pivots require either a different architecture or a different subsystem entirely, which is why the previously-registered aarch64-incompatible PoCs were retired rather than kept with synthetic workarounds.

## Skip 1 — Chapter 6 silencing SELinux (linuxkit)

**Claim.** A BPF LSM `fmod_ret` program attached to SELinux-bearing LSM hooks can flip a denial to an allow for a targeted process. The kernel's own AVC returns `-EACCES`; the BPF program replaces that with `0` and the caller proceeds as if the policy had granted access.

**What linuxkit refused.** The linuxkit kernel does not load any SELinux policy. Inspection of the LSM stack on the primary test kernel:

```
$ cat /sys/kernel/security/lsm
capability,bpf
```

`selinux` is not present in the stack. There is no policy, no AVC, no natural `-EACCES` return to observe or flip. The BPF program loads correctly (the `fmod_ret` attach type is accepted and `bpf` is in the LSM line), but the hook it was written to intercept either does not execute in the chain at all (because SELinux is not registered) or executes as the kernel-default no-op returning `0`. Either way, there is nothing for the flipper to flip. The program attaches to a silent wire.

**Where it fires: Fedora 42 aarch64 QEMU.** The secondary environment runs a Fedora 42 aarch64 kernel with SELinux in enforcing mode and `bpf` present in the LSM stack. `dBPF-pocs/qemu-runner.sh` registers a `confined01` login mapped to `user_u` via `semanage login -a -s user_u confined01`, which gives the login session the `user_t` SELinux domain. An unprivileged read by `confined01` of a sentinel file labeled outside `user_t`'s allowed types produces an organic AVC denial routed through the SELinux slot. The ch06 BPF LSM `fmod_ret` program, attached after `selinux` in the chain, observes the `-EACCES` the SELinux slot returned and overrides it to `0`. The read succeeds. Marker: `CH06_PROVEN hook=... flip=yes` captured by `run-qemu-tests.sh` and logged to the host's run output.

**A note on LSM stack ordering.** The `lsm=` kernel cmdline string determines the order in which LSM modules are called. The default on most distros is `lsm=landlock,lockdown,yama,integrity,apparmor,ima,bpf,evm` (Ubuntu) or similar — `bpf` sits near the end but before `evm`. For the fmod_ret override to see a SELinux denial, `selinux` must be registered *before* `bpf` in the chain, so that SELinux computes its decision first and the BPF program observes (and overrides) the resulting return value. Every mainstream distro that enables both SELinux and BPF LSM already orders them this way; the ordering would only be wrong on a custom-built kernel where someone deliberately reversed the chain.

## Skip 2 — Chapter 12 signed-driver swap (linuxkit)

**Claim.** A BPF LSM `fmod_ret` program attached to `mod_verify_sig`, `kernel_read_file`, or `security_locked_down` can let an unsigned kernel module load on a signature-enforcing kernel. The signature check produces `-EBADMSG` (or equivalent); the BPF program replaces that with `0` and the caller proceeds past the gate.

**What the kernel refused.** Two distinct issues, compounded:

1. The linuxkit kernel does not enforce module signatures. `module.sig_enforce=0` and `CONFIG_MODULE_SIG_FORCE=n` in the kernel config mean `mod_verify_sig` is effectively advisory — it does not return a denial the LSM chain would see. There is no natural `-EBADMSG` for the BPF program to flip.

2. The insmod test workflow feeds a fabricated module through `finit_module(2)`. Without a valid ELF header, the module loader rejects the bytes at ELF validation *before* the signature-related LSM hooks run. The failure mode is `-ENOEXEC` ("Exec format error") from the ELF validator, not `-EBADMSG` from the signature check. The fmod_ret program on `kernel_read_file` never executes against this input.

Additionally, the symbol `mod_verify_sig` is not on `/sys/kernel/debug/error_injection/list` on this kernel, which rules out a `bpf_override_return` approach even if one wanted to bypass the LSM path entirely.

**Workaround variant (proven on this kernel).** `ch12-signed-driver-swap-syscall/` moves the override to the syscall exit point — a `kretprobe` on `__arm64_sys_finit_module` (and `__arm64_sys_init_module` for the legacy path). Both syscalls are on the error-injection allowlist, so `bpf_override_return(ctx, 0)` is permitted. The kretprobe fires on exit regardless of *why* the loader failed internally — ELF validation, signature failure, symbol resolution, anything — and rewrites the syscall return value before userspace regains control.

This is an *illusion* bypass in the same class as ch14 (sched_setscheduler forge) and ch18 (token forge). The kernel's actual module loader still rejects the bytes. `lsmod` shows no new module. `/proc/modules` and `/sys/module/<name>/` do not reflect a load. Only a caller that trusts the `finit_module(2)` return value as authoritative proof is fooled. Marker on success: `CH12_CONCEPT_PROVEN syscall_override_landed=yes module_actually_loaded=no`. The honest framing is explicit in the marker: the primitive lied to userspace without achieving actual module load.

The syscall variant proves a different primitive than the LSM variant would have. The LSM variant, if it fired, would flip the in-kernel gate and cause the kernel to actually progress past signature verification — the module would be constructed in kernel memory and inserted. The syscall variant rewrites only the return value; the kernel never progressed past the gate and never constructed the module. Both primitives have utility against different monitoring stacks. The LSM variant defeats kernel-state observers that check `/sys/module/`. The syscall variant defeats only userspace consumers that trust the syscall return.

**What kernel would fire the full LSM variant.** A signature-enforcing kernel (`CONFIG_MODULE_SIG_FORCE=y`, boot-time lockdown in `confidentiality` or `integrity` mode) with a real but unsigned `.ko` blob fed through `finit_module`. On such a kernel `mod_verify_sig` returns `-EBADMSG`, the LSM chain sees it, and the fmod_ret program flips it to `0`. A subsequent detection signal — the errno shift from `EBADMSG` to `ENOEXEC` if the payload then fails downstream ELF or symbol validation — proves the LSM gate was bypassed. Marker on that kernel: `CH12_PROVEN flipped=N hook=kernel_read_file baseline=EBADMSG override=ENOEXEC`.

**The errno shift as primary evidence.** Note how the full-variant marker records both the baseline errno (`EBADMSG`) and the overridden errno (`ENOEXEC`). The shift between the two is the evidence that the LSM gate fired and was flipped. If the override had not fired, the errno would remain `EBADMSG` at the signature check. If the override fired but the payload was a real signed module, the errno would become `0` and the module would actually load. The intermediate shift — from `EBADMSG` to `ENOEXEC` — is precisely the signature that the *gate* was bypassed but the payload still failed downstream validation. This is the cleanest possible evidence for an LSM override: two distinct failure modes, distinguished by errno, separated by whether the bypass fired.

The syscall variant on this kernel does not have access to that evidence. It rewrites the final syscall return to `0`, regardless of which internal stage failed. The ringbuf event records the original return value (`orig_ret=-8` for `-ENOEXEC` on the ELF validation path; it would be `orig_ret=-74` for `-EBADMSG` on a sig-enforcing kernel hitting the signature path), so a careful reader can tell which internal rejection happened. But the userspace caller sees only `0`, and a detection mechanism that checks `/sys/module/<name>/` after the call will catch the forgery immediately. The two variants are therefore not substitutes but complements — the LSM variant defeats kernel-state observers, the syscall variant defeats naive userspace consumers.

## Skip 4 — Chapter 13 powercap override

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

**Why the analog exists.** It would have been possible to emit `CH13_SKIP` and leave the chapter without any positive result. The reason for the analog is that the *primitive* the chapter describes — "a BPF program rewrites a kernel-mediated value as it crosses into userspace" — is independent of the specific subsystem. RAPL is one instance; any sysfs-exposed sensor reader is another. Proving the primitive on a surface that exists makes the chapter's claim legible even to readers whose kernels do not have RAPL. The disclaimer in the analog's marker is the explicit acknowledgement that the RAPL-specific path was not exercised; readers should not count the analog as evidence for or against any claim about RAPL itself, only as evidence that the underlying primitive shape (Class II userspace buffer rewrite) is live on this kernel.

This is a small methodological point but it matters for the book's overall honesty. Every skip in this chapter is paired with either a workaround variant that proves a related primitive (ch06, ch07, ch13, ch17) or a pivot variant that proves a different primitive of comparable utility (ch08 kprobe, ch12 syscall). No skip is left without a positive counterpart. The counterparts are not substitutes for the originals — they prove different things, against different surfaces, with different detection signatures — but they ensure the chapter documents what the primitive *shape* can and cannot do on this kernel, not just what the specific attach path cannot do.

## Skip 5 — Chapter 17 ACPI WSMI ping

**Claim.** A kprobe on `acpi_evaluate_object` observes ACPI method invocations and, with `bpf_override_return` on `acpi_ps_execute_method`, rewrites the path argument or the return value of an ACPI ping in flight. The primitive demonstrates kernel-mediated string substitution against WMI / WSMI firmware interfaces used by laptop platform drivers.

**What the kernel refused.** aarch64 linuxkit has no ACPI interpreter. None of the target symbols exist in `/proc/kallsyms`:

```
[acpi] === symbol availability ===
  acpi_evaluate_object       : ABSENT
  acpi_ns_evaluate           : ABSENT
  acpi_ps_execute_method     : ABSENT
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

The marker recorded by the analog is `ACPI_PROBE_PROVEN arch=aarch64 substituted=firmware_loader`. The `substituted=` field is the honest disclosure: it records that the kernel's ACPI interpreter was not exercised, that the `firmware_loader` path stood in for it, and that the primitive reader should weigh the result accordingly. The kprobes-on-firmware path had no natural traffic, so the analog's userspace `fw_requester` provides the traffic explicitly — it is not observing an organic firmware request, it is simulating one. This is a deliberate choice: proving "kernel-mediated string rewrite is feasible when traffic exists" is cleaner than waiting for organic traffic that may never arrive.

**What kernel would fire the full variant.** Any x86 host with ACPI interpreter active — which is essentially every laptop, desktop, and x86 server in production use. Platform drivers on Dell, HP, Lenovo, and ThinkPad systems routinely evaluate ACPI methods for WMI pings (battery state, thermal sensors, lid state, keyboard backlight, fan control, firmware update triggers). On such a host the kprobe attaches at `acpi_evaluate_object`, observes the path strings, and can optionally override the return value to forge a ping response. The x86-specific marker is `ACPI_PROBE_PROVEN arch=x86_64 substituted=none`.

**The two-layer refusal.** ch17 is the only skip in this chapter with a two-layer refusal, worth examining briefly. Layer one (ACPI symbols absent) is pure Shape C — the subsystem is not in the kernel, no attach is possible, the chapter could have stopped there. Layer two (firmware-loader symbols present but cold) is Shape A — the target hook exists in the kernel, the attach succeeds, but no caller produces traffic. A linuxkit image loaded with `test_firmware` and an actual driver that calls `request_firmware` would have produced warm probes; the absence of both means the probes attach but observe nothing.

The layered structure is informative for defenders. Removing a subsystem (Shape C) is a more aggressive hardening than removing the traffic that drives a subsystem (Shape A) — the former requires a kernel rebuild, the latter requires only controlling which drivers are loaded. Many production kernels take the latter path: `request_firmware` is compiled in because *some* driver needs it, but the specific drivers that call it at runtime are a deployment choice. A minimal container image that loads no firmware-requesting drivers has a cold Shape-A surface at `request_firmware` even on a kernel that compiles the symbol. ch17's attachment to the cold surface on linuxkit reproduces exactly that defender posture, without needing to strip the symbol itself.

## The pattern, restated

Six skips, three shapes, two members each:

- **Shape A (no enforcement point active):** ch06, ch12-lsm. The hook loads and attaches; nothing produces the decision the program was written to flip.
- **Shape B (BTF or hook symbol missing):** ch08-lsm. The BPF program fails to load because the kernel's BTF does not expose the type or function the program references. (ch07's LSM variant hits the same shape on its `dev_open` target but is not a counted skip because the registered PoC pivots to a synthetic path that demonstrates.)
- **Shape C (target subsystem absent):** ch13, ch17. The entire subsystem is compiled out; no call sites, no traffic, no attach.

The honest takeaway: the test kernel's environment disarmed five primitives along three different axes. A different kernel would disarm different ones. Any sufficiently hardened kernel — one stripped of BTF, configured without BPF LSM, compiled without error-injection, and missing the subsystems each primitive targets — would disarm many more. Conversely, a maximally-permissive research kernel with full BTF, all LSMs stacked, every syscall allowlisted for error-injection, and every subsystem compiled in, would host more primitives than this book documents. There is no single kernel on which all twenty-five primitives fire, because the surfaces are not independent — enabling one sometimes precludes another (for example, some `CONFIG_DEBUG_*` options are incompatible with certain hardened builds).

The ledger for this book is therefore: twenty primitives fire on 6.12 linuxkit aarch64, five do not. Each of the five has a named kernel it fires on, documented per-skip above. The distinction between "works" and "does not work" is not a property of the primitive alone — it is a relation between the primitive and a specific kernel build.

**Transposing the relation.** A useful exercise for a reader reproducing this work: take the four axes and construct the hypothetical kernel on which the most primitives would fire, and the one on which the fewest would fire.

Maximum-fire kernel: x86_64, `CONFIG_BPF_LSM=y`, `lsm=capability,selinux,apparmor,lockdown,bpf,integrity,evm` with SELinux in enforcing mode, `CONFIG_MODULE_SIG_FORCE=y`, `CONFIG_X86_INTEL_RAPL=y`, `CONFIG_ACPI=y`, `CONFIG_DEBUG_INFO_BTF=y` with `pahole --btf_gen_all`, `CONFIG_FUNCTION_ERROR_INJECTION=y`, loaded drivers that exercise `request_firmware`, and an active cgroup-v2 devices enforcement policy. On this hypothetical kernel, all five cold cases go warm, and the primitive count grows from twenty to twenty-five. This is not a kernel anyone ships in production — it is a research maximum, a strawman for the upper bound of attacker capability.

Minimum-fire kernel: aarch64 embedded build, `CONFIG_BPF_LSM=n`, `CONFIG_DEBUG_INFO_BTF=n`, `CONFIG_FUNCTION_ERROR_INJECTION=n`, no ACPI, no powercap, no `test_firmware`, no loaded LSM modules beyond `capability`, and `CAP_BPF` disabled for all unprivileged users. On this kernel, Class I return-value overrides are entirely absent (no `bpf_override_return` targets, no LSM fmod_ret). Class III ringbuf exfiltration remains only for privileged root processes, which is not a meaningful threat model. The primitive count approaches zero. This also is not a kernel most deployments can ship — BPF is too useful for observability, CO-RE too useful for portability, LSM too useful for workload isolation — but it is the strawman for the lower bound of attacker capability.

Real production kernels sit between the two strawmen. The skip list for any given kernel is a function of which axes that kernel tightened and which it left open. A Fedora workstation kernel fires more primitives than linuxkit (it has ACPI, RAPL, full BTF) and fewer than the research maximum (it does not force module signatures, it does not register all LSMs). An Amazon Linux 2023 kernel fires differently still. The exercise of constructing the skip list for *your* kernel is the pre-flight that Chapter 20 introduced and Chapter 22 operationalizes.

## For red-team readers

Environmental pre-flight is mandatory. Before claiming a primitive works on a target, scan four axes:

1. **`/proc/kallsyms`** for every function symbol the program attaches to. Missing symbols mean the subsystem is not compiled in. `grep -E '^[0-9a-f]+ [tT] (symbol_name)' /proc/kallsyms`. If the symbol is absent, no attach is possible regardless of BTF, LSM stack, or error-injection state.

2. **`/sys/kernel/security/lsm`** for the active LSM stack. If `bpf` is absent, no fmod_ret is possible. If `selinux` / `apparmor` / `lockdown` is absent, those LSMs' hooks never produce decisions for a BPF program to flip. The order of the stack matters too — `capability` first means capability-based denials short-circuit before the BPF slot.

3. **`/sys/kernel/debug/error_injection/list`** for `bpf_override_return` targets. If the target is not on this list, the override is rejected at verifier time. `__arm64_sys_finit_module` being on the list is what enables ch12's syscall variant on linuxkit; it would be absent on a kernel compiled without `CONFIG_FUNCTION_ERROR_INJECTION`.

4. **BTF visibility** for every struct the program dereferences. `bpftool btf dump file /sys/kernel/btf/vmlinux format raw | grep -w 'struct key'` tells you whether `struct key` is fully defined or forward-declared in the BTF the kernel exports. A FWD in the LSM hook's function signature disarms fmod_ret against that hook — switch to kprobe/fentry against a function that imports the full type.

Any of those four axes can silently disarm a primitive. The BPF program will load, the attach will succeed, and the trigger will print nothing interesting — which is worse than a loud failure, because it looks like the kernel is immune when it is only uncooperative to this specific attach path. Mistaking "no output" for "the primitive doesn't work anymore" is a common field misdiagnosis; the correct read is usually "this axis is cold here, pivot the attach."

**Pre-flight as an artifact.** A disciplined pre-flight produces a written artifact — a record of what was checked, what was found, and what was concluded. For each of the four axes, the pre-flight records the exact probe command and its output. Example:

```
Axis 1 — kallsyms coverage:
  $ grep -c powercap /proc/kallsyms
  0                                     → Shape C, powercap subsystem absent
  $ grep -c bpf_lsm /proc/kallsyms
  187                                   → BPF LSM present, subset enumerated below

Axis 2 — LSM stack:
  $ cat /sys/kernel/security/lsm
  capability,bpf                        → bpf present, selinux absent → ch06 cold

Axis 3 — error injection:
  $ cat /sys/kernel/debug/error_injection/list | wc -l
  47
  $ grep __arm64_sys_finit_module /sys/kernel/debug/error_injection/list
  __arm64_sys_finit_module              → ch12 syscall variant warm

Axis 4 — BTF completeness:
  $ bpftool btf dump file /sys/kernel/btf/vmlinux format raw | grep -w bpf_lsm_dev_open
  (empty)                               → ch07-lsm dev_open disarmed
  $ bpftool btf dump file /sys/kernel/btf/vmlinux format raw | grep "FWD 'key'"
  [12345] FWD 'key' fwd_kind=struct     → ch08-lsm disarmed
```

This artifact makes a result portable. Another researcher reproducing the work on a different kernel can match their pre-flight output against the record and predict, before running any BPF code, which primitives will fire. An incident responder investigating a suspected kernel-level attack can check the artifact against the target host's axes and narrow the attacker's plausible primitive set. The pre-flight is a half-day exercise; the payoff is that every claim downstream of it is environment-grounded.

**Versioning by axis, not by kernel release.** It is tempting to identify a kernel by its version string and attribute primitives to it directly — "this primitive works on 6.12, does not work on 6.6, is mitigated in 6.14." That framing is wrong for BPF. The kernel version string captures which source tree the kernel came from, but not which build options the distro applied. Two kernels with the same version string can differ wildly along all four axes: one distro ships with full BTF, another without; one enforces module signatures, another does not. The relevant version for a pre-flight is the build-option tuple, not the release number. Phrasing results as "this primitive works on kernels with axes (BPF LSM active, `selinux` in stack, full BTF)" is portable across kernel versions in a way that "this primitive works on 6.12" is not.

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

**Hardening composability.** A hardening technique is composable if applying it does not require changing any other decision about the kernel. `CONFIG_FUNCTION_ERROR_INJECTION=n` is composable: removing it disables `bpf_override_return` entirely without affecting any other kernel feature. `CONFIG_BPF_LSM=n` is composable: removing it disables fmod_ret entirely, at the cost of any BPF-LSM-based workload tooling (which most deployments do not have). Stripping BTF is partially composable: it disables CO-RE, which some monitoring stacks (`bcc`, `bpftrace`) rely on, so the decision to strip BTF is coupled to the decision to not run those tools.

A defender's hardening budget should be spent on the most composable axes first. `CONFIG_FUNCTION_ERROR_INJECTION=n` costs almost nothing on a production kernel (error injection is a test feature) and removes an entire primitive class. Deregistering `bpf` from the LSM cmdline costs nothing if no workload needs BPF LSM and removes another primitive class. These are high-leverage, low-cost decisions and should be taken first. BTF stripping is higher-cost because it affects observability tooling; it is worth only on kernels where observability is handled out-of-kernel (sidecar telemetry, USDT, eBPF-free profilers) or not at all (stripped embedded builds).

**Monitoring `bpf()` enrollments.** A point not often emphasized in hardening guides: every primitive in this book requires a preceding `bpf(BPF_PROG_LOAD)` syscall and one or more `bpf(BPF_LINK_CREATE)` or `bpf(BPF_RAW_TRACEPOINT_OPEN)` attach syscalls. Those syscalls are observable. The `audit` subsystem can be configured to log every `bpf()` call with its program type, attach type, and target function name. On a production kernel where BPF is used only for observability (ingress XDP, cgroup skb, socket filter) and not for LSM fmod_ret or syscall tracing, any enrollment of `BPF_PROG_TYPE_LSM` or `BPF_PROG_TYPE_KPROBE` with `BPF_TRACE_ITER` or `BPF_MODIFY_RETURN` is a high-signal anomaly. A defender who audits `bpf()` syscalls catches the primitive before it fires — the BPF load itself is the first observable action in the chain.

Combine this with controlling who holds `CAP_BPF` and `CAP_SYS_ADMIN`. Unprivileged BPF is off on most modern distros (`kernel.unprivileged_bpf_disabled=2`). Privileged BPF still requires a process with the right capabilities, which a well-configured host grants to only a handful of daemons. Monitoring those daemons' `bpf()` enrollments is tractable. Any enrollment outside the expected set is a red flag.

## Onward

Chapter 22 is the full defender playbook, ordered from highest-leverage to lowest. It takes the four-axis model above and turns it into concrete `CONFIG_*` flags, boot-cmdline changes, and monitoring hooks. The skip list in this chapter is a diagnostic; Chapter 22 is the prescription.

The reader leaving this chapter should carry three things forward. First, a four-axis mental model: every BPF-based primitive lives in the intersection of hook availability, enforcement-point activity, BTF completeness, and subsystem presence. Second, a pre-flight protocol: before claiming any primitive fires or does not fire, enumerate the four axes on the target kernel and record the result. Third, a disposition of honest negatives: six cold cases on one kernel are not a weakness of the catalog but a feature of the documentation. A catalog that admits its failures against a specific environment is one whose successes against that environment can be trusted.
