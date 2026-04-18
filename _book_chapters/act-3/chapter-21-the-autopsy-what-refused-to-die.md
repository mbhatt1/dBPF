---
layout: book
title: "Chapter 21: Skip Accounting — Primitives That Needed Another Kernel"
date: 2026-01-11
---

# Chapter 21: Skip Accounting — Primitives That Needed Another Kernel

> **See also**: [Blog post]({{ site.baseurl }}/skip-accounting.html) · [Harness](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

> **Navigation**: [Chapter 20 — Taxonomy]({{ site.baseurl }}/book/act-3/chapter-20-the-autopsy-what-we-proved.html) · [Chapter 21 — Skip Accounting]({{ site.baseurl }}/book/act-3/chapter-21-the-autopsy-what-refused-to-die.html) · [Chapter 22 — Defender Playbook]({{ site.baseurl }}/book/act-3/chapter-22-the-defender-playbook.html)

Four primitives do not produce effects on the linuxkit 6.12 aarch64 primary environment. Not because the BPF code is wrong; because the linuxkit kernel environment does not host the surface the primitive needs to grip. ch06 (BPF LSM fmod_ret on SELinux hooks) needs a running SELinux policy that linuxkit does not load; ch12 (BPF LSM fmod_ret on `kernel_read_file`) needs module-signature enforcement that linuxkit is not built with. Both fire on the Fedora 42 aarch64 QEMU VM secondary. Act 4 added three more cross-boundary PoCs, two of which skip in both test environments for named reasons: ch23 (TPM unseal heist) needs a `/dev/tpm0` or `/dev/tpmrm0` that neither environment as provisioned exposes, and ch24 (bpf_token delegation) hits a Fedora-42-on-cloud-init `BPF_TOKEN_CREATE`=`EOPNOTSUPP` despite every documented precondition being satisfied. The third Act 4 PoC, ch25 (IMDS XDP harvest), fires on the Fedora QEMU VM. The goal of this chapter is to make every skip reproducible and environment-grounded.

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

**Shape C — target subsystem absent from this kernel build.** The entire subsystem the primitive hooks is compiled out. No symbols, no sysfs interface, no call sites. Earlier drafts of this book registered aarch64-incompatible PoCs (powercap/RAPL, ACPI) that fell under this shape; those were retired from the harness in the cleanup that produced the current manifest, because a PoC that cannot fire on either the primary or the secondary environment was adding noise, not signal. Act 4's ch23 (TPM unseal heist) is Shape C on both test environments — neither linuxkit nor the provisioned Fedora 42 QEMU VM exposes a `/dev/tpm0` or `/dev/tpmrm0`, so the PoC's trigger prints `CH23_SKIP reason="no /dev/tpm0 or /dev/tpmrm0"` and defers to a kernel with TPM hardware or swtpm passthrough.

**Shape D — syscall-level rejection despite passing all documented preconditions (new in Act 4).** The BPF program compiles and builds; all documented prerequisites (capability set, namespace placement, kernel version, build options) are satisfied; and still the kernel's `bpf(2)` syscall returns an error code the documented path does not predict. This is the shape Chapter 24's bpf_token delegation PoC hits on Fedora 42 aarch64 kernel 6.14 under cloud-init: `BPF_TOKEN_CREATE` returns `EOPNOTSUPP`, seven iterations of increasingly specific failure-mode chasing later, despite the server process holding `CAP_BPF`+`CAP_SYS_ADMIN` and `/proc/self/ns/user` matching pid 1's init user namespace. The C code is production-reviewed; the primitive is real on a kernel where the path is live. The Fedora-on-cloud-init observation is an environmental gap, not a mainline-kernel bug — specifically a gap in how cloud-init's early-boot userns management interacts with 6.14's bpf-token delegation path. Any kernel where `BPF_TOKEN_CREATE` returns a token fd will see ch24 fire end-to-end. Shape D is distinct from Shape A (enforcement point inactive at runtime), B (BTF or symbol missing), and C (subsystem absent) because the subsystem, the symbol, the BTF, and the policy are all present — the rejection is at the syscall layer itself.

Shape A is orthogonal to Shapes B, C, and D. A different kernel could move the same primitive between shapes, but on linuxkit versus Fedora QEMU the axis that matters for the Act 1–3 skips is runtime enforcement-point activity, for ch23 it is subsystem presence on the test substrates, and for ch24 it is the new Shape D rejection.

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

**Claim.** A BPF LSM `fmod_ret` program attached to `kernel_read_file` (with class `FIRMWARE`) can let an unsigned kernel module load on a signature-enforcing kernel. The signature check produces `-EBADMSG` (or equivalent); the BPF program replaces that with `0` and the caller proceeds past the gate.

**What linuxkit refused.** The linuxkit kernel does not enforce module signatures. `module.sig_enforce=0` and `CONFIG_MODULE_SIG_FORCE=n` in the kernel config mean `mod_verify_sig` is effectively advisory — it does not return a denial the LSM chain would see. There is no natural `-EBADMSG` for the BPF program to flip, so the hook attaches to a silent wire.

**Where it fires: Fedora 42 aarch64 QEMU.** The secondary VM boots with `module.sig_enforce=1` (and `CONFIG_MODULE_SIG_FORCE=y` in the Fedora kernel config). Feeding an unsigned but otherwise valid `.ko` blob through `finit_module(2)` produces an organic `-EBADMSG` at `kernel_read_file`'s signature check. The ch12 BPF LSM `fmod_ret` program observes that return and overrides it to `0`, letting the loader proceed past the signature gate. The `qemu-runner.sh` trigger for ch12-signed-driver-swap-lsm records both the baseline errno (`EBADMSG`) and the overridden errno (`ENOEXEC` if downstream ELF validation fails, or `0` if a real signed module is used). The errno shift is the evidence that the LSM gate fired and was flipped. Marker on the VM: `CH12_PROVEN flipped=N hook=kernel_read_file baseline=EBADMSG override=ENOEXEC`.

**The errno shift as primary evidence.** The Fedora-run marker records both the baseline errno (`EBADMSG`) and the overridden errno. The shift between the two is the evidence that the LSM gate fired and was flipped. If the override had not fired, the errno would remain `EBADMSG` at the signature check. If the override fired but the payload was a real signed module, the errno would become `0` and the module would actually load. The intermediate shift — from `EBADMSG` to `ENOEXEC` — is precisely the signature that the *gate* was bypassed but the payload still failed downstream validation. This is the cleanest possible evidence for an LSM override: two distinct failure modes, distinguished by errno, separated by whether the bypass fired.

**The syscall-level ch12s illusion (complementary).** The harness also registers `ch12s`, which moves the override from the LSM slot to the syscall exit point — a kretprobe on `__arm64_sys_finit_module`. `__arm64_sys_finit_module` is on the error-injection allowlist, so `bpf_override_return(ctx, 0)` is permitted. The kretprobe fires on exit regardless of *why* the loader failed internally — ELF validation, signature failure, symbol resolution, anything — and rewrites the syscall return value before userspace regains control. This is an *illusion* in the same class as ch14 and ch18. The kernel's actual module loader still rejects the bytes; `lsmod` shows no new module. Only a caller that trusts the `finit_module(2)` return value is fooled. Marker: `CH12_CONCEPT_PROVEN syscall_override_landed=yes module_actually_loaded=no`. The two PoCs are complements, not substitutes: ch12 (LSM, Fedora-only) defeats kernel-state observers that check `/sys/module/`; ch12s (syscall illusion, fires on linuxkit) defeats naive userspace consumers that trust the syscall return.

## The pattern, restated

Four skips, three shapes:

- **Shape A (no enforcement point active on linuxkit):** ch06, ch12. The BPF program loads and attaches cleanly; the surrounding kernel policy does not produce the decision the program was written to flip. Both fire end-to-end on the Fedora 42 aarch64 QEMU VM where the enforcement points (SELinux policy, module signature enforcement) are active.
- **Shape C (target subsystem absent from the test build):** ch23. No `/dev/tpm0` or `/dev/tpmrm0` on either linuxkit or the Fedora 42 QEMU VM as provisioned. The PoC will fire on any host with a TPM device or swtpm passthrough. This is an honest environmental gap — the primitive is real, the substrate is not present.
- **Shape D (syscall-level rejection despite all documented preconditions, Fedora-on-cloud-init only):** ch24. `BPF_TOKEN_CREATE` returns `EOPNOTSUPP` on Fedora 42 aarch64 kernel 6.14 under cloud-init, despite the server process matching pid 1's user namespace and holding the right capabilities. The PoC's C code is production-reviewed; the kernel's rejection in that specific environment is the ground truth this ledger absorbs. Shape D is a Fedora-on-cloud-init observation, not a mainline-kernel bug.

The honest takeaway: linuxkit's minimalist build disarms two primitives along a single axis (runtime enforcement-point activity). Act 4 added two more skips from a different direction — hardware substrate presence (ch23) and syscall-layer rejection under a specific distro/init configuration (ch24). The ledger for this book is therefore: 18 primitives fire on 6.12 linuxkit aarch64, 3 primitives fire on the Fedora 42 aarch64 QEMU VM (ch06, ch12, ch25), 2 primitives (ch23, ch24) skip in both test environments with named reasons, cross-environment total 19 demonstrated and 4 skipped. The distinction between "works" and "does not work" is not a property of the primitive alone — it is a relation between the primitive and a specific kernel build.

**Transposing the relation.** A useful exercise for a reader reproducing this work: take the four axes and construct the hypothetical kernel on which the most primitives would fire, and the one on which the fewest would fire.

Maximum-fire kernel: x86_64 or aarch64, `CONFIG_BPF_LSM=y`, `lsm=capability,selinux,apparmor,lockdown,bpf,integrity,evm` with SELinux in enforcing mode, `CONFIG_MODULE_SIG_FORCE=y`, `CONFIG_DEBUG_INFO_BTF=y` with `pahole --btf_gen_all`, `CONFIG_FUNCTION_ERROR_INJECTION=y`, and an active cgroup-v2 devices enforcement policy. On this kernel, both linuxkit-cold cases (ch06 and ch12 LSM) go warm, matching the Fedora 42 QEMU environment that the harness already exercises. The cross-environment total is 20.

Minimum-fire kernel: aarch64 embedded build, `CONFIG_BPF_LSM=n`, `CONFIG_DEBUG_INFO_BTF=n`, `CONFIG_FUNCTION_ERROR_INJECTION=n`, no loaded LSM modules beyond `capability`, and `CAP_BPF` disabled for all unprivileged users. On this kernel, Class I return-value overrides are entirely absent (no `bpf_override_return` targets, no LSM fmod_ret). Class III ringbuf exfiltration remains only for privileged root processes, which is not a meaningful threat model. The primitive count approaches zero. This also is not a kernel most deployments can ship — BPF is too useful for observability, CO-RE too useful for portability, LSM too useful for workload isolation — but it is the strawman for the lower bound of attacker capability.

Real production kernels sit between the two strawmen. The skip list for any given kernel is a function of which axes that kernel tightened and which it left open. A Fedora workstation kernel fires both linuxkit-cold cases (like the QEMU secondary) and everything that fires on linuxkit. An Amazon Linux 2023 kernel fires differently still. The exercise of constructing the skip list for *your* kernel is the pre-flight that Chapter 20 introduced and Chapter 22 operationalizes.

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

The reader leaving this chapter should carry three things forward. First, a four-axis mental model: every BPF-based primitive lives in the intersection of hook availability, enforcement-point activity, BTF completeness, and subsystem presence. Second, a pre-flight protocol: before claiming any primitive fires or does not fire, enumerate the four axes on the target kernel and record the result. Third, a disposition of honest negatives: two cold cases on linuxkit (both warming up in Fedora 42 QEMU) are not a weakness of the catalog but a feature of the documentation. A catalog that admits which environments disarm a primitive is one whose successes in other environments can be trusted.
