# dBPF — what CAP_BPF actually permits, demonstrated

**Status:** 23 PoCs registered · 19 fire across two test environments · 4 honest skips documented · primary harness: Docker Desktop linuxkit 6.12 aarch64 · secondary harness: Fedora 42 aarch64 QEMU VM.

## What this is

A defensive-security field manual paired with a reproducible Docker+QEMU harness that empirically verifies every claim in the book. The threat model assumes the attacker already holds `CAP_BPF` + `CAP_PERFMON` (and in some chapters `CAP_NET_ADMIN`) on a modern Linux kernel, because that is the capability set observability agents, service meshes, and DaemonSets routinely request. The book is not a vulnerability catalog, not a zero-day drop, and not a verifier-bug showcase. It is a scope-of-capability audit: an attempt to describe, chapter by chapter and primitive by primitive, what a process holding that grant can actually do on kernel 6.12. Every technique is documented, intentional kernel behavior. The point is to make the surface area legible for operators deciding whether to grant the capability and for researchers extending the taxonomy.

## Repository layout

```
dBPF/
├── _book_chapters/     The manuscript (canonical source of truth for prose).
│   ├── act-1/          Foundations, chapters 0–6 (chapter 0 preface).
│   ├── act-2/          Kernel intrusion, chapters 7–12.
│   ├── act-3/          Total control, chapters 14–18.
│   ├── act-4/          Cross-boundary primitives, chapters 23–25.
│   └── act-7/          Conclusion and synthesis, chapters 19–22.
├── _includes/          Jekyll site partials.
├── _layouts/           Jekyll site layouts.
├── _posts/             Web-rendered form of the manuscript (derived view).
├── assets/             Site images and static assets.
├── index.md            Site landing page.
├── _config.yml         Jekyll configuration.
├── Gemfile             Ruby dependencies for the Jekyll build.
└── dBPF-pocs/          Companion PoC collection and verification harness.
    ├── pocs/           Per-chapter PoC code (BPF C + userspace loader + trigger + README).
    │   ├── ch01-*/     …through ch25-*, one directory per PoC (23 directories total).
    ├── harness/        Python harness (proof.py), Dockerfile, run.sh entrypoint.
    ├── qemu/           Fedora 42 aarch64 QEMU VM config and cloud-init seed.
    ├── shared/         Shared Makefile rules (common.mk) and specs.
    ├── run-qemu-tests.sh   Host-side orchestrator for the Fedora secondary harness.
    ├── qemu-runner.sh  Guest-side per-PoC driver (virtio-9p mounted from host).
    └── run_all.sh      Convenience wrapper that runs both harnesses in sequence.
```

Each per-chapter PoC under `dBPF-pocs/pocs/chNN-*/` contains four load-bearing files: a BPF C program, a userspace loader (C or Python) that loads + attaches + consumes the ringbuf, a `trigger.sh` that provokes the primitive and prints the proof marker, and a `README.md` that explains the hook target, the expected BEFORE/AFTER state, and the failure modes.

## Quick start

```bash
# 1. Clone the repository.
git clone https://github.com/mbhatt1/dBPF.git && cd dBPF

# 2. Run the primary harness (Docker Desktop linuxkit 6.12 aarch64).
cd dBPF-pocs && bash harness/run.sh

# 3. Run the secondary harness (Fedora 42 aarch64 QEMU VM).
#    Requires qemu-system-aarch64, xorriso, and a Fedora 42 cloud image.
#    See dBPF-pocs/qemu/ for the expected disk image layout.
cd dBPF-pocs && bash run-qemu-tests.sh

# 4. Build the book locally.
bundle install && bundle exec jekyll serve --livereload
```

The primary harness builds a container image, mounts the PoC tree at `/w`, and runs `harness/proof.py`, which in turn iterates over the registered PoC list, builds each one against the running kernel's BTF, attaches the program, runs the trigger, scrapes stdout for proof markers, and writes a consolidated JSON verdict to `/tmp/proof-result.json`. The secondary harness boots a Fedora 42 VM with BPF LSM + SELinux enforcing + module-signature enforcement and runs the subset of PoCs that need those facilities.

## Test environments

The book is tested against two intentionally different environments. Agreement across both is the strongest reproducibility claim the harness offers; disagreement is documented in Chapter 21.

**Primary: Docker Desktop linuxkit 6.12 aarch64.** A minimal linuxkit kernel with `CONFIG_BPF=y`, `CONFIG_BPF_LSM=y`, `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_BPF_KPROBE_OVERRIDE=y`, and `CONFIG_FUNCTION_ERROR_INJECTION=y`. 18 of 23 PoCs fire here. The five that do not fire on linuxkit skip by design: ch23 (no `/dev/tpm0` in linuxkit), ch24 (no delegated-userns substrate), ch25 (no IMDS mock until the Fedora VM provides one), plus the two LSM-dependent PoCs (ch06 LSM and ch12 LSM) whose `bpf,...` boot-time LSM order is only present in the secondary.

**Secondary: Fedora 42 aarch64 QEMU VM.** Kernel 6.14 with BPF LSM in the boot-time LSM list, SELinux enforcing, and module-signature enforcement. Used for the PoCs that cannot land on linuxkit: ch06 LSM `fmod_ret`, ch12 LSM, and ch25's mock IMDSv2 endpoint on `lo`. The VM is driven by `run-qemu-tests.sh` on the host and `qemu-runner.sh` inside the guest; per-PoC artifacts cross the boundary via virtio-9p.

**One additional PoC — ch24 — is production-reviewed but exposes an environmental gap.** The code is correct and the harness entry is honest: on Fedora 42's cloud-init-bounded userns, `BPF_TOKEN_CREATE` returns `EOPNOTSUPP` despite `/proc/self/ns/user` matching pid 1. The primitive is architecturally sound and the chapter documents the exact kernel code path that produces the refusal. Until a kernel or userns configuration that accepts `BPF_TOKEN_CREATE` is available in the harness, ch24 emits `CH24_SKIP reason=...` rather than claiming a fire it did not produce. This is the kind of honesty the book trades on.

Cross-environment totals: **19 PoCs fire**, 4 skip with documented reasons.

## The harness contract

Every PoC adheres to a single, narrow contract. The trigger script prints at least one of:

```
CHxx_PROVEN <key>=<value> [<key>=<value> ...]
CHxx_SKIP reason="<human-readable reason>"
```

on stdout. `proof.py` registers each PoC with a `proof_marker` regex; a run is a "fire" if the regex matches at least once, a "skip" if `CHxx_SKIP` appears, and a "failure" if neither appears before the timeout. The consolidated verdict written to `/tmp/proof-result.json` contains, per PoC, status, event counts, the captured marker line, the present/missing hook lists from `/proc/kallsyms`, and the runtime duration. There are no hidden side channels: if the harness says a PoC fired, the marker line is in the JSON and can be cross-checked against the chapter's BEFORE/AFTER text.

## Categories

Every registered PoC is tagged with one of four categories in `proof.py`. The tags describe what the primitive observably does to the kernel, not how dangerous it is. Counts recounted directly from `dBPF-pocs/harness/proof.py`:

- **real** (16 PoCs) — hooks the actual kernel subsystem and either observes its decision inputs/outputs or mutates state that the subsystem or its userspace consumer goes on to read. Examples: ch01's `bpf_send_signal` from a kretprobe on `cap_capable`, ch08's keyring payload exfil via `bpf_probe_read_kernel`, ch05b's XDP program on a veth, ch10's `getdents64` directory-entry cloaking.
- **observer** (4 PoCs) — hooks the real subsystem but can only read, not mutate. The decision function is either not in `ALLOW_ERROR_INJECTION` or its LSM hook does not accept `fmod_ret`; the primitive captures inputs to a ringbuf without being able to flip the outcome. Examples: ch03 (audit observer), ch06/ch06o (SELinux observation), ch16 (seccomp TID sidechannel).
- **illusion** (3 PoCs) — forges a syscall return via `bpf_override_return` on an allowlisted syscall wrapper. The caller sees the forged return value; kernel state is unchanged. Examples: ch14 (SCHED_FIFO forge), ch18 (getuid forge), ch12s (finit_module return forge without the module actually loading).
- **analog** — deliberately zero. An earlier cleanup pass removed every synthetic or analog surface. Nothing in the registered PoC set is a marionette; every primitive hooks a real kernel attach point.

The real/observer/illusion split is the honest taxonomy. A reader suspicious of any specific claim can look up the PoC's category tag and cross-reference the chapter text.

## Disclaimer

Nothing in this repository is a vulnerability catalog. Every primitive is documented, intentional kernel behavior that the maintainers have chosen to make available to the `CAP_BPF` + `CAP_PERFMON` capability holder. No kernel update closes any of these primitives unless it changes the capability model itself or narrows an allowlist. The book's point is the inverse of a vulnerability report: it argues that the *scope* of the capability grant is larger than the grant's documentation tends to convey, and that operators making the grant decision should understand what the grant actually is. Grant scope matters. This book documents what the scope is.

If you are operating a workload that does not grant `CAP_BPF` to untrusted code, this repository is a description of what you are protecting against, not a toolkit against you. If you are operating a workload that does grant it — a Cilium or Tetragon or Pixie install, a BCC-based observability stack, any DaemonSet that requests the capability in its securityContext — this repository is a description of the surface area you have accepted.

## Contributing

Contributions are welcome, particularly cross-environment reproductions (other aarch64 distributions, x86_64 ports, LTS kernel versions). See `CONTRIBUTING.md` at the repository root for the workflow, the PoC specification, and the marker-regex contract that new PoCs must satisfy.

## License

BPF programs that execute in kernel context are licensed GPL-2.0-only, as required for kernel linkage and helper access. The book prose, the harness, and the site assets are licensed under a permissive license suitable for both reading and derivative work. See `LICENSE` at the repository root for the exact terms and the per-subtree license breakdown.

## Reproduce the book's claims

Every claim in every chapter has a corresponding PoC, and every PoC's run produces a line-regex-matched marker that the harness captures. The loop closes as follows: the chapter makes a claim, the claim is expressed as a BEFORE state and an AFTER state, the PoC's trigger produces both states on stdout, the harness scrapes the marker regex registered in `proof.py`, and the verdict lands in `/tmp/proof-result.json`. A reader who doubts a specific claim can re-run the PoC, diff the JSON, and either confirm or file an issue against the exact marker that disagrees. Divergence is not a bug; divergence is data, and the book's taxonomy is designed to absorb it. The honest form of the book's thesis is narrower than "CAP_BPF grants enormous power" and more precise: CAP_BPF grants exactly the seven-class primitive surface enumerated in Chapter 20, subject to the failure modes catalogued in Chapter 21, reproducible end-to-end by the harness described here.
