# dBPF — what CAP_BPF actually permits, demonstrated

**Status:** 26 PoCs registered (`real=15 · observer=8 · illusion=3`). Reproduction is environment-dependent — no single available kernel exercises all of them: the return-override/forge PoCs need `CONFIG_FUNCTION_ERROR_INJECTION`+`CONFIG_BPF_KPROBE_OVERRIDE`, the BPF-LSM PoCs need `bpf` in the *active* LSM list, and no available kernel has both. Verified live across Ubuntu 6.17, Fedora 6.17, and Docker LinuxKit 6.12 (all aarch64); see **Test environments** for per-kernel results. Two former "silence/flip" LSM claims (ch06, ch12) were corrected to observer / add-deny (BPF-LSM is deny-wins and ordered after SELinux, so it cannot silence a denial), and ch24's primitive is demonstrable on any 6.9+ kernel with its PoC rewrite pending. Per-run verdicts live in `/tmp/proof-result.json`.

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
    │   ├── ch01-*/     …through ch25-*; several chapters ship more than one variant (30 dirs, 26 registered).
    ├── harness/        Python harness (proof.py), Dockerfile, run.sh entrypoint.
    ├── qemu/           Fedora 42 aarch64 QEMU VM config and cloud-init seed.
    ├── shared/         Shared Makefile rules (common.mk) and specs.
    ├── run-qemu-tests.sh   Host-side orchestrator for the Fedora secondary harness.
    ├── qemu-runner.sh  Guest-side per-PoC driver (virtio-9p mounted from host).
    └── run_all.sh      Convenience wrapper that runs both harnesses in sequence.
```

The directory tree (30 dirs) maps to 26 registered PoC entries in `proof.py`: several chapters ship more than one variant (for example ch06 has three: the real LSM variant, the observer variant, and a synthetic LSM scaffold), and a few variant directories are not registered in the harness. Each PoC directory under `dBPF-pocs/pocs/chNN-*/` contains four load-bearing files: a BPF C program, a userspace loader (C or Python) that loads, attaches, and consumes the ringbuf, a `trigger.sh` that provokes the primitive and prints the proof marker, and a `README.md` that explains the hook target, the expected BEFORE/AFTER state, and the failure modes.

## Quick start

```bash
# 1. Clone the repository.
git clone https://github.com/mbhatt1/dBPF.git && cd dBPF

# 2. Run the primary harness (Docker Desktop linuxkit 6.12 aarch64).
cd dBPF-pocs && bash harness/run.sh

# 3. Run on Ubuntu 6.17 aarch64 (Lima VM on Apple Silicon — verified environment).
#    Provision a Lima VM with Ubuntu 24.10+ and kernel 6.17, then inside the VM:
cd dBPF-pocs && bash run_all.sh
#    Most registered PoCs prove here; which ones depends on the kernel (see Test environments).
#    ch15 requires --net=host for XDP to reach host network interfaces.

# 4. Run the secondary harness (Fedora 42 aarch64 QEMU VM).
#    Requires qemu-system-aarch64, xorriso, and a Fedora 42 cloud image.
#    See dBPF-pocs/qemu/ for the expected disk image layout.
cd dBPF-pocs && bash run-qemu-tests.sh

# 5. Build the book locally.
bundle install && bundle exec jekyll serve --livereload
```

The primary harness builds a container image, mounts the PoC tree at `/w`, and runs `harness/proof.py`, which in turn iterates over the registered PoC list, builds each one against the running kernel's BTF, attaches the program, runs the trigger, scrapes stdout for proof markers, and writes a consolidated JSON verdict to `/tmp/proof-result.json`. The secondary harness boots a Fedora 42 VM with BPF LSM + SELinux enforcing + module-signature enforcement and runs the subset of PoCs that need those facilities.

## Test environments

The book is tested against multiple environments. The Ubuntu 6.17 aarch64 Lima VM is the primary verified environment as of the latest verification pass.

**Verified: Ubuntu 6.17.0-29-generic aarch64 (Lima VM, Apple Silicon).** Full kernel feature set: CO-RE, BTF, ringbuf, kprobe, kretprobe, raw_tracepoint, XDP, `CONFIG_FUNCTION_ERROR_INJECTION`, `CONFIG_BPF_KPROBE_OVERRIDE`. Result: the return-override/forge, XDP, tracepoint, and kprobe-observer PoCs reproduce here. Caveats specific to this boot: it runs **AppArmor** (no `bpf`/`selinux` in the active LSM list), so the BPF-LSM PoCs (ch06/ch12/ch02lsm) attach only on the Fedora VM; ch23 needs a boot-time TPM (see its note); and ch24's primitive is demonstrable but its shipped PoC needs the userns rewrite. Notable environment-specific notes:
- ch01: `bpf_send_signal(SIGUSR1)` confirmed — capability denial delivers a real signal to the target process.
- ch06: `ch06-silence-selinux-lsm-synthetic` (ch06s) is a registered synthetic LSM scaffold used on kernels without SELinux active; it attaches to `lsm.s/file_open` directly without requiring `selinux_loaded()` and emits the `CH06_SYNTH_PROVEN` marker.
- ch10: BPF map renamed `active` → `active_calls` to avoid collision with a vmlinux.h kernel enum.
- ch15: Requires `--net=host` for XDP to access host network interfaces.
- ch23: kprobe on `tpm2_unseal_trusted` confirmed attached; TPM keyctl path skipped (no boot-time TPM in VM).
- ch25: XDP IMDS harvest confirmed — captures mock credentials on loopback.
- ch24: Demonstrable on the stock kernel. There is **no `CONFIG_BPF_TOKEN` option** — token support is unconditional in `CONFIG_BPF_SYSCALL` since 6.9. Verified live: in an unprivileged user namespace a program load is denied without a token and succeeds with a delegated one (`CH24_PROVEN`). The shipped PoC mints from `init_user_ns` (kernel returns `-EOPNOTSUPP`) and needs rewriting to the non-init-userns `fsopen`/`fsconfig`/`fsmount` fd-passing pattern; until then the harness does not record it as a fire.

**Primary: Docker Desktop linuxkit 6.12 aarch64.** A minimal linuxkit kernel with `CONFIG_BPF=y`, `CONFIG_BPF_LSM=y`, `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_BPF_KPROBE_OVERRIDE=y`, and `CONFIG_FUNCTION_ERROR_INJECTION=y`. Most of the registered PoCs fire here. The ones that do not skip by design: ch23 (no `/dev/tpm0` in linuxkit), ch24 (no delegated-userns substrate), ch25 (no IMDS mock until the Fedora VM provides one), plus the LSM-dependent PoCs (ch06 LSM and ch12 LSM) whose `bpf,...` boot-time LSM order is only present in the secondary.

**Secondary: Fedora 42 aarch64 QEMU VM.** Kernel 6.14 with BPF LSM in the boot-time LSM list, SELinux enforcing, and module-signature enforcement. Used for the PoCs that cannot land on linuxkit: ch06 LSM `fmod_ret`, ch12 LSM, and ch25's mock IMDSv2 endpoint on `lo`. The VM is driven by `run-qemu-tests.sh` on the host and `qemu-runner.sh` inside the guest; per-PoC artifacts cross the boundary via virtio-9p.

**ch24 — corrected from an earlier false "skip".** Earlier drafts marked ch24 a skip on `CONFIG_BPF_TOKEN=n`. That Kconfig symbol **does not exist**: BPF-token support has been unconditional in `CONFIG_BPF_SYSCALL` since Linux 6.9, so `grep CONFIG_BPF_TOKEN /boot/config-*` finding nothing means the symbol is absent, not the feature. The primitive is demonstrable on the stock Ubuntu 6.17 kernel — verified live: in an unprivileged user namespace a program load is denied (`EPERM`) without a token and succeeds with a delegated one (`CH24_PROVEN`). The shipped PoC does not fire only because it mints the token from `init_user_ns`, which the kernel refuses with `-EOPNOTSUPP` (not `ENOSYS`); it needs rewriting to the non-init-userns `fsopen`/`fsconfig(delegate_*)`/`fsmount` fd-passing pattern (with `BPF_F_TOKEN_FD` on the load) before the harness records the fire.

Verified totals: reproduction is environment-dependent — no single available kernel runs all 26 (see the per-environment notes above and the caveats in the Status line). The BPF machinery itself is confirmed working: across the three kernels, most primitives demonstrate real effects, with the remainder gated by a specific surface (SELinux enforcing, `bpf` in the LSM list, a boot-time TPM) or, for ch24, a PoC rewrite. Exact per-run verdicts are in `/tmp/proof-result.json`.

## The harness contract

Every PoC adheres to a single, narrow contract. The trigger script prints at least one of:

```
CHxx_PROVEN <key>=<value> [<key>=<value> ...]
CHxx_SKIP reason="<human-readable reason>"
```

on stdout. `proof.py` registers each PoC with a `proof_marker` regex; a run is a "fire" if the regex matches at least once, a "skip" if `CHxx_SKIP` appears, and a "failure" if neither appears before the timeout. The consolidated verdict written to `/tmp/proof-result.json` contains, per PoC, status, event counts, the captured marker line, the present/missing hook lists from `/proc/kallsyms`, and the runtime duration. There are no hidden side channels: if the harness says a PoC fired, the marker line is in the JSON and can be cross-checked against the chapter's BEFORE/AFTER text.

## Categories

Every registered PoC is tagged with one of four categories in `proof.py`. The tags describe what the primitive observably does to the kernel, not how dangerous it is. Counts are taken from `dBPF-pocs/harness/REGISTRY_STATS.md`, the machine-generated registry (26 registered PoCs total):

- **real** (15) — hooks the actual kernel subsystem and either observes its decision inputs/outputs or mutates state that the subsystem or its userspace consumer goes on to read. Examples: ch01's `bpf_send_signal` from a kretprobe on `cap_capable`, ch05b's XDP program on a veth, ch10's `getdents64` directory-entry cloaking.
- **observer** (8 PoCs) — hooks the real subsystem but can only read, not mutate. The decision function is either not in `ALLOW_ERROR_INJECTION` or its LSM hook does not accept `fmod_ret`; the primitive captures inputs to a ringbuf without being able to flip the outcome. This class includes ch03/ch03f (audit observers), ch06/ch06o/ch06s (SELinux observation, including the synthetic LSM scaffold), ch16 (seccomp TID sidechannel), and ch08/ch08k (keyring heist — the kprobe copies key metadata to a ringbuf; the access decision is unchanged, so this is an observer, not a mutation).
- **illusion** (3 PoCs) — forges a syscall return via `bpf_override_return` on an allowlisted syscall wrapper. The caller sees the forged return value; kernel state is unchanged. The three are ch14 (SCHED_FIFO forge), ch18 (getuid forge), and ch12s (finit_module return forge without the module actually loading).
- **analog** (0 PoCs) — the registered set contains no pure-analog primitive. Note this is not the same as "no synthetic surface": ch06s (`ch06-silence-selinux-lsm-synthetic`) is a registered synthetic LSM scaffold, tagged **observer**, used on kernels where SELinux is not active. It exists in the registered set and is documented honestly as a scaffold.

The real/observer/illusion split is the honest taxonomy. A reader suspicious of any specific claim can look up the PoC's category tag in `REGISTRY_STATS.md` and cross-reference the chapter text.

## Disclaimer

Nothing in this repository is a vulnerability catalog. Every primitive is documented, intentional kernel behavior that the maintainers have chosen to make available to the `CAP_BPF` + `CAP_PERFMON` capability holder. No kernel update closes any of these primitives unless it changes the capability model itself or narrows an allowlist. The book's point is the inverse of a vulnerability report: it argues that the *scope* of the capability grant is larger than the grant's documentation tends to convey, and that operators making the grant decision should understand what the grant actually is. Grant scope matters. This book documents what the scope is.

If you are operating a workload that does not grant `CAP_BPF` to untrusted code, this repository is a description of what you are protecting against, not a toolkit against you. If you are operating a workload that does grant it — a Cilium or Tetragon or Pixie install, a BCC-based observability stack, any DaemonSet that requests the capability in its securityContext — this repository is a description of the surface area you have accepted.

## Contributing

Contributions are welcome, particularly cross-environment reproductions (other aarch64 distributions, x86_64 ports, LTS kernel versions). See `CONTRIBUTING.md` at the repository root for the workflow, the PoC specification, and the marker-regex contract that new PoCs must satisfy.

## License

BPF programs that execute in kernel context are licensed GPL-2.0-only, as required for kernel linkage and helper access. The book prose, the harness, and the site assets are licensed under a permissive license suitable for both reading and derivative work. See `LICENSE` at the repository root for the exact terms and the per-subtree license breakdown.

## Reproduce the book's claims

Every claim in every chapter has a corresponding PoC, and every PoC run produces a line-regex-matched marker that the harness captures. The chapter states a claim as a BEFORE state and an AFTER state; the PoC's trigger produces both on stdout; the harness scrapes the marker regex registered in `proof.py` and writes the verdict to `/tmp/proof-result.json`. A reader who doubts a specific claim can re-run the PoC, diff the JSON, and either confirm it or file an issue against the exact marker that disagrees. The book's thesis is deliberately narrow: `CAP_BPF` plus `CAP_PERFMON` grants the primitive surface enumerated in Chapter 20, subject to the failure modes catalogued in Chapter 21, reproducible end-to-end by the harness described here.
