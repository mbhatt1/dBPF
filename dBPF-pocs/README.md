# dBPF-pocs — Defensive eBPF POCs

Twenty-five self-contained eBPF proof-of-concept programs covering every
chapter of the dBPF research notebook. Each POC is built libbpf-skeleton
+ CO-RE style and is verified on Ubuntu 6.17.0-29-generic aarch64 (Lima VM,
Apple Silicon): 24 proven, 1 skip (ch24 — CONFIG_BPF_TOKEN=n), 0 failures.
Earlier results on Docker Desktop's linuxkit 6.12 aarch64 and Fedora 42
aarch64 QEMU VM are preserved in CHANGELOG.md. Each POC lives in
`pocs/<chXX>/` with the same layout:

```
pocs/chXX-name/
  chXX-name.bpf.c     # kernel-side BPF program
  chXX-name.c         # userspace loader (libbpf-skeleton)
  Makefile            # one-liner including ../../shared/common.mk
  trigger.sh          # demonstration / event generator
  README.md           # mechanism + evidence + limitations
```

> **Companion manuscript.** The narrative write-ups for every chapter
> live in this repo under [`book_chapters/`](../book_chapters/) and are
> published as a Jekyll book at
> <https://mbhatt1.github.io/dBPF>. The POCs in this directory are the
> code artifacts referenced from those chapters.

## POC inventory

The `Variants` column lists additional sibling directories beside the
primary POC (e.g. an `-lsm` hook variant). See the [Variants](#variants)
section below for what each suffix means.

| # | Chapter | Technique | Hook(s) | Effect on this kernel | One-line evidence | Variants |
|---|---------|-----------|---------|------------------------|-------------------|----------|
| 01 | Mirror Controls       | Capability-decision mirror, optional override | `kprobe`/`kretprobe` `cap_capable` | Observer (override gated by error_injection allowlist) | `[ch01] tag=deny pid=… cap=21 ret=-1` | `+ -lsm` |
| 02 | OverlayFS Trojan      | Watch overlay copy-up to detect upper-dir tampering | `kprobe` `ovl_copy_up*` | Observer-only on this kernel | `[ovl] copy_up dentry=… upper=…` | `+ -lsm` |
| 03 | FUSE Audit Black-Hole | Suppress audit records via control map | `kprobe` `audit_log_start/end/format` | Observer-only on this kernel | `[fuse] audit_log_start tgid=… suppress=1` | `+ -fentry` |
| 04 | Phantom Syscall       | Re-route `write()` data via tracepoint | `tp/syscalls/sys_enter_write` | Mutates kernel behavior (data steered) | `[phantom] redirect fd=1 len=12 -> tap` | — |
| 05 | Cgroup Leash          | Latency / read-throttle observer per cgroup | `tp/syscalls/sys_enter_read`,`sys_exit_read` | Observer-only on this kernel | `[leash] cgid=… read_us=8421` | — |
| 05b | Ghost NIC            | XDP shadow interface that swallows packets | `SEC("xdp")` | Mutates kernel behavior (XDP_DROP) | `[ghost] drop dev=eth0 proto=0x0800` | — |
| 06 | Silence SELinux       | Mirror AVC denials, optional avc bypass | `kprobe` `avc_has_perm*`,`selinux_file_permission`,`cap_capable` | Observer-only (no SELinux on linuxkit) | `[selinux] avc_has_perm tclass=2 perm=4 ret=-13` | `+ -lsm`, `+ -lsm-synthetic` |
| 07 | Devcgroup Houdini     | Bypass device-cgroup permission check | `kprobe`/`kretprobe` `devcgroup_check_permission`,`__arm64_sys_mknodat` | Mutates kernel behavior (override on allowlist) | `[devcg] FLIP mknodat dev=10:200 ret=-1 -> 0` | `+ -lsm` |
| 08 | Keyring Heist         | Snoop keyring lookups + permission decisions | `kprobe` `key_task_permission`,`lookup_user_key` | Observer-only on this kernel | `[keyring] lookup_user_key keyid=… perm=…` | `+ -kprobe`, `+ -lsm` |
| 09 | PID Doppelgänger      | Map fork → namespaced PID divergence | `raw_tp/sched_process_fork`,`kprobe/copy_namespaces` | Observer-only on this kernel | `[doppel] fork parent=… child=… ns_pid=…` | — |
| 10 | Inode Cloak           | Hide directory entries from `getdents64` | `tp/syscalls/sys_enter_getdents64`,`sys_exit_getdents64` | Mutates kernel behavior (entries dropped) | `[cloak] hide ino=… name=evil` | — |
| 11 | IRQ Affinity Chaos    | Per-CPU IRQ counter, drift detector | `kprobe` `handle_irq_event*` | Observer-only on this kernel | `[irq] cpu=3 irq=27 count=15412` | — |
| 12 | Signed-Driver Swap    | Force `mod_verify_sig` to succeed | `kprobe`/`kretprobe` `mod_verify_sig`,`load_module`,`module_sig_check` | Observer-only on this kernel (override gated) | `[modsig] mod_verify_sig name=evilmod ret=-EKEYREJECTED` | `+ -lsm`, `+ -syscall` |
| 13 | Powercap Override     | Trap powercap registrations + max-power writes | `kprobe` powercap/thermal | Observer-only on this kernel | `[pcap] set_max_power_uw zone=… val=…` | `+ -analog` |
| 14 | SCHED_FIFO Impersonator | Force-grant `SCHED_FIFO` policy via override | `kprobe`/`kretprobe` `__arm64_sys_sched_setscheduler` | Mutates kernel behavior (override on allowlist) | `[fifo] FLIP tgid=… policy=1 ret=-EPERM -> 0` | — |
| 15 | netns VLAN Ghost      | XDP redirect into an isolated netns w/ VLAN tag | `SEC("xdp")` | Mutates kernel behavior (XDP_REDIRECT) | `[vlanghost] redir dev=… vlan=42` | — |
| 16 | seccomp TID Hop       | Bypass seccomp via TID-based override | `kprobe`/`kretprobe` `__secure_computing` | Mutates kernel behavior (override on allowlist) | `[seccomp] FLIP tid=… ret=-EPERM -> 0` | — |
| 17 | ACPI WSMI Ping        | Hook `acpi_evaluate_object` + firmware loader | `kprobe` ACPI/firmware | Observer-only on this kernel (no ACPI) | `[acpi] evaluate_object name=\\_SB_.WMI` | `+ -analog` |
| 18 | Token Bypass          | Forge `getuid`/`geteuid` to 0 via override | `kretprobe` `__arm64_sys_getuid`,`__arm64_sys_geteuid` | Mutates kernel behavior (override on allowlist) | `[token] FORGE pid=… comm=sh getuid: 1000 -> 0 (root)` | — |
| 23 | TPM Unseal Heist      | Capture plaintext trusted-key payload after TPM unseal | `kprobe/kretprobe` `tpm2_unseal_trusted` | Observer (kprobe confirmed attached; TPM keyctl path skipped — no boot-time TPM in VM) | `CH23_PROVEN hook=tpm2_unseal_trusted` | — |
| 24 | BPF Token Delegation  | Delegate BPF load rights to unprivileged process via BPF token | `BPF_TOKEN_CREATE` syscall + bpffs `delegate_*` mounts | **SKIP** — `CONFIG_BPF_TOKEN=n` on all tested kernels; requires kernel ≥ 6.9 with token support explicitly enabled | `CH24_SKIP reason=CONFIG_BPF_TOKEN=n` | — |
| 25 | IMDS Harvest          | XDP tap on loopback captures IMDSv2 IAM credential triple | `SEC("xdp")` on loopback | Mutates kernel behavior (XDP_PASS + ringbuf exfil) | `CH25_PROVEN access_key_captured=yes token_captured=yes role=demo-role` | — |

"Mutates kernel behavior" means `bpf_override_return` succeeds on this
kernel (target is on the error-injection allowlist) or the program
type itself can drop/redirect (XDP). "Observer-only" means the BPF
program loads and fires events, but the intended write side-effect is
gated off (error_injection list excludes the symbol, LSM is absent,
device class isn't present, etc.). All POCs still produce ringbuf
telemetry you can grep.

## Variants

Several chapters ship multiple sibling directories that attack the same
mechanism from a different hook or approximate it on a kernel where the
real subsystem is absent. They share the primary POC's technique and
evidence format; only the hook family (or the simulation layer) differs.

- **`-lsm`** — LSM-hook-based variant using `SEC("lsm/...")`. Only loads
  on kernels where BPF LSM is enabled (`CONFIG_BPF_LSM=y` plus
  `lsm=...,bpf` on the boot cmdline). On linuxkit this typically fails
  to attach; on a distro kernel with BPF LSM it produces stronger
  mediation than the kprobe path. Present for: ch01, ch02, ch06, ch07,
  ch08, ch12.
- **`-fentry`** — fentry-based variant. Lower per-call overhead than
  kprobe and needs a recent enough kernel with fentry support for the
  target symbol. Present for: ch03.
- **`-kprobe`** — Explicit kprobe variant kept alongside an
  fentry/LSM version of the same chapter, for contrast and for kernels
  where the newer hook type isn't available. Present for: ch08.
- **`-syscall`** — Syscall-entry variant (tracepoint / syscall-level
  rather than an internal kernel symbol). Present for: ch12.
- **`-synthetic`** / **`-analog`** — Stand-ins for subsystems that
  simply don't exist on linuxkit. They mock the inputs the real hook
  would see so the detection logic can be exercised end-to-end without
  the backing hardware or LSM. Present for: ch06 (`-lsm-synthetic`,
  SELinux absent), ch13 (`-analog`, no powercap hardware), ch17
  (`-analog`, no ACPI).

Each variant directory follows the same layout as the primary POC and
has its own `README.md` describing what it attaches to and why.

## Prerequisites

- **macOS + Apple Silicon + Lima VM** running Ubuntu with kernel 6.17 aarch64
  (the verified environment: 24/25 proven), or
- **macOS + Docker Desktop** (linuxkit 6.12 aarch64), or
- **Any Linux** with privileged Docker access and a kernel ≥ 5.13 with
  CO-RE / BTF (`/sys/kernel/btf/vmlinux` present).

Notes for the Lima VM path: ch15 requires `--net=host`; ch17 requires a
custom `fw_trigger.ko` kernel module; ch13 trigger.sh builds a kernel module
to call `powercap_register_control_type` (RAPL is x86-only).

You need the base image once:

```
docker build -t dbpf-base -f Dockerfile.base .
```

## Quick start

```
docker build -t dbpf-base -f Dockerfile.base .
bash run_all.sh
```

`run_all.sh` walks every `pocs/*/`, builds it inside `dbpf-base`, then
runs the loader briefly under `--privileged --pid=host`, fires the
trigger, and writes per-POC logs to `logs/<chXX>.log`. A summary table
is printed at the end.

## Per-POC run template

```
# Build (host clang/llvm not required — everything happens in the container)
docker run --rm -v "$PWD":/work -w /work dbpf-base \
  bash -c 'cd pocs/<chXX> && make'

# Run the loader (foreground, Ctrl-C to stop)
docker run --rm --privileged --pid=host \
  -v "$PWD":/work -w /work/pocs/<chXX> dbpf-base \
  ./build/<chXX>

# In another shell, run the trigger
docker exec -it <container> bash trigger.sh
```

Each POC's `README.md` shows the exact flags it accepts (`-h` works on
every loader).

## Known kernel-policy limitations

- **`bpf_override_return` is gated by the kernel's error-injection
  allowlist** (`/sys/kernel/debug/error_injection/list`). Targets not
  on that list will silently no-op even though the kretprobe attaches.
  The POCs that *do* mutate behavior on this kernel are: 04, 05b, 07,
  10, 14, 15, 16, 18.
- **Architecture-specific syscall wrappers.** On aarch64 syscalls are
  exposed as `__arm64_sys_<name>`; on x86_64 it's `__x64_sys_<name>`.
  Each loader does a `/proc/kallsyms` preflight and disables programs
  whose targets are missing rather than aborting.
- **Absent LSMs.** linuxkit ships without SELinux, AppArmor, IMA, and
  with a minimal audit subsystem. POCs targeting those (03, 06, parts
  of 12) only achieve their full effect on a distro kernel where the
  subsystem is actually wired up.
- **No real ACPI / powercap / thermal hardware** in linuxkit — POCs 13
  and 17 are observer-only because the kernel never invokes the
  hooked code paths.
- **No incremental migrations.** Each POC's `build/` is regenerated
  from scratch by `make clean && make`.

## Safety / ethics disclaimer

These POCs exist to study defensive detection of malicious eBPF — the
kind of attacks a sufficiently-privileged adversary can launch *from
inside* a host kernel. They are intentionally narrow, single-purpose,
and instrumented with verbose telemetry so the techniques are obvious
to a blue-teamer.

**Do not deploy these on systems you don't own.** All of them require
`CAP_BPF` + `CAP_PERFMON` (effectively root). Several of them
(`bpf_override_return`-based ones, XDP drop/redirect) can perturb a
production system in ways that are not trivially reversible without a
reboot of the affected subsystem. Use the provided Docker harness.
