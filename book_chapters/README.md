# book_chapters/

Canonical manuscript source for **The Diabolical eBPF Field Manual**, organized as a
three-act book with chapters 0–19 as standalone Markdown files. This tree is the
source of truth for the prose; the Jekyll site and companion code are derived views.

## Layout

- **`book_chapters/`** (this directory) — canonical manuscript, three-act structure,
  one file per chapter. Edit here first.
- **`_posts/`** — Jekyll-rendered web version of the same material (sibling content,
  web-formatted with front matter). Not the source of truth.
- **`dBPF-pocs/`** — working companion code: runnable eBPF proof-of-concept programs,
  loaders, and (where applicable) LSM/kprobe/fentry variants per chapter.

## Three-act arc

- **Act 1 — Foundational misuse.** Early primitives: mirroring, overlay/FUSE tricks,
  syscall shims, cgroup/NIC slips, silencing LSM telemetry.
- **Act 2 — Privilege & namespace escalation.** Device cgroups, keyrings, PID/inode
  cloaking, IRQ chaos, signed-driver swaps, powercap overrides.
- **Act 3 — System-level subversion + epilogue.** Scheduler impersonation, netns/VLAN
  ghosts, seccomp TID hops, ACPI/WMI pings, token bypass, and a closing reflection.

## Table of Contents

### Act 1 — Foundational misuse

| # | Chapter | POC |
|---|---------|-----|
| 0 | [chapter-0-field-manual-preface.md](act-1/chapter-0-field-manual-preface.md) — preface and framing for the field manual | — |
| 1 | [chapter-1-the-mirror-controls.md](act-1/chapter-1-the-mirror-controls.md) — mirroring control-plane state from eBPF | [ch01-mirror-controls](../dBPF-pocs/pocs/ch01-mirror-controls) · [lsm](../dBPF-pocs/pocs/ch01-mirror-controls-lsm) |
| 2 | [chapter-2-the-overlayfs-trojan-horse.md](act-1/chapter-2-the-overlayfs-trojan-horse.md) — overlayfs as a delivery vector | [ch02-overlayfs](../dBPF-pocs/pocs/ch02-overlayfs) · [lsm](../dBPF-pocs/pocs/ch02-overlayfs-lsm) |
| 3 | [chapter-3-the-fuse-audit-black-hole.md](act-1/chapter-3-the-fuse-audit-black-hole.md) — FUSE as an audit blind spot | [ch03-fuse-blackhole](../dBPF-pocs/pocs/ch03-fuse-blackhole) · [fentry](../dBPF-pocs/pocs/ch03-fuse-blackhole-fentry) |
| 4 | [chapter-4-the-phantom-syscall.md](act-1/chapter-4-the-phantom-syscall.md) — syscalls that leave no trace | [ch04-phantom-syscall](../dBPF-pocs/pocs/ch04-phantom-syscall) |
| 5 | [chapter-5-slipping-the-cgroup-leash.md](act-1/chapter-5-slipping-the-cgroup-leash.md) — escaping cgroup constraints | [ch05-cgroup-leash](../dBPF-pocs/pocs/ch05-cgroup-leash) |
| 5b | [chapter-5-the-ghost-nic.md](act-1/chapter-5-the-ghost-nic.md) — a NIC that isn't there | [ch05b-ghost-nic](../dBPF-pocs/pocs/ch05b-ghost-nic) |
| 6 | [chapter-6-silencing-selinux.md](act-1/chapter-6-silencing-selinux.md) — muzzling SELinux telemetry | [ch06-silence-selinux](../dBPF-pocs/pocs/ch06-silence-selinux) · [lsm](../dBPF-pocs/pocs/ch06-silence-selinux-lsm) · [lsm-synthetic](../dBPF-pocs/pocs/ch06-silence-selinux-lsm-synthetic) |

### Act 2 — Privilege & namespace escalation

| # | Chapter | POC |
|---|---------|-----|
| 7 | [chapter-7-device-cgroup-houdini.md](act-2/chapter-7-device-cgroup-houdini.md) — escaping device cgroup gates | [ch07-devcgroup-houdini](../dBPF-pocs/pocs/ch07-devcgroup-houdini) · [lsm](../dBPF-pocs/pocs/ch07-devcgroup-houdini-lsm) |
| 8 | [chapter-8-keyring-heist.md](act-2/chapter-8-keyring-heist.md) — kernel keyring exfiltration | [ch08-keyring-heist](../dBPF-pocs/pocs/ch08-keyring-heist) · [kprobe](../dBPF-pocs/pocs/ch08-keyring-heist-kprobe) · [lsm](../dBPF-pocs/pocs/ch08-keyring-heist-lsm) |
| 9 | [chapter-9-pid-namespace-doppelg-nger.md](act-2/chapter-9-pid-namespace-doppelg-nger.md) — PID namespace doppelgängers | [ch09-pid-doppel](../dBPF-pocs/pocs/ch09-pid-doppel) |
| 10 | [chapter-10-inode-cloak.md](act-2/chapter-10-inode-cloak.md) — cloaking files at the inode layer | [ch10-inode-cloak](../dBPF-pocs/pocs/ch10-inode-cloak) |
| 11 | [chapter-11-irq-affinity-chaos.md](act-2/chapter-11-irq-affinity-chaos.md) — weaponizing IRQ affinity | [ch11-irq-chaos](../dBPF-pocs/pocs/ch11-irq-chaos) |
| 12 | [chapter-12-ebpf-signed-driver-swap.md](act-2/chapter-12-ebpf-signed-driver-swap.md) — swapping signed drivers via eBPF | [ch12-signed-driver-swap](../dBPF-pocs/pocs/ch12-signed-driver-swap) · [lsm](../dBPF-pocs/pocs/ch12-signed-driver-swap-lsm) · [syscall](../dBPF-pocs/pocs/ch12-signed-driver-swap-syscall) |
| 13 | [chapter-13-powercap-override.md](act-2/chapter-13-powercap-override.md) — overriding powercap limits | [ch13-powercap-override](../dBPF-pocs/pocs/ch13-powercap-override) · [analog](../dBPF-pocs/pocs/ch13-powercap-override-analog) |

### Act 3 — System-level subversion + epilogue

| # | Chapter | POC |
|---|---------|-----|
| 14 | [chapter-14-sched-fifo-impersonator.md](act-3/chapter-14-sched-fifo-impersonator.md) — impersonating SCHED_FIFO priority | [ch14-sched-fifo](../dBPF-pocs/pocs/ch14-sched-fifo) |
| 15 | [chapter-15-netns-vlan-ghost.md](act-3/chapter-15-netns-vlan-ghost.md) — a VLAN ghost across network namespaces | [ch15-netns-vlan-ghost](../dBPF-pocs/pocs/ch15-netns-vlan-ghost) |
| 16 | [chapter-16-seccomp-tid-hop.md](act-3/chapter-16-seccomp-tid-hop.md) — hopping TIDs around seccomp filters | [ch16-seccomp-tid-hop](../dBPF-pocs/pocs/ch16-seccomp-tid-hop) |
| 17 | [chapter-17-acpi-wsmi-ping.md](act-3/chapter-17-acpi-wsmi-ping.md) — ACPI/WMI as a covert ping channel | [ch17-acpi-wsmi](../dBPF-pocs/pocs/ch17-acpi-wsmi) · [analog](../dBPF-pocs/pocs/ch17-acpi-wsmi-analog) |
| 18 | [chapter-18-ebpf-token-bypass.md](act-3/chapter-18-ebpf-token-bypass.md) — bypassing the eBPF token model | [ch18-token-bypass](../dBPF-pocs/pocs/ch18-token-bypass) |
| 19 | [chapter-19-the-new-reality.md](act-3/chapter-19-the-new-reality.md) — epilogue: the new reality | — |

## Relationship to siblings

`book_chapters/` is the **source of truth** for the manuscript. `_posts/` is the
**web-rendered form** published through Jekyll (front matter, permalinks, theming).
`dBPF-pocs/` is the **working companion code** — each chapter (except the preface
and the epilogue) has at least one runnable POC, and several have LSM, kprobe,
fentry, syscall, or analog variants that expand the same technique along a
different kernel surface.

When prose and code diverge, update the chapter here first, then propagate to
`_posts/` and, if the technique itself changed, to the corresponding POC.
