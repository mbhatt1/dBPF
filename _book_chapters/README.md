# book_chapters/

Canonical manuscript source for **The Diabolical eBPF Field Manual**, organized as a
five-act book (Acts I–IV of primitives plus a closing Act VII; Conclusion holding
the synthesis chapters). This tree is the source of truth for the prose; the Jekyll
site and companion code are derived views.

## Layout

- **`_book_chapters/`** (this directory); canonical manuscript, four-act structure,
  one file per chapter. Edit here first.
- **`_posts/`**; Jekyll-rendered web version of the same material (sibling content,
  web-formatted with front matter). Not the source of truth.
- **`../dBPF-pocs/`**; working companion code: runnable eBPF proof-of-concept programs,
  loaders, triggers, and the Python/Docker harness that verifies every claim.

## Act arc

- **Act I; Foundations.** Early primitives: mirroring, overlay/FUSE tricks, syscall
  shims, cgroup/NIC slips, silencing LSM telemetry.
- **Act II; Kernel Intrusion.** Device cgroups, keyrings, PID/inode cloaking, IRQ
  chaos, signed-driver swaps.
- **Act III; Total Control.** Scheduler impersonation, netns/VLAN ghosts, seccomp
  TID hops, token bypass.
- **Act IV; Cross-Boundary.** TPM unseal, bpf_token delegation, IMDS harvest.
- **Act VII; Conclusion.** The four synthesis chapters: what was demonstrated,
  the autopsy/taxonomy, skip accounting, and the defender playbook.

## Table of Contents

### Act 1; Foundational misuse

| # | Chapter | POC |
|---|---------|-----|
| 0 | [chapter-0-field-manual-preface.md](act-1/chapter-0-field-manual-preface.md); preface and framing |; |
| 1 | [chapter-1-the-mirror-controls.md](act-1/chapter-1-the-mirror-controls.md); mirroring control-plane state | [ch01-mirror-controls](../dBPF-pocs/pocs/ch01-mirror-controls) · [lsm](../dBPF-pocs/pocs/ch01-mirror-controls-lsm) |
| 2 | [chapter-2-the-overlayfs-trojan-horse.md](act-1/chapter-2-the-overlayfs-trojan-horse.md); overlayfs as a delivery vector | [ch02-overlayfs](../dBPF-pocs/pocs/ch02-overlayfs) · [lsm](../dBPF-pocs/pocs/ch02-overlayfs-lsm) |
| 3 | [chapter-3-the-fuse-audit-black-hole.md](act-1/chapter-3-the-fuse-audit-black-hole.md); FUSE as an audit blind spot | [ch03-fuse-blackhole](../dBPF-pocs/pocs/ch03-fuse-blackhole) · [fentry](../dBPF-pocs/pocs/ch03-fuse-blackhole-fentry) |
| 4 | [chapter-4-the-phantom-syscall.md](act-1/chapter-4-the-phantom-syscall.md); syscalls that leave no trace | [ch04-phantom-syscall](../dBPF-pocs/pocs/ch04-phantom-syscall) |
| 5 | [chapter-5-slipping-the-cgroup-leash.md](act-1/chapter-5-slipping-the-cgroup-leash.md); escaping cgroup constraints | [ch05-cgroup-leash](../dBPF-pocs/pocs/ch05-cgroup-leash) |
| 5b | [chapter-5b-the-ghost-nic.md](act-1/chapter-5b-the-ghost-nic.md); a NIC that isn't there | [ch05b-ghost-nic](../dBPF-pocs/pocs/ch05b-ghost-nic) |
| 6 | [chapter-6-silencing-selinux.md](act-1/chapter-6-silencing-selinux.md); muzzling SELinux telemetry | [ch06-silence-selinux](../dBPF-pocs/pocs/ch06-silence-selinux) · [lsm](../dBPF-pocs/pocs/ch06-silence-selinux-lsm) |

### Act 2; Privilege & namespace escalation

| # | Chapter | POC |
|---|---------|-----|
| 7 | [chapter-7-device-cgroup-houdini.md](act-2/chapter-7-device-cgroup-houdini.md); escaping device cgroup gates | [ch07-devcgroup-houdini](../dBPF-pocs/pocs/ch07-devcgroup-houdini) |
| 8 | [chapter-8-keyring-heist.md](act-2/chapter-8-keyring-heist.md); kernel keyring exfiltration | [ch08-keyring-heist](../dBPF-pocs/pocs/ch08-keyring-heist) · [kprobe](../dBPF-pocs/pocs/ch08-keyring-heist-kprobe) · [lsm](../dBPF-pocs/pocs/ch08-keyring-heist-lsm) |
| 9 | [chapter-9-pid-namespace-doppelg-nger.md](act-2/chapter-9-pid-namespace-doppelg-nger.md); PID namespace doppelgängers | [ch09-pid-doppel](../dBPF-pocs/pocs/ch09-pid-doppel) |
| 10 | [chapter-10-inode-cloak.md](act-2/chapter-10-inode-cloak.md); cloaking files at the inode layer | [ch10-inode-cloak](../dBPF-pocs/pocs/ch10-inode-cloak) |
| 11 | [chapter-11-irq-affinity-chaos.md](act-2/chapter-11-irq-affinity-chaos.md); weaponizing IRQ affinity | [ch11-irq-chaos](../dBPF-pocs/pocs/ch11-irq-chaos) |
| 12 | [chapter-12-ebpf-signed-driver-swap.md](act-2/chapter-12-ebpf-signed-driver-swap.md); swapping signed drivers | [ch12-signed-driver-swap](../dBPF-pocs/pocs/ch12-signed-driver-swap) · [lsm](../dBPF-pocs/pocs/ch12-signed-driver-swap-lsm) · [syscall](../dBPF-pocs/pocs/ch12-signed-driver-swap-syscall) |

### Act III; Total Control

| # | Chapter | POC |
|---|---------|-----|
| 14 | [chapter-14-sched-fifo-impersonator.md](act-3/chapter-14-sched-fifo-impersonator.md); impersonating SCHED_FIFO priority | [ch14-sched-fifo](../dBPF-pocs/pocs/ch14-sched-fifo) |
| 15 | [chapter-15-netns-vlan-ghost.md](act-3/chapter-15-netns-vlan-ghost.md); VLAN ghost across network namespaces | [ch15-netns-vlan-ghost](../dBPF-pocs/pocs/ch15-netns-vlan-ghost) |
| 16 | [chapter-16-seccomp-tid-hop.md](act-3/chapter-16-seccomp-tid-hop.md); hopping TIDs around seccomp filters | [ch16-seccomp-tid-hop](../dBPF-pocs/pocs/ch16-seccomp-tid-hop) |
| 18 | [chapter-18-ebpf-token-bypass.md](act-3/chapter-18-ebpf-token-bypass.md); bypassing the eBPF token model | [ch18-token-bypass](../dBPF-pocs/pocs/ch18-token-bypass) |

### Act IV; Cross-Boundary

| # | Chapter | POC |
|---|---------|-----|
| 23 | [chapter-23-tpm-unseal-heist.md](act-4/chapter-23-tpm-unseal-heist.md); reading plaintext at the post-unseal window | [ch23-tpm-unseal-heist](../dBPF-pocs/pocs/ch23-tpm-unseal-heist) |
| 24 | [chapter-24-the-token-hand-off.md](act-4/chapter-24-the-token-hand-off.md); bpf_token delegation via SCM_RIGHTS | [ch24-bpf-token-delegation](../dBPF-pocs/pocs/ch24-bpf-token-delegation) |
| 25 | [chapter-25-the-metadata-faucet.md](act-4/chapter-25-the-metadata-faucet.md); XDP IMDS credential capture | [ch25-imds-harvest](../dBPF-pocs/pocs/ch25-imds-harvest) |

### Act VII; Conclusion

| # | Chapter | POC |
|---|---------|-----|
| 19 | [chapter-19-the-new-reality.md](act-7/chapter-19-the-new-reality.md); synthesis: what was demonstrated |; |
| 20 | [chapter-20-the-autopsy-what-we-proved.md](act-7/chapter-20-the-autopsy-what-we-proved.md); autopsy: the taxonomy |; |
| 21 | [chapter-21-the-autopsy-what-refused-to-die.md](act-7/chapter-21-the-autopsy-what-refused-to-die.md); skip accounting |; |
| 22 | [chapter-22-the-defender-playbook.md](act-7/chapter-22-the-defender-playbook.md); defender playbook |; |

Chapters 13 and 17 were retired in the synthetic/analog cleanup; their real
primitives require x86 (RAPL) or ACPI hardware that the aarch64 test matrix does
not host. Their analog variants demonstrated nothing about the chapter's actual
target, so both chapter files and both PoC directories were removed. See the
cleanup entry in `../CHANGELOG.md` for the history.

## Relationship to siblings

`_book_chapters/` is the **source of truth** for the manuscript. `_posts/` is the
**web-rendered form** published through Jekyll. `../dBPF-pocs/` is the **working
companion code**; every chapter has at least one runnable PoC, and several
have LSM, kprobe, fentry, syscall, or analog variants that expand the same
technique along a different kernel surface.

When prose and code diverge, update the chapter here first, then propagate to
`_posts/` and, if the technique itself changed, to the corresponding PoC. The
`.audit/chapter-xref-audit.md` report (if present) enumerates known drift.
