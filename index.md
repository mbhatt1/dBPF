---
layout: book
title: "dBPF — a modern-kernel eBPF primitive catalogue"
permalink: /
---

This book is a catalogue of what `CAP_BPF` plus `CAP_PERFMON` (or `CAP_SYS_ADMIN`) actually permits on a modern aarch64 Linux kernel. Every chapter ships with a reproducible POC that runs under a Docker harness, a BEFORE/AFTER line on stdout, and an honest note when the primitive did not fire on the test kernel. Nothing here is a zero-day, an escalation from unprivileged, or a verifier bug. Read [Chapter 0: What CAP_BPF Actually Permits]({{ site.baseurl }}/book/act-1/chapter-0-field-manual-preface.html) first — it pins down the threat model, the non-claims, and how to read the rest of the catalogue.

## Start here

- [Chapter 20: What We Proved — The Taxonomy]({{ site.baseurl }}/book/act-7/chapter-20-the-autopsy-what-we-proved.html): five primitive classes, three motions.
- [Chapter 21: Skip Accounting — Primitives That Needed Another Kernel]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html): what didn't fire and why.
- [Chapter 22: The Defender Playbook]({{ site.baseurl }}/book/act-7/chapter-22-the-defender-playbook.html): inventory, restrict, baseline, audit.

## Act I — Foundations

0. [Chapter 0: What CAP_BPF Actually Permits]({{ site.baseurl }}/book/act-1/chapter-0-field-manual-preface.html) — threat model, non-claims, and how to read this book.
1. [Chapter 1: The Mirror Controls]({{ site.baseurl }}/book/act-1/chapter-1-the-mirror-controls.html) — `cap_capable` as an observation channel when override-return refuses to fire.
2. [Chapter 2: The OverlayFS Trojan Horse]({{ site.baseurl }}/book/act-1/chapter-2-the-overlayfs-trojan-horse.html) — forging upperdir writes the lowerdir never sees.
3. [Chapter 3: The FUSE Audit Black-Hole]({{ site.baseurl }}/book/act-1/chapter-3-the-fuse-audit-black-hole.html) — userspace filesystems as a bypass for in-kernel audit.
4. [Chapter 4: The Phantom Syscall]({{ site.baseurl }}/book/act-1/chapter-4-the-phantom-syscall.html) — tracepoint-driven syscall behaviour without touching the syscall table.
5. [Chapter 5: Slipping the Cgroup Leash]({{ site.baseurl }}/book/act-1/chapter-5-slipping-the-cgroup-leash.html) — teaching the kernel to miscount CPU accounting.
5b. [Chapter 5b: The Ghost NIC]({{ site.baseurl }}/book/act-1/chapter-5b-the-ghost-nic.html) — sock_ops and XDP as a phantom interface invisible to `ip link`.
6. [Chapter 6: Silencing SELinux]({{ site.baseurl }}/book/act-1/chapter-6-silencing-selinux.html) — AVC hook that does not fire on the test kernel (see Chapter 21).

## Act II — Kernel Intrusion

7. [Chapter 7: Device-cgroup Houdini]({{ site.baseurl }}/book/act-2/chapter-7-device-cgroup-houdini.html) — slipping past device-cgroup allow/deny enforcement.
8. [Chapter 8: Keyring Heist]({{ site.baseurl }}/book/act-2/chapter-8-keyring-heist.html) — reading keyring payloads that were never meant to leave the kernel.
9. [Chapter 9: PID Namespace Doppelgänger]({{ site.baseurl }}/book/act-2/chapter-9-pid-namespace-doppelg-nger.html) — impersonating PIDs across namespace boundaries.
10. [Chapter 10: Inode Cloak]({{ site.baseurl }}/book/act-2/chapter-10-inode-cloak.html) — the `d_reclen` swallow trick for hiding directory entries.
11. [Chapter 11: IRQ Affinity Chaos]({{ site.baseurl }}/book/act-2/chapter-11-irq-affinity-chaos.html) — steering interrupts away from the cores that would notice.
12. [Chapter 12: eBPF Signed-Driver Swap]({{ site.baseurl }}/book/act-2/chapter-12-ebpf-signed-driver-swap.html) — substituting driver behaviour without touching the signed module.
13. [Chapter 13: Powercap Override]({{ site.baseurl }}/book/act-2/chapter-13-powercap-override.html) — rewriting the energy ceiling the firmware thought it owned.

## Act III — Total Control

14. [Chapter 14: SCHED_FIFO Impersonator]({{ site.baseurl }}/book/act-3/chapter-14-sched-fifo-impersonator.html) — claiming realtime priority without the paperwork.
15. [Chapter 15: NetNS VLAN Ghost]({{ site.baseurl }}/book/act-3/chapter-15-netns-vlan-ghost.html) — VLAN-tagged exfil across network namespaces.
16. [Chapter 16: Seccomp TID Hop]({{ site.baseurl }}/book/act-3/chapter-16-seccomp-tid-hop.html) — escaping a seccomp filter by hopping threads.
17. [Chapter 17: ACPI WSMI Ping]({{ site.baseurl }}/book/act-3/chapter-17-acpi-wsmi-ping.html) — talking to firmware through a path the LSM never learned to watch.
18. [Chapter 18: eBPF Token Bypass]({{ site.baseurl }}/book/act-3/chapter-18-ebpf-token-bypass.html) — what the token model actually gates and what it does not.
19. [Chapter 19: What This Book Actually Demonstrated]({{ site.baseurl }}/book/act-7/chapter-19-the-new-reality.html) — the closing argument before the autopsy.

### Synthesis

20. [Chapter 20: What We Proved — The Taxonomy]({{ site.baseurl }}/book/act-7/chapter-20-the-autopsy-what-we-proved.html) — five primitive classes, three motions, cross-referenced to every firing chapter.
21. [Chapter 21: Skip Accounting — Primitives That Needed Another Kernel]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html) — the six primitives that refused to fire, with the kernel-environment reason for each.
22. [Chapter 22: The Defender Playbook]({{ site.baseurl }}/book/act-7/chapter-22-the-defender-playbook.html) — inventory, restrict, baseline, audit.

## The harness

Every claim in this catalogue runs out of [`dBPF-pocs/harness/proof.py`](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py). The harness builds each POC, attaches it, triggers the primitive, and records both the BEFORE/AFTER lines and any verifier refusals or missing hooks. One-command reproduction:

```
docker run --rm -it --privileged --pid=host \
  -v /sys:/sys -v /sys/kernel/debug:/sys/kernel/debug -v /sys/fs/bpf:/sys/fs/bpf \
  -v $PWD/dBPF-pocs:/w -w /w \
  dbpf-harness:latest python3 /w/harness/proof.py
```

## Scope

- This book does not document zero-days, privilege escalation without `CAP_BPF`, or verifier bugs. Remove the capability from the threat model and every chapter stops working.
- Every chapter was reproduced on kernel 6.12.54-linuxkit aarch64 via Docker Desktop on macOS. Other kernels may expose more — see [Chapter 21: Skip Accounting — Primitives That Needed Another Kernel]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html) for the primitives that did not fire here and the kernel conditions they would need.
