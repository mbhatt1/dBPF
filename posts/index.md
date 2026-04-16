---
permalink: /posts/
layout: book
title: "All Posts"
---

<p class="posts-index-banner"><strong>15 active posts</strong> · <strong>6 retired posts</strong> · last updated {{ site.time | date: "%B %Y" }}</p>

Blog-post versions of the book chapters. Shorter and web-formatted; the expanded investigation notes live in [the book]({{ site.baseurl }}/book/). Each entry links to its post, its companion chapter, and the primitive's harness entry where one exists.

## January 2025

<details class="posts-month" open markdown="1">
<summary>2 posts · framing and the first capability-check primitive</summary>

| Date | Post | Chapter | Read |
| --- | --- | --- | --- |
| 2025-01-01 | [Chapter 0: What CAP_BPF Actually Permits]({{ site.baseurl }}/chapter-0-field-manual-preface.html) | [Chapter 0]({{ site.baseurl }}/book/act-1/chapter-0-field-manual-preface.html) | 3 min |
| 2025-01-31 | [The Mirror Controls]({{ site.baseurl }}/the-mirror-controls.html) | [Chapter 1]({{ site.baseurl }}/book/act-1/chapter-1-the-mirror-controls.html) | 4 min |

</details>

## February 2025

<details class="posts-month" open markdown="1">
<summary>8 posts · Act I wraps and Act II opens — overlayfs, audit, syscall shims, cgroup/NIC slips, PID-ns, dirent hiding, IRQ chaos</summary>

| Date | Post | Chapter | Read |
| --- | --- | --- | --- |
| 2025-02-01 | [The OverlayFS Trojan Horse]({{ site.baseurl }}/the-overlayfs-trojan-horse.html) | [Chapter 2]({{ site.baseurl }}/book/act-1/chapter-2-the-overlayfs-trojan-horse.html) | 4 min |
| 2025-02-02 | [The FUSE Audit Black-Hole]({{ site.baseurl }}/the-fuse-audit-black-hole.html) | [Chapter 3]({{ site.baseurl }}/book/act-1/chapter-3-the-fuse-audit-black-hole.html) | 4 min |
| 2025-02-03 | [The Phantom Syscall]({{ site.baseurl }}/the-phantom-syscall.html) | [Chapter 4]({{ site.baseurl }}/book/act-1/chapter-4-the-phantom-syscall.html) | 4 min |
| 2025-02-04 | [The Ghost NIC]({{ site.baseurl }}/the-ghost-nic.html) | [Chapter 5b]({{ site.baseurl }}/book/act-1/chapter-5-the-ghost-nic.html) | 4 min |
| 2025-02-05 | [Slipping the Cgroup Leash]({{ site.baseurl }}/slipping-the-cgroup-leash.html) | [Chapter 5]({{ site.baseurl }}/book/act-1/chapter-5-slipping-the-cgroup-leash.html) | 4 min |
| 2025-02-09 | [PID Namespace Doppelgänger]({{ site.baseurl }}/pid-namespace-doppelg-nger.html) | [Chapter 9]({{ site.baseurl }}/book/act-2/chapter-9-pid-namespace-doppelg-nger.html) | 5 min |
| 2025-02-10 | [Inode Cloak]({{ site.baseurl }}/inode-cloak.html) | [Chapter 10]({{ site.baseurl }}/book/act-2/chapter-10-inode-cloak.html) | 6 min |
| 2025-02-11 | [IRQ Affinity Chaos]({{ site.baseurl }}/irq-affinity-chaos.html) | [Chapter 11]({{ site.baseurl }}/book/act-2/chapter-11-irq-affinity-chaos.html) | 6 min |

</details>

## March 2025

<details class="posts-month" open markdown="1">
<summary>1 post · scheduler return-value forge</summary>

| Date | Post | Chapter | Read |
| --- | --- | --- | --- |
| 2025-03-15 | [SCHED_FIFO Impersonator]({{ site.baseurl }}/sched-fifo-impersonator.html) | [Chapter 14]({{ site.baseurl }}/book/act-3/chapter-14-sched-fifo-impersonator.html) | 4 min |

</details>

## April 2025

<details class="posts-month" open markdown="1">
<summary>2 posts · cross-namespace XDP redirect and seccomp sidechannel</summary>

| Date | Post | Chapter | Read |
| --- | --- | --- | --- |
| 2025-04-15 | [NetNS VLAN Ghost]({{ site.baseurl }}/netns-vlan-ghost.html) | [Chapter 15]({{ site.baseurl }}/book/act-3/chapter-15-netns-vlan-ghost.html) | 6 min |
| 2025-04-20 | [Seccomp TID Hop]({{ site.baseurl }}/seccomp-tid-hop.html) | [Chapter 16]({{ site.baseurl }}/book/act-3/chapter-16-seccomp-tid-hop.html) | 5 min |

</details>

## May 2025

<details class="posts-month" open markdown="1">
<summary>1 post · the canonical wrong-enforcement-point bug, reimplemented with a kretprobe</summary>

| Date | Post | Chapter | Read |
| --- | --- | --- | --- |
| 2025-05-09 | [eBPF Token Bypass]({{ site.baseurl }}/ebpf-token-bypass.html) | [Chapter 18]({{ site.baseurl }}/book/act-3/chapter-18-ebpf-token-bypass.html) | 5 min |

</details>

## December 2025

<details class="posts-month" open markdown="1">
<summary>1 post · closing ledger</summary>

| Date | Post | Chapter | Read |
| --- | --- | --- | --- |
| 2025-12-31 | [Epilogue: What This Book Actually Demonstrated]({{ site.baseurl }}/epilogue-the-new-reality.html) | [Chapter 19]({{ site.baseurl }}/book/act-3/chapter-19-the-new-reality.html) | 4 min |

</details>

## Retired posts

<details class="posts-retired" markdown="1">
<summary>Six posts that used to live here but no longer do. Their book chapters remain; the posts don't.</summary>

These posts described POCs that couldn't fire on the test kernel; their book chapters remain for the primitive shape. See [Chapter 21]({{ site.baseurl }}/book/act-3/chapter-21-the-autopsy-what-refused-to-die.html) for the full skip accounting.

| Retired post | Retained chapter |
| --- | --- |
| `silencing-selinux` | [Chapter 6 — Silencing SELinux]({{ site.baseurl }}/book/act-1/chapter-6-silencing-selinux.html) |
| `device-cgroup-houdini` | [Chapter 7 — Device-cgroup Houdini]({{ site.baseurl }}/book/act-2/chapter-7-device-cgroup-houdini.html) |
| `keyring-heist` | [Chapter 8 — Keyring Heist]({{ site.baseurl }}/book/act-2/chapter-8-keyring-heist.html) |
| `signed-driver-swap` | [Chapter 12 — eBPF Signed-Driver Swap]({{ site.baseurl }}/book/act-2/chapter-12-ebpf-signed-driver-swap.html) |
| `powercap-override` | [Chapter 13 — Powercap Override]({{ site.baseurl }}/book/act-2/chapter-13-powercap-override.html) |
| `acpi-wsmi-ping` | [Chapter 17 — ACPI WSMI Ping]({{ site.baseurl }}/book/act-3/chapter-17-acpi-wsmi-ping.html) |

</details>
