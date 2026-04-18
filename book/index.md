---
permalink: /book/
layout: book
title: "Book Index"
---

<p class="book-index-banner"><strong>24 chapters</strong> · <strong>13 proven effects</strong> · <strong>6 honest skips</strong> · <strong>5 synthesis chapters</strong> · <strong>~84 minutes</strong> total reading time</p>

Twenty-four chapters across three acts. One reproducible harness, one kernel (6.12.54-linuxkit aarch64), one honest ledger of what fired and what didn't. Chapters stand alone; read Chapter 0 first if you have never met `CAP_BPF`, then read Chapter 20 for the five-class taxonomy that organizes the rest.

<aside class="book-index-callout" markdown="1">
**If you read one chapter, read this.**
[**Chapter 20: What We Proved — The Taxonomy**]({{ site.baseurl }}/book/act-7/chapter-20-the-autopsy-what-we-proved.html) is the durable artifact of the book. Thirteen primitives produced proof markers on the test kernel; this chapter sorts them into five classes (return-value override, userspace-buffer rewrite, out-of-band copy, XDP packet-path interception, ringbuf-as-trigger) and names each class's blast radius. Every other chapter is either evidence feeding the taxonomy or an honest record of what the kernel refused. If you are deciding whether to grant `CAP_BPF` to a workload, this is the chapter that tells you what you are granting.
</aside>

Status legend:

- **proven** — BEFORE/AFTER proof marker printed under the harness on 6.12 aarch64.
- **skip** — BPF code loads and attaches cleanly, but the enforcement point, symbol, or subsystem this primitive needed was not present on the test kernel. Skip reasoning in Chapter 21; workaround variants are listed there and in [`dBPF-pocs/`](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs).
- **synthesis** — meta-chapter: preface, taxonomy, skip accounting, or defender playbook. No standalone POC.

## Act I — Foundations

| # | Chapter | What it shows | Status | Read |
| --- | --- | --- | --- | --- |
| 0 | [Chapter 0: What CAP_BPF Actually Permits]({{ site.baseurl }}/book/act-1/chapter-0-field-manual-preface.html) | Framing. What the capability is, what the book covers, what it refuses to claim. | synthesis | 2 min |
| 1 | [Chapter 1: The Mirror Controls]({{ site.baseurl }}/book/act-1/chapter-1-the-mirror-controls.html) | Kprobe on `cap_capable` as a capability-check observation channel, and why `bpf_override_return` against it silently no-ops on stock kernels. | proven | 4 min |
| 2 | [Chapter 2: The OverlayFS Trojan Horse]({{ site.baseurl }}/book/act-1/chapter-2-the-overlayfs-trojan-horse.html) | The `ovl_copy_up_one` window as a signal for a userspace racer that touches the upper file before overlayfs finishes wiring it in. | proven | 5 min |
| 3 | [Chapter 3: The FUSE Audit Black-Hole]({{ site.baseurl }}/book/act-1/chapter-3-the-fuse-audit-black-hole.html) | Why the classic override-against-`audit_log_start` trick is inert on stock kernels, and what a FUSE-backed suppression channel looks like when you give up on the override. | proven | 4 min |
| 4 | [Chapter 4: The Phantom Syscall]({{ site.baseurl }}/book/act-1/chapter-4-the-phantom-syscall.html) | Tail-called BPF walking `task_struct` from a syscall kprobe: what the verifier accepts and what it refuses. | proven | 4 min |
| 5 | [Chapter 5: Slipping the Cgroup Leash]({{ site.baseurl }}/book/act-1/chapter-5-slipping-the-cgroup-leash.html) | Rewriting `cpu.stat` reads on exit so the orchestrator reads the numbers you want it to read. | proven | 2 min |
| 5b | [Chapter 5b: The Ghost NIC]({{ site.baseurl }}/book/act-1/chapter-5b-the-ghost-nic.html) | XDP as a covert channel on UDP/31337: packets fly cleanly past `ip`, `ifconfig`, and `netstat`. | proven | 2 min |
| 6 | [Chapter 6: Silencing SELinux]({{ site.baseurl }}/book/act-1/chapter-6-silencing-selinux.html) | The natural hook needs SELinux in enforcing mode; linuxkit runs permissive. The synthetic LSM variant fires. | skip | 1 min |

Act I total: **24 min**.

## Act II — Kernel Intrusion

| # | Chapter | What it shows | Status | Read |
| --- | --- | --- | --- | --- |
| 7 | [Chapter 7: Device-cgroup Houdini]({{ site.baseurl }}/book/act-2/chapter-7-device-cgroup-houdini.html) | Why a pure "flip deny to allow" LSM program cannot see an unprivileged `mknod` — the capability check runs before the LSM hook. | skip | 2 min |
| 8 | [Chapter 8: Keyring Heist]({{ site.baseurl }}/book/act-2/chapter-8-keyring-heist.html) | When LSM BTF exposes `struct key` as a forward declaration, drop to a `key_task_permission` kprobe and read the payload via CO-RE. | skip | 3 min |
| 9 | [Chapter 9: PID Namespace Doppelgänger]({{ site.baseurl }}/book/act-2/chapter-9-pid-namespace-doppelg-nger.html) | `sched_process_fork` raw tracepoint recovers host PID + namespace PID in one event. `kill` from the host lands in the container. | proven | 3 min |
| 10 | [Chapter 10: Inode Cloak]({{ site.baseurl }}/book/act-2/chapter-10-inode-cloak.html) | Rewriting `d_reclen` on `getdents64` exit so `ls`, `find`, and Python all stride right over the hidden names. Open-by-path still works. | proven | 3 min |
| 11 | [Chapter 11: IRQ Affinity Chaos]({{ site.baseurl }}/book/act-2/chapter-11-irq-affinity-chaos.html) | Three overlapping kprobes along the IRQ dispatch ladder, with honest accounting of why the override fantasy dies at the verifier on 6.12. | proven | 4 min |
| 12 | [Chapter 12: eBPF Signed-Driver Swap]({{ site.baseurl }}/book/act-2/chapter-12-ebpf-signed-driver-swap.html) | Forging the return of `finit_module` — a userspace illusion, not an actual module load. Natural LSM hook inert; syscall kretprobe variant proves the primitive. | skip | 4 min |
| 13 | [Chapter 13: Powercap Override]({{ site.baseurl }}/book/act-2/chapter-13-powercap-override.html) | Intel RAPL is x86-only. What the override would look like on x86, plus a userspace-analog that runs on aarch64. | skip | 4 min |

Act II total: **23 min**.

## Act III — Total Control

| # | Chapter | What it shows | Status | Read |
| --- | --- | --- | --- | --- |
| 14 | [Chapter 14: SCHED_FIFO Impersonator]({{ site.baseurl }}/book/act-3/chapter-14-sched-fifo-impersonator.html) | `__arm64_sys_sched_setscheduler` return-value forge: `orig_ret=-1 flipped=1` and `chrt` reports success. | proven | 3 min |
| 15 | [Chapter 15: NetNS VLAN Ghost]({{ site.baseurl }}/book/act-3/chapter-15-netns-vlan-ghost.html) | XDP plus `bpf_redirect_map` into a devmap slot whose target ifindex lives in another network namespace. Cross-ns covert forwarding. | proven | 4 min |
| 16 | [Chapter 16: Seccomp TID Hop]({{ site.baseurl }}/book/act-3/chapter-16-seccomp-tid-hop.html) | A kprobe on `__secure_computing` gets a free pre/post decision trace for every seccomp policy on the host. The literal TID hop is refused by the verifier; the sidechannel is not. | proven | 4 min |
| 17 | [Chapter 17: ACPI WSMI Ping]({{ site.baseurl }}/book/act-3/chapter-17-acpi-wsmi-ping.html) | Docker Desktop's aarch64 kernel has no ACPI interpreter. `request_firmware` is the same-shape analog that exists. | skip | 3 min |
| 18 | [Chapter 18: eBPF Token Bypass]({{ site.baseurl }}/book/act-3/chapter-18-ebpf-token-bypass.html) | Two kretprobes on `getuid`/`geteuid`, both in the error-injection allowlist. `id` prints `0`, `whoami` prints `root`, `current->cred` is unchanged. | proven | 4 min |
| 19 | [Chapter 19: What This Book Actually Demonstrated]({{ site.baseurl }}/book/act-7/chapter-19-the-new-reality.html) | Line under the ledger: 13 fired, 6 skipped, 0 CVEs, 0 verifier bugs, 0 escalations without CAP_BPF. | synthesis | 3 min |
| 20 | [Chapter 20: What We Proved — The Taxonomy]({{ site.baseurl }}/book/act-7/chapter-20-the-autopsy-what-we-proved.html) | The five-class taxonomy (return-value override, buffer rewrite, out-of-band copy, XDP interception, ringbuf-as-trigger). The durable artifact of the book. | synthesis | 6 min |
| 21 | [Chapter 21: Skip Accounting — Primitives That Needed Another Kernel]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html) | Six skips, three refusal shapes (inactive enforcement, missing BTF, absent subsystem), and the kernels on which each would fire. | synthesis | 5 min |
| 22 | [Chapter 22: The Defender Playbook]({{ site.baseurl }}/book/act-7/chapter-22-the-defender-playbook.html) | Seven operational steps mapped to the five primitive classes. Start at step 1: inventory `CAP_BPF`. | synthesis | 5 min |

Act III total: **37 min**.

## Skips, explained

<details class="book-index-skips" markdown="1">
<summary>Six primitives did not fire on the test kernel. Click for the one-line reason each.</summary>

| Chapter | Why it skipped |
| --- | --- |
| [Chapter 6: Silencing SELinux]({{ site.baseurl }}/book/act-1/chapter-6-silencing-selinux.html) | linuxkit 6.12 runs SELinux permissive, so there was no denial to flip. Fires on RHEL/Fedora/Amazon Linux with `setenforce 1`. |
| [Chapter 7: Device-cgroup Houdini]({{ site.baseurl }}/book/act-2/chapter-7-device-cgroup-houdini.html) | `CAP_MKNOD` is checked in `do_mknodat()` before the LSM hook runs; the program never sees an unprivileged request to flip. LSM variant against `devcgroup_inode_permission` fires. |
| [Chapter 8: Keyring Heist]({{ site.baseurl }}/book/act-2/chapter-8-keyring-heist.html) | LSM BTF exposed `struct key` as a forward declaration (`arg0 type FWD is not a struct`). Kprobe variant on `key_task_permission` fires. |
| [Chapter 12: eBPF Signed-Driver Swap]({{ site.baseurl }}/book/act-2/chapter-12-ebpf-signed-driver-swap.html) | `CONFIG_MODULE_SIG_FORCE` is off on linuxkit; nothing was checking signatures, so there was nothing to flip. Syscall-kretprobe analog fires. |
| [Chapter 13: Powercap Override]({{ site.baseurl }}/book/act-2/chapter-13-powercap-override.html) | Intel RAPL is x86-only. None of the powercap symbols exist on aarch64 linuxkit. Userspace sensor analog fires. |
| [Chapter 17: ACPI WSMI Ping]({{ site.baseurl }}/book/act-3/chapter-17-acpi-wsmi-ping.html) | Docker Desktop's aarch64 kernel has no ACPI interpreter. `request_firmware` analog fires on the same platform. |

Full accounting and the kernels on which each of these six fires: [Chapter 21: Skip Accounting — Primitives That Needed Another Kernel]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html).

</details>

---

Blog-post versions of the chapters — same material, shorter, web-formatted — are indexed at [`/posts/`]({{ site.baseurl }}/posts/). The runnable POCs live in [`dBPF-pocs/`](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs). The harness that produces the proof markers is [`dBPF-pocs/harness/proof.py`](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py).
