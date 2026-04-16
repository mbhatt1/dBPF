---
layout: book
title: "The Taxonomy"
date: 2026-01-10
---

# The Taxonomy

> **See also**: [Full chapter with investigation notes]({{ site.baseurl }}/book/act-3/chapter-20-the-autopsy-what-we-proved.html) · [Chapter 21 — Skip Accounting]({{ site.baseurl }}/book/act-3/chapter-21-the-autopsy-what-refused-to-die.html) · [Chapter 22 — Defender Playbook]({{ site.baseurl }}/book/act-3/chapter-22-the-defender-playbook.html)

Every primitive in this book reduces to one of three motions: change the API return, rewrite the userspace buffer, copy the decision out of band. That is the result after nineteen POCs and thirteen clean `PROVEN` markers on linuxkit 6.12 aarch64. XDP looks different at first, but it is a specialization of the first motion — the API is the netdev rx path and the return is `XDP_DROP` or `XDP_TX`. Ringbuf-as-trigger looks different too, but it is a specialization of the third — the decision copied out of band is a kernel event, and a userspace racer converts that event into action. Once you see the three motions, the five classes fall out cleanly.

## Class I — Return-value override

The kernel's computation happened; the caller sees a different answer. Three implementations share this shape: `kretprobe + bpf_override_return` against a function on `/sys/kernel/debug/error_injection/list`, BPF LSM `fmod_ret` against an active security hook, and `XDP_DROP` at the driver rx path. Ch01 is the purest example — `cap_capable` and `selinux_file_permission` return forged to zero, marker `CH01_WEAPON_PROVEN`. Ch14 forges `sched_setscheduler` to pretend a `SCHED_FIFO` promotion succeeded. Ch18 forges the `bpf()` syscall return to bypass the token check entirely. The illusion lies to userspace consumers of the syscall return; kernel-side logic that runs later in the call chain is unaffected.

## Class II — Userspace buffer rewrite

The kernel writes a correct result into a userspace buffer, and a BPF program mutates the buffer in the narrow window between kernel write and userspace read, using `bpf_probe_write_user` from a return probe. Ch05 zeroes the `memory.current` readout for a cgroup so accounting looks clean after real allocation. Ch10 reproduces the 2016-era `d_reclen` swallow against `getdents64` on a modern CO-RE kernel — `before_count=4 after_count=2 hidden=2`, with `stat_still_works=yes` to prove the hidden entries are still on disk. The primitive needs a stable window: kernel has written, userspace has not yet been returned, the page is still mapped. `kretprobe` or `tp/syscalls/sys_exit_*` gives that window.

## Class III — Ringbuf exfiltration

Observation, not modification. A BPF program reads a kernel-internal structure that userspace could not otherwise see and copies it out-of-band through a ringbuf that the privileged loader drains. The victim syscall returns whatever it would have returned; the fact of the read is the primitive. Ch03 exfiltrates FUSE request metadata via fentry, bypassing the audit black hole. Ch04 leaks phantom-syscall fields. Ch09 cross-maps PID namespaces and confirms a host-PID kill. Ch11 builds a per-IRQ timing sidechannel with unique-event evidence. Ch16 reads a seccomp decision for a sibling TID — labeled `SIDECHANNEL` not `BYPASS` because seccomp's threat model explicitly excludes a privileged CAP_BPF sibling. Ch08 leaks keyring descriptions during `keyctl`. Six chapters, one motion.

## Class IV — Packet-path interception

XDP runs as a peer to the netdev, below the IP stack and below every userspace observer. `XDP_DROP` makes packets vanish before `tcpdump` on the host sees them; `XDP_TX` and `bpf_redirect_peer` reroute them across namespaces. Ch05b proves the covert-channel shape — packets dropped with `tcpdump=0` while ringbuf logs them for the loader. Ch15 proves cross-namespace reach — VLAN traffic redirected across a netns boundary via XDP peer. Because XDP executes in the driver's rx path or veth tx peer, captures taken above that layer do not see what happened.

## Class V — Kernel-event-triggered userspace racer

The most composite primitive in the book. A BPF program watches a kernel event — a kprobe fires, a tracepoint records a specific inode being touched — and emits to ringbuf. A privileged userspace racer drains the ringbuf and, on seeing the target event, wins a write race against the legitimate code path. Ch02 is the representative: ringbuf fires on `ovl_copy_up_one`, the racer writes a payload to the upper-layer inode before the container reads back, and `[ch02] PWNED path=/mnt/ovlbacking/upper/secret.txt bytes=N hits=M` lands on stdout. The class exists because BPF alone cannot win a write race — you need the BPF event channel and a userspace hand working in concert.

## Why the taxonomy matters for defenders

Detection patterns are cleaner when built against the class, not the chapter. A Class I signature is "syscall return disagrees with state readable via `/proc/self/status` or a follow-up check against `current->cred`" — the same signature catches ch01, ch06, ch07, ch14, and ch18. A Class II signature is "userspace buffer differs between kernel write and userspace read" — `bpf_probe_write_user` use is the loud artifact, and it catches ch05 and ch10 with one rule. A Class III signature is ringbuf drain accompanied by a load event against a kernel-internal symbol — one rule catches six chapters. Class IV wants link-layer captures taken from the XDP peer, not from above the driver. Class V wants ringbuf correlation with a userspace racer process doing writes on a shared inode. Five signatures cover the nineteen chapters. That is the payoff of writing the taxonomy down.

---

**Related material**
- Full chapter: [Chapter 20 — What We Proved: The Taxonomy]({{ site.baseurl }}/book/act-3/chapter-20-the-autopsy-what-we-proved.html)
- Companion chapters: [Ch 20]({{ site.baseurl }}/book/act-3/chapter-20-the-autopsy-what-we-proved.html), [Ch 21]({{ site.baseurl }}/book/act-3/chapter-21-the-autopsy-what-refused-to-die.html), [Ch 22]({{ site.baseurl }}/book/act-3/chapter-22-the-defender-playbook.html)
- Harness: `dBPF-pocs/harness/proof.py`
