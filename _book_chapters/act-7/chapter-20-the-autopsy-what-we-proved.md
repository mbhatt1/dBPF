---
layout: book
title: "Chapter 20: What We Proved; The Taxonomy"
date: 2026-01-10
---

# Chapter 20: What We Proved; The Taxonomy

> **See also**: [Blog post]({{ site.baseurl }}/the-taxonomy.html) · [Harness](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

> **Navigation**: [Chapter 20; Taxonomy]({{ site.baseurl }}/book/act-7/chapter-20-the-autopsy-what-we-proved.html) · [Chapter 21; Skip Accounting]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html) · [Chapter 22; Defender Playbook]({{ site.baseurl }}/book/act-7/chapter-22-the-defender-playbook.html)

Every primitive in this book reduces to one of three motions: change the API return, rewrite the userspace buffer, copy the decision out of band. That is the result after twenty-three POCs and twenty-two `PROVEN` markers across three kernels. XDP looks different at first, but it is a specialization of the first motion; the API is the netdev rx path and the return is `XDP_DROP` or `XDP_TX`. Ringbuf-as-trigger looks different too, but it is a specialization of the third; the decision copied out of band is a kernel event, and a userspace racer converts that event into action. Once you see the three motions, the five classes fall out cleanly.

**Final tally: 22 PROVEN across all environments, 1 SKIP (ch24; `CONFIG_BPF_TOKEN=n` on all available kernels), 0 failures.** The harness runs 23 POCs on the primary test environment (linuxkit 6.12.54 aarch64). 17 produce `_PROVEN` markers there; 3 (ch06 LSM, ch06o kprobe observer, ch12 LSM) skip on linuxkit and fire on the Fedora 42 aarch64 QEMU VM secondary; 2 (ch23 TPM unseal, ch25 IMDS via XDP) are PROVEN on the Ubuntu 6.17.0-29-generic aarch64 Lima VM. Chapter 21 accounts for every skip. This chapter walks the proven cases and organizes them.

Act 4 extended the scope along two axes without changing the taxonomy. The on-host primitives of Chapters 1–18 all manipulate state inside the running kernel's address space. Act 4 tested hardware-rooted key material that transits the kernel during TPM-backed trusted-key operations (ch23), off-host cloud-metadata credentials (ch25), and the delegated-capability boundary between a privileged process and an unprivileged client holding its token (ch24). All three fit the existing five classes: ch23 is Class III (ringbuf exfil, now of hardware-rooted bytes), ch25 is Class IV (packet-path interception, now at a cross-boundary address), ch24 is a threat-model subversion using Class III mechanics. No new class was needed.

## Class I; Return-value override

The kernel's computation happened; the caller sees a different answer. Three implementations share this shape: `kretprobe + bpf_override_return` against a function on `/sys/kernel/debug/error_injection/list`, BPF LSM `fmod_ret` against an active security hook, and `XDP_DROP` at the driver rx path.

Ch01 is the purest example; the POC attaches kprobe+kretprobe to `cap_capable`. `bpf_override_return` on `cap_capable` is silently no-op on linuxkit (the function is not on the error-injection list), so the POC upgraded to deliver `bpf_send_signal(SIGUSR1)` from the kretprobe when the observed deny lands on a targeted tgid. Marker: `CH01_WEAPON_PROVEN flips=N signals=N`. Ch14 forges `sched_setscheduler` to pretend a `SCHED_FIFO` promotion succeeded; `SCHED_WEAPON_PROVEN flips=N`. Ch18 forges the `getuid`/`geteuid` syscall return to bypass the token check; `TOKEN_FORGE_PROVEN uid_forges=N`; with the `gid=1001` tell still visible. Ch12 (LSM `fmod_ret` on `kernel_read_file`) fires only on Fedora 42 QEMU where module signature enforcement is live. Ch06 (LSM `fmod_ret` on SELinux hooks) also fires only on Fedora QEMU where SELinux is enforcing.

The framing matters: this class is an illusion against userspace consumers of the syscall return. Kernel-side logic that runs later in the call chain; a subsequent LSM check on `current->cred`, a VFS enforcement point; is unaffected. The override lies to the caller. It does not change what the kernel actually did.

## Class II; Userspace buffer rewrite

The kernel writes a correct result into a userspace buffer, and a BPF program mutates the buffer in the narrow window between kernel write and userspace read, using `bpf_probe_write_user` from a return probe.

Ch05 zeroes the `memory.current` readout for a cgroup so accounting looks clean after real allocation; `CH05_PROVEN before_usage=X after_usage=0 zeroed=yes`. Ch10 reproduces the 2016-era `d_reclen` swallow against `getdents64` on a modern CO-RE kernel; `CLOAK_PROVEN before_count=4 after_count=2 hidden=2 stat_still_works=yes`. The `stat_still_works=yes` field is the honesty field: the file is still on disk; only readdir is blind.

The primitive needs a stable window: kernel has written, userspace has not yet been returned, the page is still mapped. `kretprobe` or `tp/syscalls/sys_exit_*` gives that window.

When a BPF program using `bpf_probe_write_user` loads, the kernel emits a `pr_warn_ratelimited` dmesg message. `journalctl -k | grep bpf_probe_write_user` catches every Class II program load at zero cost. This is the loudest artifact in the book.

## Class III; Ringbuf exfiltration

Observation, not modification. A BPF program reads a kernel-internal structure that userspace could not otherwise see and copies it out-of-band through a ringbuf that the privileged loader drains. The victim syscall returns whatever it would have returned; the fact of the read is the primitive.

Ch03 exfiltrates FUSE request metadata via fentry, bypassing the audit black hole. Ch04 leaks phantom-syscall fields. Ch08/ch08k copy keyring descriptions during `key_task_permission`. Ch09 cross-maps PID namespaces and confirms a host-PID kill. Ch11 builds a per-IRQ timing sidechannel with unique-event evidence. Ch16 reads a seccomp decision for a sibling TID; labeled `SIDECHANNEL` not `BYPASS` because seccomp's threat model explicitly excludes a privileged `CAP_BPF` sibling.

Ch23 (Act 4) extends this to hardware-rooted key material: a kretprobe on `tpm2_unseal_trusted` copies plaintext key bytes out of the kernel's TPM unseal path to ringbuf. The kprobe attaches and entry intercept events fire on Ubuntu 6.17 aarch64; `CH23_PROVEN hook=attached kind=kprobe-on-tpm2_unseal_trusted sym-confirmed`. Full byte-capture requires a host with a boot-registered TPM backend.

Class III's unifying property: the kernel's access-control invariants hold perfectly. What leaks is confidentiality of kernel state to a peer process holding `CAP_BPF`. There is no mitigation at runtime once the program has loaded; mitigation must be at the load boundary.

Detection is genuinely hard. The difference between a Datadog agent attaching to a tracepoint to count syscalls and a malicious agent attaching to the same tracepoint to exfiltrate credentials is not visible in `bpftool` output. The true defense is at the next layer up: who is running the privileged ringbuf drainer, and what do they do with what they drain?

## Class IV; Packet-path interception

XDP runs as a peer to the netdev, below the IP stack and below every userspace observer. `XDP_DROP` makes packets vanish before `tcpdump` on the host sees them; `XDP_TX` and `bpf_redirect_peer` reroute them across namespaces. Because XDP executes in the driver's rx path, captures taken above that layer do not see what happened.

Ch05b proves the covert-channel shape; `GHOST_COVERT_CHANNEL_PROVEN dropped=2 tcpdump=0`. Ch15 proves cross-namespace reach; VLAN traffic redirected across a netns boundary via XDP peer; `VLAN_GHOST_CROSSNS_PROVEN redirect_count=N`.

Ch25 (Act 4) extends this to cloud-metadata credentials: an XDP program on `lo` (or eth0 on a real EC2 host) intercepts the IMDSv2 exchange and harvests access keys and session tokens; `CH25_PROVEN access_key_captures=1 token_captures=1 role=demo-role`. IMDSv2's hop-limit and PUT-then-GET defenses do not address an on-host attacker reading the wire before any hops are traversed.

The detection story for Class IV is more hopeful than for Class III. `bpftool net show` enumerates attached XDP programs by interface. Baseline diff against expected programs; alert on new ones. A one-minute continuous audit interval via `bpf()` syscall records catches even short-lived attaches.

## Class V; Kernel-event-triggered userspace racer

The most composite primitive in the book. A BPF program watches a kernel event and emits to ringbuf. A privileged userspace racer drains the ringbuf and, on seeing the target event, wins a write race against the legitimate code path.

Ch02 is the representative: ringbuf fires on `ovl_copy_up_one`, the racer writes a payload to the upper-layer inode before the container reads back; `[ch02] PWNED path=/mnt/ovlbacking/upper/secret.txt bytes=N hits=M`. The class exists because BPF alone cannot win a write race; you need the BPF event channel and a userspace hand working in concert. BPF cannot write to kernel page cache; `bpf_probe_write_user` is userspace only. The userspace racer cannot detect the exact moment of copy-up without the kprobe signal.

## Why the taxonomy matters for defenders

Detection patterns are cleaner when built against the class, not the chapter.

A Class I signature is "syscall return disagrees with state readable via `/proc/self/status` or a follow-up check against `current->cred`"; the same signature catches ch01, ch06, ch07, ch14, and ch18. A Class II signature is "bpf_probe_write_user loaded"; one dmesg grep catches ch05 and ch10 with one rule. A Class III signature is ringbuf drain accompanied by a load event against a kernel-internal symbol. Class IV wants link-layer captures taken from the XDP peer, not from above the driver. Class V wants ringbuf correlation with a userspace racer process doing writes on a shared inode.

Five signatures cover the twenty-two proven chapters. That is the payoff of writing the taxonomy down. Build rules against the patterns, not the instances.

## The four-category system

Every POC carries a `category` field classifying the honesty of what was demonstrated.

- **REAL** (16 POCs): hooks the actual kernel subsystem and can observe or mutate.
- **OBSERVER** (4 POCs): hooks the real subsystem but cannot mutate; the error-injection allowlist blocks `bpf_override_return`, or atomic context prevents it.
- **ILLUSION** (3 POCs): hooks the real syscall entry point but only forges the return value; kernel state unchanged.
- **ANALOG** (0 POCs): no analog variants are registered in the current manifest.

The category is orthogonal to the class. A Class I primitive can be `real` (ch01, ch12) or `illusion` (ch14, ch18, ch12s). A Class III primitive can be `real` (ch04, ch08k) or `observer` (ch03, ch06o). The category tells you how much to trust the demonstration; the class tells you what the primitive does.

## Master table

All 23 registered POCs, mapped to category, primitive class, and effect. Status is `effect_demonstrated` on linuxkit unless otherwise noted.

| POC | Category | Class | Effect (marker) | Notes |
|-----|----------|-------|-----------------|-------|
| ch01 | real | I | `CH01_WEAPON_PROVEN flips=N signals=N` | `bpf_send_signal(SIGUSR1)` on deny; override is no-op on linuxkit |
| ch02 | real | V | `[ch02] PWNED path=... bytes=... hits=...` | Overlayfs copy-up race |
| ch03 | observer | III | `CH03_PROVEN variant=fentry before=N after=M` | Audit record exfil; read-only |
| ch04 | real | III | `CH04_PROVEN leaked_fields=N` | Phantom-syscall field leakage |
| ch05 | real | II | `CH05_PROVEN ... zeroed=yes patched_events=N` | cgroup cpu.stat rewrite |
| ch05b | real | IV | `GHOST_COVERT_CHANNEL_PROVEN dropped=2 tcpdump=0` | XDP ghost NIC |
| ch06 | observer | I | `CH06_PROVEN` | **Skips on linuxkit** (no SELinux); fires on Fedora 42 QEMU |
| ch06o | observer | III | `CH06_PROVEN hook=...` | SELinux kprobe observer; skips if SELinux absent |
| ch07 | real | I | `CH07_WEAPON_PROVEN ...` | devcgroup kprobe |
| ch08 | real | III | `CH08_PROVEN` | Keyring heist kprobe |
| ch08k | real | III | `CH08_CONCEPT_PROVEN events=N` | Kept kprobe variant |
| ch09 | real | III | `CH09_PROVEN host_pid=N mapped=yes` | Cross-namespace PID mapping |
| ch10 | real | II | `CLOAK_PROVEN before_count=4 after_count=2 hidden=2` | d_reclen swallow |
| ch11 | real | III | `CH11_PROVEN events=N unique=M per_event_timing=yes` | Per-IRQ timing sidechannel |
| ch12 | real | I | `CH12_PROVEN` | **Skips on linuxkit** (no module sig enforcement); fires on Fedora 42 QEMU |
| ch12s | illusion | I | `CH12_CONCEPT_PROVEN syscall_override_landed=yes module_actually_loaded=no` | finit_module return forge; aarch64-only |
| ch14 | illusion | I | `SCHED_WEAPON_PROVEN flips=N` | sched_setscheduler return forge; aarch64-only |
| ch15 | real | IV | `VLAN_GHOST_CROSSNS_PROVEN redirect_count=N` | Cross-namespace VLAN redirect |
| ch16 | observer | III | `SECCOMP_SIDECHANNEL_PROVEN events=N` | Seccomp decision exfil |
| ch18 | illusion | I | `TOKEN_FORGE_PROVEN uid_forges=N` | getuid return forge; aarch64-only |
| ch23 | real | III | `CH23_PROVEN hook=attached kind=kprobe-on-tpm2_unseal_trusted sym-confirmed` | **PROVEN** on Ubuntu 6.17 Lima VM; skips on linuxkit (no TPM symbol). Full byte-capture requires boot-registered TPM backend |
| ch24 | real |; | `CH24_SKIP` | **SKIP in all environments**; `CONFIG_BPF_TOKEN=n` on Ubuntu 6.17 and Fedora 6.17; BPF_TOKEN_CREATE returns ENOSYS |
| ch25 | real | IV | `CH25_PROVEN access_key_captures=1 token_captures=1 role=demo-role` | **PROVEN** on Ubuntu 6.17 Lima VM via XDP mock IMDSv2 on `lo`; skips on linuxkit |

**Category counts**: real=16, observer=4, illusion=3, analog=0.
**Status counts**: 17 on linuxkit; 3 (ch06, ch06o, ch12) on Fedora 42 QEMU; 2 (ch23, ch25) on Ubuntu 6.17 Lima VM; 1 SKIP (ch24); 0 failures.
**Across-environment total: 22 PROVEN, 1 SKIP.**

---

**Related material**
- Companion: [Ch 21 Skip Accounting]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html), [Ch 22 Defender Playbook]({{ site.baseurl }}/book/act-7/chapter-22-the-defender-playbook.html)
- Harness: `dBPF-pocs/harness/proof.py`
