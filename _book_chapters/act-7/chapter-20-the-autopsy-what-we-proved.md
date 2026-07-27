---
layout: book
title: "Chapter 20: What We Proved; The Taxonomy"
date: 2026-01-10
---

# Chapter 20: What We Proved; The Taxonomy

> **See also**: [Blog post]({{ site.baseurl }}/the-taxonomy.html) · [Harness](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

> **Navigation**: [Chapter 20; Taxonomy]({{ site.baseurl }}/book/act-7/chapter-20-the-autopsy-what-we-proved.html) · [Chapter 21; Skip Accounting]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html) · [Chapter 22; Defender Playbook]({{ site.baseurl }}/book/act-7/chapter-22-the-defender-playbook.html)

Every primitive in this book reduces to one of three motions: change the API return, rewrite the userspace buffer, copy the decision out of band. That is the result after 26 registered PoCs, 25 of which reproduce in the reference environment. XDP looks different at first, but it is a specialization of the first motion — the API is the netdev rx path and the return is `XDP_DROP` or `XDP_TX`. Ringbuf-as-trigger looks different too, but it is a specialization of the third — the decision copied out of band is a kernel event, and a userspace racer converts that event into action. Once you see the three motions, the five classes fall out cleanly.

**The tally: 26 registered PoCs — real=15, observer=8, illusion=3, analog=0 — of which 25 reproduce in the reference environment (Ubuntu 6.17.0-29-generic aarch64) and 1 skips.** The skip is ch24, whose reference kernel is built with `CONFIG_BPF_TOKEN=n`. Chapter 21 accounts for the skip and for the primitives whose reproduced result depends on the surface being present. This chapter walks the reproduced cases and organizes them.

Act 4 extended the scope along two axes without changing the taxonomy. The on-host primitives of Chapters 1–18 all manipulate state inside the running kernel's address space. Act 4 added hardware-rooted key material that transits the kernel during TPM-backed trusted-key operations (ch23), off-host cloud-metadata credentials (ch25), and the delegated-capability boundary between a privileged process and an unprivileged client holding its token (ch24). All three fit the existing five classes: ch23 is Class III (a kprobe on the TPM unseal path — attachment and entry-intercept events reproduce; capturing plaintext key bytes needs a boot-registered TPM backend), ch25 is Class IV (packet-path interception, now at a cross-boundary address), and ch24 is a threat-model subversion built on Class III mechanics. No new class was needed.

## Class I; Return-value override

The kernel did the work; the caller got lied to about the result. That is the cleanest summary of Class I, and it is also what makes the primitives in this class feel counterintuitive at first. Nothing went wrong inside the kernel. The kernel's data structures are correct. The security checks ran normally. The caller just received a different return value than the computation produced.

Three implementations share this shape: `kretprobe + bpf_override_return` against a function on `/sys/kernel/debug/error_injection/list`, BPF LSM `fmod_ret` against an active security hook, and `XDP_DROP` at the driver rx path.

Ch01 is the canonical Class I target: it attaches kprobe+kretprobe to `cap_capable`. Whether `bpf_override_return` actually flips the result depends on the kernel — the override lands only if `cap_capable` is on that kernel's error-injection allowlist. Where it is not, the primitive falls back to signal delivery: `bpf_send_signal(SIGUSR1)` from the kretprobe when an observed deny lands on a targeted tgid. Marker: `CH01_WEAPON_PROVEN flips=N signals=N`, and the honest `flips=0` case says the override was a no-op on that kernel. The real capability flip is what the LSM `fmod_ret` variant does where an LSM hook is active. Ch14 forges `sched_setscheduler` to pretend a `SCHED_FIFO` promotion succeeded (`SCHED_WEAPON_PROVEN flips=N`). Ch18 forges the `getuid`/`geteuid` syscall return to bypass a token check (`TOKEN_FORGE_PROVEN uid_forges=N`), leaving the `gid=1001` tell visible. Ch12 (LSM `fmod_ret` on `kernel_read_file`) and ch06 (LSM `fmod_ret` on SELinux hooks) reproduce as registered, but only flip a *real* refusal where module-signature enforcement or SELinux enforcing is actually live; ch06s is the synthetic scaffold that manufactures the condition when it is not.

The framing matters: this class is an illusion against userspace consumers of the syscall return. Kernel-side logic that runs later in the call chain — a subsequent LSM check on `current->cred`, a VFS enforcement point — is unaffected. The override lies to the caller. It does not change what the kernel actually did.

## Class II; Userspace buffer rewrite

If Class I lies about the return value, Class II lies about the data itself. The kernel writes a correct result into a userspace buffer, and a BPF program mutates the buffer in the narrow window between kernel write and userspace read, using `bpf_probe_write_user` from a return probe. The caller gets back memory it believes the kernel filled in accurately.

Ch05 zeroes the `memory.current` readout for a cgroup so accounting looks clean after real allocation; `CH05_PROVEN before_usage=X after_usage=0 zeroed=yes`. Ch10 reproduces the 2016-era `d_reclen` swallow against `getdents64` on a modern CO-RE kernel; `CLOAK_PROVEN before_count=4 after_count=2 hidden=2 stat_still_works=yes`. The `stat_still_works=yes` field is the honesty field: the file is still on disk; only readdir is blind.

The primitive needs a stable window: kernel has written, userspace has not yet been returned, the page is still mapped. `kretprobe` or `tp/syscalls/sys_exit_*` gives that window.

When a BPF program using `bpf_probe_write_user` loads, the kernel emits a `pr_warn_ratelimited` dmesg message. `journalctl -k | grep bpf_probe_write_user` catches every Class II program load at zero cost. This is the loudest artifact in the book.

## Class III; Ringbuf exfiltration

Class III is the quiet one. No return values are touched. No buffers are rewritten. The kernel's access-control invariants hold perfectly. What Class III primitives do is read kernel-internal state — state that userspace could not otherwise see — and copy it out through a ringbuf that a privileged loader drains. The victim syscall returns whatever it would have returned. The only trace is a BPF program in the program table and a userspace process reading a ringbuf fd.

Ch03 exfiltrates FUSE request metadata via fentry, bypassing the audit black hole. Ch04 leaks phantom-syscall fields. Ch08/ch08k copy keyring descriptions during `key_task_permission`. Ch09 cross-maps PID namespaces and confirms a host-PID kill. Ch11 builds a per-IRQ timing sidechannel with unique-event evidence. Ch16 reads a seccomp decision for a sibling TID; labeled `SIDECHANNEL` not `BYPASS` because seccomp's threat model explicitly excludes a privileged `CAP_BPF` sibling.

Ch23 (Act 4) targets hardware-rooted key material: a kretprobe on `tpm2_unseal_trusted` is intended to copy plaintext key bytes out of the kernel's TPM unseal path to ringbuf. What was demonstrated on Ubuntu 6.17 aarch64 is kprobe attachment and entry-intercept events; `CH23_PROVEN hook=attached kind=kprobe-on-tpm2_unseal_trusted sym-confirmed`. No key bytes were present in the ringbuf — byte capture requires a host with a boot-registered TPM backend that actually exercises the unseal path.

Class III's unifying property: there is no mitigation at runtime once the program has loaded; mitigation must be at the load boundary.

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

The taxonomy is not just an organizational convenience — it is the reason five detection signatures can cover everything in the book.

A Class I signature is "syscall return disagrees with state readable via `/proc/self/status` or a follow-up check against `current->cred`"; the same signature catches ch06, ch14, and ch18 (real flips or forged returns), with ch01 a partial case because it may deliver a signal rather than a flip depending on the kernel's error-injection list. A Class II signature is "`bpf_probe_write_user` loaded"; one dmesg grep catches ch05 and ch10. A Class III signature is a ringbuf drain accompanied by a load event against a kernel-internal symbol. Class IV wants link-layer captures taken from the XDP peer, not from above the driver. Class V wants ringbuf correlation with a userspace racer doing writes on a shared inode.

Five signatures cover the whole catalog. That is the payoff of writing the taxonomy down: build rules against the patterns, not the instances.

## The four-category system

Every PoC carries a `category` field classifying the honesty of what was demonstrated.

- **REAL** (15 PoCs): hooks the actual kernel subsystem and can observe or mutate.
- **OBSERVER** (8 PoCs): hooks the real subsystem but cannot change the access decision; it reads kernel-internal state through a kprobe or fentry and ships it to ringbuf while the syscall return is left untouched.
- **ILLUSION** (3 PoCs): hooks the real syscall entry point but only forges the return value; kernel state unchanged. These are ch14 (`sched_setscheduler`), ch18 (`getuid`), and ch12s (`finit_module`).
- **ANALOG** (0 PoCs): a synthetic stand-in that manufactures the condition it then intercepts rather than intercepting a real external event. Nothing is registered here. That does not mean every synthetic surface was removed — ch06s is a registered LSM-synthetic scaffold, but it hooks the real BPF LSM path read-only, so it lives under `observer`, not `analog`.

The category is orthogonal to the class. A Class I primitive can be `real` (ch01, ch07, ch12), `observer` (ch06, ch06s), or `illusion` (ch14, ch18, ch12s). A Class III primitive can be `real` (ch04, ch09, ch11, ch23) or `observer` (ch03, ch03f, ch06o, ch08, ch08k, ch16). The category tells you how much to trust the demonstration; the class tells you what the primitive does.

## Master table

All 26 registered PoCs, mapped to category, primitive class, and effect. Status is reproduced in the reference environment (Ubuntu 6.17.0-29-generic aarch64) unless otherwise noted.

| PoC | Category | Class | Effect (marker) | Notes |
|-----|----------|-------|-----------------|-------|
| ch01 | real | I | `CH01_WEAPON_PROVEN flips=N signals=N` | kprobe/kretprobe on `cap_capable`; the override lands only where `cap_capable` is on the kernel's error-injection list, otherwise falls back to `bpf_send_signal(SIGUSR1)` on deny (`flips=0`) |
| ch02 | real | V | `[ch02] PWNED path=... bytes=... hits=...` | Overlayfs copy-up race |
| ch02lsm | real | I | `CH02_PROVEN` / `DENIED (-EPERM)` | Overlayfs copy-up denied via BPF LSM `fmod_ret` |
| ch03 | observer | III | `CH03_PROVEN` (SUPPRESSED/EXFIL) | Audit-record exfil (kprobe); read-only |
| ch03f | observer | III | `CH03_PROVEN` | Same primitive, fentry suppressor variant |
| ch04 | real | III | `CH04_PROVEN` | Phantom-syscall field leakage |
| ch05 | real | II | `CH05_PROVEN` | cgroup `cpu.stat` readout rewrite via `bpf_probe_write_user` |
| ch05b | real | IV | `GHOST_COVERT_CHANNEL_PROVEN dropped=2 tcpdump=0` | XDP ghost NIC |
| ch06 | observer | I | `CH06_PROVEN` | LSM `fmod_ret` on SELinux hooks; flips a real denial only where SELinux is enforcing |
| ch06s | observer | I | `CH06_SYNTH_PROVEN` | LSM-synthetic scaffold; manufactures the denial to demonstrate the flip |
| ch06o | observer | III | `CH06_PROVEN hook=...` / `CH06_SKIP reason=...` | SELinux kprobe observer (`avc_has_perm`) |
| ch07 | real | I | `CH07_PROVEN` / `SIGUSR2_SENT` | devcgroup kprobe (`devcgroup_check_permission`); signal on observed denial |
| ch08 | observer | III | `CH08_PROVEN` (EXFIL=) | Keyring metadata exfil during `key_task_permission`; syscall return unchanged |
| ch08k | observer | III | `CH08_CONCEPT_PROVEN events=N` | Kprobe variant; sidesteps a BTF forward-decl of `struct key` |
| ch09 | real | III | `CH09_PROVEN host_pid=N mapped=yes` | Cross-namespace PID mapping |
| ch10 | real | II | `CLOAK_PROVEN before_count=4 after_count=2 hidden=2` | `getdents64` d_reclen swallow; `stat_still_works=yes` |
| ch11 | real | III | `CH11_PROVEN` | Per-IRQ timing sidechannel |
| ch12 | real | I | `CH12_PROVEN` | LSM `fmod_ret` on `kernel_read_file`; flips a real refusal only where module-signature enforcement is on |
| ch12s | illusion | I | `CH12_CONCEPT_PROVEN ... module_actually_loaded=no` | `finit_module` return forge; aarch64 |
| ch14 | illusion | I | `SCHED_WEAPON_PROVEN flips=N` | `sched_setscheduler` return forge; aarch64 |
| ch15 | real | IV | `VLAN_GHOST_CROSSNS_PROVEN redirect_count=N` | Cross-namespace VLAN redirect |
| ch16 | observer | III | `SECCOMP_SIDECHANNEL_PROVEN events=N` | Seccomp decision exfil for a sibling TID |
| ch18 | illusion | I | `TOKEN_FORGE_PROVEN uid_forges=N` | `getuid`/`geteuid` return forge; `gid=1001` tell left visible; aarch64 |
| ch23 | real | III | `CH23_PROVEN key_bytes_captured=N` / `CH23_SKIP` | kprobe on `tpm2_unseal_trusted`; attachment and entry-intercept events reproduce, but plaintext key capture needs a boot-registered TPM backend |
| ch24 | real | — | `CH24_SKIP reason=...` | **The single skip**: reference kernel built `CONFIG_BPF_TOKEN=n`, so `BPF_TOKEN_CREATE` is unavailable to exercise |
| ch25 | real | IV | `CH25_PROVEN access_key_captured=yes` | XDP IMDSv2 capture; the reference run uses a mock exchange on `lo` |

**Category counts**: real=15, observer=8, illusion=3, analog=0 (total 26).
**Reproduction**: 25 of 26 reproduce in the reference environment (Ubuntu 6.17.0-29-generic aarch64); 1 skip (ch24); 0 failures.

(ch13 powercap/RAPL and ch17 ACPI-WMI were retired as x86-only stubs and are not in the catalog; they are absent from this table by design.)

---

**Related material**
- Companion: [Ch 21 Skip Accounting]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html), [Ch 22 Defender Playbook]({{ site.baseurl }}/book/act-7/chapter-22-the-defender-playbook.html)
- Harness: `dBPF-pocs/harness/proof.py`
