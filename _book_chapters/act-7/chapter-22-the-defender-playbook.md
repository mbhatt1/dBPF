---
layout: book
title: "Chapter 22: The Defender Playbook"
date: 2026-01-12
---

# Chapter 22: The Defender Playbook

> **See also**: [Blog post]({{ site.baseurl }}/the-defender-playbook.html) · [Harness](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

> **Navigation**: [Chapter 20; Taxonomy]({{ site.baseurl }}/book/act-7/chapter-20-the-autopsy-what-we-proved.html) · [Chapter 21; Skip Accounting]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html) · [Chapter 22; Defender Playbook]({{ site.baseurl }}/book/act-7/chapter-22-the-defender-playbook.html)

Every primitive in this book required `CAP_BPF`, and most additionally required `CAP_PERFMON` or `CAP_SYS_ADMIN`. That single observation collapses the defender's problem into four verbs: **inventory**, **restrict**, **baseline**, **audit**. The whole chapter is those verbs expanded; the whole book is the justification for doing any of it.

## Inventory `CAP_BPF`

The inventory step comes first because nothing else works without it. You cannot restrict what you have not found, cannot baseline what you do not know is running, and cannot audit syscalls from processes whose existence surprised you. Find the holders before you do anything else. Running processes, systemd unit bounding sets, and file capabilities baked into binaries are three separate views; you need all three.

```bash
# Running processes
getpcaps $(pgrep -u root) 2>&1 | grep -i bpf

# Per-unit bounding set
systemctl show --property=CapabilityBoundingSet <unit>

# File capabilities
getcap -r / 2>/dev/null | grep -i bpf
```

Typical unexpected holders in the wild: the Datadog agent, Dynatrace, the Cilium operator, Pixie, bpftrace, `bcc` tools installed system-wide, and CI runners doing Docker-in-Docker with nested observability. None of them are malicious. They are the point at which "who holds `CAP_BPF` on this fleet" stops being rhetorical and starts being a list you pin to version control and alert on diffs.

The per-container view matters too. In Kubernetes, `CapEff` from `/proc/<pid>/status` is the ground truth. The OCI `config.json`'s `capabilities.effective` array is what the runtime declared; read both and compare. A container that declares `NET_BIND_SERVICE` in its manifest but whose process tree shows `cap_bpf` has been escalated somehow.

Treat the inventory as a living artifact. Every CI config that passes `--privileged`, every Helm chart that mounts bpffs with `delegate=any`, every systemd unit file with `AmbientCapabilities=CAP_SYS_ADMIN` is a line in this artifact that requires an owner-of-record. Grants without owners get removed at the next review cycle. That is the only reliable control against the cumulative-drift failure mode that produces ambient `CAP_BPF` exposure across a fleet.

## Restrict with BPF LSM

Once you know who holds the capability, BPF LSM is how you constrain what they can do with it. It is the single highest-leverage control in this chapter, because it sits at the exact entry point every primitive in this book had to pass through: `BPF_PROG_LOAD`. Confirm it's active:

```bash
cat /sys/kernel/security/lsm   # expect: ...,bpf,...
```

Then write a `SEC("lsm/bpf_prog_load")` program that gates `BPF_PROG_LOAD` by attach type, source path, and caller credential. A minimal policy refuses attach types that should never appear on the host; `BPF_XDP` where no workload is supposed to run XDP, `fmod_ret` where nothing legitimate hooks error-injection-annotated functions.

The Cilium "enforce signed programs only" pattern is the reference implementation: permit only programs whose instruction-hash (`tag`) is in a list signed by a known key, refuse everything else. This catches an entire category of threats; a privileged process that the vendor trusts gets subverted and tries to load a program the vendor never shipped. The signed-tag check fails; the program never enters the kernel's program table.

A per-attach-type gate is simpler and still highly effective:

```c
SEC("lsm/bpf_prog_load")
int BPF_PROG(gate_by_type, struct bpf_prog *prog, union bpf_attr *attr,
             struct bpf_token *token, int ret)
{
    if (ret != 0) return ret;
    __u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid == 0) return 0;
    __u32 prog_type = BPF_CORE_READ(prog, type);
    if (prog_type == BPF_PROG_TYPE_TRACEPOINT) return 0;
    return -EPERM;
}
```

Non-root workloads may load tracepoint programs only; everything else (kprobe, kretprobe, LSM, XDP) is denied. This eliminates Class I and Class II for every non-root workload. Deploy in shadow mode first; log denials but return 0; for 48 hours to enumerate every caller the gate would have denied; add each legitimate caller to the allowlist; then flip to enforce.

## Pin and baseline

Restriction at load time is necessary but not sufficient on its own — programs loaded before your policy was deployed, or by processes running as root, will not be caught there. The baseline step closes that gap. At boot, capture the set of loaded programs and pin it:

```bash
bpftool prog show -j \
  | jq -c '.[] | {id, name, type, tag, load_time}' \
  | sort > /var/lib/bpf-baseline.json
```

A systemd timer runs every minute, repeats the capture, and diffs against the baseline. New attachments produce an alert shipped to a sink that does not itself hold `CAP_BPF`. Include `tag` (SHA of the program instructions), `name`, and `load_time` so you can correlate the alert back to the process that issued `BPF_PROG_LOAD`.

This is what catches late-loaded persistence; the program that wasn't on the host at boot and is on the host now. It also catches Class IV: a new XDP attachment on an interface that previously had none is the signature of chapters 5b, 15, and 25.

Also enumerate attach points separately:

```bash
# kprobes and kretprobes currently attached
cat /sys/kernel/tracing/kprobe_events 2>/dev/null

# XDP and tc-bpf programs per netdev
bpftool net show -j | jq '.[] | {devname: .devname, xdp: .xdp}'
```

A new entry in `kprobe_events` targeting `__arm64_sys_getuid`, `tpm2_unseal_trusted`, or any other symbol on the error-injection list correlates directly with a Class I or Class III primitive. Include these files in the baseline diff.

## Audit `bpf(2)`

The baseline catches what is loaded. The audit catches the moment of loading — which process, which credentials, which command. Kernel auditing of the syscall gives you one record per `BPF_PROG_LOAD`, `BPF_MAP_CREATE`, and `BPF_PROG_ATTACH`, tagged with the caller's `comm`, `pid`, and effective credentials.

```bash
# aarch64
auditctl -a always,exit -F arch=aarch64 -S bpf -k bpf_syscall
# x86_64
auditctl -a always,exit -F arch=b64 -S bpf -k bpf_syscall
```

A sample record on aarch64:

```
type=SYSCALL ... syscall=280 success=yes exit=4 a0=5 ...
  auid=1000 uid=1000 euid=0 ... comm="tokforge" exe="/home/ci/tokforge"
  key="bpf_syscall"
```

`a0=5` is `BPF_PROG_LOAD`. `euid=0` with `uid=1000` is the credential tell: a non-root user is calling `bpf(2)` with effective-root privileges. On a workload that does not legitimately need it, that is a finding.

Ship the records to a tamper-evident sink; remote syslog, a write-only append log, a SIEM; that does **not** run with `CAP_BPF`. The point is that a Class III exfil primitive running on the monitored host cannot rewrite the records after the fact. If your audit pipeline runs on the same host as the attacker's ringbuf reader, your audit pipeline is part of the attack surface.

Filter in the pipeline to keep `a0` values `{0, 5, 6, 8, 28}` (MAP_CREATE, PROG_LOAD, OBJ_PIN, PROG_ATTACH, LINK_CREATE) and drop MAP_UPDATE_ELEM/MAP_LOOKUP_ELEM, which are thousands-per-second on active agents. That reduces volume by 99%+ while preserving the security-relevant events.

## Per-primitive mitigations

Each class from Chapter 20 has a primary control and a set of audit fallbacks.

| Class | Representative chapters | Key mitigation |
|-------|-------------------------|----------------|
| I; return override | ch01, ch14, ch18 | Restrict `ALLOW_ERROR_INJECTION` list; audit `bpf(2)`; do not trust userspace syscall returns for security decisions |
| II; userspace buffer rewrite | ch05, ch10 | BPF LSM deny on `bpf_probe_write_user`; audit attach events; `journalctl -k | grep bpf_probe_write_user` |
| III; ringbuf exfil | ch03, ch04, ch08, ch09, ch11, ch16, ch23 | Cannot prevent post-load; minimize the `CAP_BPF` footprint; off-box audit sink; for ch23, treat any `CAP_BPF` holder on a host with TPM-backed trusted keys as having seen those keys in plaintext |
| IV; XDP packet path | ch05b, ch15, ch25 | Inventory XDP attachments; cgroup and net policies; BPF LSM gate on `BPF_XDP` attach; for ch25, pair with IAM-policy scope-down on the instance role |
| V; copy-up racer | ch02 | Rootless containers; non-overlayfs storage; ringbuf-attach monitoring on the observer half |

Two observations about this table.

First, Class III and Class V share a mitigation posture: once the program is loaded, the data is gone; your only real lever is how many places on the fleet can call `BPF_PROG_LOAD` in the first place.

Second, Class I is the one where the orchestrator itself has to change. No amount of in-kernel auditing helps if the userspace caller still believes the forged syscall return. Consult `current->cred` at the enforcement point, or post-check ground truth; `/proc/self/status` after a credential change, `/proc/modules` after a module load, `/proc/<pid>/sched` after a policy change. Cheap compared to acting on a forged answer.

## Do not trust userspace syscall returns for security decisions

Every Class I primitive in this book forges a syscall-layer answer. The defense is at the orchestrator layer: do not base security decisions on what `syscall(...)` returned.

- **`getuid()` / `geteuid()` return**; ch18 can forge both. Read `/proc/self/status` and parse `Uid:` instead. The ch18 primitive leaves `gid=1001` intact; any consistency checker that reads both uid and gid and expects them to cohere catches the half-hooked forge immediately.
- **`sched_setscheduler()` return**; ch14 forges it to 0. The task's actual policy is readable via `/proc/<pid>/sched` and is unchanged.
- **`insmod` / `finit_module` return**; ch12s forges it. Verify via `/proc/modules` and `/sys/module/<name>/`. A forged syscall return does not populate either.

The consistency-checker pattern:

```c
uid_t claim = getuid();
// parse Uid: line from /proc/self/status
if (claim != truth_real) {
    syslog(LOG_ALERT, "uid consistency violation: getuid=%u status=%u",
           claim, truth_real);
}
```

The ch18 primitive cannot simultaneously forge `getuid()` and the `/proc/self/status` text; doing so would require a second BPF program, visible as a new entry in the baseline diff.

## Accept what you cannot stop

Class III primitives; ringbuf exfiltration of kernel-internal state; cannot be prevented once a peer holds `CAP_BPF`. Chapter 16 states this plainly for seccomp: the primitive sits in the documented gap in seccomp's threat model. The same is true for chapters 3, 4, 8, 9, 11, and 16.

Accept does not mean ignore. It means:

**Minimize `CAP_BPF` holders.** Every holder is a peer observer. The inventory step is the operational expression of this. An observability agent with `CAP_BPF` on a host that boots a TPM-sealed LUKS volume (ch23), hosts a Vault credential store (Class III via ch08 et al.), or makes IAM-credentialed API calls (ch25) has seen every credential that transited the kernel since the agent was loaded. Design accordingly.

**Ship critical records off-host synchronously.** The audit sink is the template. If a Class III primitive reads a credential, and the legitimate consumer of that credential has already written it to an off-host sink, the exfil is a duplicate of a record the defender already has.

**Use short-lived credentials as a compensating control.** Class III exfiltration is structurally unstoppable once the program loads. Making the exfil unprofitable; TTL of 30 seconds on database credentials, per-workload IRSA rather than instance roles; is the best available control. Credentials that cannot be short-TTLed belong in an enclave or on a host that does not host peer `CAP_BPF` workloads.

## Closing

None of this is novel. Inventory the capability holders, restrict who can load programs, baseline what is loaded, audit the syscall to a sink the attacker cannot reach. The techniques have been available for years. The justification for investing in them is what the twenty-four attack chapters provide: a concrete, reproducible demonstration that each step an operator skips is a primitive an attacker already has working.

---

**Related material**
- Companion: [Ch 20 Taxonomy]({{ site.baseurl }}/book/act-7/chapter-20-the-autopsy-what-we-proved.html), [Ch 21 Skips]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html)
- Harness: `dBPF-pocs/harness/proof.py`
