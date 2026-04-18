---
layout: book
title: "The Defender Playbook"
date: 2026-01-12
---

> **See also**: [Full chapter]({{ site.baseurl }}/book/act-7/chapter-22-the-defender-playbook.html) · [Chapter 20 — Taxonomy]({{ site.baseurl }}/book/act-7/chapter-20-the-autopsy-what-we-proved.html) · [Chapter 21 — Skip Accounting]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html)

Every primitive in this book required `CAP_BPF`, and most additionally required `CAP_PERFMON` or `CAP_SYS_ADMIN`. That single observation collapses the defender's problem into four verbs: inventory, restrict, baseline, audit. The whole chapter is those verbs expanded; the whole book is the justification for doing any of it.

## Inventory `CAP_BPF`

Find the holders before you do anything else. Running processes, systemd unit bounding sets, and file capabilities baked into binaries are three separate views; you need all three.

```bash
getpcaps $(pgrep -u <user>) 2>&1 | grep -i bpf
systemctl show --property=CapabilityBoundingSet <unit>
getcap -r / 2>/dev/null | grep -i bpf
```

Typical unexpected holders in the wild: the Datadog agent, Dynatrace, the Cilium operator, Pixie, bpftrace, `bcc` tools installed system-wide, and CI runners doing Docker-in-Docker with nested observability. None of them are malicious. They are the point at which "who holds `CAP_BPF` on this fleet" stops being rhetorical and starts being a list you pin to version control and alert on diffs.

## Restrict with BPF LSM

BPF LSM is the single highest-leverage control, because it sits on the entry point every primitive in this book had to pass through. Confirm it's active:

```bash
cat /sys/kernel/security/lsm   # expect: ...,bpf,...
```

Then write a `SEC("lsm/bpf_prog")` program that gates `BPF_PROG_LOAD` by attach type, source path, and caller credential. Cilium's "enforce signed programs only" pattern is the reference implementation: permit only programs signed by a known key, refuse everything else. A minimal policy can simply refuse attach types that should never appear on the host — `BPF_XDP` where no workload is supposed to run XDP, `fmod_ret` where nothing legitimate hooks error-injection-annotated functions.

## Pin and baseline

At boot, capture the set of loaded programs and pin it:

```bash
bpftool prog show -j \
  | jq -c '.[] | {id, name, type, tag, load_time}' \
  | sort > /var/lib/bpf-baseline.json
```

A systemd timer (or cron) runs every minute, repeats the capture, and diffs against the baseline. New attachments produce an alert shipped to a sink that does not itself hold `CAP_BPF`. Include `tag` (SHA of the program instructions), `name`, and `load_time` so you can correlate the alert back to the process that issued `BPF_PROG_LOAD`. This is what catches late-loaded persistence — the program that wasn't on the host at boot and is on the host now.

## Audit `bpf(2)`

Kernel auditing of the syscall gives you one record per `BPF_PROG_LOAD`, `BPF_MAP_CREATE`, and `BPF_PROG_ATTACH`, tagged with the caller's `comm`, `pid`, and effective credentials.

```bash
# aarch64
auditctl -a always,exit -F arch=aarch64 -S bpf -k bpf_syscall
# x86_64 (in addition, not instead of, on multi-arch boxes)
auditctl -a always,exit -F arch=b64 -S bpf -k bpf_syscall
```

Ship the records to a tamper-evident sink — remote syslog, a write-only append log, a SIEM — that does **not** run with `CAP_BPF`. The point of the off-box sink is that a Class III exfil primitive running on the monitored host cannot rewrite the records after the fact. If your audit pipeline runs on the same host as the attacker's ringbuf reader, your audit pipeline is part of the attack surface.

## Per-primitive mitigations

Each class from Chapter 20 has a primary control and a set of audit fallbacks. The table compresses what the book spent eighteen chapters demonstrating:

| Class | Representative chapters | Key mitigation |
|-------|-------------------------|----------------|
| I — return override | ch01, ch14, ch18 | Restrict `ALLOW_ERROR_INJECTION` list; audit `bpf(2)`; do not trust userspace syscall returns for security decisions |
| II — userspace buffer rewrite | ch05, ch10 | BPF LSM deny on `bpf_probe_write_user`; audit attach events |
| III — ringbuf exfil | ch03, ch04, ch09, ch11, ch16 | Cannot be prevented post-load; minimize the `CAP_BPF` footprint; off-box audit sink |
| IV — XDP packet path | ch05b, ch15 | Inventory XDP attachments; cgroup and net policies; BPF LSM gate on `BPF_XDP` attach |
| V — copy-up racer | ch02 | Rootless containers; non-overlayfs storage; ringbuf-attach monitoring on the observer half |

Two observations about this table. First, Class III and Class V share a mitigation posture: once the program is loaded, the data is gone; your only real lever is how many places on the fleet can call `BPF_PROG_LOAD` in the first place. Second, Class I is the one where the orchestrator itself has to change. No amount of in-kernel auditing helps if the userspace caller still believes the forged syscall return. Consult `current->cred` at the enforcement point, or post-check ground truth — `/proc/modules` after a module load, `/proc/self/status` after a capability change, `/proc/<pid>/sched` after a policy change. Cheap compared to acting on a forged answer.

## Closing

None of this is novel. Inventory the capability holders, restrict who can load programs, baseline what is loaded, audit the syscall to a sink the attacker cannot reach. The techniques have been available for years. The justification for investing in them is what the eighteen attack chapters provide: a concrete, reproducible demonstration that each step an operator skips is a primitive an attacker already has working.

---
**Related material**
- Full chapter: [Chapter 22 — The Defender Playbook]({{ site.baseurl }}/book/act-7/chapter-22-the-defender-playbook.html)
- Companion: [Ch 20 Taxonomy]({{ site.baseurl }}/book/act-7/chapter-20-the-autopsy-what-we-proved.html), [Ch 21 Skips]({{ site.baseurl }}/book/act-7/chapter-21-the-autopsy-what-refused-to-die.html)
- Harness: `dBPF-pocs/harness/proof.py`
