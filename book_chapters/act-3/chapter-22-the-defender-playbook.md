---
layout: book
title: "Chapter 22: The Defender Playbook"
date: 2026-01-12
---

# Chapter 22: The Defender Playbook

The preceding twenty-one chapters establish what `CAP_BPF` permits. This chapter is the operational response. Seven steps, ordered from highest leverage to lowest. A mapping table at the end ties each step to the five primitive classes from chapter 20.

## 1. The threat model, restated

Every primitive in this book required `CAP_BPF`, and most additionally required `CAP_PERFMON` or `CAP_SYS_ADMIN`. The defender's job is to know which workloads on the fleet hold that capability, what they do with it, and how to restrict or revoke it where the answer is "nothing good." If you remember one sentence from this chapter: the threat is not BPF; the threat is ambient grants of `CAP_BPF` to workloads whose lineage and runtime behavior you do not audit.

## 2. Inventory `CAP_BPF` on your fleet

Start with the running process tree:

```bash
# Per-process effective capabilities
getpcaps $(pgrep -u <user>) 2>&1 | grep -i bpf

# Per-systemd-unit capability bounding set
systemctl show --property=CapabilityBoundingSet <unit>

# File capabilities baked into binaries
getcap -r / 2>/dev/null | grep -i bpf
```

Typical unexpected holders in the wild: the Datadog agent, Dynatrace, Cilium, Pixie, bpftrace, `bcc` tools installed system-wide, and CI runners doing Docker-in-Docker with nested observability. None of those are malicious; they are the point at which the question "who holds CAP_BPF" stops being rhetorical. Pin the inventory to version control. Alert on diffs.

## 3. Restrict with BPF LSM

Confirm BPF LSM is active:

```bash
cat /sys/kernel/security/lsm
# expect: ...,bpf,...
```

Write a `SEC("lsm/bpf_prog")` program that gates program load by `attach_type` and caller credential. The Cilium "enforce signed programs only" pattern is a good starting point: permit only programs signed by a known key, refuse everything else. A minimal policy gate refuses `BPF_PROG_LOAD` for attach types that should never appear in your environment — for example, refusing `BPF_XDP` if no workload on the host is supposed to run XDP.

This is the single highest-leverage control, because it operates on the entry point every primitive in this book had to pass through.

## 4. Pin loaded programs, baseline them

At boot, capture the set of loaded BPF programs:

```bash
bpftool prog show -j | jq -c '.[] | {id, name, type, tag, load_time}' | sort \
  > /var/lib/bpf-baseline.json
```

A systemd timer (or plain cron) runs every minute, repeats the capture, and diffs against the baseline. New attachments produce an alert shipped to a log sink that does not itself run with `CAP_BPF`. The alert includes `tag` (SHA of program instructions), `name`, and `load_time`, so you can correlate against the process that issued `BPF_PROG_LOAD`.

This catches Class I, Class II, Class IV, and Class V primitives at load time, before the effect fires.

## 5. Audit `bpf(2)`

Enable kernel auditing of the `bpf` syscall:

```bash
# aarch64
auditctl -a always,exit -F arch=aarch64 -S bpf -k bpf_syscall
# x86_64 (add in addition, not instead of, on multi-arch boxes)
auditctl -a always,exit -F arch=b64 -S bpf -k bpf_syscall
```

This produces one audit record per `bpf(2)` call, including `BPF_PROG_LOAD`, `BPF_MAP_CREATE`, and `BPF_PROG_ATTACH`, tagged with the caller's `comm`, `pid`, and effective credentials. Ship those records to a tamper-evident sink — a remote syslog receiver, a write-only append log, a SIEM — that itself does not run with `CAP_BPF`. The point of the off-box sink is that a Class III exfil primitive running on the monitored host cannot rewrite the records after the fact.

## 6. Restrict error-injection where possible

Chapter 20's Class I depends on `bpf_override_return`, which only fires on functions annotated in `ALLOW_ERROR_INJECTION`. Inspect the list on production:

```bash
cat /sys/kernel/debug/error_injection/list
```

If you build your own kernel, audit the `ALLOW_ERROR_INJECTION` annotations during the kernel config review, and delete any that your workload does not need to inject into. On stock distro kernels where you cannot re-audit, restrict debugfs mount visibility (`hidepid=2` is not enough; consider not mounting debugfs at all in production containers) and gate `bpf_override_return` via BPF LSM.

## 7. Do not trust userspace syscall returns for security decisions

Chapters ch18, ch14, and the ch12 syscall variant all forge syscall-layer results. The orchestrator that reads the forged return believes the kernel did something it did not do. The mitigation is not at the BPF layer; it is at the orchestrator layer: do not make security decisions based on what `syscall(...)` returned, because that value is writable by anyone with `CAP_BPF`.

Instead: consult `current->cred` at the kernel enforcement point, or post-check ground-truth state. After a module load that claims success, read `/proc/modules` and `/sys/module/<name>/` to confirm the module actually exists. After a capability grant that claims success, read `/proc/self/status` and parse `CapEff`. After a scheduler-policy change that claims success, read `/proc/<pid>/sched` and parse the policy field. These checks are not free, but they are cheap compared to acting on a forged answer.

## Per-class mitigation table

| Class from ch. 20 | Highest-leverage mitigation | Secondary |
|-------------------|-----------------------------|-----------|
| I — Return-value override | BPF LSM gate on `fmod_ret` and `kretprobe` attach; audit `ALLOW_ERROR_INJECTION`; post-check ground truth in the orchestrator | bpf(2) audit; program-baseline diff |
| II — Userspace buffer rewrite | BPF LSM gate on `bpf_probe_write_user` permission | bpf(2) audit; program-baseline diff |
| III — Ringbuf exfiltration | Restrict who can `CAP_BPF`; fewer tracepoints/kprobes exposed (strip BTF where not needed) | bpf(2) audit to off-box sink |
| IV — XDP packet-path interception | BPF LSM gate on `BPF_XDP` attach; netlink audit on netdev attach | bpf(2) audit; program-baseline diff |
| V — Userspace racer | Same as Class III for the observer half; filesystem-level hardening (read-only OverlayFS lower layers, integrity monitoring on upper layer) for the racer half | bpf(2) audit |

## Closing

None of this is novel. Inventory the capability holders, restrict who can load programs, baseline what is loaded, audit the syscall to a sink the attacker cannot reach, and stop trusting forged return values for security decisions. The justification for doing it — not the content of what to do — is what chapters 1 through 18 provide.
