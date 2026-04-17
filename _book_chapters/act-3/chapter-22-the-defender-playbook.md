---
layout: book
title: "Chapter 22: The Defender Playbook"
date: 2026-01-12
---

# Chapter 22: The Defender Playbook

> **See also**: [Blog post]({{ site.baseurl }}/the-defender-playbook.html) · [Harness](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

> **Navigation**: [Chapter 20 — Taxonomy]({{ site.baseurl }}/book/act-3/chapter-20-the-autopsy-what-we-proved.html) · [Chapter 21 — Skip Accounting]({{ site.baseurl }}/book/act-3/chapter-21-the-autopsy-what-refused-to-die.html) · [Chapter 22 — Defender Playbook]({{ site.baseurl }}/book/act-3/chapter-22-the-defender-playbook.html)

The preceding twenty-one chapters establish what `CAP_BPF` permits. This chapter is the operational response. Seven steps, ordered from highest leverage to lowest. Four verbs carry the work: **inventory**, **restrict**, **baseline**, **audit**. A mapping table at the end ties each step to the five primitive classes from chapter 20, and three case studies describe real-world misconfigurations that produced ambient `CAP_BPF` exposure across a fleet.

## 1. The threat model, restated

Every primitive in this book required `CAP_BPF`, and most additionally required `CAP_PERFMON` or `CAP_SYS_ADMIN`. The defender's job is to know which workloads on the fleet hold that capability, what they do with it, and how to restrict or revoke it where the answer is "nothing good." If you remember one sentence from this chapter: the threat is not BPF; the threat is ambient grants of `CAP_BPF` to workloads whose lineage and runtime behavior you do not audit.

The rest of the chapter assumes a Linux fleet of mixed hosts (bare metal, VMs, Kubernetes nodes, CI runners) running a recent-ish kernel (5.8+ for per-capability `CAP_BPF` / `CAP_PERFMON` splits, introduced in commit 2c78ee898d8f; 5.7+ for BPF LSM). On older kernels where `CAP_BPF` was folded into `CAP_SYS_ADMIN`, read "`CAP_SYS_ADMIN`" wherever this chapter says "`CAP_BPF`." The inventory and restriction guidance is the same; the granularity is coarser.

## 2. Inventory `CAP_BPF` on your fleet

You cannot restrict what you cannot enumerate. Inventory runs at four granularities: per-user, per-unit, per-file, per-container. Each produces a list. Pin the lists in version control. Alert on diffs.

### 2.1 Per-process inventory

The running process tree is the lived state. `getpcaps(1)` from the `libcap2-bin` package reads `/proc/<pid>/status` and decodes the `CapEff`, `CapPrm`, `CapInh`, and `CapBnd` bitmaps into a readable capability set.

```bash
# All processes with any BPF-related capability
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
    caps=$(getpcaps "$pid" 2>/dev/null | grep -Ei 'cap_bpf|cap_perfmon|cap_sys_admin')
    [ -n "$caps" ] && echo "pid=$pid $caps"
done
```

Sample output on a Kubernetes worker node with the Datadog agent, Cilium agent, and systemd-journald running:

```
pid=1823 1823: cap_bpf,cap_perfmon=ep
pid=1824 1824: cap_bpf,cap_perfmon=ep
pid=2105 2105: cap_sys_admin,cap_bpf,cap_perfmon,cap_net_admin=ep
pid=2106 2106: cap_sys_admin,cap_bpf,cap_perfmon,cap_net_admin=ep
pid=915  915:  cap_sys_admin=ep
```

Interpretation. The suffix `=ep` means **e**ffective and **p**ermitted. Effective is the set currently active on the process; permitted is the ceiling the process can raise itself to via `capset(2)`. `i` would indicate inheritable across `execve`. A capability shown in only the permitted set but not the effective set means the process is privileged but has voluntarily dropped that capability for the current execution — the process can raise it back at any time, so for threat-model purposes treat `p` and `ep` identically. The pairing `cap_bpf,cap_perfmon` is the common shape for legitimate observability agents; they need `CAP_PERFMON` to attach kprobes and tracepoints in addition to `CAP_BPF` to load programs.

### 2.2 Per-systemd-unit inventory

Units that legitimately need `CAP_BPF` declare it in their service file. Query the bounding set directly:

```bash
# Per-unit capability bounding set
for u in $(systemctl list-units --type=service --state=running --no-legend | awk '{print $1}'); do
    cbs=$(systemctl show --property=CapabilityBoundingSet "$u" | cut -d= -f2)
    if [ -n "$cbs" ] && [ "$cbs" != "" ]; then
        caps=$(capsh --decode="$cbs" 2>/dev/null | grep -Ei 'bpf|perfmon|sys_admin')
        [ -n "$caps" ] && echo "unit=$u $caps"
    fi
done
```

Sample output on a node running the Datadog agent, Dynatrace OneAgent, and Cilium:

```
unit=datadog-agent.service 0x0000001800000000=cap_bpf,cap_perfmon
unit=oneagent.service 0x00000020001fffff=cap_sys_admin,...,cap_bpf,cap_perfmon,cap_net_admin
unit=cilium-agent.service 0x00000020001fffff=cap_sys_admin,...,cap_bpf,cap_perfmon,cap_net_admin
```

The Datadog agent restricts its bounding set to the minimum required (`CAP_BPF + CAP_PERFMON`). The OneAgent and Cilium unit files declare a maximal bounding set — they are designed to run with full `CAP_SYS_ADMIN`. That is not a misconfiguration per se; it is a vendor choice that shifts the trust question from "what can this process do?" to "do I trust this vendor's entire binary and supply chain?"

### 2.3 Per-file inventory

File capabilities are baked into the extended attributes of a binary. A `setcap cap_bpf+ep /usr/bin/foo` means any user who executes `/usr/bin/foo` gets `CAP_BPF` on that process, regardless of their own capability set.

```bash
# Walk the whole filesystem
getcap -r / 2>/dev/null | grep -Ei 'bpf|perfmon|sys_admin'
```

On a fresh Debian 12 install, expected output is empty or nearly so. On a host where somebody has installed `bpftrace` or `bcc-tools` system-wide, expect:

```
/usr/bin/bpftrace cap_bpf,cap_perfmon,cap_sys_resource=ep
/usr/bin/bcc-tools/biosnoop cap_bpf,cap_perfmon=ep
```

A less-obvious discovery tool is `filecap` from the `audit` package, which walks the filesystem in the same way but presents the result as a table. Use whichever fits your tooling.

Unexpected grants to look for: any file capability on a binary in a user-writable directory (`/home`, `/tmp`, `/var/tmp`, `/opt` if non-root-owned), any file capability on a binary whose package provenance cannot be established via `dpkg -S` or `rpm -qf`.

### 2.4 Per-container inventory

In Docker, the default capability set already excludes `CAP_BPF` and `CAP_PERFMON`. A container gets them only by explicit opt-in via `--cap-add=BPF --cap-add=PERFMON` or by running with `--privileged`. Prefer explicit drops to make the intent visible in the run manifest:

```bash
# Docker: drop the BPF-adjacent capabilities even from the already-restricted default set
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE myapp:latest
```

In Kubernetes, the equivalent lives in `securityContext`:

```yaml
spec:
  containers:
    - name: app
      image: myapp:latest
      securityContext:
        capabilities:
          drop:
            - ALL
          add:
            - NET_BIND_SERVICE
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
```

At the OCI runtime layer, the effective capability set lives in the container bundle's `config.json`:

```json
{
  "process": {
    "capabilities": {
      "bounding":   ["CAP_NET_BIND_SERVICE"],
      "effective":  ["CAP_NET_BIND_SERVICE"],
      "permitted":  ["CAP_NET_BIND_SERVICE"],
      "inheritable": []
    }
  }
}
```

If `CAP_BPF` appears in any of those lists for a workload that is not an observability agent or a programmable-network component, that is a finding. Write it down.

### 2.5 Common unexpected holders

Itemized so the inventory step has somewhere concrete to start:

- **Datadog agent (`datadog-agent`, `system-probe`)** — Uses `CAP_BPF + CAP_PERFMON` when eBPF-based Network Performance Monitoring or Universal Service Monitoring is enabled. Without those features the agent does not need either capability. Documented in the agent's `system-probe.yaml`.
- **Dynatrace OneAgent (`oneagent`)** — Ships with `CAP_SYS_ADMIN`. The product's eBPF-based observability is not separable from its kernel-module-based observability; a single binary holds both. Reducing this grant requires vendor support.
- **Cilium agent (`cilium-agent`, `cilium-operator`)** — Needs `CAP_BPF + CAP_PERFMON + CAP_NET_ADMIN` at minimum; most deployments also grant `CAP_SYS_ADMIN` because L7 visibility (Hubble) and some tc-bpf attach modes require it on older kernels. The Cilium chart's `securityContext` block is the place to audit.
- **Pixie (`vizier-pem`)** — Runs as a DaemonSet with `CAP_BPF + CAP_PERFMON + CAP_SYS_ADMIN` to attach uprobes on arbitrary language runtimes. The "always-on profiling" model requires broad capability.
- **`bpftrace` and `bcc`** — Usually installed either as root-only tools or with file capabilities. The `bpftrace` apt package in Debian 12 installs without file capabilities; some third-party RPM packages install with `cap_bpf,cap_perfmon=ep`.
- **Falco** — In `ebpf` driver mode, needs `CAP_BPF + CAP_PERFMON`. In `kmod` mode, needs to load a kernel module (distinct threat model). In `modern-bpf` mode on recent kernels, same as `ebpf` mode.
- **Tetragon (Isovalent)** — Attaches LSM BPF and kprobes. Needs `CAP_BPF + CAP_PERFMON`. In enforcement mode, also needs to be trusted because it can kill processes from a BPF program via `bpf_send_signal`.
- **Isovalent Enterprise (Cilium Enterprise, Tetragon Enterprise)** — Same capability shape as the OSS versions but with additional enterprise features (policy sync, observability pipelines) whose binaries the defender must independently verify.
- **CI runners (GitLab Runner, Jenkins agents, GitHub self-hosted runners)** — Frequently configured with `--privileged` Docker to support Docker-in-Docker, nested virtualization, or eBPF-based test observability. The `--privileged` flag grants `CAP_BPF` (and everything else) transitively. See case study 1.

Not every agent in that list is dangerous. Each entry answers a different question the defender must hold in their head: is this agent genuinely required, is its capability grant minimal, and is its supply chain audited? An agent that holds `CAP_BPF` but updates itself automatically from a vendor CDN without signature verification is a fleet-wide `CAP_BPF` acquisition vector for anyone who compromises the vendor CDN.

### 2.6 Inventory pipeline

Treat the four inventory sources as inputs to a single pipeline:

```bash
#!/bin/bash
# /usr/local/bin/capbpf-inventory
set -euo pipefail
OUT=/var/lib/capbpf-inventory.json
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

jq -n \
  --argjson procs   "$(for pid in $(ls /proc | grep -E '^[0-9]+$'); do
                         getpcaps "$pid" 2>/dev/null | grep -Ei 'cap_bpf|cap_perfmon' \
                           | jq -R --arg pid "$pid" '{pid:$pid, caps:.}'
                       done | jq -s '.')" \
  --argjson units   "$(systemctl list-units --type=service --state=running --no-legend \
                       | awk '{print $1}' \
                       | while read -r u; do
                           cbs=$(systemctl show --property=CapabilityBoundingSet "$u" | cut -d= -f2)
                           [ -n "$cbs" ] && echo "{\"unit\":\"$u\",\"bounding\":\"$cbs\"}"
                         done | jq -s '.')" \
  --argjson files   "$(getcap -r / 2>/dev/null | grep -Ei 'bpf|perfmon|sys_admin' \
                        | jq -R 'split(\" \") | {path:.[0], caps:.[1]}' | jq -s '.')" \
  --arg host "$(hostname)" --arg at "$(date -u +%FT%TZ)" \
  '{host:$host, at:$at, procs:$procs, units:$units, files:$files}' > "$TMP"

mv "$TMP" "$OUT"
```

Run under a systemd timer on every host; ship `$OUT` to a central index keyed by host and date. The diff between consecutive days of inventory for a single host is the daily report; the diff between today's inventory across the fleet and last week's fleet-wide inventory is the change-management artifact that goes to audit.

## 3. Restrict via BPF LSM

BPF LSM is the single highest-leverage control in this chapter. It operates on the kernel entry point every primitive in this book had to pass through: the `bpf(2)` syscall. If your policy rejects a `BPF_PROG_LOAD` call, nothing downstream in the attack chain can fire.

### 3.1 Confirm availability

```bash
cat /sys/kernel/security/lsm
# expected output includes 'bpf' somewhere in the comma-separated list
```

On kernels where BPF LSM is compiled in but not enabled at boot, you must pass `lsm=...,bpf` on the kernel command line and reboot. On most recent distro kernels (Ubuntu 22.04+, Debian 12+, RHEL 9+, Amazon Linux 2023) BPF LSM is enabled by default.

### 3.2 A minimal gate program

The following LSM BPF program gates `BPF_PROG_LOAD` by caller UID. The pattern generalizes: replace the UID check with any credential, tag, or signature check you care about.

```c
// gate_bpf.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// Allowlist of UIDs permitted to load programs. Populated from
// userspace at load time.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u8);
} allowed_uids SEC(".maps");

SEC("lsm/bpf_prog_load")
int BPF_PROG(gate_prog_load, struct bpf_prog *prog, union bpf_attr *attr,
             struct bpf_token *token, int ret)
{
    // If some earlier LSM already denied, respect that.
    if (ret != 0)
        return ret;

    __u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    __u8 *ok = bpf_map_lookup_elem(&allowed_uids, &uid);
    if (!ok)
        return -EPERM;

    return 0;
}
```

Line-by-line:

- `#include "vmlinux.h"` pulls in the CO-RE kernel type definitions.
- The `allowed_uids` map is populated from userspace at load time. Each key is a UID that may load BPF programs.
- `SEC("lsm/bpf_prog_load")` picks the LSM hook that fires just before the kernel accepts a program into its program table.
- `BPF_PROG(...)` is the standard libbpf macro for typed LSM program signatures. The exact signature depends on the kernel version; verify with `bpftool btf dump file /sys/kernel/btf/vmlinux | grep bpf_prog_load` for your kernel.
- `if (ret != 0) return ret;` honors prior LSM denials. Do not flip a denial to allow from a stacked LSM.
- The map lookup is the policy check. UID not in map → `-EPERM`.
- Return `0` to permit.

Compile and load:

```bash
clang -O2 -g -target bpf -D__TARGET_ARCH_arm64 \
    -I/usr/include/aarch64-linux-gnu \
    -c gate_bpf.bpf.c -o gate_bpf.bpf.o

bpftool prog load gate_bpf.bpf.o /sys/fs/bpf/gate_bpf \
    autoattach type lsm
```

Verify the attach:

```bash
bpftool prog show pinned /sys/fs/bpf/gate_bpf
# expect: ... type lsm  tag <sha> ... attached_to bpf_prog_load
```

Once attached, every `BPF_PROG_LOAD` call on the system passes through this hook. Attempts by unallowed UIDs fail with `-EPERM` at the syscall level. The denial is visible in `dmesg` only if you add a `bpf_printk` or emit to a ringbuf. Add one in production; silent denials are hard to debug.

### 3.3 Signed-program enforcement

The Cilium pattern: only permit programs whose instruction-hash (`tag`) is in a list signed by a trusted key. At boot, userspace reads the signed allowlist, verifies the signature against a baked-in public key, and populates a BPF map with the approved tags. The LSM program then checks each incoming program's tag against that map.

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u8[8]);   // prog tag is 8 bytes
    __type(value, __u8);
} signed_tags SEC(".maps");

SEC("lsm/bpf_prog_load")
int BPF_PROG(gate_signed, struct bpf_prog *prog, union bpf_attr *attr,
             struct bpf_token *token, int ret)
{
    if (ret != 0)
        return ret;

    __u8 tag[8];
    bpf_probe_read_kernel(&tag, sizeof(tag), &prog->tag);
    __u8 *ok = bpf_map_lookup_elem(&signed_tags, &tag);
    if (!ok)
        return -EPERM;
    return 0;
}
```

This is slower to roll out than the UID gate — it requires a build pipeline that signs BPF objects and a boot-time loader that populates the tag map — but it catches an entire category of threats: a privileged process that the vendor trusts gets subverted and tries to load a program the vendor never shipped. The signed-tag check fails; the program never enters the kernel's program table.

### 3.4 Per-attach-type gating

Different attach types carry different risk. A tracepoint attach for audit purposes is low-risk; a kprobe attach is a prerequisite for every Class I and Class III primitive in this book. Gate accordingly:

```c
SEC("lsm/bpf_prog_load")
int BPF_PROG(gate_by_type, struct bpf_prog *prog, union bpf_attr *attr,
             struct bpf_token *token, int ret)
{
    if (ret != 0)
        return ret;

    __u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    __u32 prog_type = BPF_CORE_READ(prog, type);

    // Root may load anything.
    if (uid == 0)
        return 0;

    // Non-root workloads may load tracepoint programs only.
    if (prog_type == BPF_PROG_TYPE_TRACEPOINT)
        return 0;

    // Deny kprobe, kretprobe, LSM, XDP, cgroup_skb, etc. from non-root.
    return -EPERM;
}
```

This policy, deployed on a fleet where auditd is the only legitimate non-root BPF user, eliminates the Class I and Class II attack shapes for every non-root workload. Class III (ringbuf exfiltration) remains available via tracepoint for any non-root workload that still has `CAP_BPF`, which is why this gate composes with step 2's inventory: drop `CAP_BPF` from the non-root workload entirely if it does not need it.

Cross-references into the attack chapters: this step mitigates ch01 (LSM attach), ch06, ch07, ch10 (kretprobe on getdents64), ch14 (kretprobe on sched_setscheduler), ch18 (kretprobe on getuid/geteuid), ch02 (kprobe on ovl_copy_up_one). The POCs live at `dBPF-pocs/pocs/ch01-mirror-controls-lsm/`, `dBPF-pocs/pocs/ch06-silence-selinux-lsm/`, `dBPF-pocs/pocs/ch07-devcgroup-houdini-lsm/`, `dBPF-pocs/pocs/ch10-inode-cloak/`, `dBPF-pocs/pocs/ch14-sched-fifo/`, `dBPF-pocs/pocs/ch18-token-bypass/`, and `dBPF-pocs/pocs/ch02-overlayfs/`.

### 3.5 Rollout discipline

A BPF LSM gate is a kernel-level control. A bug in the gate program can deny every legitimate BPF load on the fleet, including the load of the gate's replacement. Three operational guardrails reduce the blast radius:

- **Staged rollout.** Deploy the gate to one canary host first. Let it run for at least one observability-agent restart cycle (typically once per hour) and confirm every legitimate load is permitted. Then widen to one availability zone. Then widen to the fleet.
- **Fail-open during the first hour.** The gate program maintains a mode map. In `shadow` mode, the program logs denials to ringbuf but returns `0` (permit) from the LSM hook. In `enforce` mode, it returns `-EPERM`. Deploy in shadow for 48 hours; examine the ringbuf output to enumerate every caller the gate would have denied; add each legitimate caller to the allowlist; then flip the mode map to enforce.
- **Out-of-band revert.** The gate program is pinned at `/sys/fs/bpf/gate_bpf`. Removing the pin and unlinking the program detaches the LSM hook on most kernels. Maintain an ansible playbook (or equivalent) that removes the pin and the program, runnable via an out-of-band management plane that does not itself depend on the gate permitting its actions. The `bpftool` binary needed to run the playbook is itself a BPF consumer and loads BTF; a gate that denies `BPF_BTF_LOAD` or `BPF_OBJ_GET` blocks the revert path. Allowlist the revert tooling's UID explicitly.

## 4. Pin and baseline loaded programs

Restriction is preventive. Baselining is detective. A baseline of what loaded BPF programs look like on a known-good host is the diff target that surfaces unexpected attachments later.

### 4.1 Boot-time capture

```bash
bpftool prog show -j \
  | jq '[.[] | {id, name, type, tag, load_time, pinned: (.pinned // []), ids_attached: (.ids_attached // [])}]' \
  > /var/lib/bpf-baseline.json
```

The `tag` field is the SHA-1 of the program's verified instruction stream. Two BPF programs with the same instructions on the same kernel produce the same tag. That makes tags diff-friendly across reboots; `id` (assigned monotonically at load) is not.

Sample baseline entry:

```json
{
  "id": 42,
  "name": "cil_from_host",
  "type": "sched_cls",
  "tag": "2e8c4f1b9a3d0000",
  "load_time": 1739461827123456789,
  "pinned": ["/sys/fs/bpf/cilium/cil_from_host"],
  "ids_attached": []
}
```

### 4.2 Runtime diff

Run the capture on a timer and diff against the baseline:

```bash
# /etc/systemd/system/bpf-baseline-check.service
[Unit]
Description=BPF program set diff

[Service]
Type=oneshot
ExecStart=/usr/local/bin/bpf-baseline-check
```

```bash
# /etc/systemd/system/bpf-baseline-check.timer
[Unit]
Description=Run BPF baseline diff every minute

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min
Unit=bpf-baseline-check.service

[Install]
WantedBy=timers.target
```

```bash
#!/bin/bash
# /usr/local/bin/bpf-baseline-check
set -euo pipefail
BASELINE=/var/lib/bpf-baseline.json
CURRENT=$(mktemp)
trap 'rm -f "$CURRENT"' EXIT
bpftool prog show -j \
  | jq '[.[] | {name, type, tag}] | sort_by(.tag)' > "$CURRENT"
EXPECTED=$(jq '[.[] | {name, type, tag}] | sort_by(.tag)' "$BASELINE")
DIFF=$(diff <(echo "$EXPECTED") "$CURRENT" || true)
if [ -n "$DIFF" ]; then
    logger -t bpf-baseline -p security.warn "bpf program set diverged"
    echo "$DIFF" | logger -t bpf-baseline -p security.warn
fi
```

The alert ships to the host's syslog, which an off-host log sink then relays. `security.warn` is the right facility; tooling that watches `security.*` is the natural place for BPF attach notifications to land.

### 4.3 Pinned programs in `/sys/fs/bpf/`

A pinned program survives the exit of its loader. Pinning is legitimate (Cilium pins its programs so they persist across agent restarts) and a pattern attackers use (pin and then exit the loader; the program keeps running as long as something — including the pin — holds a reference).

Enumerate:

```bash
find /sys/fs/bpf/ -type f -o -type l 2>/dev/null | while read -r p; do
    bpftool prog show pinned "$p" 2>/dev/null || true
done
```

Known-good pin paths on a Cilium-managed node:

```
/sys/fs/bpf/tc/globals/cilium_events
/sys/fs/bpf/tc/globals/cilium_metrics
/sys/fs/bpf/cilium/cil_from_host
...
```

An unexpected pin at `/sys/fs/bpf/foo` with `name cloak` and `type kprobe` is a finding. The name and type are attacker-controllable, so do not rely on them; rely on the tag and the pin path combined.

### 4.4 What this catches

Baselining catches Class I, Class II, Class IV, and Class V primitives at load time, before the effect fires. It does not catch Class III primitives that attach and exfiltrate before the next baseline check runs — a one-minute poll leaves up to sixty seconds for a Class III primitive to operate. Tighten the interval if your threat model demands it; the cost is the `bpftool` invocation per tick. A ten-second interval is feasible.

Cross-references: a new pinned kprobe at `/sys/fs/bpf/` with a name resembling `cloak`, `hide`, `forge`, `override`, or anything similarly descriptive should be treated as a Class I or Class II primitive until proven otherwise. The POCs for those classes pin into `/sys/fs/bpf/` under names that match the chapter (`dBPF-pocs/pocs/ch10-inode-cloak/loader.c` pins as `cloak`; `dBPF-pocs/pocs/ch18-token-bypass/loader.c` pins as `tokforge`).

### 4.5 Attach-point enumeration

The baseline in 4.1 captures programs but not the attach points those programs sit on. For kprobes, kretprobes, and tracepoints, enumerate the attach point separately:

```bash
# kprobes (including kretprobes) currently attached
cat /sys/kernel/tracing/kprobe_events 2>/dev/null
# tracepoints currently enabled
cat /sys/kernel/tracing/events/*/*/enable 2>/dev/null | grep -v '^0$'
# uprobes
cat /sys/kernel/tracing/uprobe_events 2>/dev/null
```

These files show the kernel-level trace probes, some of which are installed by BPF programs and some by `perf_event_open`. A new entry in `kprobe_events` that targets `__arm64_sys_getuid`, `__arm64_sys_sched_setscheduler`, or any other syscall wrapper on the error-injection list correlates directly with a Class I primitive. Include these files in the baseline diff.

A separate enumeration for network-path attachments:

```bash
# XDP and tc-bpf programs per netdev
bpftool net show -j | jq '.[] | {devname: .devname, xdp: .xdp, tc: .tc}'
```

Sample output on a Cilium node:

```json
{"devname":"cilium_host","xdp":null,"tc":{"ingress":[{"id":127,"name":"cil_from_host"}]}}
{"devname":"eth0","xdp":{"mode":"generic","id":89,"name":"cil_xdp_entry"},"tc":null}
```

Baseline this output too. An `xdp` entry appearing on an interface that previously had none is the signature of Class IV primitives from chapters 5b and 15.

## 5. Audit `bpf(2)`

Kernel auditing of the `bpf(2)` syscall produces a record per invocation, including `BPF_PROG_LOAD`, `BPF_MAP_CREATE`, `BPF_PROG_ATTACH`, and every other command. The record includes the caller's PID, UID, comm, exe, and (critically) the first argument to `bpf(2)` — the command ID — so you can discriminate load from create from attach without extending the rule.

### 5.1 The audit rule

```bash
# aarch64
auditctl -a always,exit -F arch=aarch64 -S bpf -k bpf_syscall

# x86_64 (add in addition on multi-arch boxes; b64 is the x86_64 ABI)
auditctl -a always,exit -F arch=b64 -S bpf -k bpf_syscall
```

Persist in `/etc/audit/rules.d/50-bpf.rules`:

```
-a always,exit -F arch=b64 -S bpf -k bpf_syscall
-a always,exit -F arch=b32 -S bpf -k bpf_syscall
```

On a multi-arch host you need both rules. The audit subsystem matches on the syscall ABI at the time of the call, not the host architecture.

### 5.2 A sample record

```
type=SYSCALL msg=audit(1739462001.123:9471): arch=c00000b7 syscall=280 \
  success=yes exit=4 a0=5 a1=7ffeabcd1200 a2=90 a3=0 items=0 \
  ppid=1822 pid=1830 auid=1000 uid=1000 gid=1000 \
  euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 \
  comm="tokforge" exe="/home/ci/tokforge" \
  subj=unconfined key="bpf_syscall"
```

Parsing:

- `syscall=280` is `bpf` on aarch64 (`__NR_bpf` from `arch/arm64/include/uapi/asm/unistd.h`). On x86_64 it is `321`. The `arch=c00000b7` field in the record above is `AUDIT_ARCH_AARCH64`, so the 280 is consistent. Verify with `ausyscall bpf` on the host.
- `a0=5` is the first argument to `bpf(2)`, which is the command. `5` decodes to `BPF_PROG_LOAD` per `include/uapi/linux/bpf.h`. `0` is `BPF_MAP_CREATE`, `8` is `BPF_PROG_ATTACH`, `28` is `BPF_LINK_CREATE`, and so on (see the full enum in `include/uapi/linux/bpf.h`).
- `success=yes exit=4` means the syscall returned a file descriptor (fd 4) to the loaded program.
- `auid=1000 uid=1000 euid=0` — the caller's login UID is 1000, their real UID is 1000, and their effective UID is 0. This is the credential tell: a non-root user is calling `bpf(2)` with effective-root privileges. That combination on a workload that does not legitimately need it is a finding.
- `comm="tokforge"` is the program's own name, attacker-controllable. Do not gate alerting on `comm` alone.

### 5.3 What to log vs. what to drop

Audit records can be voluminous. A high-traffic Cilium node issues thousands of `bpf(2)` calls per second during agent restarts (map creates, map updates, program loads). Filtering at the audit rule level is coarse; filtering in the log pipeline is where you get precision.

- **Loud but tractable**: `BPF_PROG_LOAD`, `BPF_PROG_ATTACH`, `BPF_LINK_CREATE`. These are the load-and-attach events; they correspond one-to-one with new BPF programs entering the kernel's program table. Log every one.
- **Loud and not tractable**: `BPF_MAP_UPDATE_ELEM`, `BPF_MAP_LOOKUP_ELEM`. Thousands per second on an active agent. Drop in the audit pipeline unless you are specifically investigating map-based covert channels.
- **Medium**: `BPF_MAP_CREATE`, `BPF_BTF_LOAD`. Dozens per second at agent startup, essentially zero after steady state. Keep.

A good log-pipeline filter keeps every `a0` value in the set `{0, 5, 6, 8, 28}` (MAP_CREATE, PROG_LOAD, OBJ_PIN, PROG_ATTACH, LINK_CREATE — per `include/uapi/linux/bpf.h`, where `BPF_OBJ_PIN=6` and `BPF_PROG_ATTACH=8`) and drops the rest. That reduces volume by 99%+ on busy nodes while preserving the security-relevant events.

### 5.4 Off-host sink

The audit records must land somewhere that an on-host attacker with `CAP_BPF` cannot rewrite. Three practical sinks:

- **systemd-journal-upload** to a remote journald receiver over TLS. Write-once on the receive side, authenticated by client cert.
- **syslog-ng or rsyslog** with TLS and `disk-buffer` on the sender side so an on-host outage does not lose records. Receive on a central syslog host that is not part of the monitored fleet.
- **Splunk Universal Forwarder** or similar vendor agent reading `/var/log/audit/audit.log` and shipping to a SIEM. Same principle: the destination is outside the threat model.

The sink itself must not hold `CAP_BPF`. If the audit forwarder runs on the same node and uses eBPF for its own purposes, the Class III primitives in chapters 3, 4, 8, 9, 11, and 16 can observe the forwarder's in-memory buffers or intercept its writes. `systemd-journal-upload` is a plain binary with no need for BPF; prefer it.

Cross-references: this step is the detection control for the primitives in chapters 1, 2, 10, 14, and 18 (Class I and II, whose BPF loads are the observable event). The POCs at `dBPF-pocs/pocs/ch01-mirror-controls-lsm/`, `dBPF-pocs/pocs/ch02-overlayfs/`, `dBPF-pocs/pocs/ch10-inode-cloak/`, `dBPF-pocs/pocs/ch14-sched-fifo/`, and `dBPF-pocs/pocs/ch18-token-bypass/` all issue `BPF_PROG_LOAD` and `BPF_PROG_ATTACH` sequences that produce one audit record each; a defender with this rule in place sees them in real time.

## 6. Restrict error-injection

Chapter 20's Class I depends on `bpf_override_return`, which only fires on functions annotated with `ALLOW_ERROR_INJECTION` and listed at `/sys/kernel/debug/error_injection/list`. Reduce that list and you reduce the Class I attack surface.

### 6.1 Inspect the current list

```bash
cat /sys/kernel/debug/error_injection/list | head -40
```

Sample output on Debian 12 stock kernel 6.1:

```
ffffffff81234000 __x64_sys_read [EI_ETYPE_ERRNO]
ffffffff81234100 __x64_sys_write [EI_ETYPE_ERRNO]
...
ffffffff81345abc __x64_sys_getuid [EI_ETYPE_ERRNO]
ffffffff81345bcd __x64_sys_geteuid [EI_ETYPE_ERRNO]
ffffffff814abcde __x64_sys_sched_setscheduler [EI_ETYPE_ERRNO]
ffffffff815cafbe bio_add_page [EI_ETYPE_ERRNO]
...
```

Categories of entries:

- **Syscall entry wrappers** (`__x64_sys_*`, `__arm64_sys_*`). Expected. Kernel developers use these for fuzz-testing syscall error paths. These are also every Class I primitive's attach point. This is the tension step 6 addresses.
- **Block I/O** (`bio_add_page`, `submit_bio`, `blk_update_request`). Expected for storage-fault injection. Not an obvious attack surface, but verify nothing in your production workload is reading return values from these functions downstream.
- **Filesystem** (`open_namei`, `vfs_write`). Expected for filesystem-fault testing.
- **Networking** (`tcp_v4_connect`, `ip_output`). Expected.
- **Unexpected**: entries in modules you did not install, entries in out-of-tree drivers, entries added by vendor patches that you did not audit.

### 6.2 Build-time removal

If you build your own kernel, `ALLOW_ERROR_INJECTION(sym, TYPE)` macros are explicit in the source. A kernel config review should audit each annotation and delete those your workload does not need to inject into. On most production systems the answer for `__x64_sys_getuid` is "nobody is fuzz-testing getuid's error path on this box" — it can be removed without affecting production. The patch is a one-line deletion per annotation.

Building a kernel with `CONFIG_FUNCTION_ERROR_INJECTION=n` removes the feature entirely, stripping every `ALLOW_ERROR_INJECTION` annotation and eliminating the attack surface Class I depends on at the source. The cost is losing the ability to run the kernel's own fault-injection test suite. In production, this is almost always the right trade.

### 6.3 Runtime restriction

For distro kernels where the feature is compiled in, mount restrictions limit visibility without a kernel rebuild:

```bash
# /etc/fstab: restrict debugfs to root and avoid exec/suid
debugfs /sys/kernel/debug debugfs noauto,noexec,nosuid,mode=0700,uid=0,gid=0 0 0
```

Or do not mount debugfs at all in production containers. The BPF verifier does not require debugfs to be mounted in order to validate the override call; what requires debugfs is the attacker's preflight check ("is my target on the list?"). An attacker without debugfs visibility must guess or bring their own BTF-derived list. This is a speed bump, not a wall.

The firmer control is a BPF LSM gate on `bpf_override_return` permission. The LSM hook `bpf_prog_load` fires before the program's helpers are bound to the program; the hook can inspect the program's instruction stream for `BPF_FUNC_override_return` calls and deny if the caller is not allowlisted:

```c
SEC("lsm/bpf_prog_load")
int BPF_PROG(deny_override, struct bpf_prog *prog, union bpf_attr *attr,
             struct bpf_token *token, int ret)
{
    if (ret != 0) return ret;
    // If this program uses bpf_override_return and the caller is
    // not root, deny. (Inspecting the instruction stream from an
    // LSM hook requires bpf_core_read and care; see the full POC.)
    __u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid != 0 && prog_uses_override_return(prog))
        return -EPERM;
    return 0;
}
```

Implementing `prog_uses_override_return` is non-trivial (it requires scanning the instruction stream for `BPF_CALL` to helper 39, `bpf_override_return`). The full implementation lives outside this chapter; the point is that the hook exists and the gate is enforceable.

Cross-references: this step directly mitigates every Class I primitive — ch01, ch06, ch07, ch10 (d_reclen swallow returns modified data, not a return value, but the attach shape is the same), ch12 syscall variant, ch14, ch18. The kprobe variant of ch08 at `dBPF-pocs/pocs/ch08-keyring-heist-kprobe/` is Class III (exfil), not Class I, and is unaffected by this step; restrict it via step 3's LSM gate.

## 7. Do not trust userspace syscall returns for security decisions

Every Class I primitive in this book forges a syscall-layer answer. The orchestrator that reads the forged return believes the kernel did something it did not do. The defense is not at the BPF layer. The defense is at the orchestrator layer: do not base security decisions on what `syscall(...)` returned, because that value is writable by anyone with `CAP_BPF`.

### 7.1 What not to gate on

Specific anti-patterns, each cross-referenced to the chapter that demonstrates the forge:

- **`getuid()` / `geteuid()` return** — ch18 (`dBPF-pocs/pocs/ch18-token-bypass/`). A tool reading `getuid() == 0` and deciding the caller is root can be fooled by a kretprobe on `__arm64_sys_getuid`. Even if the tool re-reads `geteuid()` as a cross-check, both are on the error-injection list and both can be forged simultaneously.
- **`sched_setscheduler()` return** — ch14 (`dBPF-pocs/pocs/ch14-sched-fifo/`). An RT-workload orchestrator seeing a `0` return from `sched_setscheduler(SCHED_FIFO)` and concluding that the task is now real-time is trusting a kretprobed return value. The task's actual policy (read via `sched_getscheduler()` or `/proc/<pid>/sched`) is unchanged.
- **`insmod` / `finit_module` return** — ch12 syscall variant (`dBPF-pocs/pocs/ch12-signed-driver-swap-syscall/`). A provisioning script checking `insmod` exit code to confirm a kernel module loaded is trusting a forgeable syscall return. The module is not loaded; `/proc/modules` and `/sys/module/<name>/` say so.
- **`mknod` return** — ch07 workaround (`dBPF-pocs/pocs/ch07-devcgroup-houdini/`). A container-runtime convenience script reading `mknod` success and assuming the device node now exists — similar shape.
- **`setcap` / `capset` return** — equivalent primitive shape; any tool reading a capability-grant syscall return to confirm a capability was granted should cross-check via `/proc/self/status`.

### 7.2 What to gate on instead

At the kernel enforcement point: the LSM hooks, the capability checks in the VFS, the actual `cred` inspection. Those run against `current->cred` and read the actual live credential, not a cached return value. A BPF program cannot forge `current->cred`; it can only forge what `current->cred` decodes to when observed externally.

Post-checks for userspace consumers:

- **Capability checks**: after any operation that depends on a capability grant, re-read `/proc/self/status` and parse `CapEff`. The bitmask you find there is the one the kernel will use at the next syscall's enforcement point.
- **Module loads**: after `finit_module` succeeds, verify by reading `/proc/modules` for the module name and `/sys/module/<name>/` for the module's sysfs node. Both are populated by the loader only on successful load; a forged syscall return does not populate either.
- **UID/GID**: after `setuid` or any operation that claims to have changed credentials, re-read `/proc/self/status` and check `Uid:` and `Gid:` lines. The ch18 primitive forges `getuid()` but not the `/proc/self/status` read; reading the latter bypasses the forge entirely.
- **Scheduler policy**: after `sched_setscheduler`, re-read `/proc/<pid>/sched` and parse the policy field. The ch14 primitive forges only the syscall return; the task's actual `task_struct->policy` is unchanged and is what `/proc/<pid>/sched` reflects.

### 7.3 A consistency-checker pattern

A small userspace routine that reads the "truth" via one path and the "claim" via another and compares them catches any primitive in this class. Example for UID:

```c
uid_t claim = getuid();
FILE *f = fopen("/proc/self/status", "r");
char line[256];
uid_t truth_real = (uid_t)-1;
while (fgets(line, sizeof(line), f)) {
    if (strncmp(line, "Uid:", 4) == 0) {
        sscanf(line, "Uid:\t%u", &truth_real);
        break;
    }
}
fclose(f);
if (claim != truth_real) {
    syslog(LOG_ALERT, "uid consistency violation: getuid=%u status=%u",
           claim, truth_real);
}
```

The ch18 primitive forges `getuid()` to return 0 but cannot simultaneously forge the text parsing of `/proc/self/status` — the forge would require a second attach on `__arm64_sys_read` or `__arm64_sys_openat`, visible as a second BPF program in the baseline. Attach count goes up; detection via step 4 fires.

A richer version of this pattern reads both `uid` and `gid`. The ch18 POC forges `uid=0` but leaves `gid` at its pre-forge value. Any consistency checker that reads both, expects `uid=0` to be paired with `gid=0`, and alerts on the `uid=0 gid=<non-zero>` pairing catches the half-hooked forge without any kernel-layer cooperation.

### 7.4 Integration points

Several pieces of common infrastructure have a natural place to insert this kind of post-check without rewriting the caller:

- **sudoers `env_check`**. The sudo binary already re-reads credentials from the kernel on every invocation for its own enforcement. Add a `listpw=always` or similar configuration that causes sudo to log every invocation's `/proc/self/status` snapshot alongside the invocation; review the logs for `uid=0 gid=<non-zero>` mismatches or `CapEff` values that do not match the invoking user's expected set.
- **systemd `ConditionUser=` and `ConditionCapability=`**. Both conditions are evaluated against the kernel-enforced state, not a queried return value. A unit that wants to run only if the invoking user is `root` and only if `CAP_BPF` is available should use `ConditionUser=root` and `ConditionCapability=CAP_BPF`, not a shell script that calls `id -u` and greps `capsh --print`. The shell-script form is forgeable; the systemd condition form is not.
- **Container runtime probes**. Kubernetes `securityContext` runtime admission (via OPA/Gatekeeper or Kyverno) can enforce that pods' declared `runAsUser` matches the effective UID the kubelet observes in the pod sandbox's `/proc/<pid>/status`. A mismatch at admission time is a signal; enforcing admission on the policy engine side keeps the check outside the scope of any on-host BPF forge.
- **IMA/EVM measured boot**. For hosts where tampering with `/proc/self/status`-parsing trust chains is a real concern, IMA-based attestation that a particular binary is measured at execve time gives a trust anchor that no BPF program can subvert — BPF cannot modify the TPM-backed measurement. IMA does not defeat every forge class, but it defeats "an attacker has replaced the status-parsing binary with one that ignores the `gid` mismatch."

## 8. Accept what you cannot stop

Class III primitives — ringbuf exfiltration of kernel-internal state — cannot be prevented once a peer holds `CAP_BPF`. They can only be made expensive. Chapter 16 states this plainly for seccomp: the primitive sits in the documented gap in seccomp's threat model. The same is true for the credential tells from chapter 3 (FUSE metadata), chapter 4 (phantom syscall fields), chapter 8 (keyring descriptions via kprobe), chapter 9 (PID namespace cross-mapping), and chapter 11 (per-IRQ timing sidechannel).

### 8.1 What accept means

Accept does not mean ignore. It means:

- **Minimize `CAP_BPF` holders**. Every holder is a peer observer. Step 2's inventory is the operational expression of this.
- **Ship critical records off-host synchronously**. The audit sink in step 5 is the template. If a Class III primitive reads a credential, and the legitimate consumer of that credential has already written it to an off-host sink, the exfil is a duplicate of a record the defender already has. It stops being a surprise.
- **Use memory-sealed enclaves for true secrets**. SGX, TDX, and their AMD equivalents (SEV-SNP) provide a class of memory the kernel itself cannot read. A Class III primitive running with `CAP_BPF` inside the kernel cannot reach into an enclave's encrypted memory region. Use enclaves for the narrow set of secrets where this matters: signing keys, credential vault master keys, TLS private keys for the fleet's perimeter.
- **Accept structural peer-observer classes**. The audit subsystem itself has peer observers by design. Anyone with `CAP_BPF` can attach to the same tracepoint auditd attaches to. This is not a bug; it is the shape of tracepoints. The defender's job is to know this and not to build detective controls that rely on BPF-level opacity.

### 8.2 What does not help

Kernel-level opacity does not help. Marking kernel structs opaque via BTF does not prevent Class III; it only makes the primitive's loader-side preflight harder. The primitive still fires once the loader locates the right offsets by another means (pattern matching in kallsyms, trial-and-error map probes, open-source kernel configs). If the kernel's structure layout is on the internet, the attacker has it.

User-space opacity does not help either. An attacker with `CAP_BPF` reads from the kernel side, not the user side. Encrypting a secret in a user-space daemon's memory does not stop a tracepoint from logging the plaintext value as it passes through the kernel en route to or from the daemon.

### 8.3 The operational posture

Treat every host with `CAP_BPF` holders as "the agent holding `CAP_BPF` has seen every credential that transited the kernel on this host since the agent was loaded." This is strong language. It is also accurate. Class III primitives in chapters 3, 4, 8, 9, 11, and 16 each demonstrate a specific instance of this general property; the list in the book is not exhaustive.

The posture that follows: any secret whose compromise matters at the host level does not live on a host with peer `CAP_BPF` holders unless it is in an enclave or transits only the enclave's interface. For most fleets this means credential-store daemons (Vault, AWS Secrets Manager agent, HashiCorp Boundary) should run on nodes with a minimal `CAP_BPF` footprint, or the secrets those daemons emit should be short-lived enough that the observation-window-to-use-window ratio makes exfiltration operationally useless.

### 8.4 A worked example: credential TTL as compensating control

A common deployment pattern on Kubernetes: Vault issues dynamic database credentials to workloads. A pod requests credentials; Vault synthesizes a username and password valid for a configurable TTL; the pod uses them; at expiry, the database invalidates them. The defender's concern is that an agent on the node holding `CAP_BPF` observes the credential at issuance time via a Class III primitive (tracepoint on the TCP write path, kprobe on TLS-record processing in userspace via uprobe, or similar).

If the TTL is 24 hours, the exfil is operationally useful: the attacker exfiltrates, decodes at leisure, logs in. If the TTL is 5 minutes, the attacker's automation must be on-line, the exfil-to-use pipeline must be continuous, and every credential use is short enough that forensic reconstruction is tractable. If the TTL is 30 seconds and the credentials rotate on every database connection, the attacker's useful window is shorter than the baseline-polling interval in step 4, and the BPF program's attach shows up in the next diff.

This does not prevent the Class III exfil. It makes the exfil unprofitable. That is the best available control when the primitive class itself is structural.

The inverse of this reasoning: secrets that cannot be short-TTLed — signing keys, root CA material, long-lived API keys for upstream services — belong in an enclave or on a host that does not host peer `CAP_BPF` workloads. A bastion host that holds such secrets and runs no observability agents at all is a legitimate architectural choice driven by this chapter's threat model, not an over-reaction.

## 9. Per-primitive hardening table

Full mapping from primitive class to defensive controls. Each row lists the chapters that demonstrate the class, the kernel-level mitigation, the runtime monitor, and the post-incident detection path.

| Class | Chapters | Kernel mitigation | Runtime monitor | Post-incident detection |
|-------|----------|-------------------|------------------|--------------------------|
| **I — Return-value override** | ch01, ch06, ch07, ch12 syscall variant, ch14, ch18 | BPF LSM gate on `fmod_ret`, `kretprobe`, and `bpf_override_return` (step 3, 6); strip `ALLOW_ERROR_INJECTION` annotations at kernel build (step 6) | Audit `bpf(2)` with `a0=5` (`BPF_PROG_LOAD`) and ship off-host (step 5); baseline BPF program set and alert on new kretprobes (step 4) | Audit log shows `BPF_PROG_LOAD` by unexpected UID; baseline diff shows new kretprobe on syscall wrapper; post-check ground truth in orchestrator (step 7) |
| **II — Userspace buffer rewrite** | ch05, ch10 (getdents64 d_reclen swallow) | BPF LSM gate on `bpf_probe_write_user` — either deny the helper entirely for non-root or check the target address range against an allowlist; same kernel-build strip for the syscall exit wrappers | Audit `bpf(2)`; baseline; alert on new kretprobe on `sys_exit_getdents64` or similar | Re-read the buffer via a different syscall (stat the file after getdents; snapshot the cgroup memory.current via `cat` after the orchestrator reads it) and diff |
| **III — Ringbuf exfiltration** | ch03, ch04, ch08, ch09, ch11, ch16 | Cannot prevent at kernel level once the peer has `CAP_BPF`; minimize holders (step 2); ship off-host synchronously (step 5); enclaves for true secrets (step 8) | Audit `bpf(2)` for `BPF_MAP_CREATE` of type `BPF_MAP_TYPE_RINGBUF` and baseline BPF program set | Record ringbuf maps created and by whom; correlate with credential access events in other subsystems |
| **IV — Packet-path interception (XDP)** | ch05b, ch15 | BPF LSM gate on `BPF_PROG_LOAD` for type `BPF_PROG_TYPE_XDP`; netlink audit on netdev attach | Audit `bpf(2)`; baseline; alert on new XDP programs via `bpftool net show -j` | `bpftool net show` output diffs vs. baseline; `tcpdump` loss vs. `cat /proc/net/dev` counters (packets seen by netdev but not by tcpdump indicates XDP drop) |
| **V — Kernel-event-triggered userspace racer** | ch02 | Same controls as Class III for the observer half; filesystem-level hardening for the racer half — read-only OverlayFS lower layers, integrity monitoring on upper layer, auditd watches on the upper layer's inode set | Audit `bpf(2)`; baseline; file-integrity monitoring on OverlayFS upper layers | Upper-layer inode content differs from expected; auditd shows a write to the upper layer by an unexpected process in the racer's PID neighborhood |

## 10. Case studies

Three short case studies of real-world misconfigurations that produced ambient `CAP_BPF` exposure. The names are generic; the patterns are specific.

### 10.1 CI/CD runner with `--privileged` Docker-in-Docker

A CI platform at a mid-sized SaaS company runs self-hosted GitLab Runners on VMs. The runners execute CI jobs inside Docker containers. To support projects that want to run `bpftrace` scripts in their test suite as a form of observability-driven testing, the platform team configures the runner to launch the build container with `--privileged`. The relevant block in the runner's `config.toml`:

```toml
[runners.docker]
privileged = true
volumes = ["/sys/kernel/debug:/sys/kernel/debug:rw", "/cache"]
```

The effect. Every CI job on that runner executes with `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN`, access to `/sys/kernel/debug`, and unrestricted access to the host's kernel. A CI job that merely runs a test suite for a pure-Python web application has the same capability set as an intentional `bpftrace` job. A supply-chain compromise in any Python dependency pulled into any CI job becomes a `CAP_BPF` compromise of the runner host.

The fix. Separate runners by capability requirement. The `bpftrace`-using jobs run on a small pool of runners with `--privileged` and a narrow access-control list. The 99% of jobs that do not need eBPF run on the default runner pool with `--cap-drop=ALL`. Tag jobs by capability requirement; the dispatcher routes accordingly. Re-inventory via step 2.4 (OCI config) to confirm the default pool drops `CAP_BPF`.

The detail that makes this case study worth writing. The platform team had no evidence that any job was abusing the capability. The `--privileged` setting was in place for six months. Attribution after the fact is nearly impossible: every job's audit records show a legitimate `bpftrace` invocation shape (the build environment ran `bpftrace` as part of setup even when the job itself did not use it, because of a shared `.gitlab-ci.yml` fragment). The fix was not driven by an incident; it was driven by the inventory step catching `CapabilityBoundingSet=cap_sys_admin,cap_bpf,cap_perfmon,...` on the runner unit files and nobody on the platform team being able to justify it. That is what step 2 is for.

### 10.2 Observability-vendor agent, supply-chain-wide exposure

An observability vendor ships a node-level agent that installs as a Kubernetes DaemonSet. The agent's default Helm chart configures `CAP_SYS_ADMIN` (superset of `CAP_BPF` and `CAP_PERFMON`) because one of its optional features — application-level uprobe profiling — needs it, and the chart does not distinguish between the feature being enabled and the capability being necessary. Operators install the chart, the agent runs fleet-wide, every node holds `CAP_SYS_ADMIN` via the agent's container.

The agent auto-updates from a vendor CDN. The update binary is signed, but the vendor's signing key is stored in a single build-infrastructure HSM that is reachable from a CI system where the vendor's contractors have push access to the build pipeline.

The failure mode. A supply-chain compromise of the vendor's build pipeline — a compromised contractor account, a dependency confusion attack on a transitive vendor dependency, a CI-runner compromise at the vendor — injects an attacker-controlled binary into the signed update. The update rolls out to every node in every customer's fleet. Every one of those nodes now runs attacker-controlled code with `CAP_SYS_ADMIN`. All five primitive classes are available on every node.

The fix. Inventory (step 2) surfaces the capability grant. Restrict (step 3) via an allowlist of signed program tags that the vendor's legitimate build pipeline produces — this is the Cilium pattern in section 3.3 — means an attacker-controlled update ships BPF programs whose tags are not in the allowlist and the LSM gate refuses them. Baseline (step 4) surfaces new programs before they attach. Audit (step 5) records the attempted loads for post-incident forensics. None of these fully prevent the supply-chain class of compromise; they raise the cost and the noise to the point where the attacker's window is measured in the baseline-polling interval, not in months until discovery.

### 10.3 Legacy `bpftrace` wrapper with convenient `CAP_SYS_ADMIN`

An ops team at a telco maintains a legacy `bpftrace` wrapper script shipped with a systemd service file that grants `CAP_SYS_ADMIN` to the wrapper. The wrapper is intended to be run by on-call operators during incident response; the `CAP_SYS_ADMIN` grant is described in a README as "for convenience, so the operator doesn't need sudo." The unit file:

```ini
[Service]
ExecStart=/opt/telco-ops/bin/bpftrace-wrap.sh
AmbientCapabilities=CAP_SYS_ADMIN CAP_BPF CAP_PERFMON
# NoNewPrivileges= is unset
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_BPF CAP_PERFMON
```

A later deployment adds a setuid shim binary at `/usr/local/bin/run-bpftrace` that internally calls `systemctl start telco-bpftrace@$USER.service` with a templated unit name. The shim is group-writable to `ops`, and `ops` membership is granted liberally because most of the telco's developers occasionally need to run ops scripts. The shim does not validate its argument beyond "is a path." An `ops`-group user invokes the shim with a crafted path, the templated unit starts with `ExecStart=<crafted path>`, the crafted path holds `CAP_SYS_ADMIN`.

The failure mode. Every user in the `ops` group has ambient `CAP_SYS_ADMIN` on demand. That group has 40 members. The capability grant intended for on-call operators during incidents is now a routine entitlement for 40 people, their shells, their editor plugins, and any supply-chain dependency those shells and editors load.

The fix. Do not grant capabilities at the unit level for the sake of convenience; use `sudo` with a specific `Cmnd_Alias`. If a privileged wrapper is unavoidable, the wrapper should run non-setuid and invoke a narrow `systemd-run --scope` with an explicit and auditable capability set that names the specific BPF program to run, not a user-controlled path. The inventory in step 2 catches the entire shape — `AmbientCapabilities=CAP_SYS_ADMIN` in a service file not owned by the agent runtime is a finding on its own.

### 10.4 Pattern across the three

Each of the three case studies has the same two-act structure. Act one: a reasonable operational convenience — CI flexibility, vendor defaults, on-call ergonomics — produces a capability grant that the person making the grant did not recognize as `CAP_BPF` exposure. Act two: the grant persists long past the original justification because no inventory process surfaces it.

The first act is unavoidable. The people writing CI configs, installing Helm charts, and maintaining systemd units do not carry the full taxonomy from chapter 20 in their heads when they make each decision. The defender's job is not to prevent the first act.

The second act — persistence past the original justification — is preventable. An inventory that runs weekly, produces a diff, and requires an owner-of-record for every line that includes `cap_bpf`, `cap_perfmon`, `cap_sys_admin`, or `AmbientCapabilities=`, makes the second act impossible. The owner-of-record has to re-justify the grant at every review cycle. Grants without owners get removed. This is boring work. It is also the only reliable control against the cumulative-drift failure mode these three case studies share.

## 11. Closing

None of this is novel. Inventory the capability holders. Restrict who can load programs. Baseline what is loaded. Audit the syscall to a sink the attacker cannot reach. Stop trusting forged return values for security decisions. Accept the Class III observation channels as structural. The attack chapters justify each step; the playbook is what you do with the justification.

The four verbs in order, one more time: **inventory, restrict, baseline, audit**. Each is a cron job, a systemd unit, or a config file diff away from being in place. The rest is discipline.
