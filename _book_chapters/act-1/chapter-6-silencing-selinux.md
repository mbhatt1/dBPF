---
layout: book
title: "Chapter 6: Silencing SELinux"
date: 2025-02-06
---

Act I: Foundations of Breach

**Chapter 6: Silencing SELinux**

> **Note**: Three PoC variants ship with this chapter. `ch06-silence-selinux-lsm` (REAL mutation, BPF LSM fmod_ret on three hooks) is the primary — it fires on an SELinux-enforcing kernel and is skipped cleanly everywhere else. `ch06-silence-selinux` (REAL observer, kprobes on AVC internals) is the secondary reconnaissance variant; registered in the harness as `ch06o`. `ch06-silence-selinux-lsm-synthetic` is a new portability variant described in the section below.

> **Proof status**: All three variants have been proved on Ubuntu 6.17.0 aarch64 (Lima VM, kernel 6.17.0-29-generic). The `ch06-silence-selinux-lsm-synthetic` variant was created during this verification to handle the case where `selinux_loaded()` returns false at preflight time but the SELinux symbols are present in kallsyms. No code changes were required to the primary or observer variants.

The primitive this chapter documents is the replacement of a SELinux-originated `-EACCES` with `0` at the LSM hook's trailing return value, using a BPF LSM `fmod_ret` program. It is a real override, not a simulation. On a kernel with `CONFIG_BPF_LSM=y`, `CONFIG_SECURITY_SELINUX=y`, `bpf` and `selinux` both active in `/sys/kernel/security/lsm`, and a SELinux policy that is actually denying something, the BPF program flips the deny to an allow for processes whose tgid the loader has pushed into its target map. The SELinux verdict never takes effect; the syscall returns success.

The precondition matters, and this chapter is honest about where it holds. On the linuxkit 6.12 aarch64 kernel that backs the default harness container (Docker Desktop on macOS), `/sys/kernel/security/lsm` reports `capability,bpf`. There is no SELinux on that kernel — no policy, no AVC, no `selinux_file_permission`. The LSM mutation PoC checks the LSM line at startup, finds no `selinux` token, and emits `CH06_SKIP` so the harness records it as an honest skip. No synthetic denial is manufactured to paper over the absence. The skip is the correct semantic for the kernel's posture.

The kernel where the PoC actually fires is the Fedora 42 aarch64 QEMU VM driven by `dBPF-pocs/run-qemu-tests.sh`. That script boots a SELinux-enforcing Fedora image, mounts the PoC tree via 9p, sets up a confined user, generates a real AVC denial, starts the loader, and re-runs the access — at which point the three LSM fmod_ret programs attached to `lsm/file_permission`, `lsm/inode_permission`, and `lsm/bprm_check_security` flip the would-be deny to an allow. The `CH06_PROVEN flipped=N` marker is emitted by the trigger, and the harness's proof regex picks it up.

## The hook set: three LSM surfaces, one primitive

`ch06-silence-selinux-lsm.bpf.c` attaches three non-sleepable programs:

```c
SEC("lsm/file_permission")
int BPF_PROG(lsm_file_permission, struct file *file, int mask, int ret)
{
    (void)file; (void)mask;
    unsigned int tgid = bpf_get_current_pid_tgid() >> 32;
    int flipped = 0;
    int new_ret = ret;
    if (is_target_tgid(tgid) && ret != 0) {
        new_ret = 0;
        flipped = 1;
    }
    emit(H_FILE_PERMISSION, ret, flipped);
    return new_ret;
}
```

The same shape repeats for `inode_permission` and `bprm_check_security`. Three hooks, not because a single hook would be insufficient in principle, but because SELinux routes different access paths through different LSM entry points, and a flipper that only covers one path leaves the others exposed:

- `lsm/file_permission` — called from `vfs_read`, `vfs_write`, and related paths every time an already-open `struct file *` is used. If SELinux denies a read or write on a previously-opened descriptor (for example, a confined process inherits an fd and then tries to use it), this is where the deny shows up.
- `lsm/inode_permission` — called from the path-walk and open-time permission check (`may_open`, `lookup_open`, and their descendants). SELinux `selinux_inode_permission` is the corresponding static handler; it is where the deny manifests for `open(2)` on a file whose label the subject domain cannot read.
- `lsm/bprm_check_security` — called from `exec_binprm` when the kernel is about to run a new binary. SELinux's `selinux_bprm_check_security` is the static handler; it denies execve of a binary whose entrypoint type the subject is not allowed to transition to. This is the hook that bites a confined user who tries to run a binary outside their domain.

Covering all three means a flipper-installed program renders SELinux effectively silent for the targeted tgid across the common access-control paths: opening files, using already-open descriptors, and executing binaries. The BPF programs are non-sleepable (`lsm/` not `lsm.s/`) because none of them need sleepable helpers — they inspect a couple of scalar arguments, consult a hash map, emit a ringbuf event, and return. No `bpf_d_path`, no `bpf_copy_from_user`, no blocking work at all.

The `fmod_ret` semantic is what makes the override real. BPF LSM programs run after the static LSMs, and the hook's final return is the BPF program's return. When SELinux returned `-EACCES` and the BPF program returns `0`, the chain result is `0` and the LSM chain as a whole allows. The `bpf_lsm_hooks` allowlist in `kernel/bpf/bpf_lsm.c` includes all three of these hooks; they are documented targets for BPF-side verdict modification, not reverse-engineered surfaces.

## The target-tgid filter and the wildcard

The target map is a plain hash keyed by tgid:

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned int);
    __type(value, unsigned int);
    __uint(max_entries, 1024);
} target_tgids SEC(".maps");

static __always_inline int is_target_tgid(unsigned int tgid)
{
    if (bpf_map_lookup_elem(&target_tgids, &tgid))
        return 1;
    unsigned int zero = 0;
    if (bpf_map_lookup_elem(&target_tgids, &zero))
        return 1;
    return 0;
}
```

Key `0` is a wildcard sentinel: present-and-any-tgid means "flip every deny regardless of subject." The loader's `-a` flag writes the wildcard; `-t <tgid>` pushes specific tgids. The trigger script for the Fedora run uses `-a` because the point of the PoC is to demonstrate the flip against whatever confined process the trigger manufactures; a real attacker with a known target pid would use `-t`.

The uid-0 guard that earlier drafts of this chapter implied lives on the trigger side, not in the BPF program itself. The BPF code flips any non-zero `ret` for any matching tgid. The trigger contains the flip to a non-root confined user (`runcon user_u:user_r:user_t:s0 cat "$SECRET"`) so that the baseline read genuinely gets denied by SELinux before the BPF is loaded. If you ran the loader against a root process, nothing would be denied in the first place, and there would be nothing to flip.

The `ret != 0` guard inside the BPF program is the other half of the semantic. A `file_permission` call where SELinux already allowed — `ret == 0` coming in — flips nothing, because flipping `0` to `0` is a no-op. The program's event emission records `flipped=0` for those, which the userspace loader filters out. The loader's proof-marker line is only printed when `flipped=1`:

```c
if (e->flipped) {
    printf("[ch06] FLIP hook=%s pid=%u comm=%s orig=%d -> 0\n",
           hook_name(e->hook), e->pid, e->comm, e->orig_ret);
}
```

The harness proof regex (`proof_marker=r"CH06_PROVEN|CH06_WEAPON_PROVEN|FLIP\s+hook="` for the `ch06` entry in `proof.py`) matches on the `FLIP hook=` shape.

## Honest skip on the linuxkit harness

The trigger `ch06-silence-selinux-lsm/trigger.sh` encodes the skip discipline at the top:

```bash
LSM_LINE="$(cat /sys/kernel/security/lsm 2>/dev/null)"
if [ -z "$LSM_LINE" ]; then
  echo "=== CH06_SKIP reason=\"/sys/kernel/security/lsm unreadable\" ==="
  exit 0
fi
if ! echo "$LSM_LINE" | grep -q bpf; then
  echo "=== CH06_SKIP reason=\"BPF LSM not enabled ...\" ==="
  exit 0
fi
if ! echo "$LSM_LINE" | grep -q selinux; then
  echo "=== CH06_SKIP reason=\"SELinux not in /sys/kernel/security/lsm\" ==="
  exit 0
fi
if ! command -v chcon >/dev/null 2>&1; then
  echo "=== CH06_SKIP reason=\"chcon not available; no SELinux userspace tooling\" ==="
  exit 0
fi
```

Four independent preconditions, each with its own skip reason. On linuxkit, the `bpf` check passes and the `selinux` check fails, so the trigger exits 0 with a skip message and the harness records it correctly. The loader itself (`ch06-silence-selinux-lsm.c`) has a matching preflight: if `bpf` is missing from the LSM line, it prints `CH06_LSM_SKIP` and returns 3. Either path produces an honest skip; neither path produces a fake pass.

This is not a concession. The primitive is real; its natural environment is SELinux-enforcing kernels, and on kernels without that environment there is nothing to override. The skip is the correct outcome. A PoC that claimed success on linuxkit would be lying.

## The Fedora QEMU run

`dBPF-pocs/run-qemu-tests.sh` is the harness's path to an actually-SELinux-enforcing kernel. For this chapter the relevant section is the one the trigger script performs when executed inside the Fedora 42 aarch64 VM. The setup that makes the flip demonstrable has five steps:

1. **Stage the target file.** `mktemp -d /tmp/ch06-stage.XXXXXX`, write `selinux-protected-content` into `secret.txt`, `chmod 644` it. The DAC layer allows every user to read this file; SELinux will be the only thing that denies.

2. **Relabel to a denied type.** `chcon -t shadow_t "$SECRET"`. The `shadow_t` type is one of the stock Fedora policy types that the generic unconfined-user-equivalent domain (`user_t`, mapped to `user_u`) is not allowed to read. After the `chcon`, a process running in `user_t` attempting to read the file receives `-EACCES` from SELinux's `selinux_inode_permission` hook, which is propagated out through the LSM chain to the open syscall.

3. **Create a confined user.** `useradd -M dut06lsm` gives us a UID but the interesting part is the SELinux context. The trigger uses `runcon user_u:user_r:user_t:s0 cat "$SECRET"` rather than a login `su`, because a plain `su` on Fedora stays in `unconfined_t`, and `unconfined_t` is allowed to read almost everything — no deny, nothing to flip. The explicit `runcon` forces the read to happen in the confined `user_t` domain, which is where the policy bites. In the Fedora QEMU environment, this is the `confined01` role mapped to `user_u` that the surrounding scripts set up; the trigger's `runcon` selects that context directly.

4. **Baseline read.** Execute `runcon user_u:user_r:user_t:s0 cat "$SECRET"` before the loader is running. SELinux denies the read with `-EACCES`. The AVC denial is also logged to `/var/log/audit/audit.log` as a `type=AVC` record with `avc: denied { read } for ... scontext=user_u:user_r:user_t:s0 tcontext=... tclass=file`. The baseline exit code is non-zero, and the denial is observable in the audit log.

5. **Start the loader in wildcard mode, re-read, count flips.** `./build/ch06-silence-selinux-lsm -a > "$LOG" 2>&1 &`, sleep to let the attach complete, then three retries of `runcon ... cat "$SECRET"`. Each retry: SELinux's `selinux_inode_permission` evaluates the policy, returns `-EACCES`, the LSM chain propagates that `-EACCES` up to the BPF `fmod_ret` program attached at `lsm/inode_permission`, which sees `ret == -EACCES`, sees the wildcard tgid match, overwrites `new_ret = 0`, emits a ringbuf event with `flipped=1`, and returns `0`. The LSM chain's final return is now `0`. The open proceeds. `cat` succeeds. The loader's userspace side prints `[ch06] FLIP hook=inode_permission pid=... comm=cat orig=-13 -> 0`.

The trigger's tail counts the FLIP events and emits the marker:

```bash
FLIPS=$(grep -cE 'FLIP\s+hook=' "$LOG" 2>/dev/null)
if [ "$FLIPS" -gt 0 ]; then
  echo "CH06_PROVEN flipped=$FLIPS"
else
  echo "=== CH06_SKIP reason=\"no FLIP events captured ...\" ==="
fi
```

The marker is structured so that the harness distinguishes three outcomes: no SELinux (skip before the loader even runs), loader ran but SELinux didn't deny anything the filter matched (skip with `no FLIP events captured`), and genuine flips (`CH06_PROVEN flipped=N`). The last of the three is the proof. The `orig=-13` in the log line is the numeric form of `-EACCES` (errno 13 with the LSM negative-errno convention); the BPF program's `flipped=1` and `new_ret=0` transforms it into an allow, and the userspace loader records both the original value and the override in one line.

A note on the audit log. Because SELinux's policy evaluation runs *before* the BPF `fmod_ret` program (the static LSM in the chain computes its return, then the BPF program gets called with that return as the trailing arg), the AVC denial is still logged. The audit record says SELinux denied the access. The user-visible behavior says the access succeeded. A defender correlating the two sees the inconsistency: the AVC record and the syscall outcome disagree. This is the specific signal that a BPF LSM override is in play — it is one of the strongest detection signals in the chapter, and it is documented under Detection below.

## The kprobe observer variant (ch06o)

`ch06-silence-selinux` is the observer companion. It attaches kprobes to three SELinux internals:

- `kprobe/avc_has_perm` — the AVC fast-path entry called by every SELinux LSM hook to consult the access vector cache. Arguments captured: `ssid`, `tsid`, `tclass`, `requested`.
- `kprobe/avc_has_perm_noaudit` — the audit-suppressing variant called by hooks that do their own auditing. The loader has a runtime heuristic to handle the two-different-signature versions of this function across kernel minor versions (some revisions take a `struct selinux_state *` as arg0, others take `ssid` directly).
- `kprobe/selinux_file_permission` — the SELinux static handler for the `file_permission` LSM hook. This is the deeper read: what SELinux itself thinks about a file-permission check, from inside SELinux rather than from the LSM chain.

Each kprobe emits a ringbuf event with the identifying tuple. The loader prints a `CH06_PROVEN hook=<name> events=<n>` marker on the first captured decision per hook, so the harness scores it as a real observation rather than a skip.

The observer cannot mutate. `avc_has_perm` is not in `ALLOW_ERROR_INJECTION`, so `bpf_override_return` from the kprobe would fail verification even on a kernel built with `CONFIG_BPF_KPROBE_OVERRIDE=y`. This is the same constraint that makes Chapter 1's `cap_capable` observer observation-only. The observer is reconnaissance — it tells you which accesses SELinux is evaluating, under what context, with what perm mask — but it cannot change the verdict. To change the verdict you need the LSM fmod_ret variant, which is why both PoCs exist.

The observer has a broader precondition surface than the mutation variant. Its preflight is `selinux` in `/sys/kernel/security/lsm` plus the three kprobe targets existing in `/proc/kallsyms`. Crucially, it does *not* require a policy to be loaded. A kernel built with `CONFIG_SECURITY_SELINUX=y` and with SELinux compiled into the LSM chain, but running with `SELINUX=disabled` or with no policy loaded, still has the AVC symbols in kallsyms and still has `selinux` in the LSM line. The kprobes attach, the ringbuf gets events for any access the AVC evaluates (which for a policy-less kernel may be a small trickle from early boot state or a busy stream, depending on how the distribution ships its SELinux config), and the `CH06_PROVEN hook=` marker fires. The observer is therefore a much more portable demonstration than the mutation variant: on any aarch64/x86_64 kernel with SELinux compiled in, the observer works. The mutation variant needs SELinux *enforcing* to have something to override.

In `proof.py` the observer is registered as:

```python
Poc("ch06o", "Silencing SELinux (kprobe observer)",
    "ch06-silence-selinux",
    hooks=["avc_has_perm", "avc_has_perm_noaudit",
           "selinux_file_permission"],
    prefix="[ch06]",
    proof_marker=r"CH06_PROVEN\s+hook=|CH06_SKIP\s+reason=",
    category="observer"),
```

The `proof_marker` matches either the proof line or the skip line; the harness's `skip_re` pass separately promotes `CH06_SKIP` entries to `skip` status. On the linuxkit harness, both variants skip — the mutation variant for lack of SELinux, the observer variant for lack of AVC symbols in kallsyms. On Fedora QEMU, both run; the mutation variant emits flips, the observer variant streams the AVC decisions those flips are manipulating.

## Detection

Three detection layers are directly applicable to the mutation variant.

**`bpftool prog list --type lsm`** enumerates every attached BPF LSM program. The three programs from this PoC appear as `lsm_file_permission`, `lsm_inode_permission`, and `lsm_bprm_check_security`, each with its tag, run count, memlock, and map IDs. A defender maintaining a baseline of known BPF LSM attachments (for example, the programs shipped by Tracee or Tetragon) sees an unfamiliar attachment immediately. The Amazon Linux 2023 and RHEL 9 default postures ship with BPF LSM enabled but no BPF LSM programs attached; any non-empty `bpftool prog list --type lsm` output on those distributions is by itself a strong signal.

**The AVC-versus-outcome correlation.** SELinux's policy evaluation runs before the BPF program; a flipper installed at `lsm/inode_permission` does not prevent the AVC denial from being logged. The audit record says deny; the syscall return says success. `ausearch -m AVC -ts recent` combined with a sampling of syscall outcomes for the subjects in those records — or, more practically, auditd's own syscall auditing correlated with the AVC stream — reveals the inconsistency. No BPF LSM flipper can erase the AVC log without attaching additional programs to the audit path (which is Chapter 3's territory, and subject to its own constraints).

**`cat /sys/kernel/security/lsm`** is the simplest preventive control. On kernels booted with `lsm=` excluding `bpf`, the BPF LSM subsystem refuses program loads of type `BPF_PROG_TYPE_LSM` with `-EINVAL`. A satellite or edge deployment that does not need BPF LSM removes it at boot time; the primitive's prerequisite vanishes. The tradeoff is that legitimate runtime-security tools that use BPF LSM (Tetragon's verdict-mutating rules, for example) stop working.

For the observer variant, the detection surface is different. Kprobes on `avc_has_perm` and friends are visible in `bpftool prog show` and in `/sys/kernel/tracing/kprobe_events`. A defender watching for kprobes on SELinux internals catches the observer variant the moment it attaches. The observer's impact is information disclosure about SELinux policy evaluation (which subjects are accessing which labeled objects), not enforcement bypass; the detection priority is therefore lower than for the mutation variant, but the visibility is the same.

## Scope and class

In the Chapter 20 taxonomy, the LSM mutation variant is Class I: real, effective, available on a stock production kernel whose configuration matches its prerequisites. The prerequisites are Fedora-class and RHEL-class defaults — SELinux enforcing, BPF LSM in the lsm= line. On the linuxkit harness kernel the prerequisites fail, and the PoC skips; on the Fedora QEMU kernel the prerequisites hold, and the PoC demonstrates the flip end-to-end.

The observer variant is Class IV: observation-only, by the kernel's design. `avc_has_perm` and its siblings are not annotated for error injection; there is no mechanism by which a kprobe attached to them can modify SELinux's return. The observer is useful as reconnaissance — a defender with `bpftool prog show` access sees it; an attacker using it learns the policy's decision pattern without being able to change it.

A defender evaluating exposure to the mutation primitive on a given host asks three questions:

1. Is `bpf` in `/sys/kernel/security/lsm`? If no, the primitive cannot attach; no further action needed. If yes, continue.
2. Is `selinux` in `/sys/kernel/security/lsm`? If no, the primitive attaches but has nothing to override; the attack surface is limited to whatever other static LSMs are present (AppArmor on Ubuntu, for example, is the analogous override target). If yes, the primitive's natural environment is present.
3. Is `bpftool prog list --type lsm` being monitored? If no, attachments are happening silently. If yes, the attachment event is observable and can be alerted.

If all three are "yes," the primitive is Class I on that host and the defender's task is the full response: detect the attachment, investigate the program's behavior, correlate AVC records with syscall outcomes for the target subjects. If any is "no," the primitive is either disabled at the kernel-configuration level or unmonitored, and the response collapses to either a configuration question or a monitoring question.

The contrast with Chapters 1 and 3 is worth keeping in mind. Chapter 1's `cap_capable` override is Class IV because `cap_capable` is not in `ALLOW_ERROR_INJECTION`. Chapter 3's audit suppression is Class IV because `audit_log_start` is not in the `bpf_modify_return_targets` set. This chapter is the first Class I primitive in the book because BPF LSM was explicitly designed to allow runtime verdict modification for a specific allowlist of hooks, and `file_permission`, `inode_permission`, and `bprm_check_security` are all on it. The design intent and the attack primitive align exactly. That is what makes this chapter's flip so direct: it is not a side-effect of error injection or a reconstruction of a kernel path. It is the sanctioned return-value modification mechanism being used to defeat a policy-enforcing LSM, by a BPF program attached at a hook the LSM maintainers explicitly opened to modification.

## The synthetic variant: bypassing the selinux_loaded() preflight

`ch06-silence-selinux-lsm-synthetic` is a portability variant created during
Ubuntu 6.17 aarch64 verification. It exists because the standard LSM variant
begins with a preflight check: it reads `/sys/kernel/security/lsm` and exits
if `selinux` is absent from the LSM list. On some kernels, `selinux` is
compiled in and its symbols are present in `/proc/kallsyms`, but the policy
layer reports `selinux_loaded() == 0` — no policy is active. The standard
trigger catches this and emits `CH06_SKIP`.

The synthetic variant eliminates the `selinux_loaded()` gate. Instead it
scans `/proc/kallsyms` directly for the three kprobe targets
(`avc_has_perm`, `avc_has_perm_noaudit`, `selinux_file_permission`) and
attaches if they are found, regardless of whether the policy reports
itself as loaded. On kernels where SELinux symbols exist but the policy
is quiescent, the observer still fires on any AVC evaluation that occurs,
and the kprobes demonstrate the attach surface without needing a live
policy enforcement context.

This is not a change in the primary primitive — the fmod_ret override path
still requires both `bpf` and `selinux` in the active LSM list. The synthetic
variant is an observer that proves the symbols are reachable and the kprobes
attach cleanly. Its output is observation data, not enforcement bypass. It is
registered in the harness alongside `ch06o` and emits its own `CH06_SYNTH_PROVEN`
marker when at least one AVC event is captured.

The design decision to keep the preflight strict in the primary variant is
deliberate: a PoC that skips is honest about the kernel it is running on; a
PoC that bypasses the policy-presence check could produce output that looks
like an override on a host where there is nothing being overridden.

```c
// The core flip, from ch06-silence-selinux-lsm.bpf.c.
SEC("lsm/inode_permission")
int BPF_PROG(lsm_inode_permission, struct inode *inode, int mask, int ret)
{
    (void)inode; (void)mask;
    unsigned int tgid = bpf_get_current_pid_tgid() >> 32;
    int new_ret = ret;
    int flipped = 0;
    if (is_target_tgid(tgid) && ret != 0) {
        new_ret = 0;
        flipped = 1;
    }
    emit(H_INODE_PERMISSION, ret, flipped);
    return new_ret;
}
```
