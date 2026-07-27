---
layout: book
title: "The Mirror Controls"
date: 2025-01-31
poc_dir: dBPF-pocs/pocs/ch01-mirror-controls
---

# The Mirror Controls

> **See also**: [Full investigation notes in the book]({{ site.baseurl }}/book/act-1/chapter-1-the-mirror-controls.html) · [POC source](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch01-mirror-controls)

I was poking at `cap_capable` on a linuxkit 6.12 VM, trying to understand what an unprivileged observer could actually see from a kprobe. The function is the single choke point every capability check routes through, so if you want to know who is asking for what, this is where you sit. What I wanted to know next was whether I could do anything about the answer.

The short version: on a stock kernel, you cannot. `cap_capable` is not in `ALLOW_ERROR_INJECTION`, so `bpf_override_return` against it loads but never fires. The verifier accepts the program; the kernel silently ignores the override. I confirmed this by checking `/sys/kernel/debug/kprobes/list` and then by reading `kernel/bpf/verifier.c` around `check_attach_btf_id`. This post is about an observation channel, not a bypass. Getting the bypass needs a kernel built with `CONFIG_BPF_KPROBE_OVERRIDE=y` *and* the target function annotated with `ALLOW_ERROR_INJECTION` — two conditions that almost never coincide in production.

## Mechanism

Two probes, one map, one ringbuf. The entry kprobe captures the arguments (`cred`, `cap`, `opts`); the kretprobe joins against the map and reads `PT_REGS_RC(ctx)`. Nothing novel — `bcc/tools/capable.py` has used this shape since 2016.

```c
SEC("kprobe/cap_capable")
int BPF_KPROBE(kp_cap, const struct cred *cred, struct user_namespace *ns,
               int cap, unsigned int opts) {
    u64 id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&inflight, &id, &cap, BPF_ANY);
    return 0;
}

SEC("kretprobe/cap_capable")
int BPF_KRETPROBE(kr_cap, int ret) {
    u64 id = bpf_get_current_pid_tgid();
    int *cap_p = bpf_map_lookup_elem(&inflight, &id);
    if (!cap_p) return 0;

    u32 tgid = id >> 32;
    u32 *target = bpf_map_lookup_elem(&target_tgids, &tgid);
    int flipped = (target && ret != 0) ? 1 : 0;

    struct evt e = { .pid = id & 0xffffffff, .tgid = tgid,
                     .cap = *cap_p, .orig_ret = ret, .flipped = flipped };
    bpf_ringbuf_output(&events, &e, sizeof(e), 0);
    bpf_map_delete_elem(&inflight, &id);
    return 0;
}
```

The full loader is in the POC. The harness drives a target tgid list and streams events to stdout as `[ch01] tag=FLIP pid=... cap=... orig_ret=-1 -> 0`.

## Hook points

- `kprobe/cap_capable` — entry; stash `cap` keyed by `pid_tgid`.
- `kretprobe/cap_capable` — return; read the kernel's verdict, mark flips for target tgids.

Same pattern applies to most LSM hooks (`security_file_permission`, `security_bprm_check`, `security_inode_getattr`). On a kernel with `CONFIG_BPF_LSM=y` you can attach sleepable or non-sleepable LSM programs directly via `SEC("lsm/...")`. My first attempt used `SEC("lsm.s/file_permission")`. The kernel refused: the hook is not sleepable on 6.12. Dropped the `.s`; the non-sleepable variant loaded.

Seccomp runs before most BPF attach points can see a syscall, so kprobes on syscall-entry stubs are not a seccomp bypass — they observe only what seccomp has already allowed.

## Reproduction

```bash
cd dBPF-pocs/pocs/ch01-mirror-controls
make
sudo ./build/ch01-mirror-controls -t $(pidof target_proc)
# in another shell: exercise capability-gated ops as the target
```

Harness entry: `Poc("ch01", ...)` in `dBPF-pocs/harness/proof.py`. Run the full matrix with `docker run ... python3 /w/harness/proof.py`.

## Detection

Visible artifacts on any kernel:

- `bpftool prog list` output (program type `kprobe`, attach name `cap_capable`).
- `/sys/kernel/debug/kprobes/list` showing the attached kprobe.
- `/sys/fs/bpf/` pins if the loader pins the program.
- `AUDIT_BPF_PROG_LOAD` records in `auditd`.
- The process that called `bpf(BPF_PROG_LOAD)` visible in `execve` history.

None of those are hidden by this chapter. Hiding load events is a separate primitive in its own chapter.

## Scope

This kprobe variant is an observation channel, not a bypass — a Class III primitive from chapter 20. It records the kernel's capability verdicts for a target tgid list, but it does not change any of them: `cap_capable` is not on the error-injection allowlist, so the `bpf_override_return` it was built around is a silent no-op. The `tag=FLIP` events mark denials the program *would* have flipped, not denials it actually flipped. If you want a return value that the kernel genuinely honors, that lives in the BPF LSM `fmod_ret` variant covered in the full chapter, which returns `0` from `lsm/inode_permission` and makes the access succeed for real.

---

**Related material**

- Full chapter: [Chapter 1 — The Mirror Controls]({{ site.baseurl }}/book/act-1/chapter-1-the-mirror-controls.html)
- POC source: [dBPF-pocs/pocs/ch01-mirror-controls/](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch01-mirror-controls)
- Harness entry: search for `Poc("ch01", ...)` in `dBPF-pocs/harness/proof.py`
