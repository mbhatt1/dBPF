---
layout: book
title: "Slipping the Cgroup Leash"
date: 2025-02-05
---

Act I: Foundations of Breach

**Chapter 6: Breaking Free from All Constraints**

> **See also**: [Blog post]({{ site.baseurl }}/slipping-the-cgroup-leash.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch05-cgroup-leash) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

I still remember the first time I saw my CPU usage throttled by a cgroup. It felt like a comfy prison cell at first—tightly controlled, predictable.

But predictability breeds complacency. At 3 AM, caffeine coursing through my veins, I realized that cgroups are nothing more than teller lines for kernel accountants. They trust the kernel to count me, but what if I taught the kernel to miscount?

I slipped an eBPF probe onto the very function that charged my CPU time, `cgroup_account_cputime()`. It was like jamming a blank check into the accountant’s ledger.

In that moment, the scheduler nodded and handed me back a receipt that said I’d only used 5 percent of the CPU.

Meanwhile, my payload was chewing through 95 percent like a worm in an apple.

To keep the throttle off my back, I muted the calls that slowed me down when I “exceeded” limits. No more sudden pauses, no more watching the meter creep up—just sweet, unbridled cycles.

I even whispered to the monitoring API, feeding it made-up stats so the dashboards stayed neon-green with compliance.

It was beautiful: the orchestrator danced to my tune, blissfully unaware that I was hijacking its own metrics.

That’s the power of slipping the cgroup leash—convincing the kernel to believe its own lies.

My toolkit was complete: from bypassing LSM controls to escaping containers, ducking audits, crafting phantom syscalls, and now this—resource theft in broad daylight.

Act I closed with a grin; Act II would hit harder, but that’s a story for later.

```c
SEC("cgroup/account") int cheat_cputime(struct bpf_cgroup *cgrp) {
    u64 real = bpf_get_cgroup_cpu_time(cgrp);
    u64 fake = real / USAGE_DIVISOR;
    bpf_update_cgroup_cpu_stat(cgrp, fake);
    return 0;
}