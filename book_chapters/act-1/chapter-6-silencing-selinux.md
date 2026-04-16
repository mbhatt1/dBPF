---
layout: book
title: "Silencing SELinux"
date: 2025-02-06
---

Act I: Foundations of Breach

**Chapter 6: Silencing SELinux**

I used to think SELinux was the unbreakable seal in the kernel’s vault—the one thing that even root couldn’t fudge. Turns out, that guard is just another piece of code you can whisper to.

Under cover of a stealthy kprobe, I hooked into `avc_has_perm()`, the function that decides who gets in and who stays out. One line of eBPF, and every "deny" became a "permit."

Then I poisoned the AVC cache with fake "allow" records so the kernel never bothered to recheck its rulebook. The audit stream? Muted. Not a single kernel log dared to whisper that I slipped past the bouncer.

Watching my exploits dance through protected filesystems felt like walking through a locked museum with the lights off. Everything looked lawful, even though I owned every exhibit.

And best of all, SELinux never knew it was being played. I hadn’t disabled it—I’d made it my puppet.

```c
SEC("kprobe/avc_has_perm")
int bypass_avc(struct pt_regs *ctx) {
    return 0; // always allow
}

char LICENSE[] SEC("license") = "GPL";