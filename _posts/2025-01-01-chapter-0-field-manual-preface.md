---
layout: book
title: "Preface"
date: 2025-01-01
---

# Chapter 0: The Dark Side of BPF

**Hey there, fellow kernel spelunker.**

Look, we're gonna level with you right from the start. This isn't your typical security research. There are no CVEs here, no bug bounties waiting at the end of the rainbow. What you're about to dive into is something far more interesting—and arguably more terrifying.

### What You're Really Looking At

This field manual documents what `CAP_BPF` plus `CAP_PERFMON` (or `CAP_SYS_ADMIN`) actually permits on a modern Linux kernel. Every technique here assumes the attacker already holds that capability.

Every technique in here: working as intended. Every "exploit": a feature used for its documented purpose. Every bypass: exactly what the kernel developers designed eBPF to do, operating against a workload whose threat model did not price in a privileged sibling holding `CAP_BPF`.

### The Uncomfortable Truth

Here's the thing that keeps us up at night: eBPF isn't broken. It's *perfect*. It does exactly what it says on the tin—gives you kernel-level programmability with surgical precision. The problem (if you want to call it that) is that "kernel-level programmability" is just a fancy way of saying "god mode for your operating system."

When you load an eBPF program, you're not exploiting anything. You're literally injecting code into the kernel that runs with ring-0 privileges. The kernel *wants* you to do this. It's the whole point.

### Why This Matters (And Why You Should Care)

We've spent years in the trenches—red teams, blue teams, that weird purple space where you're not sure whose side you're on anymore. And we can tell you this: most defenders have no idea what they're up against when it comes to eBPF.

They see it as this cool observability tool, maybe a fancy way to do network filtering. They don't see it as what it really is: **the most powerful userland-to-kernel interface ever created.**

### The Hacker's Perspective

From a hacker's point of view, eBPF is like finding out your target left the front door unlocked, the alarm system disabled, and a note saying "please come in and make yourself at home." Except it's not a mistake—it's by design.

Every security boundary you've spent years learning to respect? eBPF can step right over them. Not by breaking them, but by operating at a level where they simply don't apply.

- Want to bypass seccomp? eBPF runs before seccomp even knows what hit it.
- Need to evade audit logs? eBPF can intercept and modify them in real-time.
- Trying to hide from process monitoring? eBPF can make you invisible to the very tools designed to watch for you.

And here's the kicker: **none of this is a vulnerability**. It's all working exactly as designed.

### The Real Game

This manual isn't about finding bugs. It's about understanding power. Real, fundamental, kernel-level power. The kind that makes traditional privilege escalation look quaint.

When you understand these techniques, you're not just learning new attack vectors. You're learning to think like the kernel itself. You're seeing the matrix, if you'll forgive the reference.

### A Word of Warning (Because We Have To)

Look, we're not your parents, and we're not going to lecture you about responsible disclosure or ethical hacking. You're smart enough to know that with great power comes great responsibility, and all that Spider-Man nonsense.

But we will say this: these techniques are *powerful*. Like, "accidentally-brick-your-test-lab" powerful. Like, "explain-to-your-boss-why-the-production-server-is-on-fire" powerful.

Use them wisely. Use them legally. Use them with permission. And for the love of all that is holy, use them in a lab first.

### The Journey Ahead

This isn't just a collection of techniques—it's a story. The story of what happens when you discover that the Linux kernel has become programmable, and what that really means for security.

**Act I: The Discovery** (Chapters 1-6)
We start with **The Mirror Controls** — overriding the return value of kernel security-decision functions so userspace sees a forged answer. From there, we explore container escapes through **OverlayFS manipulation**, **audit evasion** via ringbuf exfiltration, **phantom syscalls** that leak kernel struct fields, **ghost network interfaces** via XDP, and cgroup accounting rewrites that let a workload **slip its resource limits**.

**Act II: The Deep Dive** (Chapters 7-12)
We silence **SELinux** itself, perform the ultimate **device access escape**, steal secrets from the **kernel keyring**, create **process doppelgängers** across namespaces, make files **invisible to detection**, and weaponize **interrupt handling** for chaos.

**Act III: The Advanced Game** (Chapters 13-18)
We violate the deepest trust with **signed driver swaps**, override **power management** for hardware attacks, hijack **real-time scheduling**, create **network namespace ghosts**, perform **thread identity hops**, communicate directly with **firmware interfaces**, and finally subvert **authentication itself** at the kernel level.

**Epilogue: The New Reality**
We step back and confront the ultimate truth—that in a fully programmable computing stack, everything from security controls to hardware behavior to cryptographic trust to identity itself can be rewritten. This is where you realize that you haven't just learned attack techniques—you've discovered that the fundamental nature of computing has changed.

Each chapter builds on the last, not just in complexity, but in understanding. You'll start thinking like a traditional attacker and end up understanding that in the age of programmable systems, the very concept of "attack" versus "legitimate functionality" becomes meaningless.

### Ready to Go Down the Rabbit Hole?

eBPF is not vulnerable. eBPF is not broken. eBPF is not a mistake.

eBPF is working as documented. The surprises come from what "working as documented" means when the capability is granted to observability agents by default.
