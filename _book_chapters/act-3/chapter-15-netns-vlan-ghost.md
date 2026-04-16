---
layout: book
title: "Chapter 15: NetNS VLAN Ghost"
date: 2025-04-15
---

**Chapter 15: Cross-Namespace Redirect via XDP and DEVMAP**

> **See also**: [Blog post]({{ site.baseurl }}/netns-vlan-ghost.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch15-netns-vlan-ghost) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

Cross-namespace XDP redirect via `bpf_redirect_map` is not novel. Cilium's datapath has used the pattern since approximately 2019 for legitimate cross-namespace forwarding in service-mesh topologies. `tc-bpf` and `xdp-tutorial` examples have demonstrated it in pedagogical form for about the same span. The primitive is mature, documented, and shipping in a large fraction of production Kubernetes clusters today.

What is new in this chapter is the *direction*. Cilium uses the redirect to pull traffic into the right namespace on the way toward a pod. This POC uses the redirect to ferry VLAN-tagged covert traffic *between* two tenant-style namespaces without the tagged fr