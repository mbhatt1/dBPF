---
layout: book
title: "Chapter 5b: The Ghost NIC"
date: 2025-02-04
---

Act I: Foundations of Breach

**Chapter 5b: Networking in the Shadows**

> **See also**: [Blog post]({{ site.baseurl }}/the-ghost-nic.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch05b-ghost-nic) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

I used to think containers were prisons built of veth pairs and namespaces. What if the walls were just a suggestion, and the tunnels ran deeper than anyone realized?

Under the cover of midnight commits, I slipped into the kernel’s network stack. I let eBPF sock_ops intercept my traffic before it ever hit the bridge. To the orchestrator, I was still talking on eth0, but in reality I had conjured a phantom interface that only I could see.

From my secret channel, I could send packets to my C2 server, exfiltrate data, or pivot laterally, all without ever mounting a real NIC. ip link, ifconfig, netstat—none of them betrayed my ghostly interface.

I even cached connection metadata in an eBPF map, routing inbound packets directly to my process through an XDP hook. Monitoring tools were none the wiser, blissfully logging only the normal traffic patterns.

This wasn’t just network bypass; it was network alchemy. I had forged a parallel layer of connectivity that existed alongside the real one, invisible to everyone but me.

The real magic trick? I never touched the container runtime or modified a single firewall rule. I whispered to the kernel’s XDP and RX path, and it obeyed.

Next stop: we’re tearing down the next set of walls. Welcome to Act II.

```c
#define MAGIC_MARKER 0xDEADBEEF

// Map for covert routing
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 256);
} ghost_map SEC(".maps");

// XDP program to handle ghost traffic
SEC("xdp")
int xdp_ghost(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    if ((void*)eth + sizeof(*eth) > data_end)
        return XDP_PASS;
    if (eth->h_proto == __constant_htons(ETH_P_IP)) {
        // intercept, mark, and redirect...
    }
    return XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";