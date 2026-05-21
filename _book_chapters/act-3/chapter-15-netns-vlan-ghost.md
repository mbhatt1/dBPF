---
layout: book
title: "Chapter 15: NetNS VLAN Ghost"
date: 2025-04-15
---

# Chapter 15: Cross-Namespace Redirect via XDP and DEVMAP

> **See also**: [Blog post]({{ site.baseurl }}/netns-vlan-ghost.html) · [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch15-netns-vlan-ghost) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

My first attempt at this chapter was a kprobe on `__netif_receive_skb_core` that rewrote the namespace metadata on an incoming `skb` and let the kernel re-receive it on the other side. The verifier rejected it. Writes to `sk_buff` from kprobe context are not permitted, and `__netif_receive_skb_core` is not in the error-injection list, so there is no legal way to intercept-and-divert from that attach point on 6.12.

The working form of the same primitive is XDP plus `bpf_redirect_map` into a DEVMAP slot whose target ifindex lives in a different network namespace. None of this is novel: Cilium has been using exactly this pattern since around 2019 for legitimate cross-namespace forwarding in its service-mesh datapath. The only contribution here is pointing it in a hostile direction. VLAN-based segmentation was never designed to resist host-level XDP ; an XDP program is a peer to the netdev, not above it.

## Mechanism

The XDP program attached to the host side of a veth pair runs on every ingress frame:

1. Parse the ethernet header. If ethertype is `0x8100` and the VID in the 802.1Q TCI matches `COVERT_VLAN_ID` (4242), the frame is in scope.
2. Save the original src/dst MAC and the inner ethertype from offset +16.
3. Rewrite a fresh 14-byte ethernet header at offset +4, overlaying the old `src_mac` tail, the `0x8100` ethertype bytes, and the VLAN TCI.
4. Call `bpf_xdp_adjust_head(ctx, +4)` to trim the leading 4 bytes. The VLAN tag is gone; the new untagged ethernet header is the packet head.
5. If userspace registered an egress ifindex in the `tx_port` DEVMAP (slot 0) and `cfg[0] == 1`, call `bpf_redirect_map(&tx_port, 0, 0)`. Otherwise return `XDP_PASS`.

The egress ifindex can point at a veth whose peer lives in a different netns. That is the "ghost" part: the orchestrator's VLAN-aware bridge never sees the tagged frame because XDP ran first, before the bridge, before netfilter, before the rest of the stack.

## Verification

Captured running `bash trigger.sh` in the privileged `dbpf-base` container on linuxkit aarch64. veth does not implement native XDP on this platform, so XDP was forced to SKB-mode:

```
=== loading XDP ghost on veth_host -> redirect to veth_host2 (SKB-mode) ===
[ch15] tag=ready ingress=veth_host ifidx=42 mode=redirect egress=veth_host2 ifidx=44 xdp_flags=0x2

=== sending 5 VLAN-4242 AF_PACKET frames from inside ghost_a ===
sent 5 VLAN-4242 covert frames

=== loader ringbuf events ===
[vghost] ifin=42 vid=4242 inner=0x88b5 ee:f0:6e:11:22:33 -> ff:ff:ff:ff:ff:ff  STRIP+REDIRECT ifout=44

=== tcpdump on veth_host2 ===
ee:f0:6e:11:22:33 > ff:ff:ff:ff:ff:ff, ethertype Unknown (0x88b5), length 78: ...
```

The `tcpdump` frame is untagged ; no `vlan 4242` in the dissector output, inner ethertype `0x88b5` is the outermost now. That is evidence the strip ran before the egress veth saw the packet.

## Threat model, honestly

Calling this a "VLAN escape" is overselling it. The correct framing: **if an attacker holds `CAP_BPF` on the host, netns isolation between containers wired via veth is not a barrier.** XDP runs at the netdev edge, ahead of the bridge, ahead of netfilter, ahead of the namespace routing logic. VLAN segmentation is an orchestration-layer control that presumes the bridge will see the tag; an XDP program on the veth peer sees frames the bridge never does. This is the expected behaviour of the XDP hook. What's being demonstrated is that a control you might assume gates cross-namespace traffic was never in the path to begin with.

## Hook points

- `SEC("xdp")` `xdp_vlan_ghost` on the ingress veth.
- `BPF_MAP_TYPE_DEVMAP tx_port` ; slot 0 holds the egress ifindex for `bpf_redirect_map`.
- `BPF_MAP_TYPE_ARRAY cfg` ; slot 0 is the mode flag, slot 1 an audit copy of the egress ifindex.

The dead-end sketch ; the kprobe on `__netif_receive_skb_core` that the original outline called for ; is documented here because the dead end is instructive. The "rewrite skb namespace metadata" intuition is natural and wrong for two independent reasons: the verifier rejects skb writes from kprobe context, and the symbol is not error-injectable. XDP is the correct landing site.

```c
SEC("kprobe/__netif_receive_skb_core")
int ghost_vlan(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    // Detect covert VLAN tag
    if (skb_vlan_tag_present(skb) && skb_vlan_tag_get(skb) == COVERT_VLAN_ID) {
        // Rewrite namespace metadata for cross-namespace routing
        redirect_skb_to_namespace(skb, target_ns);
    }
    return XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
```

(The kprobe snippet above is the rejected original sketch; the working code is an XDP program that adjusts the head and redirects via DEVMAP. See the POC repo.)

**Category: REAL.** This is actual VLAN header manipulation and cross-namespace packet redirect, not a userspace illusion. The XDP program physically strips the 802.1Q tag and `bpf_redirect_map` delivers the frame to a device in a different network namespace. The orchestrator's VLAN-enforcement layer is preempted because XDP runs before the bridge and netfilter.

## Build

```
cd /Users/mbhatt/spaceclaw/evilBPF/dBPF-pocs
docker run --rm -v "$PWD":/work -w /work dbpf-base \
  bash -c 'cd pocs/ch15-netns-vlan-ghost && make'
```

## Run

```
./build/ch15-netns-vlan-ghost --skb -i veth_host -o veth_host2
./build/ch15-netns-vlan-ghost -i veth_host                    # strip-only
./build/ch15-netns-vlan-ghost veth_host veth_host2            # back-compat
```

SIGINT/SIGTERM detaches XDP from every interface it attached to; `detach_all()` runs on every error-path exit as well.

End-to-end demo (creates `ghost_a` / `ghost_b` netns, sends one VLAN-4242-tagged AF_PACKET frame from inside `ghost_a`, sniffs egress on `veth_host2`):

```
docker run --rm --privileged --pid=host --net=host \
  -v "$PWD":/work -w /work \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/fs/bpf:/sys/fs/bpf \
  dbpf-base bash pocs/ch15-netns-vlan-ghost/trigger.sh
```

## Detection

- `bpftool net show dev <ifname>` lists XDP programs attached to an interface. Almost nothing legitimate loads XDP on container veths; a datapath-class program on a veth in a conventional workload is a reliable signal.
- `bpftool prog show` plus `bpftool map dump name tx_port` reveals DEVMAP entries pointing at veths whose peers live in foreign namespaces.
- `ip -d link show dev <ifname>` annotates `xdpgeneric`, `xdp`, or `xdpoffload` when a program is attached.
- The combination of `bpf_xdp_adjust_head` and `bpf_redirect_map` is rare outside dataplane software. Auditing programs that call both is worthwhile.

## Limitations

- Docker Desktop linuxkit aarch64: veth drivers do not implement native XDP; the loader falls back to SKB-mode (or `--skb` skips the probe). Native-mode redirect is unavailable. `--net=host` is required in the Docker run command so the XDP program can attach to host-side veth interfaces. Without it the container's netns hides the veths.
- `bpf_redirect_map` to a device in another netns requires the egress device to also have an XDP program loaded on many kernels; the loader attaches the same program there.
- The verifier rejects `skb` writes from kprobe context, so the chapter's original `__netif_receive_skb_core` mutation cannot be done directly. XDP at the NIC edge is the equivalent primitive.
- `arping` and `ping` will not generate the covert frames reliably; the trigger uses an embedded AF_PACKET sender for deterministic VLAN-4242 emission with inner ethertype `0x88b5`.

> **Proof status**: **PROVEN** on Ubuntu 6.17.0-29-generic aarch64 (Lima VM), 2026-05-20. Proof marker: `VLAN_GHOST_CROSSNS_PROVEN redirect_count=3`.
