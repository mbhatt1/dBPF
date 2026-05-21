// ch25 Metadata Faucet — XDP tap on IMDS traffic (final).
// Uses direct packet access after bpf_xdp_load_bytes for header parsing.
// Payload copy uses a byte loop bounded by verifier-proven length.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define ETH_P_IP    0x0800
#define IPPROTO_TCP 6
#define MAX_PAYLOAD 256  /* smaller to simplify verifier analysis */
#define ETH_HLEN    14

#define IMDS_IP_LE  0xfea9fea9
#define MOCK_IP_LE  0x0100007f

struct evt {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u16 payload_len;
    __u8  direction;
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
    __u32 pkt_len  = (__u32)((long)data_end - (long)data);

    if (pkt_len < ETH_HLEN + 20 + 20)
        return XDP_PASS;

    /* Read via bpf_xdp_load_bytes to avoid LLVM optimizing away code */
    __be16 h_proto = 0;
    bpf_xdp_load_bytes(ctx, 12, &h_proto, 2);
    if (h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    __u8 ihl_byte = 0, ip_proto = 0;
    bpf_xdp_load_bytes(ctx, ETH_HLEN, &ihl_byte, 1);
    bpf_xdp_load_bytes(ctx, ETH_HLEN + 9, &ip_proto, 1);
    if (ip_proto != IPPROTO_TCP)
        return XDP_PASS;

    __u32 ip_hlen = ((__u32)(ihl_byte & 0x0f)) * 4;
    if (ip_hlen < 20)
        return XDP_PASS;

    __u32 saddr = 0, daddr = 0;
    bpf_xdp_load_bytes(ctx, ETH_HLEN + 12, &saddr, 4);
    bpf_xdp_load_bytes(ctx, ETH_HLEN + 16, &daddr, 4);

    __u32 zero = 0;
    __u32 *m = bpf_map_lookup_elem(&cfg, &zero);
    __u32 mock_mode = m ? *m : 0;
    __u32 target_ip = mock_mode ? MOCK_IP_LE : IMDS_IP_LE;

    __u8 direction;
    if (daddr == target_ip)
        direction = 0;
    else if (saddr == target_ip)
        direction = 1;
    else
        return XDP_PASS;

    __u32 tcp_off = ETH_HLEN + ip_hlen;
    if (tcp_off + 20 > pkt_len)
        return XDP_PASS;

    __u8 doff_byte = 0;
    bpf_xdp_load_bytes(ctx, tcp_off + 12, &doff_byte, 1);
    __u32 tcp_hlen = ((__u32)((doff_byte >> 4) & 0x0f)) * 4;
    if (tcp_hlen < 20)
        return XDP_PASS;

    __be16 sport_be = 0, dport_be = 0;
    bpf_xdp_load_bytes(ctx, tcp_off, &sport_be, 2);
    bpf_xdp_load_bytes(ctx, tcp_off + 2, &dport_be, 2);

    __u32 payload_off = tcp_off + tcp_hlen;
    if (payload_off >= pkt_len)
        return XDP_PASS;

    __u32 payload_len = pkt_len - payload_off;
    if (payload_len > MAX_PAYLOAD)
        payload_len = MAX_PAYLOAD;
    /* payload_len is in [1, MAX_PAYLOAD]. Store in stack for later use. */

    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return XDP_PASS;

    e->saddr       = saddr;
    e->daddr       = daddr;
    e->sport       = bpf_ntohs(sport_be);
    e->dport       = bpf_ntohs(dport_be);
    e->direction   = direction;
    e->_pad        = 0;

    __builtin_memset(e->payload, 0, MAX_PAYLOAD);

    /* Manual byte copy — verifier-safe via explicit loop bound */
    __u8 tmp = 0;
    __u32 i;
    for (i = 0; i < MAX_PAYLOAD; i++) {
        if (i >= payload_len) break;
        if (bpf_xdp_load_bytes(ctx, payload_off + i, &tmp, 1) < 0)
            break;
        e->payload[i] = tmp;
    }
    e->payload_len = (__u16)i;

    bpf_ringbuf_submit(e, 0);
    return XDP_PASS;
}
