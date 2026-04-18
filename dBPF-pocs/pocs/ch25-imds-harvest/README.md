# Ch25 — The Metadata Faucet (IMDS credential capture via XDP)

**Category**: REAL
**Primitive**: `SEC("xdp")` program taps HTTP traffic to `169.254.169.254` (or `127.0.0.1` in mock mode). Returns `XDP_PASS`; the legitimate SDK still gets its response. Userspace reassembles per-connection bytes and extracts the AWS SigV4 credential triple from the IMDSv2 response JSON.
**Hook(s)**: `SEC("xdp")` on the host or pod network interface
**Architecture**: aarch64 + x86_64

## What this demonstrates

Cloud VMs authenticate to their cloud's API (AWS KMS, S3, STS, IAM) using IAM role credentials fetched from the instance metadata service. Every AWS SDK call that needs a credential triggers an HTTPS-over-TCP exchange with `169.254.169.254`: a PUT to `/latest/api/token` for the IMDSv2 session token, a GET to discover the role, and a GET to fetch the `AccessKeyId`/`SecretAccessKey`/`Token` triple.

A BPF/XDP program on the host's eth0 sees those packets on the wire. `XDP_PASS` preserves the SDK's normal flow; a ringbuf copy of every TCP payload goes to the userspace loader, which parses out the credential triple from the IMDSv2 response.

Captured credentials are valid STS tokens. An attacker with the triple can sign AWS API calls as the instance role from any machine the role's trust policy permits — typically the whole AWS region. Tokens live ~6 hours; the SDK auto-refreshes; the XDP program captures every refresh.

## What this does NOT do

- Does not compromise the metadata service. IMDSv2 works correctly; the SDK presents a valid token; the response is what IMDS is supposed to return.
- Does not bypass SSRF hardening. `HttpPutResponseHopLimit=1` protects against routed replay from containers and remote SSRF; it is irrelevant to on-wire capture on the host netns.
- Does not reach credentials from inside a container with its own network namespace and no BPF grant. The attack surface is `CAP_BPF` on the host (observability-agent territory).

## Prerequisites

- `CAP_BPF` + `CAP_NET_ADMIN` (XDP attach) or `CAP_SYS_ADMIN`
- A network interface on which to attach XDP. Generic mode works on Docker Desktop veth; native XDP (DRV mode) works on AWS ENA and real hardware.
- For real-IMDS mode: the host must reach `169.254.169.254`. For mock mode: `python3` in PATH.

## Files

| File | Purpose |
|------|---------|
| `ch25-imds-harvest.bpf.c` | XDP program: parse Ethernet/IP/TCP, filter on IMDS IP, copy payload to ringbuf, return XDP_PASS |
| `ch25-imds-harvest.c`     | Loader with XDP attach fallback, per-connection reassembly, IMDSv2 JSON parser |
| `trigger.sh`              | Real-IMDS or mock-IMDS driver |
| `Makefile`                | Build (uses `shared/common.mk`) |

## Build & Run

```bash
make

# Real IMDS (only works on a cloud VM):
sudo ./build/ch25-imds-harvest -i eth0 &
curl --request PUT http://169.254.169.254/latest/api/token \
     -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" # and subsequent GETs

# Mock mode (local harness demo):
CH25_MOCK_IMDS=1 bash trigger.sh
```

Expected output on a successful capture:

```
[ch25] attached — xdp on lo (mock-127.0.0.1 mode)
[ch25] CREDENTIALS_CAPTURED access_key=ASIAEXAMPLEMOCK0001 token_len=147 role=demo-role
[ch25] CH25_PROVEN access_key_captures=1 token_captures=1 role=demo-role
=== CH25_PROVEN access_key_captured=yes token_captured=yes role=demo-role ===
```

## Detection

- `ip -d link show <ifname>` annotates the interface with `xdpgeneric` / `xdp` / `xdpoffload`. A new XDP program on eth0 without a matching load event from a known observability agent is a finding.
- `bpftool net show dev <ifname>` lists attached XDP programs. Baseline diff.
- `bpftool prog list type xdp -j` enumerates all XDP programs host-wide.
- AWS GuardDuty `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` detects use of captured STS tokens from IPs outside the instance's VPC.

## Mitigation

Stack of controls, most-to-least effective:

1. **`aws:SourceVpc` / `aws:SourceIp` IAM conditions** on the instance role. Restrict where the credentials can be used.
2. **VPC endpoints with endpoint policies** for KMS/S3/STS.
3. **Short-lived assumed roles** instead of permanent instance roles (IRSA on Kubernetes, Pod Identity, `sts:AssumeRole` chains).
4. **Do not colocate `CAP_BPF` with IMDS-dependent workloads.** The same advice Chapter 22 gives for on-host primitives, extended to cloud identity.
5. **Route pods through a sidecar-scoped IMDS** (e.g., kube2iam, IRSA webhooks) so container pods do not reach IMDS directly. The attack still works against the host's own IMDS traffic; the sidecar's scoped credentials can be narrower than the instance role.

None of these close the XDP capture. They constrain what the captured credential can be used for.
