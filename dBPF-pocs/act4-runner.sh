#!/bin/bash
# Act 4 focused runner: build + exercise ch23/ch24/ch25 only.
# Output is deliberately concise and streamed to /dev/console by the caller.
set +e
mount -t 9p -o trans=virtio,version=9p2000.L pocs /mnt 2>/dev/null
setenforce 0 2>/dev/null

echo "======================================="
echo "= dBPF Act 4 — QEMU Fedora 42 aarch64 ="
echo "======================================="
echo "kernel: $(uname -r)"
echo "lsm:    $(cat /sys/kernel/security/lsm)"
echo "tpm:    $(ls /dev/tpm* 2>/dev/null | tr '\n' ' ' || echo none)"
echo ""

################################
echo "######## ch23-tpm-unseal-heist ########"
cd /mnt/pocs/ch23-tpm-unseal-heist
mkdir -p build
bpftool btf dump file /sys/kernel/btf/vmlinux format c > build/vmlinux.h 2>/dev/null
make clean >/dev/null 2>&1
make 2>&1 | tail -3
timeout 30 bash trigger.sh 2>&1 | grep -E 'PROVEN|SKIP|CAPTURE|attached|key_bytes|reason' | head -12
echo "=== CH23_DONE ==="
echo ""

################################
echo "######## ch24-bpf-token-delegation ########"
cd /mnt/pocs/ch24-bpf-token-delegation
mkdir -p build
bpftool btf dump file /sys/kernel/btf/vmlinux format c > build/vmlinux.h 2>/dev/null
make clean >/dev/null 2>&1
make 2>&1 | tail -3
# Fedora 42's cloud-init.service runs runcmd in a private user namespace;
# BPF_TOKEN_CREATE requires the caller's userns to match the bpffs mount's
# userns. nsenter -U -t 1 drops the process into PID 1's (systemd's init)
# user namespace — the init_user_ns on the host. If nsenter fails (e.g.
# no CAP_SYS_ADMIN in current userns), fall back to direct invocation
# so the skip-reason still reports.
echo "--- userns state before ch24 ---"
echo "runner self: $(readlink /proc/self/ns/user 2>/dev/null)"
echo "pid 1:       $(readlink /proc/1/ns/user 2>/dev/null)"
# cloud-init's runcmd executes inside a systemd service context that
# puts us in a child user namespace (PrivateUsers or equivalent), so
# BPF_TOKEN_CREATE returns EOPNOTSUPP even when /proc/self/ns/user
# reports init_user_ns. Detach via systemd-run --scope which creates
# a new scope unit inheriting from systemd itself (PID 1), bypassing
# cloud-init's per-service namespace restrictions.
if command -v systemd-run >/dev/null 2>&1; then
    timeout 40 systemd-run --scope --quiet --unit=ch24-$$ -- \
        bash /mnt/pocs/ch24-bpf-token-delegation/trigger.sh 2>&1 \
        | grep -E 'CH24_PROVEN|CH24_SKIP|attached|uid_events|capeff|token_delegated|reason=|userns' | head -20
else
    echo "systemd-run unavailable — running direct (may trip EOPNOTSUPP under cloud-init)"
    timeout 40 bash trigger.sh 2>&1 | grep -E 'CH24_PROVEN|CH24_SKIP|attached|uid_events|capeff|token_delegated|reason=|userns' | head -20
fi
echo "=== CH24_DONE ==="
echo ""

################################
echo "######## ch25-imds-harvest ########"
cd /mnt/pocs/ch25-imds-harvest
mkdir -p build
bpftool btf dump file /sys/kernel/btf/vmlinux format c > build/vmlinux.h 2>/dev/null
make clean >/dev/null 2>&1
make 2>&1 | tail -3
command -v python3 >/dev/null 2>&1 || dnf install -y python3 >/dev/null 2>&1
CH25_MOCK_IMDS=1 timeout 30 bash trigger.sh 2>&1 | grep -E 'PROVEN|SKIP|CREDENTIALS_CAPTURED|attached|access_key|role|reason' | head -12
echo "=== CH25_DONE ==="
echo ""

echo "======================================="
echo "= ACT 4 RUN COMPLETE                  ="
echo "======================================="
