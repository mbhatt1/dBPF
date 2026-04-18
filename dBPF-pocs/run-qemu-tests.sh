#!/bin/bash
set +e
mount -t 9p -o trans=virtio pocs /mnt 2>/dev/null
setenforce 0

echo "======== ch01-mirror-controls-lsm ========"
cd /mnt/pocs/ch01-mirror-controls-lsm
mkdir -p build; bpftool btf dump file /sys/kernel/btf/vmlinux format c > build/vmlinux.h
make clean >/dev/null 2>&1; make 2>&1 | tail -1
useradd -M tu02 2>/dev/null
echo "secret-data-here" > /tmp/ch01-test; chmod 600 /tmp/ch01-test
echo "--- baseline: unpriv read (expect denied) ---"
su -l tu02 -s /bin/sh -c "cat /tmp/ch01-test 2>&1"
echo "--- starting loader (wildcard + uid>0 filter) ---"
./build/ch01-mirror-controls-lsm -a >/tmp/ch01.out 2>/tmp/ch01.err &
LPID=$!; sleep 1
echo "--- with BPF LSM: unpriv read (expect allowed) ---"
su -l tu02 -s /bin/sh -c "cat /tmp/ch01-test 2>&1"
sleep 1; kill -INT $LPID 2>/dev/null; wait $LPID 2>/dev/null
echo "--- stdout ---"; cat /tmp/ch01.out
echo "--- stderr ---"; cat /tmp/ch01.err
echo "===CH01LSM==="

echo "======== ch02-overlayfs-lsm ========"
cd /mnt/pocs/ch02-overlayfs-lsm
mkdir -p build; bpftool btf dump file /sys/kernel/btf/vmlinux format c > build/vmlinux.h
make clean >/dev/null 2>&1; make 2>&1 | tail -1
timeout 20 bash trigger.sh 2>&1 | grep -E 'PROVEN|SKIP|denied|copy-up|EPERM|write ret|upper layer'
echo "===CH02LSM==="

echo "======== ch03-fuse-blackhole-fentry ========"
cd /mnt/pocs/ch03-fuse-blackhole-fentry
mkdir -p build; bpftool btf dump file /sys/kernel/btf/vmlinux format c > build/vmlinux.h
make clean >/dev/null 2>&1; make 2>&1 | tail -1
timeout 20 bash trigger.sh 2>&1 | grep -E 'PROVEN|SKIP|SUPPRESSED|attached'
echo "===CH03FE==="

echo "======== ch12-signed-driver-swap-lsm ========"
cd /mnt/pocs/ch12-signed-driver-swap-lsm
mkdir -p build; bpftool btf dump file /sys/kernel/btf/vmlinux format c > build/vmlinux.h
make clean >/dev/null 2>&1; make 2>&1 | tail -1
timeout 30 bash trigger.sh 2>&1 | grep -E 'PROVEN|SKIP|FLIP|baseline|override|errno'
echo "===CH12LSM==="

# --- Act 4 -------------------------------------------------------------
# Three Act-4 primitives that need the Fedora VM's surface to fire:
#   ch23 needs swtpm + trusted-key type + CONFIG_TCG_TPM2
#   ch24 needs kernel 6.9+ with bpf_token support
#   ch25 fires in mock mode on any kernel with XDP support

echo "======== ch23-tpm-unseal-heist ========"
cd /mnt/pocs/ch23-tpm-unseal-heist
mkdir -p build; bpftool btf dump file /sys/kernel/btf/vmlinux format c > build/vmlinux.h
make clean >/dev/null 2>&1; make 2>&1 | tail -1
# Best-effort: if swtpm is installed and /dev/tpm0/tpmrm0 exists, trigger fires.
# Otherwise trigger emits CH23_SKIP cleanly.
if ! command -v keyctl >/dev/null 2>&1; then
    dnf install -y keyutils >/dev/null 2>&1 || apt-get install -y keyutils >/dev/null 2>&1
fi
if ! [ -e /dev/tpm0 ] && ! [ -e /dev/tpmrm0 ]; then
    echo "--- swtpm not running; starting it ---"
    if command -v swtpm >/dev/null 2>&1; then
        mkdir -p /tmp/ch23-swtpm
        swtpm socket --tpm2 --tpmstate dir=/tmp/ch23-swtpm \
            --ctrl type=unixio,path=/tmp/ch23-swtpm/ctrl \
            --server type=tcp,port=2321 --flags not-need-init \
            --daemon 2>/dev/null
        sleep 1
        # The kernel won't auto-attach swtpm over a socket without the
        # vTPM proxy driver (tpm_vtpm_proxy). Best-effort:
        modprobe tpm_vtpm_proxy 2>/dev/null
    fi
fi
timeout 30 bash trigger.sh 2>&1 | grep -E 'PROVEN|SKIP|CAPTURE|attached|key_bytes'
echo "===CH23==="

echo "======== ch24-bpf-token-delegation ========"
cd /mnt/pocs/ch24-bpf-token-delegation
mkdir -p build; bpftool btf dump file /sys/kernel/btf/vmlinux format c > build/vmlinux.h
make clean >/dev/null 2>&1; make 2>&1 | tail -1
# bpf_token landed in 6.9. Fedora 42's 6.x kernel should have it.
# Trigger emits CH24_SKIP cleanly if BPF_TOKEN_CREATE is rejected.
timeout 35 bash trigger.sh 2>&1 | grep -E 'CH24_PROVEN|CH24_SKIP|attached|uid_events|capeff|token_delegated|reason='
echo "===CH24==="

echo "======== ch25-imds-harvest ========"
cd /mnt/pocs/ch25-imds-harvest
mkdir -p build; bpftool btf dump file /sys/kernel/btf/vmlinux format c > build/vmlinux.h
make clean >/dev/null 2>&1; make 2>&1 | tail -1
# No real IMDS in the VM; force mock mode so the primitive demonstrates
# against a local Python mock server on 127.0.0.1:80.
if ! command -v python3 >/dev/null 2>&1; then
    dnf install -y python3 >/dev/null 2>&1 || apt-get install -y python3 >/dev/null 2>&1
fi
CH25_MOCK_IMDS=1 timeout 30 bash trigger.sh 2>&1 | grep -E 'PROVEN|SKIP|CREDENTIALS_CAPTURED|attached|access_key|role'
echo "===CH25==="

echo "===ALLDONE==="
