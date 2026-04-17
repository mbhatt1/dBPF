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

echo "===ALLDONE==="
