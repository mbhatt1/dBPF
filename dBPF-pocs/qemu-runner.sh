#!/bin/bash
# One-shot runner for all remaining SKIP PoCs in QEMU Fedora VM.
# Assumes: BPF LSM + SELinux active, tools installed, /mnt = 9p mount of pocs.
set -x
exec 2>&1

echo "=== ENVIRONMENT ==="
cat /sys/kernel/security/lsm
getenforce
uname -r

echo "=== SETUP: SELinux confined user ==="
# Map a test user to the confined user_u SELinux user
userdel -r confined01 2>/dev/null
useradd -M confined01
# This is the key: map login to user_u so su inherits user_t domain
semanage login -a -s user_u confined01 2>/dev/null || echo "semanage failed"
# Verify
semanage login -l | grep confined01
# Set password for su
echo "confined01:test123" | chpasswd

# Also need staff_u for some tests
userdel -r staff01 2>/dev/null  
useradd -M staff01
semanage login -a -s staff_u staff01 2>/dev/null
echo "staff01:test123" | chpasswd

echo "=== SETUP: SELinux enforcing ==="
setenforce 1
getenforce

echo "=== SETUP: mount pocs ==="
mount -t 9p -o trans=virtio pocs /mnt 2>/dev/null
ls /mnt/pocs/ | wc -l

########################################################################
# ch06-silence-selinux: base kprobe variant  
########################################################################
echo ""
echo "################################################################"
echo "# ch06-silence-selinux"
echo "################################################################"
cd /mnt/pocs/ch06-silence-selinux
mkdir -p build
bpftool btf dump file /sys/kernel/btf/vmlinux format c > build/vmlinux.h
make 2>&1 | tail -2

# The trigger needs SELinux denials in the event stream.
# Run loader, then generate AVC denials as confined user.
./build/ch06-silence-selinux 2>/tmp/ch06.err &
LPID=$!; sleep 1

echo "=== generating SELinux denials as confined user ==="
# confined01 is mapped to user_u:user_r:user_t — reading shadow_t is denied
STAGE=$(mktemp -d)
echo "secret-content" > "$STAGE/secret.txt"
chmod 644 "$STAGE/secret.txt"
chcon -t shadow_t "$STAGE/secret.txt" 2>/dev/null

su -l confined01 -c "cat $STAGE/secret.txt 2>&1; cat /etc/shadow 2>&1" || true
su -l confined01 -c "ls /root 2>&1" || true
sleep 1
kill $LPID 2>/dev/null; wait $LPID 2>/dev/null

echo "=== ch06 loader output ==="
cat /tmp/ch06.err
EVENTS=$(grep -c '\[ch06\]' /tmp/ch06.err 2>/dev/null)
echo "=== CH06_RESULT events=$EVENTS ==="
rm -rf "$STAGE"

########################################################################
# ch06-silence-selinux-lsm: BPF LSM fmod_ret + SELinux denials
########################################################################
echo ""
echo "################################################################"
echo "# ch06-silence-selinux-lsm"
echo "################################################################"
cd /mnt/pocs/ch06-silence-selinux-lsm
make 2>&1 | tail -2

STAGE=$(mktemp -d)
echo "lsm-protected-content" > "$STAGE/secret.txt"
chmod 644 "$STAGE/secret.txt"
chcon -t shadow_t "$STAGE/secret.txt" 2>/dev/null

echo "=== baseline: confined user reads shadow_t file ==="
su -l confined01 -c "cat $STAGE/secret.txt 2>&1; echo base_rc=\$?"

echo "=== starting BPF LSM loader (wildcard) ==="
./build/ch06-silence-selinux-lsm -a >/tmp/ch06-lsm.log 2>&1 &
LPID=$!; sleep 1

echo "=== with BPF LSM: retry read ==="
for i in 1 2 3; do
  su -l confined01 -c "cat $STAGE/secret.txt 2>&1; echo retry${i}_rc=\$?"
done
sleep 1
kill $LPID 2>/dev/null; wait $LPID 2>/dev/null

echo "=== loader log ==="
cat /tmp/ch06-lsm.log
FLIPS=$(grep -cE 'FLIP' /tmp/ch06-lsm.log 2>/dev/null)
echo "=== CH06LSM_RESULT flips=$FLIPS ==="
rm -rf "$STAGE"

########################################################################
# ch01-mirror-controls-lsm: BPF LSM fmod_ret on capable
########################################################################
echo ""
echo "################################################################"  
echo "# ch01-mirror-controls-lsm"
echo "################################################################"
cd /mnt/pocs/ch01-mirror-controls-lsm
make 2>&1 | tail -2

echo "=== baseline: confined user reads /etc/shadow ==="
su -l confined01 -c "cat /etc/shadow 2>&1 | head -1; echo base_rc=\$?" 2>&1

echo "=== starting loader (wildcard) ==="
./build/ch01-mirror-controls-lsm -a >/tmp/ch01-lsm.log 2>&1 &
LPID=$!; sleep 1

echo "=== with BPF LSM: retry ==="
su -l confined01 -c "cat /etc/shadow 2>&1 | head -1; echo retry_rc=\$?" 2>&1
sleep 1
kill $LPID 2>/dev/null; wait $LPID 2>/dev/null

echo "=== loader log ==="
cat /tmp/ch01-lsm.log
FLIPS=$(grep -cE 'FLIP\b|flipped=1' /tmp/ch01-lsm.log 2>/dev/null)
echo "=== CH01LSM_RESULT flips=$FLIPS ==="

########################################################################
# ch02-overlayfs-lsm: use tmpfs (not btrfs) for overlay
########################################################################
echo ""
echo "################################################################"
echo "# ch02-overlayfs-lsm"
echo "################################################################"
cd /mnt/pocs/ch02-overlayfs-lsm
make 2>&1 | tail -2
# The trigger handles overlay setup — run it directly
timeout 25 bash trigger.sh 2>&1 | tail -10
echo "=== CH02LSM_DONE ==="

########################################################################
# ch03-fuse-blackhole-fentry
########################################################################
echo ""
echo "################################################################"
echo "# ch03-fuse-blackhole-fentry"
echo "################################################################"
cd /mnt/pocs/ch03-fuse-blackhole-fentry
make 2>&1 | tail -2
timeout 25 bash trigger.sh 2>&1 | tail -10
echo "=== CH03FE_DONE ==="

########################################################################
# ch08-keyring-heist-lsm
########################################################################
echo ""
echo "################################################################"
echo "# ch08-keyring-heist-lsm"
echo "################################################################"
cd /mnt/pocs/ch08-keyring-heist-lsm
make 2>&1 | tail -2
timeout 25 bash trigger.sh 2>&1 | tail -10
echo "=== CH08LSM_DONE ==="

########################################################################
# ch12-signed-driver-swap-lsm
########################################################################
echo ""
echo "################################################################"
echo "# ch12-signed-driver-swap-lsm"
echo "################################################################"
cd /mnt/pocs/ch12-signed-driver-swap-lsm
make 2>&1 | tail -2
timeout 30 bash trigger.sh 2>&1 | tail -10
echo "=== CH12LSM_DONE ==="

echo ""
echo "################################################################"
echo "# ALL DONE"
echo "################################################################"
