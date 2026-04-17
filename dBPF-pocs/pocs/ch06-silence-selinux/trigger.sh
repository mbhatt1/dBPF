#!/bin/bash
# ch06 trigger — drive SELinux AVC decisions so the observer has traffic.
#
# On hosts without SELinux (linuxkit aarch64, most WSL setups, containers
# without securityfs), emit CH06_SKIP and exit 0 — the harness treats
# that as an honest skip.
set +e

HERE="$(cd "$(dirname "$0")" && pwd)"

LSM_FILE="/sys/kernel/security/lsm"
if [ ! -r "$LSM_FILE" ]; then
    echo "=== CH06_SKIP reason=\"SELinux not enabled on this host\" ==="
    echo "(missing ${LSM_FILE}; securityfs not mounted)"
    exit 0
fi
if ! grep -qw selinux "$LSM_FILE"; then
    echo "=== CH06_SKIP reason=\"SELinux not enabled on this host\" ==="
    echo "(/sys/kernel/security/lsm = $(cat $LSM_FILE))"
    exit 0
fi

echo "=== selinux present in $(cat $LSM_FILE) ==="
echo "=== getenforce: $(getenforce 2>/dev/null || echo unknown) ==="

echo "=== ls -Z /etc/shadow (labeled stat) ==="
ls -Z /etc/shadow 2>&1 | head -5

echo "=== ls -Z / (drive selinux_file_permission on directory read) ==="
ls -Z / 2>&1 | head -5

echo "=== cat /etc/shadow as root (should succeed; exercises AVC) ==="
cat /etc/shadow >/dev/null 2>&1 && echo "OK: read shadow" || echo "denied (as expected for non-root)"

# Attempt a deliberately mis-labeled access via runcon if it exists.
if command -v runcon >/dev/null 2>&1; then
    # Pick a context that's nearly guaranteed not to have permission
    # on /etc/shadow — the user_t generic unconfined label.
    echo "=== runcon user_u:user_r:user_t:s0 cat /etc/shadow (expect deny) ==="
    runcon user_u:user_r:user_t:s0 cat /etc/shadow 2>&1 | head -3
    echo "=== runcon user_u:user_r:user_t:s0 id (harmless labeled exec) ==="
    runcon user_u:user_r:user_t:s0 id 2>&1 | head -3
else
    echo "(runcon not installed; skipping labeled exec tests)"
fi

# Any chmod/chown exercises avc_has_perm for file { setattr } class.
TMP="$(mktemp)"
chmod 600 "$TMP" 2>/dev/null
rm -f "$TMP"

# Exercise the exec path (bprm_check_security + avc_has_perm).
for i in 1 2 3; do
    /bin/true
    /bin/false
done

echo "=== done — AVC decisions should be visible in loader stdout ==="
