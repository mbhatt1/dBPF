#!/usr/bin/env bash
set -euo pipefail
echo "=== KALLSYMS ==="
grep -E ' (__netif_receive_skb_core|__secure_computing|__arm64_sys_seccomp|bpf_skb_vlan_pop|skb_vlan_tag_present)$' /proc/kallsyms || echo "(no matches)"
echo "=== ERROR_INJECTION ==="
cat /sys/kernel/debug/error_injection/list 2>/dev/null | grep -iE 'seccomp|netif|netns' || echo "(no matches or unavailable)"
echo "=== AVAIL FILTER FNS ==="
grep -E '^(__netif_receive_skb_core|__secure_computing|__arm64_sys_seccomp)' /sys/kernel/tracing/available_filter_functions 2>/dev/null || echo "(unavailable)"
