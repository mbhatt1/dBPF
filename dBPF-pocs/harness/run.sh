#!/bin/bash
# Host-side entry point. Builds (once) the dbpf-harness image and runs the
# rich TUI inside a privileged container with the repo bind-mounted.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
IMG=dbpf-harness:latest

if ! docker image inspect "$IMG" >/dev/null 2>&1; then
    echo "[host] building $IMG"
    docker build -t "$IMG" "$HERE"
fi

# Use -it when stdout is a TTY; omit when piped (CI / log capture).
TTY_FLAGS=""
if [[ -t 1 ]]; then TTY_FLAGS="-it"; fi

exec docker run --rm $TTY_FLAGS \
    --privileged --pid=host \
    -v /sys:/sys \
    -v /sys/kernel/debug:/sys/kernel/debug \
    -v /sys/fs/bpf:/sys/fs/bpf \
    -v "$REPO":/w -w /w \
    -e TERM="${TERM:-xterm-256color}" \
    "$IMG" python3 /w/harness/proof.py "$@"
