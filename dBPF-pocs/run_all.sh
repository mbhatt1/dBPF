#!/bin/bash
# run_all.sh — build + briefly exercise every POC, capture per-POC logs,
# print a summary table at the end.
#
# Designed for macOS/Docker Desktop linuxkit aarch64. set +e everywhere
# so one failing POC doesn't abort the whole run.
set +e

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE" || exit 1

IMAGE=${IMAGE:-dbpf-base}
LOGDIR="$HERE/logs"
mkdir -p "$LOGDIR"

# Sanity: base image must exist.
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "[run_all] base image $IMAGE not found — build it first:"
    echo "  docker build -t $IMAGE -f Dockerfile.base ."
    exit 1
fi

declare -A COMPILE_STATUS ATTACH_STATUS EVENT_COUNT

POC_DIRS=()
while IFS= read -r d; do
    POC_DIRS+=("$d")
done < <(find "$HERE/pocs" -mindepth 1 -maxdepth 1 -type d | sort)

for dir in "${POC_DIRS[@]}"; do
    poc="$(basename "$dir")"
    chap="${poc%%-*}"
    log="$LOGDIR/${chap}.log"
    : > "$log"

    echo "=========================================================="
    echo "[run_all] === $poc ==="
    echo "=========================================================="

    # Determine binary name by walking the .c file.
    bpf_loader_src="$(find "$dir" -maxdepth 1 -name '*.c' ! -name '*.bpf.c' | head -1)"
    if [[ -z "$bpf_loader_src" ]]; then
        echo "[run_all] $poc: no loader .c found — skipping" | tee -a "$log"
        COMPILE_STATUS[$poc]="skip"
        ATTACH_STATUS[$poc]="-"
        EVENT_COUNT[$poc]=0
        continue
    fi
    app="$(basename "${bpf_loader_src%.c}")"

    # ----- compile -----
    {
        echo "--- compile ---"
        docker run --rm \
            -v "$HERE":/work -w /work \
            "$IMAGE" \
            bash -c "cd pocs/$poc && make clean >/dev/null 2>&1; make"
    } >>"$log" 2>&1
    if [[ -x "$dir/build/$app" ]]; then
        COMPILE_STATUS[$poc]="ok"
    else
        COMPILE_STATUS[$poc]="FAIL"
        ATTACH_STATUS[$poc]="-"
        EVENT_COUNT[$poc]=0
        echo "[run_all] $poc: compile failed (see $log)"
        continue
    fi

    # ----- run loader + trigger -----
    cname="dbpf_${chap}_$$"
    {
        echo "--- run ---"
        # Best-effort default args. Most loaders accept either no args
        # or a tgid/--all; we try a couple of fallbacks.
        run_args=""
        case "$poc" in
            ch18-token-bypass) run_args="--all" ;;
            ch01-mirror-controls) run_args="" ;;
            *) run_args="" ;;
        esac

        docker run --rm -d \
            --name "$cname" \
            --privileged --pid=host --network=host \
            -v "$HERE":/work -w "/work/pocs/$poc" \
            "$IMAGE" \
            bash -c "timeout 8 ./build/$app $run_args; sleep 1" \
            >/dev/null 2>&1

        # Give it a moment to attach.
        sleep 2

        if [[ -x "$dir/trigger.sh" ]]; then
            docker run --rm \
                --privileged --pid=host --network=host \
                -v "$HERE":/work -w "/work/pocs/$poc" \
                "$IMAGE" \
                bash trigger.sh
        else
            echo "[run_all] (no trigger.sh)"
        fi

        # Wait for the loader to wind down, then dump its logs.
        sleep 3
        docker logs "$cname" 2>&1 || true
        docker rm -f "$cname" >/dev/null 2>&1 || true
    } >>"$log" 2>&1

    # ----- post-mortem -----
    if grep -qE 'status=ready|attached=' "$log"; then
        ATTACH_STATUS[$poc]="ok"
    elif grep -qiE 'attach .* failed|load failed|verifier' "$log"; then
        ATTACH_STATUS[$poc]="FAIL"
    else
        ATTACH_STATUS[$poc]="?"
    fi

    # Count ringbuf-style event lines: anything matching [tag] key=val ... .
    n=$(grep -cE '^\[[a-z0-9]+\][[:space:]]' "$log")
    EVENT_COUNT[$poc]=$n
done

# ----- summary -----
echo
echo "=========================================================="
echo "Summary"
echo "=========================================================="
printf "%-28s %-10s %-10s %-10s\n" "chapter" "compile" "attach" "events"
printf "%-28s %-10s %-10s %-10s\n" "----------------------------" "--------" "--------" "--------"
for dir in "${POC_DIRS[@]}"; do
    poc="$(basename "$dir")"
    printf "%-28s %-10s %-10s %-10s\n" \
        "$poc" "${COMPILE_STATUS[$poc]:-?}" "${ATTACH_STATUS[$poc]:-?}" "${EVENT_COUNT[$poc]:-0}"
done
echo
echo "Per-POC logs in: $LOGDIR/"
