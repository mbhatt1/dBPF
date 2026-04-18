#!/bin/bash
# ch24-bpf-token-delegation smoke test.
#
# Static verification of the PoC: files present, expected markers in sources,
# Makefile produces the required artifacts, README covers the delegation
# mechanics. Does NOT invoke clang/BPF compilation or run the binaries.
# Safe to run on macOS (the dev box).

set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
USER_C="$DIR/ch24-bpf-token-delegation.c"
BPF_C="$DIR/ch24-bpf-token-delegation.bpf.c"
MAKEFILE="$DIR/Makefile"
TRIGGER="$DIR/trigger.sh"
README="$DIR/README.md"

PASS=0
FAIL=0
TOTAL=0

check() {
    # check <name> <ok:0|1> <reason>
    TOTAL=$((TOTAL + 1))
    if [ "$2" -eq 0 ]; then
        echo "PASS  $1"
        PASS=$((PASS + 1))
    else
        echo "FAIL  $1 -- $3"
        FAIL=$((FAIL + 1))
    fi
}

# ---------------------------------------------------------------------------
# 1. Required files present.
# ---------------------------------------------------------------------------
for f in \
    "ch24-bpf-token-delegation.c" \
    "ch24-bpf-token-delegation.bpf.c" \
    "Makefile" \
    "trigger.sh" \
    "README.md"
do
    if [ -f "$DIR/$f" ]; then
        check "file-present: $f" 0 ""
    else
        check "file-present: $f" 1 "missing at $DIR/$f"
    fi
done

# ---------------------------------------------------------------------------
# 2. trigger.sh is executable.
# ---------------------------------------------------------------------------
if [ -x "$TRIGGER" ]; then
    check "trigger.sh executable" 0 ""
else
    check "trigger.sh executable" 1 "trigger.sh lacks +x (chmod +x trigger.sh)"
fi

# ---------------------------------------------------------------------------
# 3. ch24-bpf-token-delegation.c expected markers.
# ---------------------------------------------------------------------------
grep_user_c() {
    # grep_user_c <label> <pattern> [extended=1]
    local label="$1"
    local pat="$2"
    local ext="${3:-0}"
    if [ ! -f "$USER_C" ]; then
        check "userspace-c: $label" 1 "source file missing"
        return
    fi
    if [ "$ext" -eq 1 ]; then
        if grep -qE -- "$pat" "$USER_C"; then
            check "userspace-c: $label" 0 ""
        else
            check "userspace-c: $label" 1 "pattern not found: $pat"
        fi
    else
        if grep -qF -- "$pat" "$USER_C"; then
            check "userspace-c: $label" 0 ""
        else
            check "userspace-c: $label" 1 "literal not found: $pat"
        fi
    fi
}

# --server / --client flag handling.
grep_user_c "--server flag"    '--server'
grep_user_c "--client flag"    '--client'

# BPF_TOKEN_CREATE usage.
grep_user_c "BPF_TOKEN_CREATE" 'BPF_TOKEN_CREATE'

# SCM_RIGHTS usage.
grep_user_c "SCM_RIGHTS"       'SCM_RIGHTS'

# bpf_prog_load / bpf_map_create with .token_fd opts.
grep_user_c "bpf_prog_load"                 'bpf_prog_load'
grep_user_c "bpf_map_create"                'bpf_map_create'
grep_user_c ".token_fd opts"                '\.token_fd'  1

# perf_event_open + PERF_EVENT_IOC_SET_BPF.
grep_user_c "perf_event_open"         'perf_event_open'
grep_user_c "PERF_EVENT_IOC_SET_BPF"  'PERF_EVENT_IOC_SET_BPF'

# BPF_PSEUDO_MAP_FD instruction relocation logic.
grep_user_c "BPF_PSEUDO_MAP_FD"       'BPF_PSEUDO_MAP_FD'

# CH24_PROVEN and CH24_SKIP markers.
grep_user_c "CH24_PROVEN marker"      'CH24_PROVEN'
grep_user_c "CH24_SKIP marker"        'CH24_SKIP'

# ---------------------------------------------------------------------------
# 4. BPF program expected content.
# ---------------------------------------------------------------------------
if [ -f "$BPF_C" ]; then
    if grep -qF 'SEC("tp/syscalls/sys_enter_getuid")' "$BPF_C"; then
        check "bpf-c: SEC(tp/syscalls/sys_enter_getuid)" 0 ""
    else
        check "bpf-c: SEC(tp/syscalls/sys_enter_getuid)" 1 "tracepoint SEC not found"
    fi

    if grep -qE '"?events"?[[:space:]]+SEC\(".maps"\)' "$BPF_C" \
         || grep -qE '^[[:space:]]*\}[[:space:]]+events[[:space:]]+SEC\(".maps"\)' "$BPF_C"; then
        check "bpf-c: 'events' ringbuf map" 0 ""
    else
        check "bpf-c: 'events' ringbuf map" 1 "ringbuf map name 'events' not found"
    fi
else
    check "bpf-c: SEC(tp/syscalls/sys_enter_getuid)" 1 "bpf source missing"
    check "bpf-c: 'events' ringbuf map"              1 "bpf source missing"
fi

# ---------------------------------------------------------------------------
# 5. Makefile produces the expected artifacts.
# ---------------------------------------------------------------------------
if [ -f "$MAKEFILE" ]; then
    # The Makefile uses variables APP and BUILD. We accept either the
    # expanded literal or the variable form referring to the correct names.
    if grep -qE 'APP[[:space:]]*:?=[[:space:]]*ch24-bpf-token-delegation' "$MAKEFILE" \
       && grep -qE 'BUILD[[:space:]]*:?=[[:space:]]*build' "$MAKEFILE"; then
        vars_ok=1
    else
        vars_ok=0
    fi

    bpf_obj_ok=1
    if grep -qE 'build/ch24-bpf-token-delegation\.bpf\.o' "$MAKEFILE"; then
        bpf_obj_ok=0
    elif [ "$vars_ok" -eq 1 ] && grep -qE '\$\(BUILD\)/\$\(APP\)\.bpf\.o|\$\(BPF_OBJ\)' "$MAKEFILE"; then
        bpf_obj_ok=0
    fi

    bin_ok=1
    if grep -qE 'build/ch24-bpf-token-delegation([^./[:alnum:]_-]|$)' "$MAKEFILE"; then
        bin_ok=0
    elif [ "$vars_ok" -eq 1 ] && grep -qE '\$\(BUILD\)/\$\(APP\)([^./[:alnum:]_-]|$)|\$\(BIN\)' "$MAKEFILE"; then
        bin_ok=0
    fi

    if [ "$bpf_obj_ok" -eq 0 ]; then
        check "Makefile: build/ch24-bpf-token-delegation.bpf.o target" 0 ""
    else
        check "Makefile: build/ch24-bpf-token-delegation.bpf.o target" 1 "no target resolves to build/ch24-bpf-token-delegation.bpf.o"
    fi

    if [ "$bin_ok" -eq 0 ]; then
        check "Makefile: build/ch24-bpf-token-delegation target" 0 ""
    else
        check "Makefile: build/ch24-bpf-token-delegation target" 1 "no target resolves to build/ch24-bpf-token-delegation"
    fi
else
    check "Makefile: build/ch24-bpf-token-delegation.bpf.o target" 1 "Makefile missing"
    check "Makefile: build/ch24-bpf-token-delegation target"       1 "Makefile missing"
fi

# ---------------------------------------------------------------------------
# 6. README.md mentions the key concepts.
# ---------------------------------------------------------------------------
grep_readme() {
    local label="$1"
    local pat="$2"
    if [ ! -f "$README" ]; then
        check "readme: $label" 1 "README missing"
        return
    fi
    if grep -qiF -- "$pat" "$README"; then
        check "readme: $label" 0 ""
    else
        check "readme: $label" 1 "\"$pat\" not mentioned"
    fi
}
grep_readme "SCM_RIGHTS"   "SCM_RIGHTS"
grep_readme "bpf_token"    "bpf_token"
grep_readme "raw syscall"  "raw syscall"
grep_readme "CH24_PROVEN"  "CH24_PROVEN"

# ---------------------------------------------------------------------------
# 7. trigger.sh orchestrates server + client + final marker.
# ---------------------------------------------------------------------------
if [ -f "$TRIGGER" ]; then
    if grep -qE -- '--server' "$TRIGGER"; then
        check "trigger.sh: starts --server" 0 ""
    else
        check "trigger.sh: starts --server" 1 "no --server invocation"
    fi

    if grep -qE -- '--client' "$TRIGGER"; then
        check "trigger.sh: starts --client" 0 ""
    else
        check "trigger.sh: starts --client" 1 "no --client invocation"
    fi

    # Final marker: must emit CH24_PROVEN or CH24_SKIP in a === ... === line.
    if grep -qE '===[[:space:]]*CH24_(PROVEN|SKIP)' "$TRIGGER"; then
        check "trigger.sh: emits final === CH24_PROVEN/SKIP === marker" 0 ""
    else
        check "trigger.sh: emits final === CH24_PROVEN/SKIP === marker" 1 "no final CH24 marker echoed"
    fi
else
    check "trigger.sh: starts --server"                              1 "trigger.sh missing"
    check "trigger.sh: starts --client"                              1 "trigger.sh missing"
    check "trigger.sh: emits final === CH24_PROVEN/SKIP === marker"  1 "trigger.sh missing"
fi

# ---------------------------------------------------------------------------
# Summary.
# ---------------------------------------------------------------------------
echo "=== SMOKE_TEST: $PASS/$TOTAL checks passed ==="
if [ "$FAIL" -eq 0 ]; then
    exit 0
else
    exit 1
fi
