# proof.py Harness Audit

Target: `/Users/mbhatt/spaceclaw/evilBPF/dBPF/dBPF-pocs/harness/proof.py` (713 lines).
Scope: correctness, concurrency, subprocess lifecycle, parsing, atomicity, exception handling.
Defensive review only — no code changes.

---

## CRITICAL

### C1. Per-POC overall timeout is never enforced for the loader
File: `proof.py:568-576` (wait loop) and `proof.py:577-597` (finally).

The wait loop only exits when `trig_proc` finishes or `p.timeout` elapses. If `trig_proc` is `None` (e.g., in `trigger-runs-loader` mode a trigger launches the loader and exits; in plain `observer` mode `trigger.sh` is optional — `trig_path.exists()` check) or if the loader hangs but the trigger exits immediately, the loader will continue until the finally block sends SIGINT. That is correct for a hung loader, but:

- In `trigger-runs-loader` mode, `trig_proc` is the bash wrapper — when bash exits its children may still be alive (the trigger often `exec`s or backgrounds the loader). The harness's SIGINT in the finally block is sent to `trig_proc` only — orphaned sub-children (the actual loader spawned by the trigger script) are never signaled. This leaks BPF-holding processes between POC runs, which corrupts the next POC's attach.
- Also: `loader_proc.wait()` (via `st.join`) has only a 2 s join timeout. If the streamer thread hangs reading, the main thread proceeds while the subprocess is still alive — accumulating zombies across 23 POCs.

**Fix:** use `start_new_session=True` on `spawn()` and signal the process group (`os.killpg(os.getpgid(proc.pid), SIGINT)`); then escalate to SIGKILL. Always call `proc.wait()` after kill (currently only done for the non-dut path via `x.wait()`).

### C2. `subprocess.Popen.wait()` without timeout (zombie risk)
File: `proof.py:586` — `x.wait()` after `x.kill()`. This is actually fine because SIGKILL is guaranteed to reap. But at line 590, `dut_proc.wait()` has **no timeout** and is called immediately after `dut_proc.kill()` — on a slow system or if the process is in uninterruptible sleep (D-state from a BPF kprobe), this hangs forever and blocks the entire harness. The Rich Live loop is stuck too.

**Fix:** `dut_proc.wait(timeout=5)` in a try/except.

### C3. `subprocess.run` calls in `build_poc` and `pre_cmd` have no timeout in the pre_cmd path
File: `proof.py:523` — `subprocess.run(p.pre_cmd, capture_output=True, text=True, cwd=d)` has **no `timeout=`**. A misbehaving `auditctl` (kernel audit subsystem stuck, rule flush pending) can hang the entire run forever. Only `build_poc`'s `make` call has `timeout=60` (line 398) and `bpftool btf dump` has `timeout=30` (line 369).

**Fix:** add `timeout=30` + `TimeoutExpired` handler.

### C4. Streamer pipe-leak on build failure / hook-miss path
Files: `proof.py:509-517` (early returns) and `proof.py:422-477` (`dut_python_child`).

In `dut_python_child`, `subprocess.Popen` is created with `stdout=PIPE, stderr=PIPE`. If `run_poc` takes the `build_poc() == False` path at line 514 **after** `target-tgid` was the mode, the DUT is never spawned — that path is safe. **But**: the `useradd` subprocess at line 430 runs unconditionally every time `dut_python_child` is called and is never reaped — `subprocess.run` reaps internally, so that's fine.

The real leak: if `dut_python_child` returns but the caller's `state.status = "fail"` happens later, `dut_proc` **is** in the finally cleanup. OK.

However, in the `trigger-runs-loader` branch, `trig_proc` is created but `loader_proc` is `None` — **and the Streamer holds a file-descriptor reference to `trig_proc.stdout`**. After the trigger exits, the streamer thread exits naturally. Fine. No leak here.

**Real leak**: `p.stderr` in `dut_python_child` is read via `select` but never fully drained or closed. After the function returns, `p.stderr` pipe buffer can fill (64 KB on Linux) and the child blocks on a write forever — the `dut_proc.wait()` at line 590 then hangs (see C2).

**Fix:** after reading the pid, either close `p.stderr` or keep draining it in a thread.

---

## HIGH

### H1. Verdict state machine: `_PROVEN` then crash ⇒ `effect_demonstrated` (false-positive)
File: `proof.py:608-616`.

If a PoC prints its proof marker to stdout and then segfaults, `state.proof_hits > 0` wins before any return-code check. The harness treats "loader crashed after claiming victory" as success. There is no `loader_proc.returncode` check anywhere in verdict computation.

**Fix:** if `loader_proc.returncode not in (0, -signal.SIGINT, -signal.SIGTERM)` and `proof_hits > 0`, mark `effect_demonstrated_but_crashed` or downgrade to `observed`.

### H2. Regex: `proof_marker` for ch01 matches status-line noise
File: `proof.py:64` — `r"CH01_WEAPON_PROVEN|tag=FLIP.*signal=\d+"`.

`.*` is greedy and unanchored; any log line containing `tag=FLIP` followed anywhere by `signal=<digit>` matches — including concatenated multi-field events like `tag=FLIP... othersignal=42`. Because the regex is not line-anchored and the Streamer feeds line-by-line, this is mostly OK, but `tag=FLIPPED` also matches `tag=FLIP` (substring). Intentional? If not, use `tag=FLIP\b`.

### H3. Regex: `CH\d+[A-Z_]*_SKIP\s+reason=(.*?)(?:===|$)` — non-greedy until end
File: `proof.py:599`.

`(.*?)(?:===|$)` with non-greedy `.*?` and `$` (which in default mode matches EOL, not end of string) means the captured reason is empty if the line has no `===` marker. The trigger emits `=== CHxx_SKIP reason=... ===` — but the Streamer strips via `.rstrip()` and each log line is a single line, so `$` matches EOL. Non-greedy `(.*?)` followed by `$` will match zero characters at EOL. Result: **skip reason captured is always empty string** unless the `===` closer appears on the same line.

**Fix:** `reason=(.*?)(?:\s*===|\s*$)` with greedy, or `reason=(.+?)(?:\s*===|$)`.

### H4. Rich `Live` thread-safety: Streamer mutates `state.log` (deque) from worker thread while main thread iterates it in `build_log_panel`
Files: `proof.py:339` (append from Streamer), `proof.py:298` (`list(state.log)[-22:]` from main).

`collections.deque` is documented as thread-safe for `append`/`popleft`, but `list(deque)` iteration is **not** atomic — concurrent append during iteration can raise `RuntimeError: deque mutated during iteration` on CPython under load. In practice the GIL usually protects it, but this is a known footgun. The `state.lock` is used for counters but not for `log`.

**Fix:** guard the `list(state.log)` snapshot under `state.lock`, or use `tuple(state.log)` (which copies atomically under the GIL more reliably).

### H5. `/proc/kallsyms` parsing misses module-suffixed symbols and handles `0` addresses silently
File: `proof.py:202-213`.

The code matches exact `parts[2] == name`, which is correct for in-tree symbols. But kallsyms redacts addresses to `0000000000000000` when `kptr_restrict=2` and the process lacks `CAP_SYSLOG`. The filter `parts[1] in ("T","t","W","w")` is fine. However:

- Module symbols appear as `ffff... t symbol  [module_name]` — `parts[2] == name` still matches because `[module]` is `parts[3]`. OK.
- If `kptr_restrict` hides the file entirely, `FileNotFoundError` is caught silently and every symbol reports missing → every POC skips. No warning surfaced.

**Fix:** distinguish "kallsyms unreadable" from "symbol absent" and log a one-shot warning.

### H6. `/tmp/proof-result.json` non-atomic write
File: `proof.py:703` — `pathlib.Path("/tmp/proof-result.json").write_text(json.dumps(js, indent=2))`.

Not atomic. If the harness is SIGKILLed mid-write (OOM, Ctrl-C escalation), a partial JSON file remains and downstream tooling (CI parser) gets a `json.JSONDecodeError`. Also: no `fsync`, no rename-dance.

**Fix:** write to `/tmp/proof-result.json.tmp` then `os.replace`.

### H7. No `SIGINT`/`SIGTERM` handler on the harness itself
The script installs no signal handler. If the user Ctrl-C's during a POC run, the `finally` block in `run_poc` will execute (Python raises `KeyboardInterrupt` inside the wait loop), but:

- The Rich `Live` context manager may not restore the terminal cleanly (screen=False mitigates but does not eliminate).
- The outer loop in `main()` has no try/except — `KeyboardInterrupt` propagates out of the `with Live(...)` block, skipping the JSON write and the final summary. The user loses all partial results.

**Fix:** wrap `main()` body in try/finally that always emits the JSON.

---

## MEDIUM

### M1. `Streamer.run`: no drain loop if subprocess closes stdout without EOF
File: `proof.py:335-361`. Iterating `self.proc.stdout` as a file uses buffered line iteration; if the subprocess writes a long line with no `\n` before exit, the last partial line may be lost. Low-impact for BPF loader which line-buffers, but worth noting.

### M2. `build_poc` cleanup: `shutil` imported inside loop
File: `proof.py:390`. `import shutil` inside a for-loop is cosmetic only (module cache), but unusual — and blocks if the filesystem is slow. Not a bug.

### M3. `dut_python_child`: unprivileged `useradd` failure silently ignored
File: `proof.py:430-431` — `capture_output=True` with no `check=True`. If `useradd` fails because `dut01` exists (normal on reruns) it's silently fine; but if the host blocks useradd entirely (read-only `/etc`), the subsequent `su dut01` fails and the child exits without printing `pid=`. The code then falls back to `pid = p.pid` (line 476), which is the `su` wrapper's PID, not the child Python's. `-t <tgid>` on the loader targets the wrong process — the POC silently becomes an observer with 0 events.

**Fix:** surface useradd failure; or re-read pid via `/proc/<pid>/task/*` walk.

### M4. `dut_python_child`: child stderr never closed → FIFO writer orphan
If the loader crashes before `release_dut(dut_fifo)` runs, the DUT's `open(fifo).read()` blocks forever. The finally at line 591 calls `release_dut(dut_fifo)` only if `dut_fifo` is still set, which was zeroed at line 558 after a successful release. If `loader_proc` crashed at line 550-554 (before release), the finally path **does** call release_dut — OK. But if `release_dut` fails (FIFO already consumed), `dut_proc` is still waiting on `open(fifo).read()` and line 590 `dut_proc.wait()` hangs (see C2).

### M5. `bpftool` missing → uncaught `FileNotFoundError`
File: `proof.py:368`. If `bpftool` is not installed, `subprocess.run([...], check=True)` raises `FileNotFoundError` (not `CalledProcessError`) — not caught in `regen_vmlinux`, so propagates to `build_poc`, which has no try/except around `regen_vmlinux(state)` (line 396). The POC's `run_poc` has no try/except around `build_poc` either — `FileNotFoundError` propagates to the `main()` loop and aborts the entire run.

**Fix:** wrap `regen_vmlinux` in try/except and return False.

### M6. BTF existence check is only for `/sys/kernel/btf/vmlinux`, not per-POC
If BTF exists but is corrupt or kernel was built without BTF symbols for a specific probe, `bpftool btf dump` succeeds but the resulting `vmlinux.h` is empty — `make` fails with confusing compile errors. Handled by treating it as build failure. Acceptable.

### M7. Category/status `"effect_demonstrated"` vs exit-code accounting
File: `proof.py:707`. Exit code is non-zero only for `"fail"` — `"effect_demonstrated"` exits 0 (correct for a demo) but a CI pipeline that wants to detect "we proved an attack" must parse JSON. Document or expose via an env flag.

### M8. `EVENT_SIGS` regex: `arg='` unescaped apostrophe inside raw string
File: `proof.py:326`. The apostrophe in `arg='` is literal but inside a Python raw string delimited by `"`, so it's fine. No bug — just noting for reviewers.

### M9. `Poc` dataclass: required fields validated only structurally
`cid`, `name`, `dir`, `hooks`, `prefix` have no defaults — constructor will raise `TypeError` at import time if any POC entry omits them. OK. But `hooks: list[str]` accepts an empty list; combined with `mode != "trigger-runs-loader"`, `check_hooks` then returns empty `present_hooks`, `state.status = "skip"` at line 511 with verdict `"no hook symbols present: []"`. Confusing but not a crash.

### M10. `release_dut` races with POC process exit
File: `proof.py:480-496`. Opens FIFO `O_NONBLOCK | O_WRONLY` — if no reader, raises `ENXIO`. Caught. If the reader is present but consuming slowly, `os.write(fd, b"go")` could short-write (2 bytes, so practically atomic). Fine.

---

## LOW

### L1. `shell=True` — not used anywhere. Clean. (Audit item 11 resolved.)

### L2. Unicode — every decode uses `errors="replace"`. Clean. (Audit item 15 resolved.)

### L3. `except:` bare-clauses — searched. Every `except` is typed (`except Exception`, `except OSError`, `except subprocess.TimeoutExpired`, `except FileNotFoundError`). No `except:` or `except BaseException`. `KeyboardInterrupt`/`SystemExit` **are** swallowed by `except Exception` in `bpf_lsm_available` (line 188) — but that's only for the LSM-list file read, and `KeyboardInterrupt` is not an `Exception` subclass in Python 3, so it's not swallowed. **Correct.**

### L4. Docker / `/sys` not mounted — `BTF.exists()` check at line 653 handles this with `sys.exit(2)`. `/proc/version` read at line 649 will raise `FileNotFoundError` if `/proc` is missing — not caught, but that's outside any meaningful container. Acceptable.

### L5. Dict/list mutation during iteration — none found. `_built_dirs` is only `add`ed to. `states` dict is built once. `POCS` is module-level. `state.log` iteration is read-only in the panel. (Audit item 12 resolved.)

### L6. TUI refresh callback: `lambda: (refresh(), live.refresh())` evaluates both eagerly — fine but not throttled. Called from `run_poc` at ~4 Hz. No bug, but may be expensive for 23 POCs × many log lines.

### L7. `proof_marker` regexes are compiled in `Streamer.__init__` (line 319-320) but not anchored with `\A`/`\Z`. All use `.search`, so substring matching is intentional. For example ch23's `CH23_PROVEN\s+key_bytes_captured=\d+|CH23_SKIP` — `CH23_SKIP` is unqualified, so any log line containing the literal `CH23_SKIP` substring matches — including `[harness] note: previous run printed CH23_SKIP` if ever logged. Practically no such line exists. Low risk.

### L8. `start_new_session` not set on any `Popen` — see C1. Relevant also for L-tier: on Ctrl-C, `SIGINT` is delivered to the whole foreground process group; child BPF loaders may die before the harness's finally runs, and their BPF programs auto-detach. Acceptable for interactive use.

---

## Summary

**Verdict: needs-fixes.**

No show-stopper security bugs (no `shell=True` injection, no arbitrary-regex-eval, bare `except` absent, unicode decode robust). But multiple **correctness and lifecycle bugs** will cause the harness to hang, produce partial JSON, or falsely report `effect_demonstrated` in failure modes that happen in practice:

- C1/C2/C3: **hang or zombie** under bad conditions (stuck loader in trigger-runs-loader mode, D-state DUT, wedged `auditctl`).
- C4: **pipe deadlock** in `dut_python_child` stderr if child ever writes more than 64 KB.
- H1: **false-positive verdict** if loader crashes after printing `_PROVEN`.
- H3: **skip reason capture silently empty** on most skip paths.
- H6: **partial JSON on interrupt** → CI breakage.
- H7: **no summary written on Ctrl-C**.

The remaining HIGH/MEDIUM items are ergonomic or edge-case. The CRITICAL items should be fixed before the harness is used unattended or in CI. For interactive single-run use on a clean box, the script works as written.

**Recommended priority fixes (in order):**
1. C3: add `timeout=` to `pre_cmd` subprocess.run.
2. C2: add `timeout=` to `dut_proc.wait()` + fallback SIGKILL.
3. H6: atomic rename for result JSON.
4. H7: signal handler / try-finally around main body.
5. H1: gate `effect_demonstrated` on loader exit status.
6. C1: `start_new_session=True` + killpg on cleanup.
7. C4: drain/close `dut_python_child.stderr`.
8. H3: fix skip-reason regex.

Relevant file: `/Users/mbhatt/spaceclaw/evilBPF/dBPF/dBPF-pocs/harness/proof.py`.
