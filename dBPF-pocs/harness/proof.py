#!/usr/bin/env python3
"""Live TUI harness that proves every dBPF POC.

For each POC: regenerates vmlinux.h from the container kernel's BTF, builds,
checks hook-symbol availability, spawns the loader, runs the trigger, streams
ringbuf events into the TUI, then renders a verdict. Runs sequentially so
the event stream in the bottom pane is readable.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import shlex
import signal
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

ROOT = pathlib.Path("/w")
POCS_DIR = ROOT / "pocs"
BTF = pathlib.Path("/sys/kernel/btf/vmlinux")
KALLSYMS = pathlib.Path("/proc/kallsyms")

console = Console()


@dataclass
class Poc:
    cid: str                         # "ch01"
    name: str                        # pretty title
    dir: str                         # "ch01-mirror-controls"
    hooks: list[str]                 # required kernel symbols (any match -> ok)
    prefix: str                      # event line prefix ("[ch01]")
    loader_args: list[str] = field(default_factory=list)
    # modes: "observer" | "target-tgid" | "override-all" | "trigger-runs-loader"
    mode: str = "observer"
    trigger: str = "trigger.sh"
    flip_marker: str | None = None   # legacy: flip-event marker in event stream
    proof_marker: str | None = None  # NEW: line-regex that proves the effect was demonstrated
    skip_reason: str | None = None   # forced skip
    min_events: int = 1
    timeout: float = 12.0
    pre_cmd: list[str] | None = None  # runs in container before loader
    category: str = "real"           # "real" | "analog" | "observer" | "illusion"


POCS: list[Poc] = [
    Poc("ch01", "Mirror Controls (cap_capable + signal)", "ch01-mirror-controls",
        hooks=["cap_capable"], prefix="[ch01]",
        mode="target-tgid",
        flip_marker=r"\bFLIP\b|tag=flipped|SIGUSR1",
        proof_marker=r"CH01_WEAPON_PROVEN|tag=FLIP.*signal=\d+"),
    Poc("ch02", "OverlayFS Trojan (copy-up)", "ch02-overlayfs",
        hooks=["ovl_copy_up", "ovl_maybe_copy_up", "ovl_copy_up_with_data"],
        prefix="[ch02]",
        proof_marker=r"RACE_WIN|PWNED\t"),
    Poc("ch02lsm", "OverlayFS Trojan (BPF LSM copy-up deny)", "ch02-overlayfs-lsm",
        hooks=["bpf-lsm"], prefix="[ch02-lsm]",
        proof_marker=r"DENIED \(-EPERM\)|CH02_PROVEN"),
    Poc("ch03", "FUSE Audit Black-Hole", "ch03-fuse-blackhole",
        hooks=["audit_log_start", "audit_log_format", "audit_log_end"],
        prefix="[audit]",
        pre_cmd=["bash", "-c",
                 "auditctl -e 1 2>/dev/null; "
                 "auditctl -a always,exit -F arch=aarch64 -S execve 2>/dev/null; "
                 "auditctl -a always,exit -F arch=b64 -S execve 2>/dev/null; true"],
        proof_marker=r"SUPPRESSED|EXFIL|CH03_PROVEN",
        category="observer"),
    Poc("ch03f", "FUSE Audit Black-Hole (fentry suppressor)", "ch03-fuse-blackhole-fentry",
        hooks=["audit_log_start"], prefix="[ch03-fe]",
        proof_marker=r"SUPPRESSED|CH03_PROVEN",
        category="observer"),
    Poc("ch04", "Phantom Syscall (tail-call + signal)", "ch04-phantom-syscall",
        hooks=["__arm64_sys_write"], prefix="[phantom]", min_events=1,
        proof_marker=r"CH04_PROVEN|EXFIL_COMPLETE|SIGUSR1_SENT"),
    Poc("ch05", "Cgroup Leash (cpu.stat)", "ch05-cgroup-leash",
        hooks=["__arm64_sys_read"], prefix="[ch05]",
        proof_marker=r"CH05_PROVEN|LEASH_SUCCESS"),
    Poc("ch05b", "Ghost NIC (XDP UDP:31337)", "ch05b-ghost-nic",
        hooks=["veth"], prefix="[ghost]", mode="trigger-runs-loader",
        timeout=20,
        proof_marker=r"GHOST_COVERT_CHANNEL_PROVEN"),
    Poc("ch06", "Silencing SELinux (LSM)", "ch06-silence-selinux-lsm",
        hooks=["bpf-lsm"], prefix="[ch06]",
        proof_marker=r"CH06_PROVEN|CH06_WEAPON_PROVEN|FLIP\s+hook=",
        category="observer"),
    Poc("ch06s", "Silencing SELinux (LSM synthetic)", "ch06-silence-selinux-lsm-synthetic",
        hooks=["bpf-lsm"], prefix="[ch06]",
        mode="trigger-runs-loader",
        proof_marker=r"CH06_SYNTH_PROVEN",
        category="observer"),
    Poc("ch06o", "Silencing SELinux (kprobe observer)",
        "ch06-silence-selinux",
        hooks=["avc_has_perm", "avc_has_perm_noaudit",
               "selinux_file_permission"],
        prefix="[ch06]",
        proof_marker=r"CH06_PROVEN\s+hook=|CH06_SKIP\s+reason=",
        category="observer"),
    Poc("ch07", "Device-cgroup Houdini (signal)", "ch07-devcgroup-houdini",
        hooks=["devcgroup_check_permission"], prefix="[ch07]",
        mode="trigger-runs-loader", timeout=25,
        flip_marker=r"SIGUSR2_SENT|FLIP\s+hook=",
        proof_marker=r"CH07_PROVEN|CH07_WEAPON_PROVEN|CH07_CONCEPT_PROVEN|SIGUSR2_SENT"),
    Poc("ch08", "Keyring Heist (payload exfil)", "ch08-keyring-heist",
        hooks=["key_task_permission", "lookup_user_key"], prefix="[ch08]",
        mode="trigger-runs-loader", timeout=20,
        proof_marker=r"CH08_PROVEN|CH08_WEAPON_PROVEN|EXFIL=",
        # kprobes on key_task_permission/lookup_user_key return 0 and only
        # emit ringbuf metadata (serial/type/desc); no mutation, no signal,
        # no override -> read-only observation of a real subsystem.
        category="observer"),
    Poc("ch09", "PID-NS Doppelganger (cross-ns signal)", "ch09-pid-doppel",
        hooks=["tp:sched/sched_process_fork"], prefix="[ch09]",
        proof_marker=r"CH09_PROVEN|PID_NS_ESCAPE_PROVEN|SIGUSR1_SENT", timeout=40),
    Poc("ch10", "Inode Cloak (getdents64)", "ch10-inode-cloak",
        hooks=["__arm64_sys_getdents64"], prefix="[cloak]",
        proof_marker=r"CLOAK_PROVEN"),
    Poc("ch11", "IRQ Chaos (timing channel)", "ch11-irq-chaos",
        hooks=["handle_irq_event", "__handle_irq_event_percpu",
               "handle_irq_event_percpu"], prefix="[irq]",
        proof_marker=r"CH11_PROVEN|IRQ_COVERT_CHANNEL_PROVEN"),
    Poc("ch12", "Signed-Driver Swap (LSM)", "ch12-signed-driver-swap-lsm",
        hooks=["bpf-lsm"], prefix="[ch12]",
        proof_marker=r"CH12_PROVEN|CH12_WEAPON_PROVEN|FLIP\s+hook="),
    Poc("ch14", "SCHED_FIFO Impersonator", "ch14-sched-fifo",
        hooks=["__arm64_sys_sched_setscheduler"], prefix="[sched]",
        mode="trigger-runs-loader",
        flip_marker=r"flipped=1|flip|override",
        proof_marker=r"flipped=1|SCHED_WEAPON_PROVEN",
        category="illusion"),
    Poc("ch15", "NetNS VLAN Ghost (XDP VID=4242)", "ch15-netns-vlan-ghost",
        hooks=["veth"], prefix="[vghost]", mode="trigger-runs-loader",
        timeout=20,
        proof_marker=r"VLAN_GHOST_CROSSNS_PROVEN"),
    Poc("ch16", "Seccomp TID Hop", "ch16-seccomp-tid-hop",
        hooks=["__secure_computing"], prefix="[seccomp]",
        proof_marker=r"SECCOMP_SIDECHANNEL_PROVEN",
        category="observer"),
    Poc("ch18", "Token Bypass (getuid override)", "ch18-token-bypass",
        hooks=["__arm64_sys_getuid", "__arm64_sys_geteuid"], prefix="[token]",
        mode="override-all", loader_args=["--all"],
        flip_marker=r"FORGE|override|flip|uid=0",
        proof_marker=r"FORGE\s+pid=|TOKEN_FORGE_PROVEN",
        category="illusion"),
    # --- workaround kprobe variant -----------------------------------
    # A kprobe against a real kernel surface, not a synthetic or analog.
    # The LSM variant (ch08) skips on kernels where struct key is
    # forward-declared in BTF; the kprobe version sidesteps that by reading
    # through vmlinux.h BTF directly. category="observer": its own trigger
    # proves syscall_rc_unchanged=yes with the key metadata surfaced only in
    # the ringbuf -- it reads the real subsystem but cannot change the access
    # decision (no override/mutation).
    Poc("ch08k", "Keyring Heist — kprobe variant",
        "ch08-keyring-heist-kprobe",
        hooks=["key_task_permission", "lookup_user_key"], prefix="[ch08k]",
        mode="trigger-runs-loader", timeout=20,
        proof_marker=r"CH08_CONCEPT_PROVEN|CH08_PROVEN",
        category="observer"),
    # --- syscall-level illusion ---------------------------------------
    # Real kretprobe on a real syscall wrapper. category="illusion"
    # because the return value is forged (finit_module returns 0) but
    # the module never actually loads. Kept alongside ch14/ch18 as an
    # honestly-labeled syscall-return forge.
    Poc("ch12s", "Signed-Driver Swap — syscall kretprobe (illusion)",
        "ch12-signed-driver-swap-syscall",
        hooks=["__arm64_sys_finit_module", "__arm64_sys_init_module"],
        prefix="[ch12s]", mode="trigger-runs-loader", timeout=25,
        proof_marker=r"CH12_CONCEPT_PROVEN|CH12_PROVEN|FORGE\s+pid=",
        category="illusion"),
    # --- act 4 --------------------------------------------------------
    # Three primitives added in act 4: persistent theft against hardware-
    # rooted keys (ch23), threat-model subversion via delegated capability
    # (ch24), and cross-boundary cloud identity capture (ch25).
    Poc("ch23", "TPM Unseal Heist (trusted-key plaintext capture)",
        "ch23-tpm-unseal-heist",
        hooks=["tpm2_unseal_trusted"], prefix="[ch23]",
        mode="trigger-runs-loader", timeout=25,
        proof_marker=r"CH23_PROVEN\s+key_bytes_captured=\d+|CH23_SKIP"),
    Poc("ch24", "Token Hand-off (bpf_token delegation)",
        "ch24-bpf-token-delegation",
        hooks=["tp:syscalls/sys_enter_getuid"], prefix="[ch24]",
        mode="trigger-runs-loader", timeout=40,
        proof_marker=r"CH24_PROVEN\s+uid_events=\d+\s+token_delegated=yes|CH24_SKIP\s+reason="),
    Poc("ch25", "Metadata Faucet (IMDS credential capture via XDP)",
        "ch25-imds-harvest",
        hooks=["veth"], prefix="[ch25]",
        mode="trigger-runs-loader", timeout=25,
        proof_marker=r"CH25_PROVEN\s+access_key_captured=yes|CH25_SKIP"),
]


def bpf_lsm_available() -> bool:
    try:
        data = pathlib.Path("/sys/kernel/security/lsm").read_text()
        return "bpf" in data.split(",")
    except Exception:
        return False


def kallsyms_has(name: str) -> bool:
    # tracepoint names are prefixed with tp:
    if name.startswith("tp:"):
        tp = name[3:]
        p = pathlib.Path(f"/sys/kernel/debug/tracing/events/{tp}/id")
        return p.exists()
    if name == "bpf-lsm":
        return bpf_lsm_available()
    if name.startswith("veth"):
        return True  # runtime-created
    try:
        with KALLSYMS.open() as f:
            for line in f:
                parts = line.split()
                # Filter to function symbols (T/t/W/w) — skip data (D/B/etc.)
                if (len(parts) >= 3
                        and parts[2] == name
                        and parts[1] in ("T", "t", "W", "w")):
                    return True
    except FileNotFoundError:
        pass
    return False


@dataclass
class RunState:
    poc: Poc
    status: str = "queued"   # queued | building | running | effect_demonstrated | observed | skip | fail
    present_hooks: list[str] = field(default_factory=list)
    missing_hooks: list[str] = field(default_factory=list)
    events: int = 0
    flipped: int = 0
    proof_hits: int = 0
    proof_line: str = ""       # first proof-marker line captured
    verdict: str = ""
    log: deque[str] = field(default_factory=lambda: deque(maxlen=200))
    lock: threading.Lock = field(default_factory=threading.Lock)


CATEGORY_LABEL = {
    "real": ("REAL", "green"),
    "analog": ("ANLG", "yellow"),
    "observer": ("OBSV", "cyan"),
    "illusion": ("ILLU", "magenta"),
}

STATUS_COLOR = {
    "queued": "grey50",
    "building": "cyan",
    "running": "yellow",
    "effect_demonstrated": "red bold",
    "observed": "green",
    "skip": "grey50",
    "fail": "red",
}


def status_label(status: str) -> str:
    """Human-readable label for a status string.

    The internal status ``effect_demonstrated`` is rendered as
    ``EFFECT DEMONSTRATED`` in the TUI; other statuses are upper-cased
    unchanged.
    """
    if status == "effect_demonstrated":
        return "EFFECT DEMONSTRATED"
    return status.upper()


def build_table(states: dict[str, RunState], current: str | None) -> Table:
    t = Table(title="dBPF POC Proofs", expand=True, header_style="bold magenta")
    t.add_column("ID", width=5)
    t.add_column("Cat", width=4, justify="center")
    t.add_column("Name", overflow="fold")
    t.add_column("Hooks", justify="right")
    t.add_column("Events", justify="right")
    t.add_column("Flip", justify="right")
    t.add_column("Status", justify="center")
    t.add_column("Verdict", overflow="fold")
    for p in POCS:
        s = states[p.cid]
        color = STATUS_COLOR.get(s.status, "white")
        arrow = "▶ " if p.cid == current else "  "
        hooks = f"{len(s.present_hooks)}/{len(p.hooks)}"
        cat_label, cat_color = CATEGORY_LABEL.get(p.category, ("????", "white"))
        # Prefer showing the captured proof-marker line in the Verdict
        # column when we have one. Truncate to keep the table compact.
        verdict_txt = s.proof_line or s.verdict
        if len(verdict_txt) > 80:
            verdict_txt = verdict_txt[:77] + "..."
        t.add_row(
            arrow + p.cid,
            Text(cat_label, style=cat_color),
            p.name,
            hooks,
            str(s.events),
            str(s.flipped) if s.flipped else "",
            Text(status_label(s.status), style=color),
            verdict_txt,
        )
    return t


def build_log_panel(state: RunState | None) -> Panel:
    if state is None:
        return Panel(Text("idle"), title="live events")
    lines = list(state.log)[-22:]
    body = Text()
    for ln in lines:
        style = "green" if state.poc.prefix in ln else (
            "cyan" if ln.startswith(("==", ">>", "!!", "[harness]")) else "")
        if state.poc.flip_marker and re.search(state.poc.flip_marker, ln):
            style = "red bold"
        if state.poc.proof_marker and re.search(state.poc.proof_marker, ln):
            style = "red bold"
        body.append(ln.rstrip() + "\n", style=style)
    title = f"live: {state.poc.cid} — {state.poc.name}"
    return Panel(body, title=title, border_style="magenta")


class Streamer(threading.Thread):
    def __init__(self, proc: subprocess.Popen, state: RunState, tag: str):
        super().__init__(daemon=True)
        self.proc = proc
        self.state = state
        self.tag = tag
        self.pattern_event = re.compile(re.escape(state.poc.prefix))
        self.flip_re = re.compile(state.poc.flip_marker) if state.poc.flip_marker else None
        self.proof_re = re.compile(state.poc.proof_marker) if state.poc.proof_marker else None

    EVENT_SIGS = re.compile(
        r"(pid=\d|tgid=\d|hook=[a-z_]|tag=(deny|flip|flipped|event|fire)|"
        r"ino=\d|cap=\d|serial=|irq=\d|src=[a-z]|vid=\d|ifin=|uid=\d|"
        r"host_pid=|host_tgid=|FORGE|FLIP|GHOST|STRIP|patched=|ab=|fmt=|"
        r"DROPPED|cmd=|type=\d|ctx=\d|arg='|type=[A-Z]+\()"
    )
    STATUS_SIGS = re.compile(
        r"(attached=\d|skipped=\d|status=|symbol=|map_update|"
        r"attach prog=|target\ttgid=|FATAL|open_and_load|ring_buffer|"
        r"attached — |advertising|no filenames|invalid |note: |"
        r"\battach failed|\battached [0-9]+ probe)"
    )

    def run(self):
        assert self.proc.stdout is not None
        for raw in self.proc.stdout:
            line = raw.decode(errors="replace").rstrip()
            self.state.log.append(f"{self.tag}| {line}")
            # Proof-marker detection runs on ALL lines from ANY stream
            # (trigger, loader, etc) — not gated on the event prefix.
            if self.proof_re and self.proof_re.search(line):
                with self.state.lock:
                    self.state.proof_hits += 1
                    if not self.state.proof_line:
                        self.state.proof_line = line.strip()
            if not self.pattern_event.search(line):
                continue
            # skip obvious status/header lines
            if self.STATUS_SIGS.search(line):
                if self.flip_re and self.flip_re.search(line):
                    # e.g., ch14 "tag=flipped"
                    with self.state.lock:
                        self.state.flipped += 1
                        self.state.events += 1
                continue
            if self.EVENT_SIGS.search(line):
                with self.state.lock:
                    self.state.events += 1
                    if self.flip_re and self.flip_re.search(line):
                        self.state.flipped += 1


def regen_vmlinux(state: RunState):
    tgt = POCS_DIR / state.poc.dir / "build" / "vmlinux.h"
    tgt.parent.mkdir(parents=True, exist_ok=True)
    with tgt.open("wb") as out:
        subprocess.run(["bpftool", "btf", "dump", "file", str(BTF), "format", "c"],
                       check=True, stdout=out, timeout=30)


_built_dirs: set[str] = set()


def build_poc(state: RunState) -> bool:
    d = POCS_DIR / state.poc.dir
    # Skip rebuild if same directory was already built this run (e.g., ch07/ch07w).
    if state.poc.dir in _built_dirs:
        binary = d / "build" / state.poc.dir
        if binary.exists():
            state.log.append(f"build| reusing prior build of {state.poc.dir}")
            return True
    # clean everything except vmlinux.h
    build = d / "build"
    for f in build.glob("*"):
        if f.name == "vmlinux.h":
            continue
        try:
            if f.is_dir():
                import shutil
                shutil.rmtree(f)
            else:
                f.unlink()
        except OSError:
            pass
    regen_vmlinux(state)
    r = subprocess.run(["make", "-C", str(d)], capture_output=True, text=True,
                       timeout=60)
    for ln in (r.stdout + r.stderr).splitlines():
        state.log.append(f"build| {ln}")
    if r.returncode == 0:
        _built_dirs.add(state.poc.dir)
    return r.returncode == 0


def check_hooks(state: RunState):
    for h in state.poc.hooks:
        if h.startswith("veth"):
            state.present_hooks.append(h)
            continue
        if kallsyms_has(h):
            state.present_hooks.append(h)
        else:
            state.missing_hooks.append(h)


def spawn(cmd: list[str], **kw) -> subprocess.Popen:
    # start_new_session=True puts the child into its own process group so that
    # cleanup can kill grandchildren (e.g., trigger.sh → loader) atomically.
    kw.setdefault("start_new_session", True)
    return subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, **kw)


def _terminate_group(proc: subprocess.Popen, sig: int) -> None:
    """Signal the whole process group. Falls back to the single process if
    start_new_session wasn't honored (older kernels, edge cases)."""
    try:
        os.killpg(os.getpgid(proc.pid), sig)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.send_signal(sig)
        except (ProcessLookupError, OSError):
            pass


def dut_python_child() -> tuple[subprocess.Popen, int, str]:
    """Spawn an unprivileged python3 child that waits on a FIFO, then returns
    its pid for -t targeting."""
    import tempfile
    tmpdir = tempfile.mkdtemp(prefix="dut.")
    fifo = os.path.join(tmpdir, "gate.fifo")
    os.mkfifo(fifo)
    # ensure user exists
    subprocess.run(["useradd", "-m", "-s", "/bin/bash", "dut01"],
                   capture_output=True)
    script = f"""
import os, sys, socket
sys.stderr.write("pid=%d\\n" % os.getpid()); sys.stderr.flush()
open({fifo!r}).read()
try: open("/etc/shadow").read()
except Exception as e: pass
try:
    s=socket.socket(); s.bind(("0.0.0.0",80))
except Exception: pass
try: os.nice(-5)
except Exception: pass
try:
    import ctypes; libc = ctypes.CDLL(None)
    sched_param = (ctypes.c_int * 1)(50)
    libc.sched_setscheduler(0, 1, sched_param)  # SCHED_FIFO, prio 50
except Exception: pass
# tiny seccomp dance
try:
    os.getuid(); os.geteuid()
except Exception: pass
sys.stderr.write("child_done\\n")
"""
    p = subprocess.Popen(
        ["su", "dut01", "-s", "/bin/bash", "-c", "exec python3 -u -c " + shlex.quote(script)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True,
    )
    # Read pid line from stderr with a real timeout via select.
    import select
    pid = None
    t0 = time.time()
    while time.time() - t0 < 3:
        ready, _, _ = select.select([p.stderr], [], [], 0.5)
        if not ready:
            if p.poll() is not None:
                break  # child exited without printing pid
            continue
        line = p.stderr.readline().decode(errors="replace")
        if not line:
            break  # EOF
        m = re.match(r"pid=(\d+)", line)
        if m:
            pid = int(m.group(1))
            break
    if pid is None:
        pid = p.pid
    # Drain stderr in the background so the 64 KB pipe buffer can never fill
    # and deadlock the child on write. We ignore the contents — the pid was
    # already harvested above.
    def _drain_stderr(f):
        try:
            for _ in iter(f.readline, b""):
                pass
        except (OSError, ValueError):
            pass
        finally:
            try: f.close()
            except Exception: pass
    threading.Thread(target=_drain_stderr, args=(p.stderr,), daemon=True).start()
    return p, pid, fifo


def release_dut(fifo: str):
    # Open FIFO non-blocking to avoid hanging if the reader is already dead.
    try:
        fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
        os.write(fd, b"go")
        os.close(fd)
    except OSError:
        pass
    try:
        os.unlink(fifo)
    except OSError:
        pass
    # Clean up the tmpdir
    try:
        os.rmdir(os.path.dirname(fifo))
    except OSError:
        pass


def run_poc(state: RunState, refresh):
    p = state.poc
    state.status = "building"
    refresh()
    if p.skip_reason:
        state.status = "skip"
        state.verdict = p.skip_reason
        return

    check_hooks(state)
    if p.mode != "trigger-runs-loader" and not state.present_hooks:
        state.status = "skip"
        state.verdict = f"no hook symbols present: {p.hooks}"
        return

    if not build_poc(state):
        state.status = "fail"
        state.verdict = "build failed"
        return

    state.status = "running"
    refresh()
    d = POCS_DIR / p.dir
    if p.pre_cmd:
        try:
            r = subprocess.run(p.pre_cmd, capture_output=True, text=True, cwd=d,
                               timeout=30)
            for ln in (r.stdout + r.stderr).splitlines():
                state.log.append(f"pre | {ln}")
        except subprocess.TimeoutExpired as e:
            state.log.append(f"pre | TIMEOUT after 30s: {' '.join(p.pre_cmd)}")
            if e.stdout:
                for ln in e.stdout.decode(errors="replace").splitlines():
                    state.log.append(f"pre | {ln}")
            if e.stderr:
                for ln in e.stderr.decode(errors="replace").splitlines():
                    state.log.append(f"pre | {ln}")
    loader = d / "build" / p.dir

    loader_proc = None
    dut_proc = None
    dut_fifo = None
    trig_proc = None
    streamers: list[Streamer] = []
    try:
        if p.mode == "trigger-runs-loader":
            # The trigger launches the loader itself; we just run it.
            trig_proc = spawn(["bash", str(d / p.trigger)], cwd=d)
            st = Streamer(trig_proc, state, "trig")
            st.start()
            streamers.append(st)
        else:
            args = [str(loader)] + list(p.loader_args)
            if p.mode == "target-tgid":
                dut_proc, tgid, dut_fifo = dut_python_child()
                state.log.append(f"[harness] dut tgid={tgid}")
                args += ["-t", str(tgid)]
            elif p.mode == "override-all":
                if not p.loader_args:
                    args += ["-a"]
                # else loader_args already added above
            loader_proc = spawn(args, cwd=d)
            st = Streamer(loader_proc, state, "load")
            st.start()
            streamers.append(st)
            time.sleep(1.2)

            if p.mode == "target-tgid" and dut_fifo:
                release_dut(dut_fifo)
                dut_fifo = None
            # run the trigger
            trig_path = d / p.trigger
            if trig_path.exists():
                trig_proc = spawn(["bash", str(trig_path)], cwd=d)
                st = Streamer(trig_proc, state, "trig")
                st.start()
                streamers.append(st)

        # wait for trigger or overall timeout
        deadline = time.time() + p.timeout
        while time.time() < deadline:
            refresh()
            if trig_proc and trig_proc.poll() is not None:
                # give loader a moment to drain ringbuf
                time.sleep(0.6)
                break
            time.sleep(0.25)

    finally:
        # Graceful shutdown: SIGINT to the whole process group so that a
        # trigger-runs-loader trigger's grandchildren (the actual loader bash
        # spawned) are signaled, not just the bash wrapper. Then escalate to
        # SIGKILL on the group. Always reap with a bounded wait to prevent
        # zombies across 23 POCs when a child is wedged in D-state.
        for x in (loader_proc, trig_proc):
            if x and x.poll() is None:
                _terminate_group(x, signal.SIGINT)
                try:
                    x.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    _terminate_group(x, signal.SIGKILL)
                    try:
                        x.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        state.log.append(f"[harness] WARN: {x.pid} unreapable after SIGKILL")
        if dut_proc:
            if dut_proc.poll() is None:
                _terminate_group(dut_proc, signal.SIGKILL)
            try:
                dut_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                state.log.append(f"[harness] WARN: dut {dut_proc.pid} unreapable")
        if dut_fifo:
            release_dut(dut_fifo)
        # Wait for Streamer threads to finish draining pipe data so
        # verdict reads of events/proof_hits are consistent.
        for st in streamers:
            st.join(timeout=2)

    # honest SKIP: trigger emitted "=== CHxx_SKIP reason=... ==="
    # Greedy capture up to the trailing "===" closer or end-of-line; the
    # non-greedy version previously captured empty strings whenever the line
    # happened not to carry the closer on the same line.
    skip_re = re.compile(r"CH\d+[A-Z_]*_SKIP\s+reason=(.+?)(?:\s*===\s*$|\s*$)")
    for ln in state.log:
        m = skip_re.search(ln)
        if m:
            state.status = "skip"
            state.verdict = "skip: " + m.group(1).strip().strip('"')[:80]
            return

    # verdict — stricter bar: EFFECT_DEMONSTRATED requires proof_marker hit
    # AND a clean loader exit. A loader that crashes immediately after printing
    # its proof marker is not a demonstration; it's a race condition.
    if state.proof_hits > 0:
        # special case: CH0X_PROVEN with flips=0 is really a honest no-effect
        if re.search(r"CH\d+[A-Z_]*_PROVEN.*flips=0\b", state.proof_line or ""):
            state.status = "skip"
            state.verdict = "skip: proof marker printed but flips=0 (no natural denials to flip)"
            return
        crashed = False
        if loader_proc is not None:
            rc = loader_proc.returncode
            if rc is not None and rc not in (0, -signal.SIGINT, -signal.SIGTERM, -signal.SIGKILL):
                crashed = True
        if crashed:
            state.status = "observed"
            state.verdict = (f"proof marker printed but loader exited rc={loader_proc.returncode} "
                             f"— downgraded (see log): {state.proof_line or ''}")
            return
        state.status = "effect_demonstrated"
        state.verdict = (state.proof_line
                         or f"proof marker matched x{state.proof_hits}")
    elif state.flipped and p.flip_marker and not p.proof_marker:
        # legacy: flip_marker w/o proof_marker (none in the current list,
        # but preserve behavior for ad-hoc additions)
        state.status = "effect_demonstrated"
        state.verdict = f"{state.flipped} flip/override markers ({state.events} total events)"
    elif state.events >= p.min_events:
        state.status = "observed"
        state.verdict = f"captured {state.events} events on {len(state.present_hooks)}/{len(p.hooks)} hooks (no proof marker)"
    elif len(state.present_hooks) == 0:
        state.status = "skip"
        state.verdict = "no hooks present on this kernel"
    else:
        state.status = "fail"
        state.verdict = "hooks attached but 0 events and no proof (see log)"


def _emit_results(states, interrupted: bool = False) -> None:
    """Emit final summary table and /tmp/proof-result.json atomically.
    Called both on clean completion and from the Ctrl-C / fatal path so partial
    results survive an interrupt."""
    console.print()
    out = Table(title="final verdicts" + (" (INTERRUPTED)" if interrupted else ""))
    out.add_column("ID")
    out.add_column("Cat", justify="center")
    out.add_column("Status")
    out.add_column("Events", justify="right")
    out.add_column("Verdict", overflow="fold")
    for p in POCS:
        s = states[p.cid]
        cat_label, cat_color = CATEGORY_LABEL.get(p.category, ("????", "white"))
        out.add_row(p.cid,
                    Text(cat_label, style=cat_color),
                    Text(status_label(s.status), style=STATUS_COLOR.get(s.status, "")),
                    str(s.events), s.verdict)
    console.print(out)

    js = {p.cid: {
        "status": states[p.cid].status,
        "category": p.category,
        "events": states[p.cid].events,
        "flipped": states[p.cid].flipped,
        "proof_hits": states[p.cid].proof_hits,
        "proof_line": states[p.cid].proof_line,
        "verdict": states[p.cid].verdict,
        "present_hooks": states[p.cid].present_hooks,
        "missing_hooks": states[p.cid].missing_hooks,
    } for p in POCS}
    if interrupted:
        js["__interrupted__"] = True

    counts: dict[str, int] = {}
    categories: dict[str, int] = {}
    for p in POCS:
        counts[states[p.cid].status] = counts.get(states[p.cid].status, 0) + 1
        categories[p.category] = categories.get(p.category, 0) + 1
    console.print(f"[bold]counts:[/bold] {counts}  [bold]categories:[/bold] {categories}")

    # Atomic write: tmpfile + os.replace to avoid leaving a partial JSON file
    # if the harness is SIGKILLed mid-write (OOM / Ctrl-C escalation).
    final = pathlib.Path("/tmp/proof-result.json")
    tmp = final.with_suffix(".json.tmp")
    try:
        with tmp.open("w") as f:
            json.dump(js, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, final)
    except OSError as e:
        console.print(f"[yellow]could not persist {final}: {e}[/yellow]")
    else:
        console.print(f"[dim]machine-readable: {final}[/dim]")


# ---------------------------------------------------------------------------
# Structural self-check (`--check`) + authoritative stats generation.
#
# These run with NO kernel and NO root: they only read the POCS registry and
# the on-disk repo layout. Paths are derived from this file's location rather
# than the container mount (/w) so the check works on a plain clone.
# ---------------------------------------------------------------------------

RETIRED_DIRS = [
    "ch13-powercap-override",
    "ch13-powercap-override-analog",
    "ch17-acpi-wsmi",
    "ch17-acpi-wsmi-analog",
]

CATEGORY_ORDER = ["real", "observer", "illusion", "analog"]


def _local_paths() -> dict:
    """Repo-relative paths derived from this file's location.

    proof.py lives at <repo>/dBPF-pocs/harness/proof.py.
    """
    harness_dir = pathlib.Path(__file__).resolve().parent
    dbpf_pocs = harness_dir.parent
    repo = dbpf_pocs.parent
    return {
        "harness": harness_dir,
        "pocs": dbpf_pocs / "pocs",
        "stats": harness_dir / "REGISTRY_STATS.md",
        "readmes": [repo / "README.md", repo / "_book_chapters" / "README.md"],
    }


def compute_category_counts() -> dict[str, int]:
    counts = {c: 0 for c in CATEGORY_ORDER}
    for p in POCS:
        counts[p.category] = counts.get(p.category, 0) + 1
    return counts


def render_stats_md() -> str:
    """Render REGISTRY_STATS.md from the live POCS registry.

    The single ``<!-- COUNTS ... -->`` line is machine-parseable and is what
    ``--check`` reads back to prove the file is not stale.
    """
    counts = compute_category_counts()
    total = len(POCS)
    counts_line = "total={} ".format(total) + " ".join(
        f"{c}={counts[c]}" for c in CATEGORY_ORDER)
    out: list[str] = []
    out.append("# dBPF harness — authoritative registry stats")
    out.append("")
    out.append("<!-- GENERATED by `python3 proof.py --write-stats`. "
               "Do not edit by hand; regenerate after any change to POCS. -->")
    out.append(f"<!-- COUNTS {counts_line} -->")
    out.append("")
    out.append(f"Total registered PoCs: **{total}**")
    out.append("")
    out.append("## Per-category counts")
    out.append("")
    out.append("| category | count |")
    out.append("| --- | ---: |")
    for c in CATEGORY_ORDER:
        out.append(f"| {c} | {counts[c]} |")
    out.append(f"| **total** | **{total}** |")
    out.append("")
    out.append("## Registered PoCs")
    out.append("")
    out.append("| cid | category | dir |")
    out.append("| --- | --- | --- |")
    for p in POCS:
        out.append(f"| {p.cid} | {p.category} | {p.dir} |")
    out.append("")
    return "\n".join(out)


def write_stats() -> pathlib.Path:
    paths = _local_paths()
    paths["stats"].write_text(render_stats_md())
    return paths["stats"]


def _parse_stats_counts(text: str) -> dict[str, int] | None:
    m = re.search(r"<!-- COUNTS (.+?) -->", text)
    if not m:
        return None
    out: dict[str, int] = {}
    for tok in m.group(1).split():
        k, _, v = tok.partition("=")
        try:
            out[k] = int(v)
        except ValueError:
            pass
    return out


def run_check() -> int:
    """Validate structural consistency of the registry vs the repo layout.

    Returns 0 on pass, nonzero on any FATAL. Requires no kernel and no root.
    """
    paths = _local_paths()
    pocs_dir = paths["pocs"]
    fatals: list[str] = []
    warnings: list[str] = []

    # (a) every registered dir exists under pocs/
    for p in POCS:
        if not (pocs_dir / p.dir).is_dir():
            fatals.append(f"registered dir missing: {p.cid} -> pocs/{p.dir}")

    # (b) no registered dir is a retired ch13/ch17 dir, and those dirs are gone
    reg_dirs = {p.dir for p in POCS}
    for rd in RETIRED_DIRS:
        if rd in reg_dirs:
            fatals.append(f"retired dir is still registered in POCS: {rd}")
        if (pocs_dir / rd).exists():
            fatals.append(f"retired dir still present on disk: pocs/{rd}")

    # (c) recompute + print per-category counts and total
    counts = compute_category_counts()
    total = len(POCS)
    expected = {"total": total, **counts}
    print("registry counts (recomputed from POCS):")
    print("  total={} ".format(total)
          + " ".join(f"{c}={counts[c]}" for c in CATEGORY_ORDER))

    # (d) stats file must exist and agree with the recomputed counts
    stats_path = paths["stats"]
    if not stats_path.exists():
        fatals.append(f"stats file missing: {stats_path} "
                      f"(run: python3 proof.py --write-stats)")
    else:
        file_counts = _parse_stats_counts(stats_path.read_text(errors="replace"))
        if file_counts is None:
            fatals.append(f"stats file has no COUNTS marker: {stats_path}")
        elif file_counts != expected:
            fatals.append(
                f"stats file is STALE: file={file_counts} computed={expected} "
                f"(run: python3 proof.py --write-stats)")

    # (e) WARNING-ONLY doc drift scan (other agents own the docs in parallel).
    # Only flag a number when it is directly bound to a PoC-count keyword
    # ("N PoCs", "N proven", "N registered", "N directories", "of N") so we
    # do not flag chapter indices in link tables.
    total_pats = [
        re.compile(r"\b(\d{2})\s+PoCs?\b", re.I),
        re.compile(r"\b(\d{2})\s+proven\b", re.I),
        re.compile(r"\b(\d{2})\s+registered\b", re.I),
        re.compile(r"\bregistered[:\s]+(\d{2})\b", re.I),
        re.compile(r"\b(\d{2})\s+directories\b", re.I),
        re.compile(r"\bof\s+(\d{2})\b", re.I),
    ]
    for readme in paths["readmes"]:
        if not readme.exists():
            warnings.append(f"doc not found (skipped): {readme}")
            continue
        rel = readme.parent.name + "/" + readme.name
        for i, ln in enumerate(readme.read_text(errors="replace").splitlines(), 1):
            if re.search(r"\bch1[37]\b", ln):
                warnings.append(f"{rel}:{i}: mentions retired ch13/ch17: "
                                f"{ln.strip()[:90]}")
            seen: set[int] = set()
            for pat in total_pats:
                for numm in pat.findall(ln):
                    n = int(numm)
                    if n != total and 10 <= n <= 99 and n not in seen:
                        seen.add(n)
                        warnings.append(
                            f"{rel}:{i}: possible stale PoC total '{n}' "
                            f"(registry total={total}): {ln.strip()[:80]}")

    for w in warnings:
        print(f"WARNING: {w}")
    for f in fatals:
        print(f"FATAL: {f}")

    if fatals:
        print("HARNESS CHECK: FAIL")
        return 1
    print("HARNESS CHECK: PASS")
    return 0


def _run_live():
    states = {p.cid: RunState(poc=p) for p in POCS}
    layout = Layout()
    layout.split_column(
        Layout(name="top", size=len(POCS) + 4),
        Layout(name="bot", ratio=1),
    )

    current_ref = {"cid": None}

    def refresh():
        cur = current_ref["cid"]
        layout["top"].update(build_table(states, cur))
        layout["bot"].update(build_log_panel(states[cur] if cur else None))

    # one-time host info header
    kern = pathlib.Path("/proc/version").read_text().strip()
    console.print(Panel(Text(kern, style="bold cyan"),
                        title="container kernel", border_style="cyan"))

    if not BTF.exists():
        console.print("[red]BTF missing at /sys/kernel/btf/vmlinux[/red]")
        sys.exit(2)

    interrupted = False
    try:
        with Live(layout, refresh_per_second=8, console=console, screen=False) as live:
            refresh()
            for poc in POCS:
                current_ref["cid"] = poc.cid
                run_poc(states[poc.cid], lambda: (refresh(), live.refresh()))
                refresh()
            current_ref["cid"] = None
            refresh()
    except KeyboardInterrupt:
        interrupted = True
        console.print("[yellow]interrupted — emitting partial results[/yellow]")

    _emit_results(states, interrupted=interrupted)

    # exit non-zero if any POC marked fail, or on interrupt
    if interrupted:
        sys.exit(130)
    if any(states[p.cid].status == "fail" for p in POCS):
        sys.exit(1)


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="dBPF proof harness: default runs the live TUI proofs; "
                    "--check validates the registry with no kernel/root.")
    parser.add_argument(
        "--check", action="store_true",
        help="structural consistency check only (no kernel/root); "
             "exit 0 on pass, nonzero on failure")
    parser.add_argument(
        "--write-stats", action="store_true",
        help="regenerate harness/REGISTRY_STATS.md from the POCS registry, "
             "then exit")
    args = parser.parse_args()

    if args.write_stats:
        path = write_stats()
        print(f"wrote {path}")
        return
    if args.check:
        sys.exit(run_check())

    _run_live()


if __name__ == "__main__":
    main()
