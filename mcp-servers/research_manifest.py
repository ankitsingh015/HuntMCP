"""C1b -- research-run manifest: tool/model/policy versions plus a
target-snapshot hash, captured once per research run.

Why this exists (IMPLEMENTATION-TASK-TRACKER.md C1b): without a recorded
manifest, two runs against the same target can silently differ in which
scanner binary versions ran, which model drove the agent, and which
version of the safety policy (scope_gate_hook.py) was enforcing it --
making "why did this run find something the last one didn't" or "is this
finding reproducible" unanswerable after the fact. This module only
CAPTURES that state; it never influences the run itself (pure, read-only,
same philosophy as telemetry.py/coverage_signal.py).

Honest scope (do not overclaim, matching this codebase's own standard --
see telemetry.py's "Honest limits" section for the precedent): capturing
the manifest is the buildable half of C1b. The task's actual acceptance
gate is a **triager-acceptance A/B** ("promote only on uplift") -- whether
attaching this manifest to a Triager-Proof Bundle measurably improves a
real human triager's acceptance behavior. That requires accumulated real
usage data this module cannot manufacture (per `.claude/rules/
benchmarks.md`'s "do not auto-derive a success oracle"); it is the
deliberately-NOT-done remainder, tracked in the tracker, not silently
promoted here.

Every sub-capture degrades to a null/False result on failure rather than
raising -- a manifest-capture problem must never abort the research run
it's attached to.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import time

import case_store
import model_gateway
import tool_resolver

# Per-tool version flag, empirically confirmed against the actual
# installed binaries in this dev environment (see tests/
# test_research_manifest.py's fixture comment) -- not guessed from docs,
# since several of these tools don't follow GNU `--version` conventions.
TOOL_VERSION_FLAGS: dict[str, list[str]] = {
    "subfinder": ["-version"],
    "httpx": ["-version"],
    "katana": ["-version"],
    "nuclei": ["-version"],
    "nmap": ["--version"],
    "sqlmap": ["--version"],
    "dalfox": ["version"],
    "ffuf": ["-V"],
}

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|\x1b[()][A-Za-z0-9]")
# A version-looking token: at least two dot-separated digit groups, plus
# trailing identifier chars (covers nmap's "7.94SVN", ffuf's "2.1.0-dev",
# sqlmap's "1.8.4#stable", a 4-component "1.2.3.4").
_VERSION_TOKEN = r"\d+(?:\.\d+)+[A-Za-z0-9#+.-]*"
# Pass 1: the word "version" (whole word, case-insensitive -- `\b` keeps
# this from matching inside "conversion"/"diversion") immediately
# followed by the version token, so an unrelated number elsewhere on the
# same line (an IP:port, a different runtime's version) is never picked
# up -- found via review: a looser "line contains 'version' anywhere" +
# "first number anywhere on that line" check could grab the wrong digits
# (e.g. a Python-runtime version warning sharing a line with the word
# "version").
_LABELED_VERSION_RE = re.compile(rf"\bversion\b\s*[:=]?\s*v?({_VERSION_TOKEN})", re.IGNORECASE)
_BARE_VERSION_LINE_RE = re.compile(rf"^v?({_VERSION_TOKEN})$")

_SCOPE_GATE_HOOK_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "scripts", "hooks", "scope_gate_hook.py",
)


def parse_tool_version(raw_output: str) -> str | None:
    """Extracts a version token from a tool's `--version`-style stdout+
    stderr, tolerating ANSI color codes and ASCII-art banners. Two
    patterns, tried on every line in document order (first match anywhere
    wins): (1) a bare line that, once ANSI-stripped and trimmed, IS just
    a version token -- covers sqlmap's unlabeled first line and dalfox's
    unlabeled trailing line; (2) a line containing the word "version"
    (whole word, case-insensitive) immediately followed by a version-
    looking token -- covers subfinder/httpx/katana/nuclei/nmap/ffuf's
    labeled banners. Returns None rather than guessing if neither pattern
    matches anything -- an absent version must never be silently
    fabricated.

    Trying both patterns per line, in order, rather than scanning the
    whole output for pattern 2 before ever trying pattern 1, matters:
    found via review, a global "any labeled line anywhere" scan let an
    unrelated "version" mention further down the output (e.g. a
    Python-runtime version warning sharing the word "version" with a
    tool written in Python) win over the tool's own correct bare version
    line earlier in the same output. Line order is a reliable
    tie-breaker in practice -- every one of the 8 real tools this was
    verified against prints its own version on one of its first lines,
    before any unrelated "version" mention could appear."""
    if not raw_output:
        return None
    clean = _ANSI_RE.sub("", raw_output)

    for line in clean.splitlines():
        m = _BARE_VERSION_LINE_RE.match(line.strip())
        if m:
            return m.group(1)
        m = _LABELED_VERSION_RE.search(line)
        if m:
            return m.group(1)

    return None


def capture_tool_versions() -> dict[str, dict]:
    """Best-effort `--version` capture for every known scanner binary,
    resolved via tool_resolver.resolve_tool() (never a bare `which`/
    subprocess-by-name -- that's the exact Go-vs-Python-httpx shadowing
    bug this project's own tool_resolver.py exists to avoid). Never
    raises: an unresolvable or misbehaving binary degrades to
    resolved=False / version=None rather than aborting the whole
    manifest capture."""
    results: dict[str, dict] = {}
    for name, flag in TOOL_VERSION_FLAGS.items():
        resolved_path = tool_resolver.resolve_tool(name)
        is_real = os.path.isfile(resolved_path) and os.access(resolved_path, os.X_OK)
        if not is_real:
            results[name] = {"resolved": False, "path": None, "version": None, "version_raw": None}
            continue
        try:
            proc = subprocess.run(
                [resolved_path, *flag],
                capture_output=True, text=True, timeout=10, check=False,
                env=tool_resolver.minimal_subprocess_env(),
            )
            raw = (proc.stdout or "") + (proc.stderr or "")
        except Exception as e:  # noqa: BLE001 -- a version probe must degrade, never abort the manifest
            results[name] = {
                "resolved": True, "path": resolved_path, "version": None,
                "version_raw": None, "error": str(e),
            }
            continue
        results[name] = {
            "resolved": True,
            "path": resolved_path,
            "version": parse_tool_version(raw),
            "version_raw": raw[:500],
        }
    return results


def capture_model_info(agent_role: str | None = None) -> dict:
    """Which model/provider would currently drive `agent_role` (or the
    default chain if no role is given), via model_gateway.select_provider
    -- reused, not re-derived, so this can never silently disagree with
    what the orchestrator itself would pick. Degrades to an all-None dict
    with an `error` key if no provider is configured, rather than
    raising."""
    try:
        cfg = model_gateway.select_provider(agent_role)
        return {"provider": cfg.name, "model": cfg.default_model, "source": cfg.source}
    except Exception as e:  # noqa: BLE001 -- see module docstring: never abort manifest capture
        return {"provider": None, "model": None, "source": None, "error": str(e)}


def capture_policy_version() -> dict:
    """SHA-256 of scope_gate_hook.py's current bytes -- a verifiable
    fingerprint of exactly which safety-policy logic was enforcing this
    run, same hash-based integrity convention S5/S6/P2-BENCH already use
    elsewhere in this codebase (rather than a human-maintained version
    string, which could silently drift out of sync with the file)."""
    try:
        with open(_SCOPE_GATE_HOOK_PATH, "rb") as f:
            data = f.read()
    except OSError as e:
        return {"available": False, "hash": None, "error": str(e)}
    return {"available": True, "hash": hashlib.sha256(data).hexdigest()}


def hash_target_snapshot(db_path: str | None = None) -> dict:
    """SHA-256 of case_store.case_export()'s current output for this
    engagement -- a fingerprint of everything known about the target
    (hypotheses/findings/evidence/experiments/root_causes) at manifest-
    capture time, reusing the existing case-mcp export rather than a
    second, parallel query path. Known limitation, not silently
    overclaimed: case_export()'s `SELECT * FROM <table>` has no ORDER BY,
    so the hash is sensitive to row ordering, not just row content, in
    the (rare, no-intervening-write) case SQLite's own default ordering
    were to vary -- acceptable for this task's "did anything change
    between two points in time" purpose, not claimed as a canonical
    content-only digest."""
    try:
        export_text = case_store.case_export(db_path)
    except Exception as e:  # noqa: BLE001 -- see module docstring: never abort manifest capture
        return {"available": False, "hash": None, "error": str(e)}
    return {"available": True, "hash": hashlib.sha256(export_text.encode("utf-8")).hexdigest()}


def capture_manifest(target: str, agent_role: str | None = None, db_path: str | None = None) -> dict:
    """Captures the full C1b manifest for one research run against
    `target`. Pure aggregation of the four sub-captures above; never
    raises (each sub-capture already degrades gracefully on its own).

    `target` is a caller-supplied label, not cross-checked against which
    engagement's case.db is actually active -- the same convention
    case_store.log_experiment()'s own `target` param already established
    (resolving db_path is what actually picks which case.db gets read;
    see resolve_db_path()). Callers are responsible for passing the
    target that matches their current active engagement, same as every
    other case_store call that takes a `target` string."""
    return {
        "target": target,
        "captured_at": time.time(),
        "tool_versions": capture_tool_versions(),
        "model": capture_model_info(agent_role),
        "policy_version": capture_policy_version(),
        "target_snapshot_hash": hash_target_snapshot(db_path),
    }
