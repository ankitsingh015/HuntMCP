import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from mcp.server.fastmcp import FastMCP

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import job_runtime  # noqa: E402
from scope_guard import NoEngagementFile, is_in_scope, is_safe_test_host, load_engagement  # noqa: E402
from tool_resolver import run_tool  # noqa: E402

app = FastMCP("watch-mcp")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "..", "..", "data")
DB_PATH = os.path.join(DATA_DIR, "watch.db")

# start_watch()'s initial snapshot and check_target()'s change check both
# chain subfinder -> (conditionally) httpx -> katana sequentially, up to
# ~360s in the worst case -- longer than an MCP client's own per-call
# timeout can be relied on to tolerate (see job_runtime.py's module
# docstring for the exact failure this class of bug causes elsewhere in
# this repo, first reported live against dalfox-mcp). Both now run via
# job_runtime.start_thread_job() and return a job_id immediately instead
# of blocking; poll with check_status(job_id). Thread jobs only, never
# mixed with a Popen-based _Job from job_runtime.start_job() -- see that
# module's own "Job storage" docstring section.
_jobs: dict = {}

# Per-target in-flight guard: job_runtime.start_thread_job() itself has no
# concept of "target" (it's generic), so without this, two overlapping
# start_watch()/check_target() calls for the SAME target would spawn two
# independent background threads that both diff against the same stale
# load_last_snapshot() before either commits its own new snapshot, both
# insert duplicate watch_events for the same real change, and both hit
# subfinder/httpx/katana redundantly against the live target. Mirrors
# browser-mcp's start_manual_intervention() collision guard for its own
# caller-supplied key (session_file there, target here) -- see
# _start_target_job()/_release_target_job() below.
_in_flight_job_for_target: dict[str, str] = {}   # target -> job_id
_in_flight_target_for_job: dict[str, str] = {}   # job_id -> target


def _start_target_job(tool_name: str, fn, target: str, *args, **kwargs) -> dict:
    """job_runtime.start_thread_job() wrapper that refuses a second
    concurrent job for the same target -- returns the EXISTING job_id
    instead of racing a second thread against it. If the previous job for
    this target already finished but nobody ever called check_status() to
    collect it (so the guard was never released), that's detected and
    cleared here rather than blocking this target forever."""
    existing_job_id = _in_flight_job_for_target.get(target)
    if existing_job_id is not None:
        done = job_runtime.peek_thread_job_done(existing_job_id, _jobs)
        if done is False:
            return {"job_id": existing_job_id, "status": "running", "tool": tool_name,
                    "already_running": True}
        _release_target_job(existing_job_id)

    result = job_runtime.start_thread_job(tool_name, fn, _jobs, *args, **kwargs)
    job_id = result["job_id"]
    _in_flight_job_for_target[target] = job_id
    _in_flight_target_for_job[job_id] = target
    return result


def _release_target_job(job_id: str) -> None:
    target = _in_flight_target_for_job.pop(job_id, None)
    if target is not None:
        _in_flight_job_for_target.pop(target, None)


def get_db() -> sqlite3.Connection:
    os.makedirs(DATA_DIR, exist_ok=True)
    # timeout= (sqlite3's busy-wait ceiling, default 5s) matters more now
    # than it used to: before backgrounding, check_target()/start_watch()
    # ran fully synchronously per MCP call, so genuinely concurrent writers
    # to watch.db were rare. Now every call returns immediately and its DB
    # work happens on a background thread, so a burst of calls (e.g. a
    # multi-target check loop) can have several threads committing to the
    # same WAL-mode db at once -- raise the ceiling so a writer that loses
    # a short race waits instead of raising "database is locked".
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS watched_targets (
            target TEXT PRIMARY KEY,
            interval_hours INTEGER NOT NULL DEFAULT 6,
            last_check_at TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            active INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            snapshot_type TEXT NOT NULL,
            data TEXT NOT NULL,
            captured_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (target) REFERENCES watched_targets(target)
        );

        CREATE TABLE IF NOT EXISTS watch_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            event_type TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'info',
            details TEXT,
            detected_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (target) REFERENCES watched_targets(target)
        );
    """)
    conn.commit()
    conn.close()


def _scope_error(target: str) -> str | None:
    """Returns a BLOCKED message if target isn't covered by engagement.yaml, else None.

    Unlike recon/scan/exploit (where the calling agent runs check-scope.sh before
    ever invoking the MCP tool), watch-mcp can be triggered unattended by cron
    (scripts/setup-watch.sh) with no agent in the loop to enforce that convention.
    The check has to live in the tool itself.

    is_safe_test_host() exemption checked FIRST, same as every other Tier-2
    tool (scope_gate_hook.py) -- this was missing here, so watch-mcp was
    the only Tier-2 tool that couldn't be used against example.com/
    localhost/etc. without a real engagement.yaml, confirmed live.
    """
    if is_safe_test_host(target):
        return None
    try:
        engagement = load_engagement()
    except (NoEngagementFile, RuntimeError) as e:
        return f"BLOCKED: {e}"
    if not is_in_scope(target, engagement):
        return (
            f"BLOCKED: {target} is not in the in_scope list for this engagement "
            f"({engagement.target}). Refusing to watch/check it — update "
            "engagement.yaml if this target should be covered."
        )
    return None


@app.tool()
def start_watch(target: str, interval_hours: int = 6) -> str:
    """Start (or resume/re-interval) continuous monitoring of `target`:
    subdomains via subfinder, live hosts via httpx, endpoints via katana.
    Starts capturing an initial snapshot in the background, returning a
    job_id immediately -- poll check_status(job_id) until it reports
    status=done before calling check_target() the first time (a check
    that races ahead of the initial snapshot has nothing to diff against
    yet, so everything currently there would misleadingly show up as
    "new"). `target` must already be in scope (same engagement.yaml check
    every Tier-2 tool uses). Calling this again on an already-watched
    target updates its interval and reactivates it if paused."""
    err = _scope_error(target)
    if err:
        return err

    conn = get_db()
    existing = conn.execute(
        "SELECT target FROM watched_targets WHERE target = ?", (target,)
    ).fetchone()

    if existing:
        conn.execute(
            "UPDATE watched_targets SET interval_hours = ?, active = 1 WHERE target = ?",
            (interval_hours, target),
        )
        msg = f"Updated watch for {target} (interval: {interval_hours}h)"
    else:
        conn.execute(
            "INSERT INTO watched_targets (target, interval_hours, active) VALUES (?, ?, 1)",
            (target, interval_hours),
        )
        msg = f"Started watching {target} (interval: {interval_hours}h)"

    conn.commit()
    conn.close()

    result = _start_target_job("watch-initial-snapshot", take_snapshot, target, target, "initial")
    job_id = result["job_id"]
    if result.get("already_running"):
        return (f"{msg}. A background job is already running for {target} "
                f"(job_id=\"{job_id}\") -- poll check_status(\"{job_id}\") for that "
                f"one instead of starting a new one.")
    return (f"{msg}. Initial snapshot running in background (job_id=\"{job_id}\"). "
            f"Poll check_status(\"{job_id}\") until it reports status=done.")


@app.tool()
def stop_watch(target: str) -> str:
    """Pause monitoring for `target` (marks it inactive; doesn't delete its
    history/snapshots -- start_watch() later resumes with everything
    intact)."""
    conn = get_db()
    conn.execute(
        "UPDATE watched_targets SET active = 0 WHERE target = ?", (target,)
    )
    conn.commit()

    exists = conn.execute(
        "SELECT changes()"
    ).fetchone()[0]

    conn.close()

    if exists:
        return f"Stopped watching {target}"
    return f"Target {target} is not being watched"


@app.tool()
def list_watched() -> str:
    """List every target ever watched (active or paused), with interval and
    last-check time. No arguments."""
    conn = get_db()
    rows = conn.execute(
        "SELECT target, interval_hours, last_check_at, created_at, active "
        "FROM watched_targets ORDER BY created_at DESC"
    ).fetchall()
    conn.close()

    if not rows:
        return "No targets are being watched."

    lines = [f"Watched targets ({len(rows)}):", ""]
    for r in rows:
        status = "active" if r["active"] else "paused"
        last = r["last_check_at"] or "never"
        lines.append(
            f"  {r['target']:40s} [{status}] interval: {r['interval_hours']}h  last: {last}"
        )
    return "\n".join(lines)


@app.tool()
def check_target(target: str) -> str:
    """Manually trigger a change check for an already-watched target (must
    have called start_watch() first) -- re-runs subfinder+httpx+katana,
    diffs against the last snapshot, logs any new/changed subdomains or
    endpoints as watch events. Runs in the background (subfinder -> httpx
    -> katana chained together can take longer than this MCP session's own
    per-call timeout), returning a job_id immediately -- poll
    check_status(job_id) for what changed (or "no changes detected"). This
    is what the cron job (scripts/setup-watch.sh) calls periodically; this
    tool lets you trigger the same check on demand."""
    err = _scope_error(target)
    if err:
        return err

    conn = get_db()
    watched = conn.execute(
        "SELECT target, interval_hours FROM watched_targets WHERE target = ? AND active = 1",
        (target,),
    ).fetchone()

    if not watched:
        conn.close()
        return f"Target {target} is not being actively watched. Use start_watch first."

    conn.execute(
        "UPDATE watched_targets SET last_check_at = datetime('now') WHERE target = ?",
        (target,),
    )
    conn.commit()
    conn.close()

    result = _start_target_job("watch-check", _run_check_and_persist, target, target)
    job_id = result["job_id"]
    if result.get("already_running"):
        return (f"A check is already running for {target} (job_id=\"{job_id}\") -- "
                f"poll check_status(\"{job_id}\") for that one instead of starting a new one.")
    return (f"Started change check for {target} (job_id=\"{job_id}\"). "
            f"Poll check_status(\"{job_id}\") until it reports status=done.")


def _run_check_and_persist(target: str) -> str:
    """The actual run_check() + DB-write + snapshot logic check_target()
    used to do synchronously before returning -- now runs inside a
    background thread (see check_target() above) instead."""
    events, current_subdomains, current_endpoints = run_check(target)

    conn = get_db()
    for ev in events:
        conn.execute(
            "INSERT INTO watch_events (target, event_type, description, severity, details) "
            "VALUES (?, ?, ?, ?, ?)",
            (target, ev["type"], ev["description"], ev["severity"], ev.get("details", "")),
        )
    # Insert the new snapshot on the SAME connection/transaction as the
    # events above (conn=conn), one single commit -- reuses the subfinder/
    # katana results run_check() already fetched instead of running both
    # tools again just to persist the snapshot (this used to run each tool
    # twice per check), AND avoids a partial-failure gap two separate
    # connections/commits had: if something raised between them, the
    # events could land durably while the snapshot never did, so the NEXT
    # check would diff against the same stale snapshot and re-log the same
    # "new" subdomains/endpoints a second time.
    take_snapshot(target, "check", subdomains=current_subdomains, endpoints=current_endpoints, conn=conn)
    conn.commit()
    conn.close()

    if not events:
        return f"Check complete for {target}. No changes detected."

    lines = [f"Changes detected on {target} ({len(events)} event(s)):", ""]
    for ev in events:
        sev = {"critical": "🔴", "high": "🟠", "medium": "🟡", "info": "🔵"}.get(
            ev["severity"], "⚪"
        )
        lines.append(f"  {sev} [{ev['type']}] {ev['description']}")

    return "\n".join(lines)


@app.tool()
def check_status(job_id: str) -> str:
    """Poll a background job started by start_watch()'s initial snapshot or
    check_target()'s change check. Returns "status: running (Xs elapsed)"
    while still working, or the actual result text (a snapshot summary for
    start_watch()'s job, or the change summary for check_target()'s) once
    it's done. Keep polling every ~10-15s until it stops saying "running"
    -- this is also what releases the per-target in-flight guard, so
    calling this through to completion (not abandoning it mid-poll) is
    what lets a later start_watch()/check_target() call for the same
    target start a new job instead of being told one's already running."""
    result = job_runtime.poll_thread_job(job_id, _jobs)
    if "status" not in result:
        return result["error"]
    if result["status"] == "running":
        return f"Still running -- {result['elapsed_s']}s elapsed so far. Poll again shortly."
    _release_target_job(job_id)
    if result["status"] == "error":
        return f"Check failed: {result['error']}"
    return result["value"] if result["value"] is not None else "Done (no result text)."


@app.tool()
def list_checks() -> str:
    """List watch-mcp background jobs (start_watch()'s initial snapshot,
    check_target()'s change check) still running in this session -- job_id,
    which tool started it, elapsed time, and whether it's been running long
    enough (30+ min) to likely be abandoned rather than genuinely still
    busy."""
    jobs = job_runtime.list_thread_jobs(_jobs)
    if not jobs:
        return "No watch-mcp checks currently running."
    lines = ["Running watch-mcp checks:", ""]
    for j in jobs:
        marker = " [LIKELY ABANDONED]" if j["likely_abandoned"] else ""
        lines.append(f"  {j['job_id']}  {j['tool']}  {j['elapsed_s']}s{marker}")
    return "\n".join(lines)


@app.tool()
def get_watch_history(target: str, limit: int = 20) -> str:
    """List past change events logged for `target` by check_target(),
    newest first (new/removed subdomains, newly-live hosts, etc.), up to
    `limit` (default 20)."""
    conn = get_db()
    events = conn.execute(
        "SELECT event_type, description, severity, detected_at "
        "FROM watch_events WHERE target = ? "
        "ORDER BY detected_at DESC LIMIT ?",
        (target, limit),
    ).fetchall()
    conn.close()

    if not events:
        return f"No watch events for {target}."

    lines = [f"Watch history for {target} ({len(events)} event(s)):", ""]
    for ev in events:
        sev = {"critical": "🔴", "high": "🟠", "medium": "🟡", "info": "🔵"}.get(
            ev["severity"], "⚪"
        )
        lines.append(f"  {sev} [{ev['event_type']}] {ev['description']} ({ev['detected_at']})")

    return "\n".join(lines)


def take_snapshot(target: str, snapshot_type: str, subdomains: list | None = None,
                   endpoints: list | None = None, conn: sqlite3.Connection | None = None) -> str:
    """Persists a snapshot row and returns a short summary string -- used
    as check_status()'s result text for start_watch()'s initial-snapshot
    job (previously this had no return value, so a poller only ever saw
    "Done (no result text)").

    `conn`: pass an already-open connection to fold this insert into the
    CALLER's own transaction instead of opening/committing/closing a
    separate one here -- see _run_check_and_persist(), which needs its
    watch_events inserts and this snapshot insert to land in one atomic
    commit. Defaults to None (open/commit/close its own connection), which
    is what start_watch()'s standalone initial snapshot uses."""
    own_conn = conn is None
    if own_conn:
        conn = get_db()

    if subdomains is None:
        subdomains = run_subfinder(target)
    if endpoints is None:
        endpoints = run_katana(target)

    conn.execute(
        "INSERT INTO snapshots (target, snapshot_type, data) VALUES (?, ?, ?)",
        (target, snapshot_type, json.dumps({"subdomains": subdomains, "endpoints": endpoints})),
    )
    if own_conn:
        conn.commit()
        conn.close()

    return f"Snapshot captured for {target}: {len(subdomains)} subdomain(s), {len(endpoints)} endpoint(s)."


def load_last_snapshot(target: str):
    conn = get_db()
    row = conn.execute(
        "SELECT data FROM snapshots WHERE target = ? ORDER BY id DESC LIMIT 1",
        (target,),
    ).fetchone()
    conn.close()

    if row:
        return json.loads(row["data"])
    return {"subdomains": [], "endpoints": []}


def run_subfinder(target: str) -> list:
    try:
        result = run_tool("subfinder", ["-d", target, "-silent"], timeout=120)
        if result.returncode == 0 and result.stdout.strip():
            return sorted(set(result.stdout.strip().splitlines()))
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        pass
    return []


def run_httpx(domains: list) -> list:
    if not domains:
        return []
    try:
        input_text = "\n".join(domains)
        result = run_tool("httpx", ["-silent", "-sc", "-td", "-title"],
            input=input_text, capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0 and result.stdout.strip():
            lines = result.stdout.strip().splitlines()
            result_list = []
            for line in lines:
                # httpx's `-sc -td -title` output looks like:
                #   https://example.com [200] [nginx] [Example Domain - Welcome]
                # Splitting on whitespace truncates a multi-word title to its
                # first word -- pull the bracketed fields out instead.
                url_match = re.match(r"(\S+)", line)
                url = url_match.group(1) if url_match else ""
                brackets = re.findall(r"\[([^\]]*)\]", line)
                result_list.append({
                    "url": url,
                    "status": brackets[0] if len(brackets) > 0 else "",
                    "tech": brackets[1] if len(brackets) > 1 else "",
                    "title": brackets[2] if len(brackets) > 2 else "",
                })
            return result_list
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        pass
    return []


def run_katana(target: str) -> list:
    try:
        result = run_tool("katana", ["-u", f"https://{target}", "-silent", "-d", "2"],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0 and result.stdout.strip():
            return sorted(set(result.stdout.strip().splitlines()))
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        pass
    return []


def run_check(target: str) -> tuple[list, list, list]:
    events = []
    previous = load_last_snapshot(target)

    current_subdomains = run_subfinder(target)

    new_subs = set(current_subdomains) - set(previous.get("subdomains", []))
    missing_subs = set(previous.get("subdomains", [])) - set(current_subdomains)

    for sub in sorted(new_subs):
        events.append({
            "type": "new_subdomain",
            "description": f"New subdomain discovered: {sub}",
            "severity": "medium",
            "details": json.dumps({"subdomain": sub}),
        })

    if new_subs:
        live_new = run_httpx(list(new_subs))
        for entry in live_new:
            events.append({
                "type": "live_subdomain",
                "description": f"Live subdomain: {entry['url']} [{entry.get('status', '?')}] tech: {entry.get('tech', '?')}",
                "severity": "medium",
                "details": json.dumps(entry),
            })

    for sub in sorted(missing_subs):
        events.append({
            "type": "subdomain_removed",
            "description": f"Subdomain no longer resolves: {sub}",
            "severity": "low",
            "details": json.dumps({"subdomain": sub}),
        })

    current_endpoints = run_katana(target)
    new_endpoints = set(current_endpoints) - set(previous.get("endpoints", []))
    for ep in sorted(new_endpoints):
        events.append({
            "type": "new_endpoint",
            "description": f"New endpoint discovered: {ep}",
            "severity": "info",
            "details": json.dumps({"endpoint": ep}),
        })

    return events, current_subdomains, current_endpoints


if __name__ == "__main__":
    init_db()
    print("watch-mcp starting...", file=sys.stderr)
    print(f"  DB: {DB_PATH}", file=sys.stderr)
    app.run(transport="stdio")
