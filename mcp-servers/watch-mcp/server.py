import json
import os
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from mcp.server.fastmcp import FastMCP

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from tool_resolver import resolve_tool, run_tool

app = FastMCP("watch-mcp")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "..", "..", "data")
DB_PATH = os.path.join(DATA_DIR, "watch.db")


def get_db() -> sqlite3.Connection:
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
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


@app.tool()
def start_watch(target: str, interval_hours: int = 6) -> str:
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

    take_snapshot(target, "initial")

    return msg


@app.tool()
def stop_watch(target: str) -> str:
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

    events = run_check(target)

    for ev in events:
        conn.execute(
            "INSERT INTO watch_events (target, event_type, description, severity, details) "
            "VALUES (?, ?, ?, ?, ?)",
            (target, ev["type"], ev["description"], ev["severity"], ev.get("details", "")),
        )

    conn.commit()
    conn.close()

    take_snapshot(target, "check")

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
def get_watch_history(target: str, limit: int = 20) -> str:
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


def take_snapshot(target: str, snapshot_type: str):
    conn = get_db()

    subdomains = run_subfinder(target)
    endpoints = run_katana(target)

    conn.execute(
        "INSERT INTO snapshots (target, snapshot_type, data) VALUES (?, ?, ?)",
        (target, snapshot_type, json.dumps({"subdomains": subdomains, "endpoints": endpoints})),
    )
    conn.commit()
    conn.close()


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
        result = subprocess.run(
            [resolve_tool("subfinder"), "-d", target, "-silent"],
            capture_output=True, text=True, timeout=120,
        )
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
                parts = line.split()
                result_list.append({
                    "url": parts[0] if parts else "",
                    "status": parts[1] if len(parts) > 1 else "",
                    "tech": parts[2] if len(parts) > 2 else "",
                    "title": parts[3] if len(parts) > 3 else "",
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


def run_check(target: str) -> list:
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

    return events


if __name__ == "__main__":
    init_db()
    print("watch-mcp starting...", file=sys.stderr)
    print(f"  DB: {DB_PATH}", file=sys.stderr)
    app.run(transport="stdio")
