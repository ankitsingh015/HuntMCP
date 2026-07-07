import json
import os
import sqlite3
from datetime import datetime

MEMORY_DIR = os.getenv(
    "MEMORY_DIR",
    os.path.join(os.path.dirname(__file__), "../../data"),
)
MEMORY_DB = os.path.join(MEMORY_DIR, "memory.db")


def _get_conn() -> sqlite3.Connection:
    os.makedirs(MEMORY_DIR, exist_ok=True)
    conn = sqlite3.connect(MEMORY_DB)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    _init_schema(conn)
    return conn


def _init_schema(conn: sqlite3.Connection):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS hunts (
            target TEXT PRIMARY KEY,
            tech_stack TEXT NOT NULL DEFAULT '[]',
            subdomains TEXT NOT NULL DEFAULT '[]',
            bounty_estimate TEXT NOT NULL DEFAULT '',
            summary TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            finding TEXT NOT NULL,
            vuln_class TEXT NOT NULL DEFAULT '',
            confidence TEXT NOT NULL DEFAULT 'MEDIUM',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (target) REFERENCES hunts(target) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS chains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            description TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (target) REFERENCES hunts(target) ON DELETE CASCADE
        );
    """)


def save_hunt(
    target: str,
    findings: list[dict] | None = None,
    chains: list[str] | None = None,
    tech_stack: list[str] | None = None,
    subdomains: list[str] | None = None,
    bounty_estimate: str = "",
    summary: str = "",
) -> str:
    conn = _get_conn()
    try:
        now = datetime.utcnow().isoformat()
        conn.execute(
            """INSERT INTO hunts (target, tech_stack, subdomains, bounty_estimate, summary, updated_at)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(target) DO UPDATE SET
                   tech_stack = excluded.tech_stack,
                   subdomains = excluded.subdomains,
                   bounty_estimate = excluded.bounty_estimate,
                   summary = excluded.summary,
                   updated_at = excluded.updated_at""",
            (
                target,
                json.dumps(tech_stack or []),
                json.dumps(subdomains or []),
                bounty_estimate,
                summary,
                now,
            ),
        )
        if findings:
            conn.execute("DELETE FROM findings WHERE target = ?", (target,))
            for f in findings:
                conn.execute(
                    "INSERT INTO findings (target, finding, vuln_class, confidence) VALUES (?, ?, ?, ?)",
                    (target, f.get("finding", ""), f.get("vuln_class", ""), f.get("confidence", "MEDIUM")),
                )
        if chains:
            conn.execute("DELETE FROM chains WHERE target = ?", (target,))
            for c in chains:
                conn.execute(
                    "INSERT INTO chains (target, description) VALUES (?, ?)",
                    (target, c),
                )
        conn.commit()
        return f"Saved hunt for {target}"
    finally:
        conn.close()


def recall(target: str) -> str:
    conn = _get_conn()
    try:
        hunt = conn.execute("SELECT * FROM hunts WHERE target = ?", (target,)).fetchone()
        if not hunt:
            return f"No past hunts found for {target}"

        findings = conn.execute(
            "SELECT finding, vuln_class, confidence FROM findings WHERE target = ? ORDER BY created_at",
            (target,),
        ).fetchall()

        chains = conn.execute(
            "SELECT description FROM chains WHERE target = ? ORDER BY created_at",
            (target,),
        ).fetchall()

        tech = json.loads(hunt["tech_stack"]) if hunt["tech_stack"] else []
        subs = json.loads(hunt["subdomains"]) if hunt["subdomains"] else []

        lines = [f"Hunt Memory: {target}"]
        lines.append(f"  Last hunted: {hunt['updated_at']}")
        if tech:
            lines.append(f"  Tech stack: {', '.join(tech)}")
        if subs:
            lines.append(f"  Subdomains found: {', '.join(subs)}")
        if hunt["bounty_estimate"]:
            lines.append(f"  Bounty estimate: {hunt['bounty_estimate']}")
        if hunt["summary"]:
            lines.append(f"  Summary: {hunt['summary']}")
        if findings:
            lines.append(f"  Findings ({len(findings)}):")
            for f in findings:
                lines.append(f"    - [{f['confidence']}] {f['vuln_class']}: {f['finding']}")
        if chains:
            lines.append(f"  Attack chains ({len(chains)}):")
            for c in chains:
                lines.append(f"    - {c['description']}")
        return "\n".join(lines)
    finally:
        conn.close()


def search_by_tech(techs: list[str]) -> str:
    conn = _get_conn()
    try:
        all_hunts = conn.execute("SELECT * FROM hunts ORDER BY updated_at DESC").fetchall()
        matches = []
        for h in all_hunts:
            stored = json.loads(h["tech_stack"]) if h["tech_stack"] else []
            if any(t.lower() in [s.lower() for s in stored] for t in techs):
                matches.append(h)
        if not matches:
            return f"No past hunts matching tech: {', '.join(techs)}"
        lines = [f"Past hunts matching {', '.join(techs)} ({len(matches)}):"]
        for h in matches:
            tech = json.loads(h["tech_stack"]) if h["tech_stack"] else []
            lines.append(f"  - {h['target']} ({', '.join(tech)}) — {h['updated_at'][:10]}")
        return "\n".join(lines)
    finally:
        conn.close()


def list_targets() -> str:
    conn = _get_conn()
    try:
        rows = conn.execute(
            "SELECT target, updated_at, (SELECT COUNT(*) FROM findings WHERE target = hunts.target) as finding_count FROM hunts ORDER BY updated_at DESC"
        ).fetchall()
        if not rows:
            return "No targets in memory yet."
        lines = [f"Targets in memory ({len(rows)}):"]
        for r in rows:
            lines.append(f"  - {r['target']} ({r['finding_count']} findings, last: {r['updated_at'][:10]})")
        return "\n".join(lines)
    finally:
        conn.close()


def delete_hunt(target: str) -> str:
    conn = _get_conn()
    try:
        conn.execute("DELETE FROM findings WHERE target = ?", (target,))
        conn.execute("DELETE FROM chains WHERE target = ?", (target,))
        conn.execute("DELETE FROM hunts WHERE target = ?", (target,))
        conn.commit()
        return f"Deleted hunt for {target}"
    finally:
        conn.close()
