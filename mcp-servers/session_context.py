"""Per-engagement observed-id store -- the concrete first slice of the
"session knowledge base" idea (confirmed by reading a competitor
project's actual source during a broader research pass; see gitignored
RESEARCH-TODO.md's CyberStrike deep-dive). Passively records which id
VALUES have actually been seen for which endpoint TEMPLATE as recon/
browser-mcp/katana-mcp discover urls, so idor-mcp's sweep_idor()/
guess_idor() can pull real observed ids instead of requiring them to be
hand-collected first.

Deliberately narrow for this first pass: recording (template, id_value)
pairs and querying them back. Two things explicitly NOT done here, each
a natural, separately-reviewable follow-up:
  - Not yet wired into browser-mcp/katana-mcp's own tool calls -- calling
    record_observed_urls() automatically as those tools run is the
    integration that makes this actually passive; landing the storage/
    query logic tested on its own first is the more reviewable order.
  - Not yet tracking roles/credentials, the other half of the reference
    design's session-table idea (web-role/web-credential in their
    source) -- smaller and more reviewable as its own addition later.

One SQLite file per engagement (session_context.db), resolved via
engagement_paths.resolve() exactly like case.db/budget.json/
work-registry.json -- a target switch via
scripts/switch-engagement.sh set <target> isolates this the same way it
already isolates everything else, no new isolation logic needed.
"""

from __future__ import annotations

import os
import sqlite3
import sys

try:
    import engagement_paths
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import engagement_paths

try:
    from endpoint_template import endpoint_template, extract_last_id
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from endpoint_template import endpoint_template, extract_last_id

DEFAULT_DB_PATH = engagement_paths.resolve(
    "session_context.db", override_env="HUNTMCP_SESSION_CONTEXT_DB_PATH",
)


def _get_conn(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(os.path.abspath(db_path)) or ".", exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    _init_schema(conn)
    return conn


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS observed_ids (
            template TEXT NOT NULL,
            id_value TEXT NOT NULL,
            source_url TEXT NOT NULL,
            ts TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (template, id_value)
        );
    """)
    conn.commit()


def record_observed_url(url: str, db_path: str = DEFAULT_DB_PATH) -> bool:
    """Record one url's (template, id) pair if it has an id-shaped
    segment at all. Returns True if this was a genuinely NEW
    (template, id_value) pair for this engagement, False if it was a
    duplicate or the url had no id-shaped segment to record -- lets a
    caller (e.g. a crawl tool) report "N new ids observed" without
    tracking that itself."""
    template = endpoint_template(url)
    id_value = extract_last_id(url)
    if id_value is None:
        return False
    conn = _get_conn(db_path)
    try:
        cur = conn.execute(
            "INSERT OR IGNORE INTO observed_ids (template, id_value, source_url) VALUES (?, ?, ?)",
            (template, id_value, url),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def record_observed_urls(urls: list[str], db_path: str = DEFAULT_DB_PATH) -> int:
    """Batch version of record_observed_url() -- returns the count of
    genuinely new (template, id_value) pairs recorded."""
    return sum(1 for url in urls if record_observed_url(url, db_path=db_path))


def get_ids_for_template(template: str, limit: int = 50,
                          db_path: str = DEFAULT_DB_PATH) -> list[str]:
    """All id values observed for an exact endpoint_template() string,
    most-recently-seen first, capped at `limit`."""
    conn = _get_conn(db_path)
    try:
        rows = conn.execute(
            "SELECT id_value FROM observed_ids WHERE template = ? ORDER BY ts DESC LIMIT ?",
            (template, limit),
        ).fetchall()
        return [r["id_value"] for r in rows]
    finally:
        conn.close()


def suggest_object_ids(url_template: str, limit: int = 50,
                        db_path: str = DEFAULT_DB_PATH) -> list[str]:
    """Convenience wrapper taking the SAME url_template shape idor-mcp's
    own sweep_idor()/guess_idor() already accept (a url with a literal
    `{id}` placeholder, e.g. "https://target.com/api/orders/{id}", OR an
    already-concrete url with a real id in it -- endpoint_template()
    normalizes either shape to the same key) and returning previously-
    observed id values for that exact endpoint. The direct drop-in for
    idor-mcp's object_ids param: call this first, fall back to manual
    collection only if it comes back empty."""
    return get_ids_for_template(endpoint_template(url_template), limit=limit, db_path=db_path)


def clear(db_path: str = DEFAULT_DB_PATH) -> None:
    """Drop all recorded observations -- call at the start of a genuinely
    fresh engagement, same lifecycle as budget.json/work-registry.json."""
    conn = _get_conn(db_path)
    try:
        conn.execute("DELETE FROM observed_ids")
        conn.commit()
    finally:
        conn.close()
