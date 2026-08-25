"""SQLite storage for imported Burp HTTP-history endpoints. One row per
unique (target, method, url) triple -- re-importing the same export (or
an overlapping later one from the same session) updates the row instead
of duplicating it, same UPSERT pattern as memory-mcp/watch-mcp use for
their own per-target state.
"""

import json
import os
import sqlite3

DATA_DIR = os.getenv(
    "BURP_IMPORT_DATA_DIR",
    os.path.join(os.path.dirname(__file__), "../../data"),
)
DB_PATH = os.path.join(DATA_DIR, "burp-import.db")


def _get_conn(path: str = DB_PATH) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    _init_schema(conn)
    return conn


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS burp_endpoints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            method TEXT NOT NULL,
            url TEXT NOT NULL,
            host TEXT NOT NULL DEFAULT '',
            path TEXT NOT NULL DEFAULT '',
            status INTEGER,
            mimetype TEXT NOT NULL DEFAULT '',
            headers_json TEXT NOT NULL DEFAULT '{}',
            has_cookie INTEGER NOT NULL DEFAULT 0,
            has_auth_header INTEGER NOT NULL DEFAULT 0,
            source_file TEXT NOT NULL DEFAULT '',
            imported_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(target, method, url)
        );
    """)


def import_entries(target: str, entries: list[dict], source_file: str, path: str = DB_PATH) -> dict:
    conn = _get_conn(path)
    try:
        imported = 0
        updated = 0
        authenticated = 0
        for e in entries:
            existing = conn.execute(
                "SELECT id FROM burp_endpoints WHERE target = ? AND method = ? AND url = ?",
                (target, e["method"], e["url"]),
            ).fetchone()
            conn.execute(
                """INSERT INTO burp_endpoints
                   (target, method, url, host, path, status, mimetype, headers_json,
                    has_cookie, has_auth_header, source_file)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(target, method, url) DO UPDATE SET
                       host = excluded.host,
                       path = excluded.path,
                       status = excluded.status,
                       mimetype = excluded.mimetype,
                       headers_json = excluded.headers_json,
                       has_cookie = excluded.has_cookie,
                       has_auth_header = excluded.has_auth_header,
                       source_file = excluded.source_file,
                       imported_at = datetime('now')""",
                (
                    target, e["method"], e["url"], e["host"], e["path"], e["status"],
                    e["mimetype"], json.dumps(e["headers"]),
                    int(e["has_cookie"]), int(e["has_auth_header"]), source_file,
                ),
            )
            if existing:
                updated += 1
            else:
                imported += 1
            if e["has_cookie"] or e["has_auth_header"]:
                authenticated += 1
        conn.commit()
        return {
            "imported": imported,
            "updated": updated,
            "authenticated": authenticated,
            "total": len(entries),
        }
    finally:
        conn.close()


def list_endpoints(
    target: str = "",
    authenticated_only: bool = False,
    limit: int = 50,
    path: str = DB_PATH,
) -> list[dict]:
    conn = _get_conn(path)
    try:
        query = "SELECT * FROM burp_endpoints WHERE 1=1"
        args: list = []
        if target:
            query += " AND target = ?"
            args.append(target)
        if authenticated_only:
            query += " AND (has_cookie = 1 OR has_auth_header = 1)"
        query += " ORDER BY imported_at DESC LIMIT ?"
        args.append(limit)
        rows = conn.execute(query, args).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_endpoint(endpoint_id: int, path: str = DB_PATH) -> dict | None:
    conn = _get_conn(path)
    try:
        row = conn.execute("SELECT * FROM burp_endpoints WHERE id = ?", (endpoint_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()
