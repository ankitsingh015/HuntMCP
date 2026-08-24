import os
import sqlite3

DATA_DIR = os.getenv(
    "TARGET_DISCOVERY_DIR",
    os.path.join(os.path.dirname(__file__), "../../data"),
)
DB_PATH = os.path.join(DATA_DIR, "candidate-targets.db")


def _get_conn() -> sqlite3.Connection:
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    _init_schema(conn)
    return conn


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS candidates (
            domain TEXT PRIMARY KEY,
            contact TEXT NOT NULL DEFAULT '',
            policy_url TEXT NOT NULL DEFAULT '',
            expires TEXT NOT NULL DEFAULT '',
            validated INTEGER NOT NULL DEFAULT 0,
            notes TEXT NOT NULL DEFAULT '',
            discovered_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
    """)
    conn.commit()


def upsert_candidate(domain: str, contact: str, policy_url: str, expires: str,
                      validated: bool, notes: str = "") -> None:
    conn = _get_conn()
    conn.execute(
        """
        INSERT INTO candidates (domain, contact, policy_url, expires, validated, notes)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(domain) DO UPDATE SET
            contact=excluded.contact, policy_url=excluded.policy_url,
            expires=excluded.expires, validated=excluded.validated,
            notes=excluded.notes
        """,
        (domain, contact, policy_url, expires, int(validated), notes),
    )
    conn.commit()
    conn.close()


def list_candidates(validated_only: bool = True) -> list[sqlite3.Row]:
    conn = _get_conn()
    if validated_only:
        rows = conn.execute(
            "SELECT * FROM candidates WHERE validated=1 ORDER BY discovered_at DESC"
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM candidates ORDER BY discovered_at DESC"
        ).fetchall()
    conn.close()
    return rows
