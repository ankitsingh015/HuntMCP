"""Persistent per-engagement case state: hypotheses, evidence, findings,
experiments, and root causes -- the structured layer that sits underneath
what used to be pure agent-conversation reasoning.

Why this exists: before this module, a finding's confidence was whatever
the LLM said in prose ("confidence: high"), a hypothesis was never written
down anywhere durable, and nothing stopped an agent from declaring a
finding CONFIRMED with zero supporting evidence, or re-running a test it
had already run earlier in the same engagement. `dedupe_check.py` catches
duplicate CONFIRMED findings at the vuln_class+endpoint+parameter level,
and `work_registry.py` dedupes agent SPAWNS per host -- neither tracks the
finer-grained "have I already run this exact experiment" or "does this
finding actually have proof" questions this module answers.

One SQLite file per engagement (`case.db`), resolved via
engagement_paths.resolve() exactly like budget.json/work-registry.json/
findings-seen.json -- so a target switch via
`scripts/switch-engagement.sh set <target>` isolates case state the same
way it already isolates everything else, with no new isolation logic
needed.

Evidence bytes are stored content-addressed (SHA-256 filename) in an
`evidence/` directory next to the DB, so identical content written twice
is a no-op (same hash, same file) and evidence can never be silently
mutated after the fact.

Schema, in read order:
  hypotheses  -- Observation -> Hypothesis -> [Test] -> Evidence -> Verdict.
                 status in NEW/TESTING/SUPPORTED/REFUTED/INCONCLUSIVE/CONFIRMED.
  findings    -- status in DISCOVERED/SUSPECTED/VALIDATING/CONFIRMED/
                 IMPACT_PROVEN/REPORTED/FALSE_POSITIVE/DUPLICATE/INCONCLUSIVE.
                 confidence_score is a signal-based sum (see
                 score_finding_confidence), not an LLM self-rating.
  evidence    -- content-addressed, linked to a hypothesis and/or finding.
  experiments -- one row per test run, so check_experiment_exists() can
                 stop an agent repeating an identical test.
  root_causes -- groups multiple findings under one underlying flaw.

update_finding_status() is the one enforcement point: it refuses to move a
finding to CONFIRMED or IMPACT_PROVEN if it has zero linked evidence rows.
That's "no evidence = no confirmed finding" made real instead of a
docstring promise.

suggest_next_action() and group_root_cause()/suggest_root_cause() are
deliberately simple heuristics, not the full expected_value/
information_gain scoring formula sometimes proposed for this kind of
system -- this repo has no instrumentation yet for request cost, novelty,
or measured information gain per test, so a formula using invented numbers
for those inputs would just be confidence theater. The heuristic here
(finish what's already in flight before starting something new; group
findings that already share vuln_class+endpoint prefix) is honest about
what signal actually exists today. Upgrading it to the fuller formula is a
future batch once there's real cost/gain data to score against.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import sys

try:
    import engagement_paths
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import engagement_paths

# Snapshot only, for introspection/backward-compat -- _get_conn() below
# re-resolves this fresh on every call instead of using this frozen value.
DEFAULT_DB_PATH = engagement_paths.resolve("case.db", override_env="HUNTMCP_CASE_DB_PATH")

HYPOTHESIS_STATUSES = {"NEW", "TESTING", "SUPPORTED", "REFUTED", "INCONCLUSIVE", "CONFIRMED"}
FINDING_STATUSES = {
    "DISCOVERED", "SUSPECTED", "VALIDATING", "CONFIRMED", "IMPACT_PROVEN",
    "REPORTED", "FALSE_POSITIVE", "DUPLICATE", "INCONCLUSIVE",
}
EVIDENCE_GATED_STATUSES = {"CONFIRMED", "IMPACT_PROVEN"}
EVIDENCE_TYPES = {"request", "response", "callback", "screenshot", "dns", "source", "metadata"}

CONFIDENCE_BANDS = [(80, "CONFIRMED"), (60, "HIGH"), (30, "MEDIUM"), (0, "LOW")]


def _band_for_score(score: int) -> str:
    for threshold, band in CONFIDENCE_BANDS:
        if score >= threshold:
            return band
    return "LOW"


def _evidence_dir(db_path: str | None = None) -> str:
    # add_evidence() (this function's only caller) now defaults its own
    # db_path to None too -- resolve it here the same way _get_conn() does,
    # or a caller that never passed db_path explicitly would crash on
    # os.path.abspath(None) instead of using the active engagement's dir.
    if db_path is None:
        db_path = engagement_paths.resolve("case.db", override_env="HUNTMCP_CASE_DB_PATH")
    d = os.path.join(os.path.dirname(os.path.abspath(db_path)) or ".", "evidence")
    os.makedirs(d, exist_ok=True)
    return d


def _get_conn(db_path: str | None = None) -> sqlite3.Connection:
    # Re-resolved fresh here on every call when not given explicitly --
    # every other function in this module just passes its own db_path
    # straight through to here unchanged, so this is the single place that
    # needs to know about the None sentinel. NOT a bound
    # `db_path: str = DEFAULT_DB_PATH` parameter default: that's evaluated
    # once at import time and freezes onto whatever active-engagement
    # pointer existed then (confirmed live: this is exactly what caused
    # case.db to land in the repo root during ad hoc testing with no
    # active engagement set) -- see scope_guard.load_engagement's comment
    # for the full story; case_store.py had the identical bug, just missed
    # in the first pass because this module's constant is named
    # DEFAULT_DB_PATH, not DEFAULT_PATH.
    if db_path is None:
        db_path = engagement_paths.resolve("case.db", override_env="HUNTMCP_CASE_DB_PATH")
    os.makedirs(os.path.dirname(os.path.abspath(db_path)) or ".", exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    _init_schema(conn)
    return conn


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS hypotheses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            observation TEXT NOT NULL,
            hypothesis TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'NEW',
            note TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS root_causes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            description TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vuln_class TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            parameter TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'DISCOVERED',
            confidence_score INTEGER NOT NULL DEFAULT 0,
            confidence_band TEXT NOT NULL DEFAULT 'LOW',
            hypothesis_id INTEGER,
            root_cause_id INTEGER,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (hypothesis_id) REFERENCES hypotheses(id) ON DELETE SET NULL,
            FOREIGN KEY (root_cause_id) REFERENCES root_causes(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hypothesis_id INTEGER,
            finding_id INTEGER,
            type TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            content_ref TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (hypothesis_id) REFERENCES hypotheses(id) ON DELETE SET NULL,
            FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS experiments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hypothesis_id INTEGER,
            finding_id INTEGER,
            tool TEXT NOT NULL,
            input TEXT NOT NULL,
            target TEXT NOT NULL,
            result TEXT NOT NULL DEFAULT '',
            cost INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'done',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (hypothesis_id) REFERENCES hypotheses(id) ON DELETE SET NULL,
            FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE SET NULL
        );
    """)


# ---- Hypotheses ----------------------------------------------------------

def log_hypothesis(observation: str, hypothesis: str, db_path: str | None = None) -> dict:
    conn = _get_conn(db_path)
    try:
        cur = conn.execute(
            "INSERT INTO hypotheses (observation, hypothesis) VALUES (?, ?)",
            (observation, hypothesis),
        )
        conn.commit()
        return {"id": cur.lastrowid, "status": "NEW"}
    finally:
        conn.close()


def update_hypothesis(hypothesis_id: int, status: str, note: str = "",
                       db_path: str | None = None) -> dict:
    if status not in HYPOTHESIS_STATUSES:
        return {"error": f"invalid status {status!r}, expected one of {sorted(HYPOTHESIS_STATUSES)}"}
    conn = _get_conn(db_path)
    try:
        row = conn.execute("SELECT id FROM hypotheses WHERE id = ?", (hypothesis_id,)).fetchone()
        if not row:
            return {"error": f"no hypothesis with id {hypothesis_id}"}
        conn.execute(
            "UPDATE hypotheses SET status = ?, note = ?, updated_at = datetime('now') WHERE id = ?",
            (status, note, hypothesis_id),
        )
        conn.commit()
        return {"id": hypothesis_id, "status": status}
    finally:
        conn.close()


# ---- Evidence -------------------------------------------------------------

def add_evidence(type: str, content: str, hypothesis_id: int | None = None,
                  finding_id: int | None = None, db_path: str | None = None) -> dict:
    if type not in EVIDENCE_TYPES:
        return {"error": f"invalid type {type!r}, expected one of {sorted(EVIDENCE_TYPES)}"}
    if hypothesis_id is None and finding_id is None:
        return {"error": "add_evidence needs at least one of hypothesis_id/finding_id"}

    content_bytes = content.encode("utf-8")
    content_hash = hashlib.sha256(content_bytes).hexdigest()
    ev_dir = _evidence_dir(db_path)
    content_ref = os.path.join(ev_dir, content_hash)
    if not os.path.isfile(content_ref):
        with open(content_ref, "wb") as f:
            f.write(content_bytes)

    conn = _get_conn(db_path)
    try:
        cur = conn.execute(
            "INSERT INTO evidence (hypothesis_id, finding_id, type, content_hash, content_ref) "
            "VALUES (?, ?, ?, ?, ?)",
            (hypothesis_id, finding_id, type, content_hash, content_ref),
        )
        conn.commit()
        return {"id": cur.lastrowid, "hash": content_hash}
    finally:
        conn.close()


# ---- Experiments ------------------------------------------------------------

def log_experiment(tool: str, input: str, target: str, result: str = "", cost: int = 0,
                    hypothesis_id: int | None = None, finding_id: int | None = None,
                    status: str = "done", db_path: str | None = None) -> dict:
    conn = _get_conn(db_path)
    try:
        cur = conn.execute(
            "INSERT INTO experiments (hypothesis_id, finding_id, tool, input, target, result, cost, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (hypothesis_id, finding_id, tool, input, target, result, cost, status),
        )
        conn.commit()
        return {"id": cur.lastrowid}
    finally:
        conn.close()


def check_experiment_exists(tool: str, input: str, target: str, db_path: str | None = None) -> bool:
    conn = _get_conn(db_path)
    try:
        row = conn.execute(
            "SELECT 1 FROM experiments WHERE tool = ? AND input = ? AND target = ? LIMIT 1",
            (tool, input, target),
        ).fetchone()
        return row is not None
    finally:
        conn.close()


# ---- Findings ---------------------------------------------------------------

def create_finding(vuln_class: str, endpoint: str, parameter: str = "",
                    hypothesis_id: int | None = None, db_path: str | None = None) -> dict:
    conn = _get_conn(db_path)
    try:
        cur = conn.execute(
            "INSERT INTO findings (vuln_class, endpoint, parameter, hypothesis_id) VALUES (?, ?, ?, ?)",
            (vuln_class, endpoint, parameter, hypothesis_id),
        )
        conn.commit()
        return {"id": cur.lastrowid, "status": "DISCOVERED"}
    finally:
        conn.close()


def update_finding_status(finding_id: int, status: str, db_path: str | None = None) -> dict:
    if status not in FINDING_STATUSES:
        return {"error": f"invalid status {status!r}, expected one of {sorted(FINDING_STATUSES)}"}
    conn = _get_conn(db_path)
    try:
        row = conn.execute("SELECT id FROM findings WHERE id = ?", (finding_id,)).fetchone()
        if not row:
            return {"error": f"no finding with id {finding_id}"}
        if status in EVIDENCE_GATED_STATUSES:
            count = conn.execute(
                "SELECT COUNT(*) AS n FROM evidence WHERE finding_id = ?", (finding_id,)
            ).fetchone()["n"]
            if count == 0:
                return {
                    "error": f"cannot move finding {finding_id} to {status} with zero linked evidence -- "
                             "call add_evidence(type, content, finding_id=...) first"
                }
        conn.execute(
            "UPDATE findings SET status = ?, updated_at = datetime('now') WHERE id = ?",
            (status, finding_id),
        )
        conn.commit()
        return {"id": finding_id, "status": status}
    finally:
        conn.close()


def score_finding_confidence(finding_id: int, signals: dict[str, int],
                              db_path: str | None = None) -> dict:
    """signals is a caller-named {label: points} map, e.g.
    {"endpoint_confirmed": 15, "reproduction": 25, "oob_confirmation": 20} --
    summed and clamped to 0-100, then banded (see CONFIDENCE_BANDS)."""
    non_numeric = {k: v for k, v in signals.items() if not isinstance(v, (int, float))}
    if non_numeric:
        return {"error": f"signals values must be numbers, got {non_numeric!r}"}
    score = max(0, min(100, sum(signals.values())))
    band = _band_for_score(score)
    conn = _get_conn(db_path)
    try:
        row = conn.execute("SELECT id FROM findings WHERE id = ?", (finding_id,)).fetchone()
        if not row:
            return {"error": f"no finding with id {finding_id}"}
        conn.execute(
            "UPDATE findings SET confidence_score = ?, confidence_band = ?, updated_at = datetime('now') "
            "WHERE id = ?",
            (score, band, finding_id),
        )
        conn.commit()
        return {"id": finding_id, "confidence_score": score, "confidence_band": band}
    finally:
        conn.close()


# ---- Root cause -------------------------------------------------------------

def group_root_cause(finding_ids: list[int], description: str, db_path: str | None = None) -> dict:
    if len(finding_ids) < 2:
        return {"error": "group_root_cause needs at least 2 finding_ids -- a single finding doesn't need grouping"}
    conn = _get_conn(db_path)
    try:
        placeholders = ",".join("?" * len(finding_ids))
        rows = conn.execute(f"SELECT id FROM findings WHERE id IN ({placeholders})", finding_ids).fetchall()
        found_ids = {r["id"] for r in rows}
        missing = [fid for fid in finding_ids if fid not in found_ids]
        if missing:
            return {"error": f"no finding(s) with id {missing}"}
        cur = conn.execute("INSERT INTO root_causes (description) VALUES (?)", (description,))
        root_cause_id = cur.lastrowid
        conn.executemany(
            "UPDATE findings SET root_cause_id = ?, updated_at = datetime('now') WHERE id = ?",
            [(root_cause_id, fid) for fid in finding_ids],
        )
        conn.commit()
        return {"root_cause_id": root_cause_id, "grouped_findings": finding_ids}
    finally:
        conn.close()


def suggest_root_cause(db_path: str | None = None) -> str:
    """Heuristic grouping suggestion: findings that already share the same
    vuln_class + endpoint (e.g. IDOR on /api/user and IDOR on /api/user/2)
    and aren't grouped yet are flagged as a likely single root cause. This
    is a simple same-signature heuristic, not semantic root-cause
    inference -- it won't catch "different endpoint, same underlying
    authz-middleware bug" the way a human reviewer would; it just saves
    the obvious groupings from being missed."""
    conn = _get_conn(db_path)
    try:
        rows = conn.execute(
            "SELECT id, vuln_class, endpoint FROM findings WHERE root_cause_id IS NULL "
            "AND status NOT IN ('FALSE_POSITIVE', 'DUPLICATE')"
        ).fetchall()
        groups: dict[str, list[int]] = {}
        for r in rows:
            key = f"{r['vuln_class'].strip().lower()}|{r['endpoint'].strip().lower().split('?')[0]}"
            groups.setdefault(key, []).append(r["id"])
        candidates = {k: v for k, v in groups.items() if len(v) >= 2}
        if not candidates:
            return "No ungrouped findings share a vuln_class+endpoint signature yet."
        lines = ["Suggested root-cause groupings (same vuln_class+endpoint, not yet grouped):"]
        for key, ids in candidates.items():
            lines.append(f"  - {key}: finding ids {ids} -- call group_root_cause({ids}, \"<description>\") to confirm")
        return "\n".join(lines)
    finally:
        conn.close()


# ---- Next best action -------------------------------------------------------

def suggest_next_action(db_path: str | None = None) -> str:
    """Heuristic priority order, cheapest-signal-first (see module
    docstring for why this isn't the full expected_value/information_gain
    formula): 1) hypotheses already TESTING (finish what's in flight before
    starting something new -- abandoning mid-test wastes the experiments
    already logged against it), 2) findings already past DISCOVERED
    (SUSPECTED/VALIDATING/INCONCLUSIVE -- closer to resolution than a fresh
    lead), 3) hypotheses still NEW, 4) findings still at DISCOVERED."""
    conn = _get_conn(db_path)
    try:
        testing = conn.execute(
            "SELECT id, hypothesis FROM hypotheses WHERE status = 'TESTING' ORDER BY updated_at"
        ).fetchall()
        in_progress_findings = conn.execute(
            "SELECT id, vuln_class, endpoint FROM findings WHERE status IN "
            "('SUSPECTED', 'VALIDATING', 'INCONCLUSIVE') ORDER BY updated_at"
        ).fetchall()
        new_hyp = conn.execute(
            "SELECT id, hypothesis FROM hypotheses WHERE status = 'NEW' ORDER BY created_at"
        ).fetchall()
        fresh_findings = conn.execute(
            "SELECT id, vuln_class, endpoint FROM findings WHERE status = 'DISCOVERED' ORDER BY created_at"
        ).fetchall()

        if testing:
            r = testing[0]
            return f"Next: finish hypothesis #{r['id']} (already TESTING) -- \"{r['hypothesis']}\""
        if in_progress_findings:
            r = in_progress_findings[0]
            return f"Next: push finding #{r['id']} ({r['vuln_class']} @ {r['endpoint']}) toward a verdict -- already in progress"
        if new_hyp:
            r = new_hyp[0]
            return f"Next: start testing hypothesis #{r['id']} -- \"{r['hypothesis']}\""
        if fresh_findings:
            r = fresh_findings[0]
            return f"Next: investigate finding #{r['id']} ({r['vuln_class']} @ {r['endpoint']}) -- not yet started"
        return "No open hypotheses or in-progress findings -- nothing queued in the case store right now."
    finally:
        conn.close()


# ---- Summary / export --------------------------------------------------------

def case_summary(db_path: str | None = None) -> str:
    conn = _get_conn(db_path)
    try:
        hyp_counts = conn.execute(
            "SELECT status, COUNT(*) AS n FROM hypotheses GROUP BY status"
        ).fetchall()
        finding_counts = conn.execute(
            "SELECT status, COUNT(*) AS n FROM findings GROUP BY status"
        ).fetchall()
        evidence_n = conn.execute("SELECT COUNT(*) AS n FROM evidence").fetchone()["n"]
        experiment_n = conn.execute("SELECT COUNT(*) AS n FROM experiments").fetchone()["n"]
        root_cause_n = conn.execute("SELECT COUNT(*) AS n FROM root_causes").fetchone()["n"]

        lines = ["Case summary:"]
        lines.append("  Hypotheses: " + (
            ", ".join(f"{r['status']}={r['n']}" for r in hyp_counts) or "none yet"
        ))
        lines.append("  Findings: " + (
            ", ".join(f"{r['status']}={r['n']}" for r in finding_counts) or "none yet"
        ))
        lines.append(f"  Evidence rows: {evidence_n}")
        lines.append(f"  Experiments logged: {experiment_n}")
        lines.append(f"  Root causes grouped: {root_cause_n}")
        return "\n".join(lines)
    finally:
        conn.close()


def case_export(db_path: str | None = None) -> str:
    conn = _get_conn(db_path)
    try:
        def _all(table: str) -> list[dict]:
            return [dict(r) for r in conn.execute(f"SELECT * FROM {table}").fetchall()]

        return json.dumps({
            "hypotheses": _all("hypotheses"),
            "findings": _all("findings"),
            "evidence": _all("evidence"),
            "experiments": _all("experiments"),
            "root_causes": _all("root_causes"),
        }, indent=2)
    finally:
        conn.close()
