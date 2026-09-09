"""Phase-1 CEM case-store tests (PHASE1-EXECUTION-PLAN.md tasks B1 + B3).

The B1 section recovers the 4 CEM tables (`cem_meta`, `cem_conditions`,
`cem_trials`, `cem_verdicts`) into `case_store._init_schema()` and pins the
schema contract those tables must satisfy, per PHASE1-EXECUTION-PLAN.md
section 4. On a branch without the schema every B1 test is RED -- the intended
TDD order is: add this file, watch it fail, then add the CREATE TABLE
statements. B1 covers: do the 4 tables exist with the right columns/PK, are
their FKs to findings(id) declared ON DELETE CASCADE (schema-level, read from
PRAGMA foreign_key_list, not runtime-triggered), and do two different
engagements' case.db files never share CEM rows.

The CRUD helpers `cem_define` / `cem_record_trial` / `cem_record_verdict` /
`cem_load_state` themselves are task B2 (defined in case_store.py). The B3
section appended below exercises the runtime cascade-delete effect (an actual
DELETE FROM findings really wipes every dependent CEM row) and deeper
cross-engagement isolation, driving those helpers as its vehicle.

Isolation pattern follows the one already used throughout tests/test_case_store.py:
every case_store function takes an explicit db_path, so two different db_path
values are, by construction, two different engagements' case.db -- the exact
mechanism case_store already uses in production via engagement_paths.resolve(),
just made explicit for the test (no engagement_paths monkeypatching needed,
consistent with how test_case_store.py itself tests isolation).
"""
import case_store
import pytest


def _db(tmp_path, name="case.db"):
    return str(tmp_path / name)


def _table_names(db_path):
    conn = case_store._get_conn(db_path)
    try:
        rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        return {r["name"] for r in rows}
    finally:
        conn.close()


def _table_columns(db_path, table):
    conn = case_store._get_conn(db_path)
    try:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
        return {r["name"] for r in rows}
    finally:
        conn.close()


def _pk_columns(db_path, table):
    conn = case_store._get_conn(db_path)
    try:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
        return {r["name"] for r in rows if r["pk"]}
    finally:
        conn.close()


def _fk_targets_findings_cascade(db_path, table):
    """True iff `table` has a foreign key to findings(id) declared ON DELETE CASCADE."""
    conn = case_store._get_conn(db_path)
    try:
        rows = conn.execute(f"PRAGMA foreign_key_list({table})").fetchall()
        return any(
            r["table"] == "findings" and r["from"] == "finding_id" and r["on_delete"] == "CASCADE"
            for r in rows
        )
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# The 4 CEM tables exist (PHASE1-EXECUTION-PLAN.md section 4)
# ---------------------------------------------------------------------------

def test_cem_meta_table_created(tmp_path):
    assert "cem_meta" in _table_names(_db(tmp_path))


def test_cem_conditions_table_created(tmp_path):
    assert "cem_conditions" in _table_names(_db(tmp_path))


def test_cem_trials_table_created(tmp_path):
    assert "cem_trials" in _table_names(_db(tmp_path))


def test_cem_verdicts_table_created(tmp_path):
    assert "cem_verdicts" in _table_names(_db(tmp_path))


# ---------------------------------------------------------------------------
# Columns match the documented schema exactly
# ---------------------------------------------------------------------------

def test_cem_meta_columns(tmp_path):
    db = _db(tmp_path)
    assert _table_columns(db, "cem_meta") == {
        "finding_id", "base_request", "success_signature",
        "determinism_status", "cem_status", "k", "incomplete",
        "nonidempotent_approval",   # F3b/UD-4: nullable state-change authorization
    }


def test_cem_meta_primary_key_is_finding_id(tmp_path):
    # cem_meta is one row per finding -- finding_id itself is the PK (unlike the other
    # 3 CEM tables, which have their own autoincrement `id`).
    db = _db(tmp_path)
    assert _pk_columns(db, "cem_meta") == {"finding_id"}


def test_cem_conditions_columns(tmp_path):
    db = _db(tmp_path)
    assert _table_columns(db, "cem_conditions") == {
        "id", "finding_id", "name", "category", "baseline_value", "perturbation",
    }


def test_cem_conditions_primary_key_is_id(tmp_path):
    db = _db(tmp_path)
    assert _pk_columns(db, "cem_conditions") == {"id"}


def test_cem_trials_columns(tmp_path):
    db = _db(tmp_path)
    assert _table_columns(db, "cem_trials") == {
        "id", "finding_id", "condition_id", "arm", "k_index", "http_status",
        "oracle_hit", "request_evidence_hash", "response_evidence_hash",
        "controls", "created_at",
    }


def test_cem_trials_primary_key_is_id(tmp_path):
    db = _db(tmp_path)
    assert _pk_columns(db, "cem_trials") == {"id"}


def test_cem_verdicts_columns(tmp_path):
    db = _db(tmp_path)
    assert _table_columns(db, "cem_verdicts") == {
        "id", "finding_id", "condition_id", "verdict", "k", "controls",
        "detail", "created_at",
    }


def test_cem_verdicts_primary_key_is_id(tmp_path):
    db = _db(tmp_path)
    assert _pk_columns(db, "cem_verdicts") == {"id"}


# ---------------------------------------------------------------------------
# Defaults from PHASE1-EXECUTION-PLAN.md section 4
# ---------------------------------------------------------------------------

def test_cem_meta_defaults(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("IDOR", "/api/orders/{id}", db_path=db)
    conn = case_store._get_conn(db)
    try:
        conn.execute(
            "INSERT INTO cem_meta (finding_id, base_request, success_signature) VALUES (?, ?, ?)",
            (f["id"], "{}", "{}"),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM cem_meta WHERE finding_id = ?", (f["id"],)).fetchone()
    finally:
        conn.close()
    assert row["determinism_status"] == "UNTESTED"
    assert row["cem_status"] == "DEFINED"
    assert row["k"] == 5
    assert row["incomplete"] == 0


# ---------------------------------------------------------------------------
# All 4 tables declare an ON DELETE CASCADE FK to findings(id) (schema-level only --
# actually exercising the cascade is task B3's job, not B1's).
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("table", ["cem_meta", "cem_conditions", "cem_trials", "cem_verdicts"])
def test_fk_to_findings_declared_on_delete_cascade(tmp_path, table):
    db = _db(tmp_path)
    assert _fk_targets_findings_cascade(db, table)


# ---------------------------------------------------------------------------
# Per-engagement isolation: two different case.db files never share CEM rows
# ---------------------------------------------------------------------------

def test_cem_tables_isolated_per_engagement(tmp_path):
    db_a = _db(tmp_path, "engagement_a/case.db")
    db_b = _db(tmp_path, "engagement_b/case.db")

    f_a = case_store.create_finding("IDOR", "/api/orders/{id}", db_path=db_a)
    conn_a = case_store._get_conn(db_a)
    try:
        conn_a.execute(
            "INSERT INTO cem_meta (finding_id, base_request, success_signature) VALUES (?, ?, ?)",
            (f_a["id"], "{}", "{}"),
        )
        conn_a.commit()
    finally:
        conn_a.close()

    # engagement B's case.db never saw engagement A's finding or CEM row.
    conn_b = case_store._get_conn(db_b)
    try:
        assert conn_b.execute("SELECT * FROM findings").fetchall() == []
        assert conn_b.execute("SELECT * FROM cem_meta").fetchall() == []
    finally:
        conn_b.close()

    # engagement A's own row is still there, unaffected by touching engagement B.
    conn_a2 = case_store._get_conn(db_a)
    try:
        rows = conn_a2.execute("SELECT * FROM cem_meta WHERE finding_id = ?", (f_a["id"],)).fetchall()
    finally:
        conn_a2.close()
    assert len(rows) == 1


def test_cem_conditions_isolated_per_engagement(tmp_path):
    db_a = _db(tmp_path, "engagement_a/case.db")
    db_b = _db(tmp_path, "engagement_b/case.db")

    f_a = case_store.create_finding("IDOR", "/api/orders/{id}", db_path=db_a)
    conn_a = case_store._get_conn(db_a)
    try:
        conn_a.execute(
            "INSERT INTO cem_conditions (finding_id, name, category, baseline_value, perturbation) "
            "VALUES (?, ?, ?, ?, ?)",
            (f_a["id"], "auth_cookie", "identity", "present", '{"drop": true}'),
        )
        conn_a.commit()
    finally:
        conn_a.close()

    conn_b = case_store._get_conn(db_b)
    try:
        assert conn_b.execute("SELECT * FROM cem_conditions").fetchall() == []
    finally:
        conn_b.close()


# ---------------------------------------------------------------------------
# Task B3: cascade-delete on finding removal.
#
# B1 already proved (schema-level, via PRAGMA foreign_key_list) that all 4 CEM
# tables declare finding_id -> findings(id) ON DELETE CASCADE. This section
# proves the runtime effect: an actual DELETE FROM findings really does wipe
# every dependent CEM row, through the public CRUD helpers wherever practical.
# ---------------------------------------------------------------------------

def _full_cem_state(db_path, endpoint="/api/orders/{id}"):
    """Build one finding with the full CEM row shape -- one condition, one
    baseline trial, one perturbed trial, one verdict -- entirely through the
    public cem_define/cem_record_trial/cem_record_verdict helpers (no raw
    SQL), so these tests exercise B2's real CRUD surface, not just schema."""
    f = case_store.create_finding("IDOR", endpoint, db_path=db_path)
    defined = case_store.cem_define(
        f["id"],
        {"method": "GET", "url": f"https://t{endpoint}", "headers": {}, "body": None},
        {"status_in": [200], "body_contains": "total"},
        [{"name": "auth_cookie", "category": "identity", "baseline_value": "present",
          "perturbation": {"drop": True}}],
        db_path=db_path,
    )
    assert "error" not in defined, defined
    condition_id = defined["condition_ids"][0]

    t1 = case_store.cem_record_trial(f["id"], "baseline", 0, True, db_path=db_path)
    assert "error" not in t1, t1
    t2 = case_store.cem_record_trial(
        f["id"], "perturbed", 0, False, condition_id=condition_id, http_status=403, db_path=db_path,
    )
    assert "error" not in t2, t2

    v = case_store.cem_record_verdict(
        f["id"], "necessary", 5, {"cache_buster": True}, condition_id=condition_id,
        detail="killed on perturb", db_path=db_path,
    )
    assert "error" not in v, v
    return f["id"], condition_id


def _cem_row_counts(db_path, finding_id):
    # No public per-table reader exists (cem_load_state early-returns as soon
    # as cem_meta is gone, so it alone can't distinguish "everything cascaded"
    # from "meta gone but trials/verdicts orphaned"). Same rationale as B1's
    # direct-SQL schema checks: go around the CRUD layer only where there's
    # genuinely no public accessor for what's being proven.
    conn = case_store._get_conn(db_path)
    try:
        return {
            table: conn.execute(
                f"SELECT COUNT(*) AS n FROM {table} WHERE finding_id = ?", (finding_id,)
            ).fetchone()["n"]
            for table in ("cem_meta", "cem_conditions", "cem_trials", "cem_verdicts")
        }
    finally:
        conn.close()


def _delete_finding(db_path, finding_id):
    """No public case_store delete-finding API exists yet -- adding one is
    out of B3's scope (the plan's own file column for B3 lists only
    test_cem_case_store.py, no case_store.py change). Deletes through
    _get_conn() so PRAGMA foreign_keys=ON is in effect, same as every other
    connection in this module, and the declared ON DELETE CASCADE FKs fire."""
    conn = case_store._get_conn(db_path)
    try:
        conn.execute("DELETE FROM findings WHERE id = ?", (finding_id,))
        conn.commit()
    finally:
        conn.close()


def test_deleting_finding_cascades_all_four_cem_tables(tmp_path):
    db = _db(tmp_path)
    finding_id, _ = _full_cem_state(db)

    # sanity: the full state is really there before deleting (public interface)
    state = case_store.cem_load_state(finding_id, db_path=db)
    assert "error" not in state, state
    assert len(state["conditions"]) == 1
    assert len(state["trials"]) == 2
    assert len(state["verdicts"]) == 1

    _delete_finding(db, finding_id)

    # public interface: no CEM state is loadable for the deleted finding any more
    after = case_store.cem_load_state(finding_id, db_path=db)
    assert "error" in after, after

    # per-table proof that ALL FOUR tables actually cascaded, not just cem_meta
    counts = _cem_row_counts(db, finding_id)
    assert counts == {"cem_meta": 0, "cem_conditions": 0, "cem_trials": 0, "cem_verdicts": 0}, counts


def test_deleting_finding_leaves_sibling_finding_and_its_cem_state_intact(tmp_path):
    db = _db(tmp_path)
    victim_id, _ = _full_cem_state(db, endpoint="/api/orders/{id}")
    survivor_id, survivor_condition_id = _full_cem_state(db, endpoint="/api/invoices/{id}")

    _delete_finding(db, victim_id)

    survivor_state = case_store.cem_load_state(survivor_id, db_path=db)
    assert "error" not in survivor_state, survivor_state
    assert len(survivor_state["conditions"]) == 1
    assert survivor_state["conditions"][0]["id"] == survivor_condition_id
    assert len(survivor_state["trials"]) == 2
    assert len(survivor_state["verdicts"]) == 1
    assert survivor_state["verdicts"][0]["verdict"] == "necessary"


def test_deleting_finding_with_no_cem_state_does_not_error(tmp_path):
    # A plain finding that never went through cem_define -- cascading zero
    # CEM rows must behave the same as the CEM-having case, not raise.
    db = _db(tmp_path)
    f = case_store.create_finding("XSS", "/search", db_path=db)
    _delete_finding(db, f["id"])
    conn = case_store._get_conn(db)
    try:
        assert conn.execute("SELECT * FROM findings WHERE id = ?", (f["id"],)).fetchall() == []
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Task B3: deeper per-engagement isolation.
#
# B1 already proved schema-level isolation for two of the four tables via raw
# inserts. This section exercises ALL FOUR public CRUD helpers (cem_define,
# cem_record_trial, cem_record_verdict, cem_load_state) across two
# engagements -- including the case where both engagements independently
# assign the SAME finding id (their own per-engagement autoincrement
# sequences both start at 1), which is the actual isolation risk worth
# proving -- and confirms a delete in one never reaches the other.
# ---------------------------------------------------------------------------

def test_cem_load_state_never_mixes_engagements_even_with_same_finding_id(tmp_path):
    db_a = _db(tmp_path, "engagement_a/case.db")
    db_b = _db(tmp_path, "engagement_b/case.db")

    finding_id_a, _ = _full_cem_state(db_a, endpoint="/api/orders/{id}")
    finding_id_b, _ = _full_cem_state(db_b, endpoint="/api/invoices/{id}")
    assert finding_id_a == finding_id_b == 1

    state_a = case_store.cem_load_state(finding_id_a, db_path=db_a)
    state_b = case_store.cem_load_state(finding_id_b, db_path=db_b)

    assert state_a["meta"]["base_request"]["url"] != state_b["meta"]["base_request"]["url"]
    assert state_a["meta"]["base_request"]["url"] == "https://t/api/orders/{id}"
    assert state_b["meta"]["base_request"]["url"] == "https://t/api/invoices/{id}"

    conn_a = case_store._get_conn(db_a)
    try:
        assert conn_a.execute("SELECT COUNT(*) AS n FROM cem_trials").fetchone()["n"] == 2
        assert conn_a.execute("SELECT COUNT(*) AS n FROM cem_verdicts").fetchone()["n"] == 1
    finally:
        conn_a.close()


def test_cem_record_trial_and_verdict_never_cross_engagements(tmp_path):
    db_a = _db(tmp_path, "engagement_a/case.db")
    db_b = _db(tmp_path, "engagement_b/case.db")

    finding_id_a, _ = _full_cem_state(db_a)
    # engagement B's case.db has no findings at all -- attempting to record a
    # trial/verdict for A's finding id against B's db must be rejected, never
    # silently create/attach cross-engagement rows.
    r = case_store.cem_record_trial(finding_id_a, "baseline", 99, True, db_path=db_b)
    assert "error" in r, r
    r2 = case_store.cem_record_verdict(finding_id_a, "necessary", 5, {}, db_path=db_b)
    assert "error" in r2, r2

    # engagement A is completely unaffected by the rejected attempts against B
    state_a = case_store.cem_load_state(finding_id_a, db_path=db_a)
    assert len(state_a["trials"]) == 2
    assert len(state_a["verdicts"]) == 1


def test_deleting_finding_in_one_engagement_does_not_affect_the_other(tmp_path):
    db_a = _db(tmp_path, "engagement_a/case.db")
    db_b = _db(tmp_path, "engagement_b/case.db")

    finding_id_a, _ = _full_cem_state(db_a)
    finding_id_b, _ = _full_cem_state(db_b)
    assert finding_id_a == finding_id_b == 1

    _delete_finding(db_a, finding_id_a)

    # A's CEM state is gone
    assert "error" in case_store.cem_load_state(finding_id_a, db_path=db_a)
    # B's equal-numbered finding and its full CEM state are completely untouched
    state_b = case_store.cem_load_state(finding_id_b, db_path=db_b)
    assert "error" not in state_b, state_b
    assert len(state_b["conditions"]) == 1
    assert len(state_b["trials"]) == 2
    assert len(state_b["verdicts"]) == 1
