"""P4-ESCALATE -- information-value prioritization of human escalations.

The whole point of the mechanism is to spend a human's limited attention on
high-value decisions (reduce approval fatigue), NOT to suppress a required
checkpoint. These tests assert both halves: the advisory ranking does what it
says, AND -- the safety-critical property -- a REQUIRED escalation is ALWAYS
surfaced regardless of its information-value score and can never be scored into
batch/defer.
"""

import os

import case_store
import escalation_value


def _db(tmp_path):
    return str(tmp_path / "case.db")


def _confirmed_finding(db, vuln_class="SQLi", endpoint="/api/x", confidence=0):
    f = case_store.create_finding(vuln_class, endpoint, db_path=db)
    case_store.add_evidence("metadata", "proof", finding_id=f["id"], db_path=db)
    case_store.update_finding_status(f["id"], "CONFIRMED", db_path=db)
    if confidence:
        case_store.score_finding_confidence(f["id"], {"s": confidence}, db_path=db)
    return f["id"]


def _inflight_finding(db, status, vuln_class="XSS", endpoint="/api/y", confidence=0, experiments=0):
    f = case_store.create_finding(vuln_class, endpoint, db_path=db)
    for i in range(experiments):
        case_store.log_experiment("dalfox", f"id={i}", "https://y", result="ran",
                                  finding_id=f["id"], db_path=db)
    if confidence:
        case_store.score_finding_confidence(f["id"], {"s": confidence}, db_path=db)
    case_store.update_finding_status(f["id"], status, db_path=db)
    return f["id"]


# ---- SAFETY: required escalations are NEVER scored away ----------------------

def test_rank_required_candidate_with_zero_info_value_still_surfaces():
    """Safety invariant: a required/safety-bearing escalation is ALWAYS
    surface_now regardless of its information-value score. The whole never-
    suppress guarantee lives in rank_escalations(), so prove it directly with
    an adversarial required candidate scored as low as possible."""
    out = escalation_value.rank_escalations(
        [{"finding_id": 1, "kind": "review_before_submit", "required": True, "info_value": 0}]
    )
    assert out["escalations"][0]["recommendation"] == escalation_value.SURFACE
    assert out["surface_now"] and out["surface_now"][0]["finding_id"] == 1
    assert out["batch"] == [] and out["defer"] == []


def test_rank_required_candidate_surfaces_across_the_whole_score_range():
    """A required candidate must surface for EVERY possible info_value -- there
    must be no score at which a mandatory human checkpoint is batched/deferred."""
    for v in range(101):
        out = escalation_value.rank_escalations(
            [{"finding_id": 7, "kind": "review_before_submit", "required": True, "info_value": v}]
        )
        rec = out["escalations"][0]["recommendation"]
        assert rec == escalation_value.SURFACE, f"required escalation got {rec!r} at info_value={v}"


def test_rank_never_puts_a_required_candidate_in_batch_or_defer():
    """Structural: no required candidate may land in the batch/defer buckets,
    even mixed in with low-value discretionary ones."""
    out = escalation_value.rank_escalations([
        {"finding_id": 1, "required": True, "info_value": 0, "kind": "review_before_submit"},
        {"finding_id": 2, "required": False, "info_value": 0, "kind": "decision"},
        {"finding_id": 3, "required": False, "info_value": 10, "kind": "decision"},
    ])
    assert all(c["required"] is False for c in out["batch"])
    assert all(c["required"] is False for c in out["defer"])
    assert any(c["finding_id"] == 1 for c in out["surface_now"])


def test_end_to_end_confirmed_finding_scoring_zero_still_surfaces(tmp_path):
    """End-to-end safety: a CONFIRMED finding (human-review-before-submit
    checkpoint) engineered to score the LOWEST possible info-value -- no
    confidence, no experiments -- must STILL be surfaced as a required
    escalation, never batched/deferred by the info-value layer."""
    db = _db(tmp_path)
    fid = _confirmed_finding(db, confidence=0)

    out = escalation_value.compute_escalation_value(db_path=db)

    surfaced = {c["finding_id"]: c for c in out["surface_now"]}
    assert fid in surfaced
    c = surfaced[fid]
    assert c["required"] is True
    assert c["kind"] == "review_before_submit"
    assert c["recommendation"] == escalation_value.SURFACE
    # it genuinely scored low -- proving the surface is NOT because of its score
    assert c["info_value"] == 0
    # and it is in no other bucket
    assert all(x["finding_id"] != fid for x in out["batch"])
    assert all(x["finding_id"] != fid for x in out["defer"])


def test_impact_proven_is_also_a_required_review_checkpoint(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("SSRF", "/api/z", db_path=db)
    case_store.add_evidence("metadata", "proof", finding_id=f["id"], db_path=db)
    case_store.update_finding_status(f["id"], "CONFIRMED", db_path=db)
    case_store.update_finding_status(f["id"], "IMPACT_PROVEN", db_path=db)

    out = escalation_value.compute_escalation_value(db_path=db)

    c = next(x for x in out["escalations"] if x["finding_id"] == f["id"])
    assert c["required"] is True
    assert c["recommendation"] == escalation_value.SURFACE


# ---- derivation: which findings are escalations at all ----------------------

def test_discovered_finding_is_not_an_escalation(tmp_path):
    """A fresh DISCOVERED finding is nothing to escalate yet -- no human
    decision is pending."""
    db = _db(tmp_path)
    case_store.create_finding("SQLi", "/api/x", db_path=db)  # stays DISCOVERED
    out = escalation_value.compute_escalation_value(db_path=db)
    assert out["escalations"] == []


def test_reported_finding_is_not_a_pending_review_escalation(tmp_path):
    """REPORTED means the human-review-before-submit checkpoint already
    happened -- it's no longer a pending escalation."""
    db = _db(tmp_path)
    f = case_store.create_finding("SQLi", "/api/x", db_path=db)
    case_store.add_evidence("metadata", "proof", finding_id=f["id"], db_path=db)
    case_store.update_finding_status(f["id"], "CONFIRMED", db_path=db)
    case_store.update_finding_status(f["id"], "IMPACT_PROVEN", db_path=db)
    case_store.update_finding_status(f["id"], "REPORTED", db_path=db)

    out = escalation_value.compute_escalation_value(db_path=db)
    assert all(c["finding_id"] != f["id"] for c in out["escalations"])


def test_dismissed_findings_are_not_escalations(tmp_path):
    db = _db(tmp_path)
    fp = case_store.create_finding("XSS", "/api/a", db_path=db)
    case_store.update_finding_status(fp["id"], "FALSE_POSITIVE", db_path=db)
    dup = case_store.create_finding("XSS", "/api/b", db_path=db)
    case_store.update_finding_status(dup["id"], "DUPLICATE", db_path=db)

    out = escalation_value.compute_escalation_value(db_path=db)
    assert out["escalations"] == []


# ---- info-value scoring of DISCRETIONARY escalations ------------------------

def test_inconclusive_finding_is_a_discretionary_escalation(tmp_path):
    """An INCONCLUSIVE finding is a genuine judgment call (the agent couldn't
    decide) -- a discretionary, scored escalation, not a required one."""
    db = _db(tmp_path)
    fid = _inflight_finding(db, "INCONCLUSIVE", confidence=50, experiments=3)

    out = escalation_value.compute_escalation_value(db_path=db)
    c = next(x for x in out["escalations"] if x["finding_id"] == fid)
    assert c["required"] is False
    assert c["kind"] == "decision"
    assert 0 <= c["info_value"] <= 100


def test_more_prior_experiments_raise_info_value_cheap_options_exhausted(tmp_path):
    """"Would a cheap experiment resolve it instead?" -- two otherwise-identical
    INCONCLUSIVE findings; the one with MORE experiments already run (cheap
    options exhausted) is worth MORE of the human's attention than the one a
    cheap experiment might still resolve."""
    db = _db(tmp_path)
    few = _inflight_finding(db, "INCONCLUSIVE", vuln_class="XSS", endpoint="/few",
                            confidence=40, experiments=0)
    many = _inflight_finding(db, "INCONCLUSIVE", vuln_class="XSS", endpoint="/many",
                             confidence=40, experiments=6)

    out = escalation_value.compute_escalation_value(db_path=db)
    by_id = {c["finding_id"]: c for c in out["escalations"]}
    assert by_id[many]["info_value"] > by_id[few]["info_value"]


def test_low_value_discretionary_escalation_is_batched_or_deferred(tmp_path):
    """A barely-started SUSPECTED finding with no confidence and no experiments
    is low information-value -- it should NOT interrupt the human now."""
    db = _db(tmp_path)
    fid = _inflight_finding(db, "SUSPECTED", confidence=0, experiments=0)

    out = escalation_value.compute_escalation_value(db_path=db)
    c = next(x for x in out["escalations"] if x["finding_id"] == fid)
    assert c["required"] is False
    assert c["recommendation"] in (escalation_value.BATCH, escalation_value.DEFER)
    assert c not in out["surface_now"]


def test_high_value_discretionary_escalation_surfaces(tmp_path):
    """An INCONCLUSIVE finding with high confidence and many exhausted cheap
    experiments is high information-value -- surface it now."""
    db = _db(tmp_path)
    fid = _inflight_finding(db, "INCONCLUSIVE", confidence=100, experiments=6)

    out = escalation_value.compute_escalation_value(db_path=db)
    c = next(x for x in out["escalations"] if x["finding_id"] == fid)
    assert c["recommendation"] == escalation_value.SURFACE


def test_info_value_breakdown_is_auditable(tmp_path):
    """The score is not a black box: each component is returned so a human can
    see WHY something was prioritized."""
    db = _db(tmp_path)
    fid = _inflight_finding(db, "INCONCLUSIVE", confidence=50, experiments=2)
    out = escalation_value.compute_escalation_value(db_path=db)
    c = next(x for x in out["escalations"] if x["finding_id"] == fid)
    bd = c["info_value_breakdown"]
    assert set(bd) >= {"ambiguity", "stakes", "effort_exhausted", "experiment_count"}
    assert bd["experiment_count"] == 2


# ---- ordering --------------------------------------------------------------

def test_required_escalations_are_ranked_first(tmp_path):
    """Required escalations always come before discretionary ones in the
    ranked list, regardless of scores."""
    db = _db(tmp_path)
    disc = _inflight_finding(db, "INCONCLUSIVE", vuln_class="XSS", endpoint="/d",
                             confidence=100, experiments=6)  # very high score
    req = _confirmed_finding(db, vuln_class="SQLi", endpoint="/r", confidence=0)  # score 0

    out = escalation_value.compute_escalation_value(db_path=db)
    ids_in_order = [c["finding_id"] for c in out["escalations"]]
    assert ids_in_order.index(req) < ids_in_order.index(disc)


# ---- no fabrication / empty -------------------------------------------------

def test_empty_case_store_has_no_escalations(tmp_path):
    db = _db(tmp_path)
    case_store.log_hypothesis("obs", "hyp", db_path=db)
    out = escalation_value.compute_escalation_value(db_path=db)
    assert out["escalations"] == []
    assert out["surface_now"] == [] and out["batch"] == [] and out["defer"] == []


def test_never_creates_a_case_db_when_none_exists(tmp_path):
    db = _db(tmp_path)
    assert not os.path.exists(db)
    out = escalation_value.compute_escalation_value(db_path=db)
    assert "error" in out
    assert not os.path.exists(db)


# ---- read-only / redaction --------------------------------------------------

def test_compute_never_mutates_the_case_store(tmp_path):
    db = _db(tmp_path)
    _confirmed_finding(db)
    _inflight_finding(db, "INCONCLUSIVE", vuln_class="XSS", endpoint="/y", experiments=2)
    before = case_store.case_export(db_path=db)
    escalation_value.compute_escalation_value(db_path=db)
    after = case_store.case_export(db_path=db)
    assert before == after


def test_redacts_endpoint_and_vuln_class(tmp_path):
    """endpoint/vuln_class are agent-supplied free text (create_finding takes
    them as plain str, no enum) -- redact before surfacing, same defense-in-
    depth as negative_knowledge.py / coverage_signal.py."""
    fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"  # gitleaks:allow
    db = _db(tmp_path)
    _confirmed_finding(db, vuln_class=fake_jwt, endpoint=f"/x?token={fake_jwt}")

    out = escalation_value.compute_escalation_value(db_path=db)
    blob = str(out)
    assert fake_jwt not in blob


# ---- never blocks / skips anything (advisory only) --------------------------

def test_module_has_no_write_or_tool_calls():
    """Absolute invariant (MASTER-ROADMAP-FINAL-v3.md section 11-A): this layer
    is advisory -- it recommends, it never acts or suppresses. It must have no
    mechanism capable of writing case state, running a tool, or hard-blocking a
    test. Structural proof, same technique as negative_knowledge.py /
    coverage_signal.py / causal_signature.py."""
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "mcp-servers", "escalation_value.py")
    with open(path) as f:
        src = f.read()
    if src.lstrip().startswith('"""'):
        first = src.index('"""')
        second = src.index('"""', first + 3)
        src = src[second + 3:]
    src = "\n".join(line.split("#", 1)[0] for line in src.splitlines())

    forbidden = [
        "log_hypothesis(", "update_hypothesis(", "add_evidence(", "log_experiment(",
        "create_finding(", "update_finding_status(", "score_finding_confidence(",
        "group_root_cause(", "cem_define(", "cem_record_trial(", "cem_record_verdict(",
        "cem_mark_incomplete(", "tool_resolver", "job_runtime", "subprocess", "Popen",
        "scope_guard", "budget_guard", "raise PermissionError", "sys.exit(",
    ]
    for name in forbidden:
        assert name not in src, f"escalation_value.py must not reference {name!r}"
