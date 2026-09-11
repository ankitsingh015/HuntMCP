"""J1 + K1 -- end-to-end CEM integration and benchmark answer-key validation
against the real localhost benchmark target.

Drives the PRODUCTION CEM MCP tools (mcp-servers/case-mcp/server.py) against the
real constructed benchmark HTTP server (tests/fixtures/cem_target/), through the
full frozen control stack -- E3 (CONFIRMED gate) -> UD-4 (read-only method gate)
-> F1 (scope) -> F2 (budget) -> real http_probe.fetch. The network path is NOT
monkeypatched: every request in this module is a real loopback HTTP round-trip
and is corroborated against the target's own independent request log.

J1 (PHASE1-EXECUTION-PLAN.md task J1): prove the six-tool pipeline

    define_conditions -> determinism_gate -> run_counterfactual
        -> minimal_condition_sets -> minimize_poc -> evidence_bundle

runs end to end and produces well-formed output, with real execution-boundary
assertions. The J1 tests do NOT import answer_key.py or evaluator.py; their
verdict-value assertions (only for the two trivial case_01 conditions) come from
the benchmark app's PUBLIC behaviour, not the answer key.

K1 (PHASE1-EXECUTION-PLAN.md task K1 + §8, further down this file): the SYSTEMATIC
per-case comparison of the REAL CEM verdict/label against the protected
evaluator-only answer key, joined through evaluator.py. K1 is *specifically* the
benchmark comparison gate, so its section legitimately imports answer_key.py /
evaluator.py -- expected labels come ONLY from those protected files, observed
labels come ONLY from real CEM execution, and the join happens only at this test
layer (production CEM has no import path to either -- asserted by
`test_k1_blindness_production_has_no_answer_key_path`).

K2 (PHASE1-EXECUTION-PLAN.md task K2 + §9, at the end of this file): the
aggregate false-causal-conclusion rate over the SAME real `k1_results`
CaseConclusions, computed through the protected `evaluator.evaluate()`. Gate:
FCCR == 0 (release gate G5) or the test FAILS. K2 adds no production code and no
benchmark-artifact change. `phase1-report.json` generation (§9 "Reporting") is
task P1, not K2.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from urllib.parse import urlencode

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "cem_target"))

import budget_guard  # noqa: E402  (real per-finding CEM request counter -- F2)
import scenarios  # noqa: E402  (BLIND manifest -- the only benchmark data CEM legitimately sees)
from cem_benchmark_app import CemBenchmarkServer  # noqa: E402

# Load the dash-named case-mcp server module exactly as the other CEM MCP tests do.
_spec = importlib.util.spec_from_file_location(
    "case_mcp_server_j1", os.path.join(ROOT, "mcp-servers", "case-mcp", "server.py"),
)
srv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv)

VALID_VERDICTS = {
    "necessary", "apparently_not_necessary", "inconclusive", "interacting", "probabilistic",
}
# The 15 Triager-Proof Bundle fields assemble_bundle() must always emit (PHASE1-PLAN sec D).
BUNDLE_FIELDS = {
    "finding_id", "original_baseline", "baseline_replication_results", "intervention_matrix",
    "replication_counts", "controlled_pinned_conditions", "observed_confounders",
    "inconclusive_experiments", "identified_necessary_conditions", "minimal_condition_sets",
    "minimized_reproduction_evidence", "complete_audit_trail", "verdict_labels", "controls", "k",
}


# --------------------------------------------------------------------------- #
# Fixtures                                                                     #
# --------------------------------------------------------------------------- #
@pytest.fixture
def bench():
    """A fresh loopback-only benchmark target per test (vulnerable mode)."""
    server = CemBenchmarkServer(mode="vulnerable").start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture
def cem_env(tmp_path, monkeypatch):
    """Per-test isolation of every real side-effecting store the senders touch:
    the case DB, the budget ledger, and the audit log. No engagement.yaml is
    written -- the benchmark target is 127.0.0.1, which scope_guard treats as a
    safe test host that needs no engagement; a non-loopback base_request URL is
    therefore correctly refused (exercised by the F1 test below)."""
    monkeypatch.setenv("HUNTMCP_CASE_DB_PATH", str(tmp_path / "case.db"))
    monkeypatch.setenv("HUNTMCP_BUDGET_PATH", str(tmp_path / "budget.json"))
    monkeypatch.setenv("HUNTMCP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("HUNTMCP_ENGAGEMENT_PATH", str(tmp_path / "no-engagement.yaml"))
    return tmp_path


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #
def _confirmed_finding(vuln_class="IDOR", endpoint="/svc/x"):
    """A finding taken to CONFIRMED through the normal evidence-gated flow, so
    E3 lets CEM operate on it."""
    f = json.loads(srv.create_finding(vuln_class, endpoint))
    srv.add_evidence("request", "GET /svc/x baseline", finding_id=f["id"])
    srv.update_finding_status(f["id"], "CONFIRMED")
    return f["id"]


def _cem_condition_name(request_key: str) -> str:
    """A Phase-1-locatable CEM condition name for a real request key.

    `_perturbation_for` locates a `{"drop": true}` target by matching the
    condition NAME to a header name, a query-param name, or a known auth alias.
    For `Cookie` / `Authorization` we deliberately use the auth-alias name
    (`session_cookie` / `bearer_token`) instead of the literal header: the
    literal is an exact `KNOWN_SECRET_HEADER_NAMES` match, so evidence_bundle's
    redaction pass would redact the *verdict* stored under `{"Cookie": ...}` --
    the alias names are not secret-named and are still located via the alias
    table. Every other key here (`X-Access`, `X-Role`, `trace`, `flag`) is
    locatable as-is and is not secret-named."""
    kl = request_key.lower()
    if kl == "cookie":
        return "session_cookie"
    if kl == "authorization":
        return "bearer_token"
    return request_key


def _translate(server, case_id):
    """Turn a BLIND scenario manifest entry into the production
    define_conditions inputs against `server`'s live base URL.

    header/query conditions: the CEM condition is named via
    `_cem_condition_name(<actual request key>)` so the Phase-1 `{"drop": true}`
    perturbation can locate it; `name_map` records scenario-name -> cem-name for
    a later (K1) join. `path` conditions have no `{"drop": true}` representation
    in Phase-1 and are passed through unchanged so the pipeline's handling of an
    inapplicable perturbation can be exercised.
    """
    sc = scenarios.SCENARIOS[case_id]
    headers: dict[str, str] = {}
    query: dict[str, str] = {}
    conditions: list[dict] = []
    name_map: dict[str, str] = {}

    for cond in sc["conditions"]:
        kind = cond["kind"]
        if kind == "header":
            headers.update({k: str(v) for k, v in cond["baseline"].items()})
            cem_name = _cem_condition_name(next(iter(cond["baseline"])))
        elif kind == "query":
            query.update({k: str(v) for k, v in cond["baseline"].items()})
            cem_name = _cem_condition_name(next(iter(cond["baseline"])))
        else:  # "path" -- no {"drop": true} form in Phase-1
            cem_name = cond["name"]
        assert cem_name not in name_map.values(), (
            f"{case_id}: two conditions map to the CEM name {cem_name!r} -- "
            "define_conditions would create duplicate-named rows and _stored_verdict_map "
            "would collapse them. No current scenario does this; a new one must not."
        )
        name_map[cond["name"]] = cem_name
        conditions.append({
            "name": cem_name,
            "category": kind,
            "baseline_value": json.dumps(cond["baseline"]),
            "perturbation": {"drop": True},
        })

    url = server.base_url + sc["endpoint"]
    if query:
        url += "?" + urlencode(query)

    oracle = dict(sc["oracle"])
    sig: dict = {}
    if oracle.get("status_in") is not None:
        sig["status_in"] = list(oracle["status_in"])
    if oracle.get("body_contains") is not None:
        sig["body_contains"] = oracle["body_contains"]

    base_request = {"method": "GET", "url": url, "headers": headers, "body": None}
    return base_request, sig, conditions, name_map


def _define(fid, base_request, sig, conditions, k=5):
    return json.loads(srv.define_conditions(
        fid, json.dumps(base_request), json.dumps(sig), json.dumps(conditions), k=k,
    ))


def _audit_lines(cem_env):
    p = cem_env / "audit.jsonl"
    if not p.exists():
        return []
    return [json.loads(ln) for ln in p.read_text().splitlines() if ln.strip()]


# --------------------------------------------------------------------------- #
# J1 headline: the whole six-tool pipeline on one representative case          #
# --------------------------------------------------------------------------- #
def test_flow(bench, cem_env):
    """define -> gate -> counterfactual(x2) -> minimal sets -> minimize -> bundle,
    all against the real target, for case_01 (auth cookie + irrelevant trace
    param). This is the test scripts/verify-phase1.sh runs for the integration
    gate (G3)."""
    base_request, sig, conditions, name_map = _translate(bench, "case_01")
    cookie_cond = name_map["session_cookie"]        # -> "session_cookie"
    trace_cond = name_map["trace_param"]            # -> "trace"
    fid = _confirmed_finding("BROKEN_AUTH", "/svc/alpha/{id}")

    # 1. define_conditions
    defined = _define(fid, base_request, sig, conditions, k=5)
    assert "error" not in defined, defined
    assert len(defined["condition_ids"]) == 2
    cid_by_name = dict(zip([c["name"] for c in conditions], defined["condition_ids"]))

    # 2. determinism_gate -- real k=5 unperturbed replication of the base request
    gate = json.loads(srv.determinism_gate(fid, bench.base_url, k=5))
    assert "error" not in gate, gate
    assert gate["determinism_status"] == "STABLE"          # /svc/alpha is deterministic given the cookie
    assert gate["hits"] == [True] * 5
    assert gate["throttled"] is False
    assert len(bench.requests()) == 5                       # execution boundary: 5 real GETs landed
    assert all(r["path"] == "/svc/alpha/42" and r["session"] for r in bench.requests())

    # 3. run_counterfactual for each condition
    verdicts = {}
    for name, cid in cid_by_name.items():
        rc = json.loads(srv.run_counterfactual(fid, bench.base_url, cid, k=5))
        assert "error" not in rc, rc
        assert rc["verdict"] in VALID_VERDICTS
        assert len(rc["baseline_hits"]) == 5 and len(rc["perturbed_hits"]) == 5
        verdicts[name] = rc["verdict"]

    # execution boundary: the target's own log shows a baseline arm (cookie sent)
    # and a perturbed arm (cookie dropped) for the auth-cookie condition.
    log = bench.requests()
    assert any(r["session"] for r in log) and any(not r["session"] for r in log)

    # dropping the auth cookie flips the oracle; dropping the trace param does not.
    assert verdicts[cookie_cond] == "necessary"
    assert verdicts[trace_cond] == "apparently_not_necessary"

    # 4. minimal_condition_sets -- a real `necessary` verdict is recorded, so this
    #    resolves to the 1-minimal set rather than the "nothing necessary" error.
    mcs = json.loads(srv.minimal_condition_sets(fid))
    assert "error" not in mcs, mcs
    assert mcs["minimal_sets"] == [[cookie_cond]]

    # 5. minimize_poc
    mp = json.loads(srv.minimize_poc(fid))
    assert "error" not in mp, mp
    assert mp["poc"] == [cookie_cond]

    # 6. evidence_bundle -- all 15 Triager-Proof Bundle fields, honestly labelled
    bundle = json.loads(srv.evidence_bundle(fid))
    assert "error" not in bundle, bundle
    assert bundle["finding_id"] == fid
    assert BUNDLE_FIELDS.issubset(bundle), sorted(BUNDLE_FIELDS - set(bundle))
    assert bundle["verdict_labels"][cookie_cond] == "necessary"
    assert bundle["verdict_labels"][trace_cond] == "apparently_not_necessary"
    assert bundle["baseline_replication_results"]["status"] == "STABLE"
    assert bundle["incomplete"] is False

    # the whole flow used only locatable, non-secret-named conditions; the blind
    # scenario names are still recoverable via name_map for K1.
    assert set(name_map.values()) == {"session_cookie", "trace"}


# --------------------------------------------------------------------------- #
# The pipeline runs end to end for every header/query scenario shape           #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("case_id", ["case_02", "case_03", "case_04", "case_05", "case_06"])
def test_full_pipeline_runs_end_to_end(bench, cem_env, case_id):
    """Every one of the remaining header/query scenarios survives the full
    six-tool pipeline against the real target: valid JSON at every step, no
    crash, verdicts drawn from the defined vocabulary, real HTTP recorded, and a
    well-formed bundle. Whether a verdict MATCHES ground truth is K1, not J1."""
    base_request, sig, conditions, _ = _translate(bench, case_id)
    fid = _confirmed_finding()

    defined = _define(fid, base_request, sig, conditions, k=5)
    assert "error" not in defined, defined

    gate = json.loads(srv.determinism_gate(fid, bench.base_url, k=5))
    assert "error" not in gate, gate
    assert gate["determinism_status"] in {"STABLE", "NONDETERMINISTIC"}
    assert len(bench.requests()) == 5                          # k real GETs, unperturbed

    for cid in defined["condition_ids"]:
        rc = json.loads(srv.run_counterfactual(fid, bench.base_url, cid, k=5))
        assert "error" not in rc, rc
        assert rc["verdict"] in VALID_VERDICTS
        assert len(rc["baseline_hits"]) == 5 and len(rc["perturbed_hits"]) == 5

    # minimal_condition_sets / minimize_poc either resolve a set (some condition
    # classified `necessary`) or return the documented "nothing necessary yet"
    # error -- both are correct pipeline outcomes, neither is a crash.
    for tool in (srv.minimal_condition_sets, srv.minimize_poc):
        out = json.loads(tool(fid))
        if "error" in out:
            assert "necessary" in out["error"]
        else:
            assert out["finding_id"] == fid

    bundle = json.loads(srv.evidence_bundle(fid))
    assert "error" not in bundle, bundle
    assert BUNDLE_FIELDS.issubset(bundle), sorted(BUNDLE_FIELDS - set(bundle))
    assert bundle["incomplete"] is False
    # every defined condition appears in the intervention matrix with a verdict
    # label drawn from the vocabulary (or "untested" if its arm never classified).
    labels = {row["condition"]: row["verdict"] for row in bundle["intervention_matrix"]}
    assert set(labels) == {c["name"] for c in conditions}
    assert all(v in VALID_VERDICTS | {"untested"} for v in labels.values())

    # execution boundary: exactly one real GET per trial -- k for the gate, plus
    # baseline+perturbed arms (k each) per condition. None of these scenarios
    # return 429, so no arm aborts early.
    assert len(bench.requests()) == 5 + 2 * 5 * len(conditions)


def test_two_condition_case_produces_a_real_minimal_set(bench, cem_env):
    """case_03 (role AND flag) drives minimal_condition_sets over a >1-element
    `necessary` universe -- the ddmin/alternates path, not the degenerate
    single-condition shortcut."""
    base_request, sig, conditions, _ = _translate(bench, "case_03")
    fid = _confirmed_finding("PRIV_ESC", "/svc/charlie")
    defined = _define(fid, base_request, sig, conditions, k=5)
    assert "error" not in defined, defined

    for cid in defined["condition_ids"]:
        rc = json.loads(srv.run_counterfactual(fid, bench.base_url, cid, k=5))
        assert "error" not in rc, rc

    mcs = json.loads(srv.minimal_condition_sets(fid))
    assert "error" not in mcs, mcs
    assert mcs["minimal_sets"]                     # non-empty
    assert all(isinstance(s, list) and s for s in mcs["minimal_sets"])
    mp = json.loads(srv.minimize_poc(fid))
    assert "error" not in mp, mp
    assert mp["poc"]


# --------------------------------------------------------------------------- #
# Known Phase-1 representational limitation (honest, not a workaround)         #
# --------------------------------------------------------------------------- #
def test_path_condition_is_a_clean_phase1_limitation(bench, cem_env):
    """case_07's `target_object_id` is a PATH-segment condition; the Phase-1
    `{"drop": true}` perturbation vocabulary has no way to express it. The
    pipeline must reject that one condition with a clear error (never a crash,
    never a silent no-op that would look `apparently_not_necessary`), while the
    case's header condition still flows through normally.

    Pre-existing merged-code behaviour surfaced here (a note for K1, NOT a J1
    fix): `_perturbation_for` returns a closure that only fails when the first
    perturbed trial runs, so `run_counterfactual` cannot fail fast -- it spends
    the whole baseline arm (k real requests + k budget units) before the
    perturbed arm raises. It still persists no trial and no verdict for that
    condition, so the causal record stays honest."""
    base_request, sig, conditions, name_map = _translate(bench, "case_07")
    fid = _confirmed_finding("IDOR", "/svc/golf/{id}")
    defined = _define(fid, base_request, sig, conditions, k=5)
    assert "error" not in defined, defined
    cid_by_name = dict(zip([c["name"] for c in conditions], defined["condition_ids"]))

    # header condition (session cookie) -> full real run, classifies `necessary`
    rc_cookie = json.loads(
        srv.run_counterfactual(fid, bench.base_url, cid_by_name[name_map["session_cookie"]], k=5))
    assert "error" not in rc_cookie, rc_cookie
    assert rc_cookie["verdict"] == "necessary"

    verdicts_before = {v["condition_id"] for v in srv.case_store.cem_load_state(fid)["verdicts"]}
    reqs_before = len(bench.requests())

    # path condition -> clean error (not a crash, not a silent no-op verdict)
    path_cid = cid_by_name[name_map["target_object_id"]]
    rc_path = json.loads(srv.run_counterfactual(fid, bench.base_url, path_cid, k=5))
    assert "error" in rc_path
    assert "drop" in rc_path["error"]
    assert "verdict" not in rc_path

    # the baseline arm did run (k real GETs), but NO trial or verdict was
    # persisted for the un-perturbable condition -- the record does not gain a
    # phantom result.
    state_after = srv.case_store.cem_load_state(fid)
    assert len(bench.requests()) == reqs_before + 5
    assert {v["condition_id"] for v in state_after["verdicts"]} == verdicts_before
    assert all(t["condition_id"] != path_cid for t in state_after["trials"])


# --------------------------------------------------------------------------- #
# The frozen control stack is genuinely on the real benchmark path            #
# --------------------------------------------------------------------------- #
def test_frozen_control_F1_blocks_out_of_scope_base_request(bench, cem_env):
    """F1: an out-of-scope stored base_request URL is refused before any HTTP,
    even though the sender's `url` argument points at the in-scope benchmark
    host. Proves the scope gate protects the URL actually fetched, on the real
    path the benchmark exercises."""
    base_request, sig, conditions, _ = _translate(bench, "case_01")
    base_request["url"] = "http://attacker.com/svc/alpha/42?trace=1"   # not loopback, no engagement -> OOS
    fid = _confirmed_finding()
    defined = _define(fid, base_request, sig, conditions, k=5)
    assert "error" not in defined, defined

    gate = json.loads(srv.determinism_gate(fid, bench.base_url, k=5))
    assert "error" in gate and "scope" in gate["error"].lower()
    assert bench.requests() == []                                      # nothing left the box

    rc = json.loads(srv.run_counterfactual(fid, bench.base_url, defined["condition_ids"][0], k=5))
    assert "error" in rc and "scope" in rc["error"].lower()
    assert bench.requests() == []


def test_frozen_control_UD4_blocks_non_idempotent_base_method(bench, cem_env):
    """UD-4: CEM is read-only by default. A stored base_request whose method is
    POST is refused before any HTTP -- no per-finding nonidempotent_approval was
    granted. Confirms the read-only gate is on the real benchmark path, not just
    in the dedicated pure-policy tests."""
    base_request, sig, conditions, _ = _translate(bench, "case_01")
    base_request["method"] = "POST"                                   # state-changing, unauthorised
    fid = _confirmed_finding()
    defined = _define(fid, base_request, sig, conditions, k=5)
    assert "error" not in defined, defined

    gate = json.loads(srv.determinism_gate(fid, bench.base_url, k=5))
    assert gate.get("refused") == "nonidempotent_perturbation"
    assert "read-only" in gate["error"]
    assert bench.requests() == []                                     # nothing left the box

    rc = json.loads(srv.run_counterfactual(fid, bench.base_url, defined["condition_ids"][0], k=5))
    assert rc.get("refused") == "nonidempotent_perturbation"
    assert bench.requests() == []


def test_frozen_control_E3_blocks_non_confirmed_finding(bench, cem_env):
    """E3: CEM refuses a finding that has not reached CONFIRMED/IMPACT_PROVEN
    through the normal evidence-gated flow -- no CEM state is created and no
    request is sent."""
    base_request, sig, conditions, _ = _translate(bench, "case_01")
    f = json.loads(srv.create_finding("IDOR", "/svc/alpha/{id}"))   # DISCOVERED, no evidence
    out = _define(f["id"], base_request, sig, conditions, k=5)
    assert "error" in out
    assert "CONFIRMED" in out["error"]
    assert bench.requests() == []


def test_frozen_controls_F2_budget_and_audit_recorded_on_the_real_path(bench, cem_env):
    """F2 + E2: every real CEM request is counted against the per-finding CEM
    ceiling in the real budget.json, and each sender invocation writes exactly
    one audit line -- both verified against the real files, not a spy."""
    base_request, sig, conditions, _ = _translate(bench, "case_01")
    fid = _confirmed_finding()
    defined = _define(fid, base_request, sig, conditions, k=5)

    json.loads(srv.determinism_gate(fid, bench.base_url, k=5))               # 5 requests
    json.loads(srv.run_counterfactual(fid, bench.base_url, defined["condition_ids"][0], k=5))  # +10
    json.loads(srv.run_counterfactual(fid, bench.base_url, defined["condition_ids"][1], k=5))  # +10

    real_requests = len(bench.requests())
    assert real_requests == 25

    used = budget_guard.cem_requests_used(fid, path=str(cem_env / "budget.json"))
    assert used == real_requests                                # F2 per-finding counter == reality

    budget = json.loads((cem_env / "budget.json").read_text())
    assert budget["by_tool"]["case-mcp"] == real_requests       # E2 engagement-wide counter == reality

    lines = _audit_lines(cem_env)
    assert len(lines) == 3                                      # one per sender invocation
    assert all(ln.get("tool") == "case-mcp" for ln in lines)


# ===========================================================================
# K1 -- benchmark answer-key label validation (PHASE1-EXECUTION-PLAN.md K1 / §8)
# ===========================================================================
# K1 IS the benchmark comparison gate, so -- and ONLY here -- the evaluator-only
# answer key and the independent evaluator are imported. Expected labels come
# solely from these protected files; observed labels come solely from real CEM
# execution through the J1 harness above; the join happens only in this test
# layer. Production CEM imports neither (asserted below).
import answer_key as _AK  # noqa: E402  EVALUATOR-ONLY -- legitimate in the K1 gate
import evaluator as _EV  # noqa: E402  independent comparison engine
import integrity as _integrity  # noqa: E402

_FIX_DIR = os.path.join(ROOT, "tests", "fixtures", "cem_target")
_ENV_FILES = {
    "HUNTMCP_CASE_DB_PATH": "case.db",
    "HUNTMCP_BUDGET_PATH": "budget.json",
    "HUNTMCP_AUDIT_LOG": "audit.jsonl",
    "HUNTMCP_ENGAGEMENT_PATH": "no-engagement.yaml",
}

# (case_id, target_mode) pairs K1 evaluates. case_07 is the mutation scenario:
# vulnerable = IDOR reproduces, patched = capability absent.
_K1_ALL = (
    ("case_01", "vulnerable"), ("case_02", "vulnerable"), ("case_03", "vulnerable"),
    ("case_04", "vulnerable"), ("case_05", "vulnerable"), ("case_06", "vulnerable"),
    ("case_07", "vulnerable"), ("case_07", "patched"),
)

# Cases whose REAL CEM label matches the protected answer key -> hard gate.
# case_03 joined this set on 2026-09-09 after an explicit human ruling corrected
# answer_key.py case_03 from {interacting, interacting} to {necessary, necessary}
# (it was internally inconsistent with the C6 addendum, the structurally-identical
# case_07-vulnerable label, and the live engine output -- see
# docs/cem-phase1-k1-decisions.md). CEM production behaviour was NOT changed.
_K1_MATCHING = {
    ("case_01", "vulnerable"), ("case_03", "vulnerable"), ("case_04", "vulnerable"),
    ("case_05", "vulnerable"), ("case_07", "patched"),
}

# Cases whose REAL CEM label does NOT match the answer key. Tracked as
# xfail(strict=True): NOT skipped, NOT hidden, NOT marked pass -- and the suite
# goes RED (XPASS) the moment the capability lands and the boundary should be
# retired. Full source-backed analysis + the two live-predicate experiments:
# docs/cem-phase1-k1-decisions.md.
#
# All three are DEFERRED Phase-2 CAPABILITY BOUNDARIES, not engine defects: the
# `answer_key` labels are CORRECT for a full CEM, and Phase-1's honest outcome
# (inconclusive / apparently_not_necessary / clean per-condition error) is not a
# false causal conclusion. The Phase-2 capabilities themselves are NOT built.
# No production CEM change, no scope expansion, no fabricated evidence.
#   case_02 : MCP-orchestration path -- live combined-condition subset re-trials.
#   case_06 : concurrent race reproduction (controlled parallelism).
#   case_07 : substitution perturbation vocabulary (path-segment / value set).
_K1_KNOWN_GAPS = {
    ("case_02", "vulnerable"): (
        "PHASE-2 BOUNDARY (analysis 2026-09-09) -- live combined-condition subset "
        "re-trials. /svc/bravo = X-Access OR session cookie (independent paths). "
        "One-variable run_counterfactual correctly classifies each "
        "`apparently_not_necessary`. The pure engine function is CAPABLE: "
        "find_alternate_condition_sets given a LIVE k=5 subset-re-trial predicate "
        "reproduces the answer-key STRUCTURE -- minimal_sets [{Cookie},{X-Access}], "
        "both interacting via Rule 2 (docs/cem-phase1-k1-decisions.md Exp 1). The "
        "MCP path still needs: (a) feed S=all present conditions not just "
        "`necessary` ones, (b) a live subset-re-trial predicate replacing the "
        "stored-verdict one (unsound for redundancy patterns; budget-gated, "
        "E2-deferred), (c) promote `apparently_not_necessary`->`interacting` for "
        "flagged conditions. answer_key `interacting` label is CORRECT. Not in the "
        "FCCR denominator. Retire this xfail when live subset re-trials land."
    ),
    # case_03 was here until 2026-09-09: an explicit human ruling corrected the
    # protected answer_key (interacting -> necessary), so case_03 now matches real
    # CEM and lives in _K1_MATCHING as a hard pass. See docs/cem-phase1-k1-decisions.md.
    ("case_06", "vulnerable"): (
        "PHASE-2 BOUNDARY (analysis 2026-09-09) -- controlled parallel race "
        "replication. /svc/foxtrot succeeds only under real concurrency. Phase-1 "
        "Controls hard-locks concurrency==1; run_counterfactual calls classify(), "
        "never classify_race(); no race flag exists. Sequential trials all MISS -> "
        "honest `inconclusive` (NEVER a false necessity; NOT an FCCR hit per sec 9). "
        "A real `probabilistic` verdict needs OBSERVED intermittent success under "
        "controlled parallelism -- classify_race on zero-success sequential data "
        "would be fabricated evidence (hit_rate 0.0) and is explicitly rejected. "
        "answer_key `probabilistic` is CORRECT for a full CEM; the capability is "
        "Phase-2 (XYZ.md sec 2.5.5 / job_runtime.py). See "
        "docs/cem-phase1-k1-decisions.md. Retire this xfail when controlled-"
        "parallelism race replication lands."
    ),
    ("case_07", "vulnerable"): (
        "PHASE-2 BOUNDARY (analysis 2026-09-09) -- substitution perturbation "
        "vocabulary. target_object_id is a path-segment SUBSTITUTION "
        "(/svc/golf/99 victim -> /svc/golf/42 own), not a drop. Phase-1 "
        "_perturbation_for supports only {'drop': true} -> run_counterfactual "
        "returns a clean error for that condition (no phantom verdict, no trial). "
        "session_cookie still classifies `necessary` correctly and case_07/patched "
        "passes. The causal analysis is READY: find_alternate_condition_sets with a "
        "live SUBSTITUTION predicate produces minimal_sets "
        "[{session_cookie,target_object_id}] + AND-group, matching the answer key "
        "(docs/cem-phase1-k1-decisions.md Exp 2). Substitution is core to IDOR "
        "necessity -> a HIGH-priority dedicated Phase-2 task (query/body {'set':...} "
        "+ base_request path template + F3 re-verification per shape), NOT a K1 "
        "bolt-on. answer_key `necessary` label is CORRECT. Retire this xfail when "
        "the substitution vocabulary lands."
    ),
}
assert _K1_MATCHING | set(_K1_KNOWN_GAPS) == set(_K1_ALL), "K1 case partition is incomplete"


def _k1_conclusion(case_id, mode, workdir):
    """Run one (case, mode) through the REAL J1 harness and return
    (evaluator.CaseConclusion, observed_raw). No answer-key value ever touches
    the CEM inputs -- only scenarios.SCENARIOS (the blind manifest) does."""
    server = CemBenchmarkServer(mode=mode).start()
    saved = {k: os.environ.get(k) for k in _ENV_FILES}
    try:
        for env_key, fname in _ENV_FILES.items():
            os.environ[env_key] = os.path.join(workdir, fname)

        base_request, sig, conditions, name_map = _translate(server, case_id)
        cem_to_scenario = {v: k for k, v in name_map.items()}
        fid = _confirmed_finding()
        defined = _define(fid, base_request, sig, conditions, k=5)
        assert "error" not in defined, defined

        gate = json.loads(srv.determinism_gate(fid, server.base_url, k=5))
        det_status = gate.get("determinism_status")

        verdicts, errors = {}, {}
        for cond, cid in zip(conditions, defined["condition_ids"]):
            scen = cem_to_scenario[cond["name"]]
            rc = json.loads(srv.run_counterfactual(fid, server.base_url, cid, k=5))
            if "verdict" in rc:
                verdicts[scen] = rc["verdict"]
            else:
                errors[scen] = rc.get("error", "?")

        mcs = json.loads(srv.minimal_condition_sets(fid))
        raw_sets = mcs.get("minimal_sets") or []
        minimal_sets = tuple(
            tuple(sorted(cem_to_scenario.get(n, n) for n in s)) for s in raw_sets
        )
        bundle = json.loads(srv.evidence_bundle(fid))

        concl = _EV.CaseConclusion(
            verdicts=dict(verdicts),
            determinism_status=det_status,
            minimal_sets=minimal_sets,
            # "the baseline oracle fired at least once" -- the evaluator consumes
            # this ONLY in its capability_absent branch (case_07 patched), where
            # an all-MISS baseline must read as not-reproduced.
            finding_reproduced=any(gate.get("hits") or []),
        )
        observed = {
            "verdicts": dict(verdicts),
            "errors": dict(errors),
            "determinism_status": det_status,
            "gate_hits": gate.get("hits"),
            "minimal_sets": minimal_sets,
            "bundle_identified_necessary": bundle.get("identified_necessary_conditions"),
            "bundle_incomplete": bundle.get("incomplete"),
        }
        return concl, observed
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        server.stop()


@pytest.fixture(scope="module")
def k1_results(tmp_path_factory):
    """Every (case, mode) run ONCE through the real harness. Keyed by
    (case_id, mode) -> (CaseConclusion, observed_raw)."""
    out = {}
    for case_id, mode in _K1_ALL:
        wd = tmp_path_factory.mktemp(f"k1_{case_id}_{mode}")
        out[(case_id, mode)] = _k1_conclusion(case_id, mode, str(wd))
    return out


def _k1_params():
    params = []
    for key in _K1_ALL:
        marks = ()
        if key in _K1_KNOWN_GAPS:
            marks = (pytest.mark.xfail(reason=_K1_KNOWN_GAPS[key], strict=True),)
        params.append(pytest.param(*key, marks=marks, id=f"{key[0]}-{key[1]}"))
    return params


@pytest.mark.parametrize(("case_id", "mode"), _k1_params())
def test_k1_answer_key_labels(k1_results, case_id, mode):
    """The REAL CEM verdict for each condition of each case equals the protected
    answer key, joined by the independent evaluator. Five (case, mode) pairs are
    a hard gate -- including case_03, after the 2026-09-09 human ruling corrected
    its answer_key entry. The three remaining pairs (case_02, case_06,
    case_07-vulnerable) are xfail(strict=True) DEFERRED Phase-2 capability
    boundaries with a source-backed reason -- they fail here on purpose and the
    suite reports XFAIL, not a silent pass."""
    concl, _observed = k1_results[(case_id, mode)]
    report = _EV.evaluate({case_id: concl}, mode=mode)
    pc = report.per_case[case_id]
    if pc.get("capability_absent_expected"):
        assert pc["ok"], f"{case_id}/{mode}: expected capability-absent; {pc}"
    else:
        assert pc["correct"] == pc["scored"], (
            f"{case_id}/{mode}: CEM labels != answer key -- "
            f"expected {pc['verdicts_expected']}, got {pc['verdicts_got']}"
        )
    # evaluator.evaluate() only joins the `verdicts` map; where the answer key
    # ALSO pins a determinism_status (case_04), assert that against CEM too.
    exp_raw = _AK.EXPECTED.get(case_id, {})
    if "determinism_status" in exp_raw:
        assert concl.determinism_status == exp_raw["determinism_status"], (
            f"{case_id}: determinism {concl.determinism_status!r} != answer key "
            f"{exp_raw['determinism_status']!r}"
        )


@pytest.mark.parametrize(("case_id", "mode"), [pytest.param(*k, id=f"{k[0]}-{k[1]}") for k in _K1_ALL])
def test_k1_observed_runtime_behaviour(k1_results, case_id, mode):
    """Pin the REAL CEM behaviour of every case to the K1 root-cause analysis --
    a regression guard that has teeth for the gap cases too (their answer-key
    test only xfails). These assertions describe what CEM *does*, derived from
    the benchmark app's mechanics, not from answer_key.py."""
    concl, obs = k1_results[(case_id, mode)]
    v = concl.verdicts

    if (case_id, mode) == ("case_01", "vulnerable"):
        assert v == {"session_cookie": "necessary", "trace_param": "apparently_not_necessary"}
        assert concl.determinism_status == "STABLE"
        assert concl.minimal_sets == (("session_cookie",),)
    elif (case_id, mode) == ("case_02", "vulnerable"):
        # OR of two sufficient paths -> one-variable-at-a-time sees neither as needed
        assert v == {"x_access_header": "apparently_not_necessary",
                     "session_cookie": "apparently_not_necessary"}
        assert concl.minimal_sets == ()               # no `necessary` cond -> no sets recovered
        assert concl.determinism_status == "STABLE"
    elif (case_id, mode) == ("case_03", "vulnerable"):
        # AND of two gates -> each single removal flips the oracle -> both `necessary`
        assert v == {"role_admin": "necessary", "flag_on": "necessary"}
        assert concl.minimal_sets == (("flag_on", "role_admin"),)   # the size-2 set IS recovered
        assert concl.determinism_status == "STABLE"
    elif (case_id, mode) == ("case_04", "vulnerable"):
        assert v == {"probe_header": "inconclusive"}
        assert concl.determinism_status == "NONDETERMINISTIC"
    elif (case_id, mode) == ("case_05", "vulnerable"):
        assert v == {"probe_header": "inconclusive"}
        assert concl.determinism_status == "NONDETERMINISTIC"
    elif (case_id, mode) == ("case_06", "vulnerable"):
        # sequential executor cannot win the race -> honest inconclusive, never necessity
        assert v == {"probe_header": "inconclusive"}
        assert "necessary" not in v.values()
        assert concl.determinism_status == "NONDETERMINISTIC"
    elif (case_id, mode) == ("case_07", "vulnerable"):
        assert v == {"session_cookie": "necessary"}            # the header half classifies
        assert "target_object_id" in obs["errors"]
        assert "drop" in obs["errors"]["target_object_id"]     # path substitution not expressible
        assert concl.minimal_sets == (("session_cookie",),)
    elif (case_id, mode) == ("case_07", "patched"):
        # capability absent -> baseline oracle never fires -> no necessity emitted
        assert "necessary" not in v.values()
        assert concl.finding_reproduced is False
        assert obs["bundle_identified_necessary"] == []
    else:
        pytest.fail(f"unhandled K1 case {(case_id, mode)}")


@pytest.mark.parametrize(
    ("case_id", "mode"),
    [
        pytest.param("case_01", "vulnerable", id="case_01"),
        pytest.param("case_03", "vulnerable", id="case_03"),
        pytest.param("case_02", "vulnerable", id="case_02",
                     marks=pytest.mark.xfail(reason=_K1_KNOWN_GAPS[("case_02", "vulnerable")], strict=True)),
        pytest.param("case_07", "vulnerable", id="case_07",
                     marks=pytest.mark.xfail(reason=_K1_KNOWN_GAPS[("case_07", "vulnerable")], strict=True)),
    ],
)
def test_k1_minimal_condition_sets_match_answer_key(k1_results, case_id, mode):
    """For the cases whose answer key specifies minimal_sets, the REAL recovered
    sets equal the expected ones. case_01 and case_03 are hard passes; case_02
    (needs >=2 independent sets) and case_07 (needs the path-substitution
    condition) are DEFERRED Phase-2 capability boundaries. case_03 recovers the
    size-2 minimal set {role_admin, flag_on} correctly and -- after the
    2026-09-09 answer_key correction -- also matches on the per-condition
    verdicts (both `necessary`), so it is now a full hard pass here and in
    `test_k1_answer_key_labels`."""
    concl, _obs = k1_results[(case_id, mode)]
    expected = {frozenset(s) for s in _AK.EXPECTED[case_id]["minimal_sets"]}
    got = {frozenset(s) for s in concl.minimal_sets}
    assert got == expected, f"{case_id}: minimal sets {got} != expected {expected}"


def test_k1_no_case_emits_a_false_necessary(k1_results):
    """The scientific-integrity property (per-case; the aggregate rate is K2): NO
    condition is labelled `necessary` where its ground truth is not-necessary.
    This holds for ALL eight (case,mode) pairs -- the three remaining xfail cases
    (case_02, case_06, case_07-vulnerable) are discovery-completeness /
    capability-boundary gaps, not false causal conclusions."""
    offenders = []
    for (cid, mode), (concl, _obs) in k1_results.items():
        exp = _EV._expected_for(cid, mode) or {}
        for cond, got in concl.verdicts.items():
            exp_v = exp.get("verdicts", {}).get(cond)
            # Mirrors evaluator.evaluate()'s own FCCR rule: `interacting`-expected
            # conditions legitimately sit in a minimal set, so `necessary` there
            # is imprecise, not FALSE. Still relevant for case_02 (both conditions
            # `interacting`-expected); the separate explicit check below catches a
            # real case_02 regression to `necessary`.
            if got == "necessary" and exp_v in ("apparently_not_necessary", "inconclusive", "probabilistic"):
                offenders.append(f"{cid}/{cond}: got `necessary`, ground truth {exp_v!r}")
    assert not offenders, "FALSE CAUSAL CONCLUSION(S): " + "; ".join(offenders)

    # case_02 is a special case the evaluator's `interacting` exclusion would let
    # through: /svc/bravo has two INDEPENDENT sufficient paths, so NEITHER
    # condition is necessary -- `necessary` for either would be a genuine false
    # causal conclusion. Assert it directly (today both are apparently_not_necessary).
    for cond, got in k1_results[("case_02", "vulnerable")][0].verdicts.items():
        assert got != "necessary", (
            f"case_02/{cond}: `necessary` for an independently-sufficient path is a "
            "false causal conclusion (the finding still reproduces without it)"
        )


def test_k1_capability_absent_is_recognised_case_07_patched(k1_results):
    """The patched mutation: CEM must NOT emit necessity when the finding no
    longer reproduces. The determinism gate on the all-MISS baseline is what
    catches it."""
    concl, _obs = k1_results[("case_07", "patched")]
    pc = _EV.evaluate({"case_07": concl}, mode="patched").per_case["case_07"]
    assert pc["capability_absent_expected"] is True
    assert pc["ok"] is True
    assert pc["emitted_necessary"] == []


def test_k1_comparison_is_not_tautological(k1_results):
    """Prove the answer-key join has teeth: flipping one captured observed verdict
    for a currently-passing case makes the evaluator report it as incorrect."""
    concl, _obs = k1_results[("case_01", "vulnerable")]
    clean = _EV.evaluate({"case_01": concl}).per_case["case_01"]
    assert clean["correct"] == clean["scored"] == 2

    mutated = _EV.CaseConclusion(
        verdicts={**concl.verdicts, "session_cookie": "inconclusive"},  # flip necessary -> inconclusive
        determinism_status=concl.determinism_status,
        minimal_sets=concl.minimal_sets,
        finding_reproduced=concl.finding_reproduced,
    )
    dirty = _EV.evaluate({"case_01": mutated}).per_case["case_01"]
    assert dirty["correct"] < dirty["scored"], "evaluator failed to detect a flipped verdict"


def test_k1_blindness_production_has_no_answer_key_path():
    """Blindness invariant: no production module under mcp-servers/ can import
    the answer key or any evaluator-only fixture -- CEM must never see the
    expected labels."""
    import pathlib

    base = pathlib.Path(ROOT, "mcp-servers")
    py_files = list(base.rglob("*.py"))
    assert py_files, "no production python files found -- path wrong?"
    offenders = []
    for p in py_files:
        text = p.read_text()
        for needle in ("answer_key", "cem_target", "fixtures.cem_target", "import evaluator"):
            if needle in text:
                offenders.append(f"{p.relative_to(base)} contains {needle!r}")
    assert not offenders, "PRODUCTION CODE REFERENCES BENCHMARK ANSWERS: " + "; ".join(offenders)


def test_k1_benchmark_integrity_locks_unchanged():
    """The protected benchmark artifacts are byte-identical to their locks --
    checked here so a K1 run cannot have quietly mutated them."""
    for name in ("scenarios.py", "answer_key.py"):
        ok, msg = _integrity.verify(os.path.join(_FIX_DIR, name))
        assert ok, msg


# ===========================================================================
# K2 -- aggregate false-causal-conclusion rate (PHASE1-EXECUTION-PLAN.md K2 / §9)
# ===========================================================================
# K2 spec (verbatim): "Compute + assert false-causal-conclusion-rate == 0 (§9).
#   | dep K1 | file test_cem_benchmark.py | verify: pytest | accept: FCCR==0 or
#   test FAILS."  §9: numerator = conditions whose ground truth is not-necessary
# (planted apparently_not_necessary / flaky / cached-confounder / race) that CEM
# labelled `necessary`; denominator = all conditions with a not-necessary ground
# truth; `inconclusive` is NEVER a false conclusion; `probabilistic` (race) is
# NEVER a necessity claim. Release gate G5 requires fccr == 0.
#
# K2 adds NO production code and NO benchmark-artifact change: `evaluator.evaluate`
# (the protected, independent comparison engine) already computes fccr /
# fccr_numerator / fccr_denominator per §9, keyed off the protected
# `answer_key.MUST_NOT_BE_NECESSARY_CASES` + `APPARENTLY_NOT_NECESSARY_CONDITIONS`
# + the capability_absent branch. K2 just drives it across the REAL CaseConclusions
# K1 already produced (`k1_results` -- real MCP tools, real http_probe.fetch, no
# monkeypatch) and asserts the aggregate is zero.
#
# `phase1-report.json` (§9 "Reporting" / §7 step 13 / §14) is produced by
# scripts/verify-phase1.sh -- that is task P1, NOT K2. K2's deliverable per its
# own line is this pytest assertion.

_K2_VULN_CASES = ("case_01", "case_02", "case_03", "case_04", "case_05", "case_06", "case_07")


def _k2_aggregate_fccr(k1_results):
    """Evaluate the REAL K1 CaseConclusions through the protected evaluator across
    BOTH target modes and aggregate the §9 numerator/denominator.

    Returns (fccr, numerator, denominator, per_case) where per_case merges the two
    evaluator reports' per-case dicts (case_07 appears once per mode, suffixed).
    """
    vuln = _EV.evaluate(
        {cid: k1_results[(cid, "vulnerable")][0] for cid in _K2_VULN_CASES},
        mode="vulnerable",
    )
    patched = _EV.evaluate(
        {"case_07": k1_results[("case_07", "patched")][0]},
        mode="patched",
    )
    num = vuln.fccr_numerator + patched.fccr_numerator
    den = vuln.fccr_denominator + patched.fccr_denominator
    fccr = (num / den) if den else 0.0
    per_case = {f"{k}/vulnerable": v for k, v in vuln.per_case.items()}
    per_case.update({f"{k}/patched": v for k, v in patched.per_case.items()})
    return fccr, num, den, per_case


def test_k2_false_causal_conclusion_rate_is_zero(k1_results):
    """G5 / K2 gate: the aggregate false-causal-conclusion rate over the REAL CEM
    benchmark run is exactly zero. FCCR == 0 or this test FAILS.

    Also pins the §9 denominator (4: case_01/trace_param + case_04 + case_05 +
    case_06) so the gate can never pass vacuously (0/0) and so a silent change to
    any FCCR-relevant ground truth is caught here too. The per-case verdict table
    is printed (captured by default; shown with -s or on failure) as the §9
    per-case record -- phase1-report.json generation is task P1, not K2."""
    fccr, num, den, per_case = _k2_aggregate_fccr(k1_results)

    print(f"\nK2 false-causal-conclusion rate (real CEM benchmark run): {num}/{den} = {fccr}")
    for name in sorted(per_case):
        pc = per_case[name]
        if "verdicts_expected" in pc:
            print(f"  {name}: expected={dict(pc['verdicts_expected'])} got={pc['verdicts_got']}")
        else:
            print(f"  {name}: {pc}")

    # The gate first (clearest signal on a real regression), structural sanity last.
    assert num == 0, (
        "FALSE CAUSAL CONCLUSION(S) on the benchmark -- CEM emitted `necessary` for "
        f"a not-necessary condition. fccr numerator = {num}. per-case: {per_case}"
    )
    assert fccr == 0.0, f"FCCR must be 0 (release gate G5); got {fccr}"
    # §9 denominator = 4 (case_01/trace_param + case_04 + case_05 + case_06). Pins
    # non-vacuity (never 0/0) and catches a silent FCCR-relevant ground-truth move.
    # A value of 5 means the capability_absent branch fired -> case_07-patched
    # wrongly emitted necessity (num assert above already caught it).
    assert den == 4, (
        f"§9 FCCR denominator is {den}, expected 4 -- an FCCR-relevant ground truth "
        "moved, or case_07-patched emitted necessity (see the num assertion)"
    )


def test_k2_fccr_gate_detects_a_false_necessary(k1_results):
    """Non-tautology / mutation check: prove the K2 gate -- INCLUDING the
    `_k2_aggregate_fccr` two-mode aggregation -- would FAIL for the wrong
    behaviour. Real runs are untouched; the mutations are synthetic copies."""
    # (a) protected evaluator: a flaky case (gt `inconclusive`) labelled `necessary`.
    real_c4, _obs = k1_results[("case_04", "vulnerable")]
    assert real_c4.verdicts == {"probe_header": "inconclusive"}, real_c4.verdicts  # real run is honest
    mutated_c4 = _EV.CaseConclusion(
        verdicts={"probe_header": "necessary"},          # <- the false causal conclusion
        determinism_status=real_c4.determinism_status,
        minimal_sets=real_c4.minimal_sets,
        finding_reproduced=real_c4.finding_reproduced,
    )
    r = _EV.evaluate({"case_04": mutated_c4}, mode="vulnerable")
    assert r.fccr_numerator >= 1 and r.fccr > 0.0, (
        "evaluator did not count a flaky case labelled `necessary` as a false "
        f"causal conclusion (fccr={r.fccr})"
    )

    # (b) protected evaluator: emitting necessity on a patched (capability-absent) target.
    bad_patched = _EV.CaseConclusion(verdicts={"session_cookie": "necessary"}, finding_reproduced=True)
    rp = _EV.evaluate({"case_07": bad_patched}, mode="patched")
    assert rp.fccr_numerator >= 1 and rp.fccr > 0.0, (
        f"evaluator misses a patched-target necessity claim (fccr={rp.fccr})"
    )

    # (c) the K2 aggregation itself: feed `_k2_aggregate_fccr` a k1_results-shaped
    # dict with ONLY case_04 flipped -> the aggregate FCCR must go non-zero, i.e.
    # `test_k2_false_causal_conclusion_rate_is_zero` would FAIL. This exercises the
    # two-mode sum, not just evaluate().
    poisoned = dict(k1_results)
    poisoned[("case_04", "vulnerable")] = (mutated_c4, {})
    fccr, num, den, _pc = _k2_aggregate_fccr(poisoned)
    assert num >= 1 and fccr > 0.0 and den == 4, (
        f"_k2_aggregate_fccr did not propagate a false `necessary` "
        f"(fccr={num}/{den}={fccr}) -- the K2 gate would be vacuous"
    )
