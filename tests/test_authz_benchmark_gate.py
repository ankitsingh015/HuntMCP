"""P3-VALAUTHZ acceptance gate (tracker §10): on the protected authz_target range,
authz_diff must recover the multi-step authorization flaw the single-id sweep cannot
reach, at ZERO false positives, with verdicts matching the evaluator-only ground truth,
reproducibly -- and the existing sweep's own false positives on the look-alike cases are
recorded as the reason the stricter oracle exists. Nothing here reads authz_answer_key
except through authz_evaluator (benchmarks.md: independent evaluation)."""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "idor-mcp"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "authz_target"))

import authz_diff  # noqa: E402
import idor_sweep  # noqa: E402
from authz_app import ALICE, BOB, CAROL, AuthzApp  # noqa: E402
from authz_app import ROOT as ADMIN  # noqa: E402
from authz_evaluator import ObservedFinding, evaluate  # noqa: E402

OWNER = {"Authorization": f"Bearer {ALICE}"}
OTHER = {"Authorization": f"Bearer {BOB}"}

# (carried key in /authz/refs, step-2 path) -- what a hunter derives from the DISC-SPEC
# endpoint model + an observed step-1 response; NOT read from the answer key.
WORKFLOWS = [
    ("cart_ref", "/authz/carts/{carried}/invoice"),
    ("order_id", "/authz/orders/{carried}"),
    ("catalog_ref", "/authz/catalog/{carried}"),
    ("profile_ref", "/authz/profiles/{carried}"),
    ("note_ref", "/authz/notes/{carried}"),
    ("report_ref", "/authz/reports/{carried}"),
    ("stmt_ref", "/authz/statements/{carried}"),
    # create-then-read: step 1 is a POST that creates the object (needs the human gate -> library-level approval here)
    ("draft_ref", "/authz/drafts/{carried}", {"step1": "/authz/drafts", "method": "POST", "body": '{"title": "plan"}'}),
    ("receipt_ref", "/authz/receipts/{carried}", {"step1": "/authz/receipts", "method": "POST", "body": '{"title": "t"}'}),
]
APPROVAL = {"methods": ["POST"], "reason": "benchmark fixture", "authorized_by": "test harness"}

# Identity matrix: (carried key, step-2 path, identities the program's ACCESS POLICY says may read it).
# The policy is operator input (like the workflows), not read from the answer key.
MATRIX = [
    ("ledger_ref", "/authz/ledger/{carried}", {"root"}),
    ("doc_ref", "/authz/teamdocs/{carried}", {"bobby", "root"}),
]
MATRIX_TOKENS = {"bobby": BOB, "carol": CAROL, "root": ADMIN}


def _authz_arm(app, mode):
    observed, request_count = [], 0
    for key, step2, *rest in WORKFLOWS:
        extra = rest[0] if rest else {}
        wf = authz_diff.Workflow(
            f"{app.base_url}{extra.get('step1', '/authz/refs')}", key, f"{app.base_url}{step2}",
            step1_method=extra.get("method", "GET"), step1_body=extra.get("body"))
        res = authz_diff.run_two_step(wf, OWNER, OTHER, approval=APPROVAL if extra else None)
        request_count += len(res.requests)
        step2_reqs = [r for r in res.requests if r["step"] == 2]
        loc = step2_reqs[0]["url"] if step2_reqs else wf.step2_url_template
        observed.append(ObservedFinding(loc, res.verdict == "LEAKED", "authz_diff"))
    for key, step2, allowed in MATRIX:
        wf = authz_diff.Workflow(f"{app.base_url}/authz/refs", key, f"{app.base_url}{step2}")
        identities = [authz_diff.MatrixIdentity(n, {"Authorization": f"Bearer {t}"}, n in allowed)
                      for n, t in MATRIX_TOKENS.items()]
        for row in authz_diff.run_matrix(wf, OWNER, identities):
            request_count += len(row.result.requests)
            step2_reqs = [r for r in row.result.requests if r["step"] == 2]
            loc = step2_reqs[0]["url"] if step2_reqs else wf.step2_url_template
            observed.append(ObservedFinding(loc, row.verdict == "LEAKED", "authz_diff.matrix", row.name))
    return evaluate(observed, mode), request_count


def _sweep_arm(app, mode, ids_known: dict):
    observed = []
    for key, step2, *_ in WORKFLOWS:
        if key not in ids_known:
            continue  # the sweep cannot run without an id the operator already has
        res = idor_sweep.sweep_idor(f"{app.base_url}{step2.replace('{carried}', '{id}')}",
                                    [ids_known[key]], owner_bearer_token=ALICE, other_bearer_token=BOB)
        loc = f"{app.base_url}{step2.replace('{carried}', ids_known[key])}"
        observed.append(ObservedFinding(loc, res.verdicts[0].verdict == "LEAKED", "sweep_idor"))
    return evaluate(observed, mode)


def _lock(name):
    return open(os.path.join(ROOT, "tests", "fixtures", "authz_target", name + ".sha256.lock")).read().strip()


@pytest.fixture(params=["vulnerable", "patched"])
def mode_app(request):
    app = AuthzApp(mode=request.param).start()
    yield request.param, app
    app.stop()


def test_zero_false_positives_and_verdicts_match_ground_truth(mode_app):
    mode, app = mode_app
    report, _ = _authz_arm(app, mode)
    assert report.false_positives == 0
    assert report.false_negatives == 0
    assert report.unmatched_confirmed == 0
    assert report.true_positives == (7 if mode == "vulnerable" else 0)


def test_recovers_the_multistep_flaw_the_sweep_cannot_reach(mode_app):
    mode, app = mode_app
    if mode != "vulnerable":
        pytest.skip("recall is only defined where a flaw is planted")
    # The sweep's natural up-front inputs: ids visible without running step 1 (the order id
    # is in the page URL; the cart ref only ever exists inside owner's step-1 response).
    sweep = _sweep_arm(app, mode, {"order_id": "42"})
    authz, _ = _authz_arm(app, mode)
    assert sweep.per_case["case_authz_01"]["reported_confirmed"] is False  # missed by the sweep
    assert authz.per_case["case_authz_01"]["reported_confirmed"] is True   # recovered
    assert sweep.per_case["case_authz_02"]["reported_confirmed"] and authz.per_case["case_authz_02"]["reported_confirmed"]


def test_quality_floor_authz_arm_never_loses_a_finding_the_sweep_makes(mode_app):
    mode, app = mode_app
    sweep = _sweep_arm(app, mode, {"order_id": "42"})
    authz, _ = _authz_arm(app, mode)
    for case_id, row in sweep.per_case.items():
        if "reported_confirmed" not in row:  # identity-matrix case: rows are per identity (the sweep has none)
            continue
        if row["reported_confirmed"] and row["expected_confirmed"]:
            assert authz.per_case[case_id]["reported_confirmed"]


def test_recorded_baseline_the_sweep_false_positives_on_lookalikes_even_with_every_id_handed_to_it(mode_app):
    mode, app = mode_app
    every_id = {"cart_ref": "ck-7f3a91", "order_id": "42", "catalog_ref": "sku-100",
                "profile_ref": "pr-a11ce0", "note_ref": "nt-5c20e1",
                "report_ref": "rp-31c4e2", "stmt_ref": "st-6be2f0"}
    sweep = _sweep_arm(app, mode, every_id)
    # public catalog + caller-scoped profile both fuzzy-match as "LEAKED" -> the reason the
    # oracle is exact-compare + controls. (This asserts the sweep's CURRENT behavior.)
    assert sweep.false_positives >= 2
    assert sweep.per_case["case_authz_03"]["reported_confirmed"] and sweep.per_case["case_authz_04"]["reported_confirmed"]


def test_reproducible_across_runs_with_recorded_request_counts(tmp_path):
    results = []
    for _ in range(3):
        app = AuthzApp(mode="vulnerable").start()
        try:
            report, n = _authz_arm(app, "vulnerable")
            results.append((report.true_positives, report.false_positives, report.false_negatives, n))
        finally:
            app.stop()
    assert len(set(results)) == 1, results
    tp, fp, fn, requests = results[0]
    record = {  # benchmarks.md "Reproducibility": what a later reader needs to re-derive the claim
        "benchmark": "authz_target", "scenarios_sha256": _lock("authz_scenarios.py"),
        "answer_key_sha256": _lock("authz_answer_key.py"), "mode": "vulnerable", "runs": len(results),
        "seeds": "none (deterministic fixture)", "request_counts": [r[3] for r in results],
        "tp": tp, "fp": fp, "fn": fn, "verdict": "PASS" if (fp, fn) == (0, 0) and tp == 7 else "FAIL",
    }
    out = os.environ.get("HUNTMCP_AUTHZ_GATE_REPORT") or str(tmp_path / "authz-gate-report.json")
    with open(out, "w") as f:
        json.dump(record, f, indent=2)
    saved = json.load(open(out))
    assert saved["verdict"] == "PASS" and len(set(saved["request_counts"])) == 1 and saved["request_counts"][0] > 0
    assert len(saved["scenarios_sha256"]) == 64


def test_the_only_mutations_are_the_declared_create_steps_and_all_are_authenticated(mode_app):
    mode, app = mode_app
    _authz_arm(app, mode)
    posts = [e for e in app.request_log if e["method"] == "POST"]
    assert {e["path"] for e in posts} <= {"/authz/drafts", "/authz/receipts"}
    assert all(e["authorization"] for e in posts) and app.mutation_count == len(posts)
    assert {e["method"] for e in app.request_log} <= {"GET", "POST"}  # the matrix itself is GET-only
