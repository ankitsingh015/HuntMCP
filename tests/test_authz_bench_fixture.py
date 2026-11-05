"""P3-VALAUTHZ benchmark fixture self-tests (TEST-ONLY).

Proves each planted authz behavior in tests/fixtures/authz_target/ is genuine
in BOTH modes, using plain loopback HTTP (not the tool under test), so the
fixture's own ground truth is established independently of the implementation
it later scores. Also proves the blindness / integrity properties
.claude/rules/benchmarks.md requires: the app has no path to its own answer
key, the manifest carries no answers, and the protected files are locked.
"""
import json
import os
import sys
import urllib.error
import urllib.request

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE_DIR = os.path.join(ROOT, "tests", "fixtures", "authz_target")
sys.path.insert(0, FIXTURE_DIR)

from authz_app import ALICE, BOB, AuthzApp  # noqa: E402


@pytest.fixture
def vulnerable_app():
    app = AuthzApp(mode="vulnerable").start()
    try:
        yield app
    finally:
        app.stop()


@pytest.fixture
def patched_app():
    app = AuthzApp(mode="patched").start()
    try:
        yield app
    finally:
        app.stop()


def _get(app, path, token=None):
    return _req(app, "GET", path, token)


def _req(app, method, path, token=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    req = urllib.request.Request(app.base_url + path, headers=headers, method=method,
                                 data=b"" if method == "POST" else None)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def _refs(app, token):
    status, body = _get(app, "/authz/refs", token)
    assert status == 200, body
    return json.loads(body)


def test_app_binds_loopback_only(vulnerable_app):
    assert vulnerable_app.base_url.startswith("http://127.0.0.1:")


def test_refs_are_per_identity_and_require_auth(vulnerable_app):
    assert _get(vulnerable_app, "/authz/refs")[0] == 401
    a, b = _refs(vulnerable_app, ALICE), _refs(vulnerable_app, BOB)
    assert a["cart_ref"] != b["cart_ref"]
    assert a["catalog_ref"] == b["catalog_ref"]  # shared, public item


# --- case: multi-step carried id (cart invoice) --------------------------

def test_cart_invoice_vulnerable_other_identity_reads_owners_invoice(vulnerable_app):
    ref = _refs(vulnerable_app, ALICE)["cart_ref"]
    own_status, own_body = _get(vulnerable_app, f"/authz/carts/{ref}/invoice", ALICE)
    other_status, other_body = _get(vulnerable_app, f"/authz/carts/{ref}/invoice", BOB)
    assert own_status == 200 and other_status == 200
    assert json.loads(other_body) == json.loads(own_body)


def test_cart_invoice_patched_other_identity_refused_owner_still_works(patched_app):
    ref = _refs(patched_app, ALICE)["cart_ref"]
    assert _get(patched_app, f"/authz/carts/{ref}/invoice", BOB)[0] == 403
    assert _get(patched_app, f"/authz/carts/{ref}/invoice", ALICE)[0] == 200


def test_cart_invoice_requires_authentication_in_both_modes(vulnerable_app, patched_app):
    for app in (vulnerable_app, patched_app):
        ref = _refs(app, ALICE)["cart_ref"]
        assert _get(app, f"/authz/carts/{ref}/invoice")[0] == 401


# --- case: single-step order (what the existing sweep already catches) ---

def test_order_vulnerable_other_identity_reads_owners_order(vulnerable_app):
    oid = _refs(vulnerable_app, ALICE)["order_id"]
    assert _get(vulnerable_app, f"/authz/orders/{oid}", BOB)[0] == 200


def test_order_patched_other_identity_refused(patched_app):
    oid = _refs(patched_app, ALICE)["order_id"]
    assert _get(patched_app, f"/authz/orders/{oid}", BOB)[0] == 403
    assert _get(patched_app, f"/authz/orders/{oid}", ALICE)[0] == 200


# --- non-vulnerable look-alikes: must behave identically in BOTH modes ---

def test_public_catalog_is_readable_by_everyone_including_unauthenticated(vulnerable_app, patched_app):
    for app in (vulnerable_app, patched_app):
        ref = _refs(app, ALICE)["catalog_ref"]
        bodies = {_get(app, f"/authz/catalog/{ref}", t) for t in (ALICE, BOB, None)}
        assert len(bodies) == 1 and next(iter(bodies))[0] == 200


def test_profile_endpoint_ignores_the_id_and_returns_the_callers_own_view(vulnerable_app, patched_app):
    for app in (vulnerable_app, patched_app):
        alice_ref = _refs(app, ALICE)["profile_ref"]
        s_a, body_a = _get(app, f"/authz/profiles/{alice_ref}", ALICE)
        s_b, body_b = _get(app, f"/authz/profiles/{alice_ref}", BOB)
        assert s_a == s_b == 200
        assert json.loads(body_a)["owner"] == "alice"
        assert json.loads(body_b)["owner"] == "bobby"  # B's OWN data, not A's
        assert _get(app, f"/authz/profiles/{alice_ref}")[0] == 401


def test_notes_endpoint_soft_denies_with_200_for_a_non_owner(vulnerable_app, patched_app):
    for app in (vulnerable_app, patched_app):
        ref = _refs(app, ALICE)["note_ref"]
        s_own, body_own = _get(app, f"/authz/notes/{ref}", ALICE)
        s_other, body_other = _get(app, f"/authz/notes/{ref}", BOB)
        assert s_own == 200 and "error" not in json.loads(body_own)
        assert s_other == 200 and json.loads(body_other) == {"error": "not_yours"}


# --- state-changing endpoint (for the human-gate tests) ------------------

def test_cancel_is_a_post_and_is_recorded_as_a_mutation(vulnerable_app):
    ref = _refs(vulnerable_app, ALICE)["cart_ref"]
    assert vulnerable_app.mutation_count == 0
    status, _ = _req(vulnerable_app, "POST", f"/authz/carts/{ref}/cancel", BOB)
    assert status == 200
    assert vulnerable_app.mutation_count == 1


def test_cancel_patched_other_identity_refused_and_not_mutated(patched_app):
    ref = _refs(patched_app, ALICE)["cart_ref"]
    assert _req(patched_app, "POST", f"/authz/carts/{ref}/cancel", BOB)[0] == 403
    assert patched_app.mutation_count == 0


def test_request_log_records_method_path_and_authorization(vulnerable_app):
    _get(vulnerable_app, "/authz/refs", ALICE)
    entry = vulnerable_app.request_log[-1]
    assert entry["method"] == "GET" and entry["path"] == "/authz/refs"
    assert entry["authorization"] == f"Bearer {ALICE}"


# --- blindness / integrity (benchmarks.md) --------------------------------

def test_app_source_has_no_path_to_the_answer_key():
    import ast
    tree = ast.parse(open(os.path.join(FIXTURE_DIR, "authz_app.py")).read())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    assert not imported & {"authz_answer_key", "authz_scenarios", "authz_evaluator"}


def test_scenarios_manifest_is_blind():
    import authz_scenarios
    flat = json.dumps({k: dict(v) for k, v in authz_scenarios.SCENARIOS.items()}).lower()
    for field in authz_scenarios.FORBIDDEN_ANSWER_FIELDS:
        assert field not in flat
    for case_id in authz_scenarios.SCENARIOS:
        for leak in ("trap", "public", "self", "soft", "leak", "vuln", "idor", "safe"):
            assert leak not in case_id.lower()


def test_answer_key_covers_every_scenario_and_has_positives_and_negatives_per_mode():
    import authz_answer_key as AK
    import authz_scenarios as SC
    assert set(AK.EXPECTED_BY_MODE) == set(SC.SCENARIOS)
    vuln = {c for c, m in AK.EXPECTED_BY_MODE.items() if m["vulnerable"]["confirmed"]}
    assert len(vuln) == 6  # cart, order, report, draft + the two identity-matrix cases (ledger, team document)
    assert not any(m["patched"]["confirmed"] for m in AK.EXPECTED_BY_MODE.values())


def test_protected_files_integrity_locks_hold():
    import authz_integrity
    for name in ("authz_scenarios.py", "authz_answer_key.py"):
        ok, msg = authz_integrity.verify(os.path.join(FIXTURE_DIR, name))
        assert ok, msg


# --- cases 06/07: per-request (volatile) fields ----------------------------

def test_refs_carry_the_report_and_statement_refs(vulnerable_app):
    refs = _refs(vulnerable_app, ALICE)
    assert refs["report_ref"] != _refs(vulnerable_app, BOB)["report_ref"]
    assert refs["stmt_ref"] != _refs(vulnerable_app, BOB)["stmt_ref"]


def _volatile_pair(app, path, token):
    a, b = json.loads(_get(app, path, token)[1]), json.loads(_get(app, path, token)[1])
    assert a["generated_at"] != b["generated_at"] and a["request_id"] != b["request_id"]
    return a, b


def test_report_vulnerable_other_identity_reads_owners_report_with_per_request_fields(vulnerable_app):
    ref = _refs(vulnerable_app, ALICE)["report_ref"]
    own, _ = _volatile_pair(vulnerable_app, f"/authz/reports/{ref}", ALICE)
    status, body = _get(vulnerable_app, f"/authz/reports/{ref}", BOB)
    other = json.loads(body)
    strip = lambda d: {k: v for k, v in d.items() if k not in ("generated_at", "request_id")}  # noqa: E731
    assert status == 200 and strip(other) == strip(own) and other["owner"] == "alice"


def test_report_patched_other_identity_refused_owner_still_works(patched_app):
    ref = _refs(patched_app, ALICE)["report_ref"]
    assert _get(patched_app, f"/authz/reports/{ref}", BOB)[0] == 403
    assert _get(patched_app, f"/authz/reports/{ref}", ALICE)[0] == 200


def test_statement_soft_denies_a_non_owner_with_per_request_fields_in_both_modes(vulnerable_app, patched_app):
    for app in (vulnerable_app, patched_app):
        ref = _refs(app, ALICE)["stmt_ref"]
        s_own, own = _get(app, f"/authz/statements/{ref}", ALICE)
        s_other, other = _get(app, f"/authz/statements/{ref}", BOB)
        o = json.loads(other)
        assert s_own == 200 and s_other == 200 and o["error"] == "not_yours"
        assert "generated_at" in o and "request_id" in o


# --- cases 08/09: create-then-read (POST creates, GET reads) -----------------------

def _post(app, path, token, body=None):
    data = json.dumps(body if body is not None else {"title": "t"}).encode()
    req = urllib.request.Request(app.base_url + path, data=data, method="POST", headers={
        "Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def test_creating_a_draft_returns_201_with_a_per_caller_ref_and_counts_a_mutation(vulnerable_app):
    status, body = _post(vulnerable_app, "/authz/drafts", ALICE, {"title": "plan"})
    assert status == 201 and json.loads(body)["draft_ref"]
    assert vulnerable_app.mutation_count == 1


def test_creating_requires_authentication(vulnerable_app):
    req = urllib.request.Request(vulnerable_app.base_url + "/authz/drafts", data=b"{}", method="POST")
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(req, timeout=5)
    assert e.value.code == 401 and vulnerable_app.mutation_count == 0


def test_draft_vulnerable_other_identity_reads_the_owners_draft(vulnerable_app):
    ref = json.loads(_post(vulnerable_app, "/authz/drafts", ALICE, {"title": "plan"})[1])["draft_ref"]
    s_own, own = _get(vulnerable_app, f"/authz/drafts/{ref}", ALICE)
    s_other, other = _get(vulnerable_app, f"/authz/drafts/{ref}", BOB)
    assert s_own == s_other == 200 and json.loads(other) == json.loads(own)
    assert json.loads(own)["owner"] == "alice" and json.loads(own)["title"] == "plan"


def test_draft_patched_other_identity_is_refused_owner_still_reads(patched_app):
    ref = json.loads(_post(patched_app, "/authz/drafts", ALICE)[1])["draft_ref"]
    assert _get(patched_app, f"/authz/drafts/{ref}", BOB)[0] == 403
    assert _get(patched_app, f"/authz/drafts/{ref}", ALICE)[0] == 200


def test_each_create_makes_a_new_distinct_ref(vulnerable_app):
    a = json.loads(_post(vulnerable_app, "/authz/drafts", ALICE)[1])["draft_ref"]
    b = json.loads(_post(vulnerable_app, "/authz/drafts", ALICE)[1])["draft_ref"]
    assert a != b


def test_receipts_are_owner_only_in_both_modes(vulnerable_app, patched_app):
    for app in (vulnerable_app, patched_app):
        ref = json.loads(_post(app, "/authz/receipts", ALICE)[1])["receipt_ref"]
        assert _get(app, f"/authz/receipts/{ref}", ALICE)[0] == 200
        assert _get(app, f"/authz/receipts/{ref}", BOB)[0] == 403


def test_the_request_log_records_post_bodies(vulnerable_app):
    _post(vulnerable_app, "/authz/drafts", ALICE, {"title": "logged"})
    assert "logged" in vulnerable_app.request_log[-1]["body"]


# --- cases 10/11: identity matrix (user / admin / other-tenant) ----------------------

from authz_app import CAROL, ROOT  # noqa: E402


def test_four_identities_have_their_own_refs(vulnerable_app):
    seen = {t: _refs(vulnerable_app, t) for t in (ALICE, BOB, CAROL, ROOT)}
    assert len({r["ledger_ref"] for r in seen.values()}) == 4 and len({r["doc_ref"] for r in seen.values()}) == 4
    assert all(r["catalog_ref"] == "sku-100" for r in seen.values())


def test_ledger_vulnerable_any_authenticated_identity_reads_the_owners_ledger(vulnerable_app):
    ref = _refs(vulnerable_app, ALICE)["ledger_ref"]
    bodies = {t: _get(vulnerable_app, f"/authz/ledger/{ref}", t) for t in (ALICE, BOB, CAROL, ROOT)}
    assert all(s == 200 for s, _ in bodies.values()) and len({b for _, b in bodies.values()}) == 1


def test_ledger_patched_only_the_owner_and_an_admin_read_it(patched_app):
    ref = _refs(patched_app, ALICE)["ledger_ref"]
    assert _get(patched_app, f"/authz/ledger/{ref}", ALICE)[0] == 200
    assert _get(patched_app, f"/authz/ledger/{ref}", ROOT)[0] == 200
    assert _get(patched_app, f"/authz/ledger/{ref}", BOB)[0] == 403
    assert _get(patched_app, f"/authz/ledger/{ref}", CAROL)[0] == 403


def test_teamdoc_vulnerable_tenant_isolation_is_missing(vulnerable_app):
    ref = _refs(vulnerable_app, ALICE)["doc_ref"]
    assert _get(vulnerable_app, f"/authz/teamdocs/{ref}", CAROL)[0] == 200


def test_teamdoc_patched_same_tenant_reads_but_another_tenant_is_refused(patched_app):
    ref = _refs(patched_app, ALICE)["doc_ref"]
    assert _get(patched_app, f"/authz/teamdocs/{ref}", BOB)[0] == 200    # same tenant (t1)
    assert _get(patched_app, f"/authz/teamdocs/{ref}", ROOT)[0] == 200   # same tenant (t1)
    assert _get(patched_app, f"/authz/teamdocs/{ref}", CAROL)[0] == 403  # other tenant (t2)


def test_matrix_endpoints_require_authentication(vulnerable_app, patched_app):
    for app in (vulnerable_app, patched_app):
        ref = _refs(app, ALICE)
        assert _get(app, f"/authz/ledger/{ref['ledger_ref']}")[0] == 401
        assert _get(app, f"/authz/teamdocs/{ref['doc_ref']}")[0] == 401


def test_answer_key_carries_per_identity_expectations_for_the_matrix_cases():
    import authz_answer_key as AK
    ledger = AK.EXPECTED_BY_MODE["case_authz_10"]
    assert ledger["vulnerable"]["identities"] == {"bobby": True, "carol": True, "root": False}
    assert not any(ledger["patched"]["identities"].values())
    docs = AK.EXPECTED_BY_MODE["case_authz_11"]
    assert docs["vulnerable"]["identities"] == {"bobby": False, "carol": True, "root": False}
    assert not any(docs["patched"]["identities"].values())
