"""P3-VALAUTHZ (c): identity matrix -- the same owner-fetch-and-compare oracle run against several named
identities (same-tenant user, admin, other-tenant user), with an operator-declared access POLICY so an
identity that is SUPPOSED to read the object (an admin) is reported as EXPECTED_ACCESS, never as a leak."""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "idor-mcp"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "authz_target"))

import authz_diff  # noqa: E402
from authz_app import ALICE, BOB, CAROL, ROOT as ADMIN, AuthzApp  # noqa: E402
from budget_guard import BudgetExceeded  # noqa: E402

OWNER = {"Authorization": f"Bearer {ALICE}"}


def _id(name, token, allowed=False):
    return authz_diff.MatrixIdentity(name, {"Authorization": f"Bearer {token}"}, allowed)


BOBBY, CAROLX, ROOTX = _id("bobby", BOB), _id("carol", CAROL), _id("root", ADMIN, True)
IDS = [BOBBY, CAROLX, ROOTX]


@pytest.fixture
def vulnerable_app():
    app = AuthzApp(mode="vulnerable").start()
    yield app
    app.stop()


@pytest.fixture
def patched_app():
    app = AuthzApp(mode="patched").start()
    yield app
    app.stop()


def _wf(app, key, path):
    return authz_diff.Workflow(f"{app.base_url}/authz/refs", key, f"{app.base_url}{path}")


def _verdicts(rows):
    return {r.name: r.verdict for r in rows}


def test_ledger_vulnerable_flags_the_user_and_the_other_tenant_but_not_the_admin(vulnerable_app):
    rows = authz_diff.run_matrix(_wf(vulnerable_app, "ledger_ref", "/authz/ledger/{carried}"), OWNER, IDS)
    assert _verdicts(rows) == {"bobby": "LEAKED", "carol": "LEAKED", "root": "EXPECTED_ACCESS"}


def test_ledger_patched_only_the_admin_gets_in_and_that_is_by_policy(patched_app):
    rows = authz_diff.run_matrix(_wf(patched_app, "ledger_ref", "/authz/ledger/{carried}"), OWNER, IDS)
    assert _verdicts(rows) == {"bobby": "PROTECTED", "carol": "PROTECTED", "root": "EXPECTED_ACCESS"}


def test_team_document_policy_allows_the_same_tenant_and_flags_only_the_other_tenant(vulnerable_app, patched_app):
    ids = [_id("bobby", BOB, True), CAROLX, _id("root", ADMIN, True)]
    rows = authz_diff.run_matrix(_wf(vulnerable_app, "doc_ref", "/authz/teamdocs/{carried}"), OWNER, ids)
    assert _verdicts(rows) == {"bobby": "EXPECTED_ACCESS", "carol": "LEAKED", "root": "EXPECTED_ACCESS"}
    rows = authz_diff.run_matrix(_wf(patched_app, "doc_ref", "/authz/teamdocs/{carried}"), OWNER, ids)
    assert _verdicts(rows) == {"bobby": "EXPECTED_ACCESS", "carol": "PROTECTED", "root": "EXPECTED_ACCESS"}


def test_without_a_policy_an_admin_reading_the_object_is_reported(vulnerable_app):
    rows = authz_diff.run_matrix(_wf(vulnerable_app, "ledger_ref", "/authz/ledger/{carried}"), OWNER,
                                 [_id("root", ADMIN, False)])
    assert rows[0].verdict == "LEAKED"  # the default is "should NOT have access"


def test_each_row_keeps_its_own_request_log_and_no_credentials(vulnerable_app):
    rows = authz_diff.run_matrix(_wf(vulnerable_app, "ledger_ref", "/authz/ledger/{carried}"), OWNER, IDS)
    assert all(len(r.result.requests) >= 3 for r in rows)
    blob = json.dumps([r.result.to_dict() for r in rows])
    for tok in (ALICE, BOB, CAROL, ADMIN):
        assert tok not in blob


def test_the_matrix_is_read_only_and_never_mutates(vulnerable_app):
    authz_diff.run_matrix(_wf(vulnerable_app, "ledger_ref", "/authz/ledger/{carried}"), OWNER, IDS)
    assert {e["method"] for e in vulnerable_app.request_log} == {"GET"} and vulnerable_app.mutation_count == 0


def test_a_state_changing_workflow_is_rejected_before_any_request(vulnerable_app):
    wf = authz_diff.Workflow(f"{vulnerable_app.base_url}/authz/drafts", "draft_ref",
                             f"{vulnerable_app.base_url}/authz/drafts/{{carried}}", step1_method="POST",
                             step1_body='{"title": "t"}')
    with pytest.raises(authz_diff.MatrixError):
        authz_diff.run_matrix(wf, OWNER, IDS)
    assert vulnerable_app.request_log == []


@pytest.mark.parametrize("ids", [
    [],
    [_id(f"u{i}", BOB) for i in range(6)],
    [_id("bobby", BOB), _id("bobby", CAROL)],                    # duplicate name
    [_id("bad name!", BOB)],                                       # illegal name
    [_id("bobby", BOB), _id("again", BOB)],                        # same credentials twice
    [_id("owner-twin", ALICE)],                                    # same credentials as the owner
])
def test_invalid_identity_sets_are_rejected_before_any_request(vulnerable_app, ids):
    with pytest.raises(authz_diff.MatrixError):
        authz_diff.run_matrix(_wf(vulnerable_app, "ledger_ref", "/authz/ledger/{carried}"), OWNER, ids)
    assert vulnerable_app.request_log == []


def test_scope_and_budget_apply_to_every_request_of_every_row(vulnerable_app):
    seen = []
    n = []

    def budget():
        n.append(1)
        if len(n) > 10:
            raise BudgetExceeded("cap")

    rows = authz_diff.run_matrix(_wf(vulnerable_app, "ledger_ref", "/authz/ledger/{carried}"), OWNER, IDS,
                                 scope_check=seen.append, budget_cb=budget)
    assert len(vulnerable_app.request_log) == 10 and len(seen) >= 10
    assert any(r.verdict == "BLOCKED" for r in rows) and not any(
        r.verdict == "LEAKED" for r in rows if r.name == "root")


def test_a_blocked_row_stops_the_rest_of_the_matrix(vulnerable_app):
    def deny(url):
        raise authz_diff.RequestBlocked("scope: nope")

    rows = authz_diff.run_matrix(_wf(vulnerable_app, "ledger_ref", "/authz/ledger/{carried}"), OWNER, IDS,
                                 scope_check=deny)
    assert [r.verdict for r in rows] == ["BLOCKED"] and vulnerable_app.request_log == []


def test_more_than_five_distinct_identities_are_rejected_before_any_request(vulnerable_app):
    """Mutant guard for the size cap (the earlier 6-identity case tripped the same-credentials check first)."""
    ids = [_id(f"u{i}", f"tok-distinct-{i}-authz") for i in range(authz_diff.MAX_MATRIX_IDENTITIES + 1)]
    with pytest.raises(authz_diff.MatrixError, match="at most"):
        authz_diff.run_matrix(_wf(vulnerable_app, "ledger_ref", "/authz/ledger/{carried}"), OWNER, ids)
    assert vulnerable_app.request_log == []
