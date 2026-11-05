"""EVALUATOR-ONLY answer key for the P3-VALAUTHZ range. Ground truth is
fixed by how authz_app.py is built, independent of any tool's verdicts:
  01 carried opaque cart ref -> step-2 invoice with the ownership check
     missing in "vulnerable"  (multi-step; the single-id sweep cannot reach it)
  02 by-id order, ownership check missing in "vulnerable" (single-step)
  03 public catalog item -- readable by everyone, never an authz bug
  04 profile endpoint that ignores the id, returns the caller's own view
  05 note endpoint that denies with HTTP 200 + error body for a non-owner
  06 carried report ref, ownership check missing in "vulnerable"; every response carries
     per-request fields (generated_at, request_id) that differ on each fetch
  07 statement endpoint that soft-denies a non-owner (HTTP 200 + error body), the body also
     carrying per-request fields
  08 create-then-read: POST /authz/drafts creates an object for the caller (201 + ref); GET of
     another identity's draft has the ownership check missing in "vulnerable"
  09 create-then-read look-alike: receipts are owner-only (403 for others) in BOTH modes
  10 identity matrix, ledger: should be readable by its owner (alice) and an admin (root) only;
     "vulnerable" has no ownership check, so bobby (same tenant) and carol (other tenant) can read
     it while root's access is by design (not a finding)
  11 identity matrix, team document: should be readable within the owner's tenant (t1: bobby, root)
     only; "vulnerable" has no tenant isolation, so only carol (tenant t2) is wrongly allowed
`kind` is documentation only; evaluate() scores on `confirmed`."""
from __future__ import annotations

from types import MappingProxyType

_NEVER = MappingProxyType({"confirmed": False})


def _matrix_case(kind: str, vulnerable_identities: dict) -> MappingProxyType:
    """Identity-matrix case: ground truth per identity (True = that identity can read what it must
    not). `confirmed` mirrors "any identity is wrongly allowed"; evaluate() scores per identity."""
    return MappingProxyType({
        "kind": kind,
        "vulnerable": MappingProxyType({"confirmed": any(vulnerable_identities.values()),
                                        "identities": MappingProxyType(dict(vulnerable_identities))}),
        "patched": MappingProxyType({"confirmed": False,
                                     "identities": MappingProxyType({k: False for k in vulnerable_identities})}),
    })


def _case(kind: str, vulnerable: bool) -> MappingProxyType:
    return MappingProxyType({
        "kind": kind,
        "vulnerable": MappingProxyType({"confirmed": vulnerable}),
        "patched": _NEVER,
    })


EXPECTED_BY_MODE = MappingProxyType({
    "case_authz_01": _case("multistep_carried_id", True),
    "case_authz_02": _case("single_step_by_id", True),
    "case_authz_03": _case("public_resource", False),
    "case_authz_04": _case("caller_scoped_view", False),
    "case_authz_05": _case("soft_deny_200", False),
    "case_authz_06": _case("per_request_fields_leak", True),
    "case_authz_07": _case("soft_deny_200_with_per_request_fields", False),
    "case_authz_08": _case("create_then_read_leak", True),
    "case_authz_09": _case("create_then_read_owner_only", False),
    "case_authz_10": _matrix_case("owner_or_admin_only_ledger", {"bobby": True, "carol": True, "root": False}),
    "case_authz_11": _matrix_case("tenant_scoped_document", {"bobby": False, "carol": True, "root": False}),
})
