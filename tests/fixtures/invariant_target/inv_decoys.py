"""Hand-built precision decoys for the P4-M0 shallow-invariant probe (TEST
FIXTURE ONLY).

The P4-BM long-horizon simulator (lh_target.py) plants broken invariants and a
*secured* decoy (golf: a non-owner is denied 403).  It does NOT contain the
canonical shallow-probe FALSE POSITIVE: a legitimately PUBLIC / SHARED resource
that returns 2xx + content to several identities with NO denial anywhere.  A
`{identity, resource, status, body}`-only heuristic cannot tell that apart from
an IDOR leak, so the high-recall probe is EXPECTED to flag it -- and the frozen
CEM counterfactual is what must then REJECT it (dropping the identity still
returns the same content => identity is not necessary => not a confirmed bug).

This module is the deterministic in-process *target* for that decoy, mirroring
lh_target.py's discipline: no network, no filesystem, no randomness; a pure
function of (resource, identity, replays).  It is the genuinely-observable
behaviour the probe mines and the executor re-issues -- it imports neither the
evaluator-only answer key nor the probe.
"""
from __future__ import annotations

# A public, unauthenticated-equivalent resource: EVERY identity sees the SAME
# object content and NO identity is ever denied.  Returning 2xx + content to
# >=2 identities with no denial is exactly the shallow ownership false positive.
_PUBLIC_SHARED_BODY = "PUBLIC-SHARED-DOC company-handbook v3 (visible to all staff)"

PUB_SHARED = "pub_shared"


def serve(resource: str, identity: str, action: str = "read",
          replays: int = 1, epoch: int = 0) -> tuple[int, str]:
    """Return (status, body) for a decoy resource.  Deterministic in
    (resource, identity, action, replays)."""
    if resource == PUB_SHARED:
        if action != "read":
            return 400, "bad action"
        # identical content for everyone, never denied -> genuinely public.
        return 200, _PUBLIC_SHARED_BODY
    return 404, f"unknown decoy resource {resource!r}"


def observe(resource: str, identities) -> list[dict]:
    """Build the observed-exchange corpus the probe mines for a decoy."""
    out = []
    for ident in identities:
        status, body = serve(resource, ident, "read")
        out.append({"identity": ident, "resource": resource, "action": "read",
                    "args": {}, "status": status, "body": body})
    return out
