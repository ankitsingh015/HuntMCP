"""Structured scan-policy fields, consumed by scan-agent before tool
selection.

Why this exists: the scan specialist's default is full scanner runs, but
a program that prohibits or caps automated scanning previously required
the orchestrator to notice the conflict and manually re-scope the scan
task into a bounded/manual pass -- policy was held only in
engagement.yaml's free-text `notes` field, not something the scan
specialist itself consumed. Reported live in an engagement retrospective:
worked, but only because the orchestrator happened to notice the
conflict, with per-engagement re-scoping overhead and real risk of policy
drift on a future engagement where it's missed.

Deliberately a SEPARATE module reading engagement.yaml directly, rather
than a change to scope_guard.py's own Engagement dataclass -- scope_guard.py
is part of the scope-gate enforcement boundary (protected, requires an
explicit interactive human confirm to edit, scripts/confirm-hook-edit.sh)
and these two new fields are a scan-PLANNING policy, not a scope-
authorization boundary; keeping them independent means this addition
needs no such confirmation and can never accidentally touch scope
enforcement itself.

scan_policy values: "manual" (no bulk automated scanning at all -- a
bounded, hand-picked check only), "bounded" (bulk scanning allowed up to
scanner_volume_cap calls), "full" (no restriction -- the historical
default, so an engagement.yaml written before this field existed behaves
identically to before).
"""

from __future__ import annotations

import os

try:
    import yaml
except ImportError:
    yaml = None

try:
    import engagement_paths
except ImportError:
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import engagement_paths

VALID_SCAN_POLICIES = {"manual", "bounded", "full"}

DEFAULT_POLICY = {"scan_policy": "full", "scanner_volume_cap": None}


def load_scan_policy(path: str | None = None) -> dict:
    """Reads `scan_policy`/`scanner_volume_cap` directly from
    engagement.yaml. Returns DEFAULT_POLICY ("full", no cap -- identical
    to the pre-existing scanner-first default) when the file is missing or
    the fields are simply absent. Returns {"error": ...} for a present-but-
    invalid scan_policy value -- fail loud rather than silently defaulting
    to "full" and letting bulk scanning proceed on a program that
    explicitly restricted it."""
    if path is None:
        path = engagement_paths.resolve("engagement.yaml", override_env="HUNTMCP_ENGAGEMENT_PATH")
    if not os.path.isfile(path):
        return dict(DEFAULT_POLICY)
    if yaml is None:
        # SECURITY regression this closes (code-review finding): this used
        # to be folded into the "no engagement.yaml" branch above, both
        # returning the unrestricted DEFAULT_POLICY -- but "the file is
        # missing" (legitimately nothing to restrict) and "PyYAML isn't
        # importable" (an environment defect -- we genuinely cannot tell
        # whether the file restricts anything) are not the same case. An
        # engagement.yaml with `scan_policy: manual` must not silently
        # read back as unrestricted "full" just because this particular
        # invocation's Python environment lacks PyYAML -- fail loud here
        # too, matching scope_guard.py's own convention for the identical
        # yaml-missing case, and matching this function's own stated
        # "fail loud" behavior for an invalid scan_policy value below.
        return {"error": f"PyYAML not installed; cannot determine scan_policy restrictions "
                          f"(would otherwise silently default to unrestricted 'full' for {path!r})"}
    with open(path) as f:
        data = yaml.safe_load(f) or {}

    scan_policy_value = data.get("scan_policy", "full")
    if scan_policy_value not in VALID_SCAN_POLICIES:
        return {"error": f"invalid scan_policy {scan_policy_value!r} in {path!r}, "
                          f"expected one of {sorted(VALID_SCAN_POLICIES)}"}
    return {"scan_policy": scan_policy_value, "scanner_volume_cap": data.get("scanner_volume_cap")}


def should_run_bulk_scanner(policy: dict, calls_so_far: int = 0) -> bool:
    """True if a bulk/template-based automated scanner call is currently
    allowed under `policy` (as returned by load_scan_policy()).
    "manual" -> always False. "full" -> always True. "bounded" -> True
    only while calls_so_far is still under scanner_volume_cap."""
    scan_policy_value = policy.get("scan_policy", "full")
    if scan_policy_value == "manual":
        return False
    if scan_policy_value == "full":
        return True
    cap = policy.get("scanner_volume_cap")
    if cap is None:
        return True
    return calls_so_far < cap
