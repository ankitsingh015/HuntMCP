"""Independent read-back oracle for state-changing controls (CSRF / auth-bypass).

GitHub issue #144, from the behindthename.com engagement (2026-11-12):
`POST /members/doedit_settings.php` returned HTTP 302 with no error page whether
or not a valid CSRF token was sent. Judged on status alone that looked like the
token was NOT enforced (an apparent CSRF bypass). A follow-up read-back of the
profile field showed the write was silently rejected -- the token IS enforced;
the server returns a benign 302 on rejection, indistinguishable by status from a
real write. This nearly became a false CSRF report.

The rule this module encodes: a state-changing control (CSRF, auth-bypass, any
"the request was accepted" claim) may be concluded bypassable / vulnerable ONLY
after an INDEPENDENT read-back -- a separate re-fetch of the affected resource, a
second request, or an out-of-band callback -- proves the target state ACTUALLY
changed. An HTTP 2xx / 201 / 3xx / redirect, or a reflected-success body on the
mutating response itself, is necessary-but-insufficient and is never accepted
here as evidence that the state changed.

Pure logic: no network, no MCP, no DB. The caller (exploit-agent, via browser-mcp
/ curl / oob-mcp) performs the real read-back fetch and hands the observed state
to confirm_state_change(). Same shape as cors_probe / upload_retrievability: a
small, unit-testable classifier an agent invokes rather than a server. False
negatives (an unproven real bug left INCONCLUSIVE) are acceptable here; a false
positive (concluding a change that never happened) is exactly what it prevents.
"""

from __future__ import annotations

import json

# Verdicts. CONFIRMED is the only one that may back a "control bypassable"
# conclusion; the other two must NOT be reported as a confirmed state change.
CONFIRMED = "CONFIRMED_STATE_CHANGE"
NOT_CHANGED = "NO_STATE_CHANGE"      # read-back proves the control held (the #144 case)
INCONCLUSIVE = "INCONCLUSIVE"         # no / insufficient independent read-back evidence

# Mirrors cem_engine.CEM_READ_ONLY_METHODS -- kept local so this module stays
# dependency-free (case-mcp imports both; importing cem_engine here would add an
# import-order coupling for no benefit). A method outside this set is treated as
# state-changing.
_READ_ONLY_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# The status families a caller is most tempted to read as "it worked". Listed only
# so why_status_is_insufficient() can name them; the rule does not depend on the
# list -- NO status, of any value, is on its own proof of a persisted state change.
TEMPTING_SUCCESS_STATUSES = frozenset({200, 201, 202, 204, 301, 302, 303, 307, 308})


def _normalize(value) -> str | None:
    """Canonical comparable form of an observed state. A dict/list is JSON with
    sorted keys; any other value is its str() with whitespace collapsed. None (no
    observation supplied) stays None. An empty/blank string also collapses to None:
    "I read it back and saw nothing" is not an observation to compare."""
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    collapsed = " ".join(str(value).split())
    return collapsed or None


def why_status_is_insufficient(status: int | None = None) -> str:
    """The reason, in one place, that an HTTP status/redirect on the mutating
    request is never sufficient to conclude a state-changing control is bypassable.
    For error messages and the agent methodology -- the rule itself is enforced by
    confirm_state_change(), which ignores the status entirely."""
    seen = f"HTTP {status}" if isinstance(status, int) else "an HTTP 2xx/201/302/redirect"
    return (
        f"{seen} on the mutating request is necessary but NOT sufficient to conclude a "
        "state-changing control (CSRF, auth-bypass) is bypassable: a server can return a "
        "benign 2xx/302 -- or echo a success page -- while silently rejecting the write "
        "(issue #144). Confirm with an independent read-back via confirm_state_change()."
    )


def confirm_state_change(readback_before, readback_after, *,
                         expected_after=None, oob_confirmed: bool = False) -> tuple[str, str]:
    """Decide whether an INDEPENDENT read-back proves the target state changed.

    Inputs are observations the caller gathered OUT OF BAND from the mutating
    response -- never that response's status/headers/body:
      - readback_before: the affected resource re-read BEFORE the attack (the
        baseline). Required for a CONFIRMED verdict -- with no baseline, a value
        merely present afterwards cannot be shown to have CHANGED (INCONCLUSIVE),
        even if expected_after matches it.
      - readback_after:  the affected resource re-read AFTER the attack.
      - expected_after:  (optional) the attacker-intended value; when given, the
        changed read-back must actually equal/contain it, so an unrelated change
        is not mistaken for the attack landing. Best a scalar/unique marker.
      - oob_confirmed:   True iff an out-of-band callback (DNS/HTTP, e.g. oob-mcp)
        independently fired -- itself proof the action occurred.

    Returns (verdict, human-readable reason). CONFIRMED only when the read-back (or
    OOB) actually shows the change; the silent-rejection case returns NOT_CHANGED;
    a missing/insufficient read-back returns INCONCLUSIVE -- never CONFIRMED from a
    status code. There is deliberately no parameter for the mutating response: it
    cannot be passed in, so it cannot be mistaken for evidence.
    """
    if oob_confirmed:
        return CONFIRMED, ("an independent out-of-band callback fired -- proof the action actually "
                           "occurred, not merely that the request was accepted")

    before = _normalize(readback_before)
    after = _normalize(readback_after)
    expected = _normalize(expected_after)

    if after is None:
        return INCONCLUSIVE, (
            "no independent read-back of the target state was supplied. " + why_status_is_insufficient())

    if before is None:
        # Only the post-attack state is known. A value that is merely PRESENT afterwards is not proof
        # it CHANGED -- it may have held that value all along. Concluding a bypass from a post-only
        # read-back is the #144 false positive one level in, so this stays INCONCLUSIVE even when an
        # expected value is supplied and matches: without a baseline, "present" never implies "changed".
        return INCONCLUSIVE, (
            "only a post-attack read-back was supplied (no baseline from BEFORE the attack): a value "
            "that is merely present afterwards cannot be distinguished from one that was already there "
            "-- re-read the resource before the attack too, or use a value only the attack could set")

    if after == before:
        return NOT_CHANGED, (
            "the target state is identical on an independent read-back before and after the attack -- "
            "the control held and the write was silently rejected; a 2xx/302 on the mutating request "
            "is not evidence of a change (issue #144)")

    # before != after: the state demonstrably changed against a real baseline. If an intended value was
    # named, it must be the one that landed (so an unrelated concurrent change is not mistaken for the
    # attack). Match on normalized equality first, then substring -- equality catches a structured
    # (dict/list) expected value that substring would miss once JSON braces are re-sorted.
    if expected is not None and expected != after and expected not in after:
        return INCONCLUSIVE, (
            "the read-back changed from the baseline, but does not contain the attacker-intended value "
            "-- the change may be unrelated to the attack; confirm the mutation that landed is intended")

    return CONFIRMED, (
        "independent read-back shows the target state changed from the baseline read before the attack"
        + (" to the attacker-intended value" if expected is not None else "")
        + " -- the state actually changed")


def readback_signature_advisory(success_signature, method, state_change_authorized: bool) -> str | None:
    """Advisory for a CEM success_signature used on a STATE-CHANGING experiment.

    A CEM experiment is state-changing when its base_request method is not
    read-only, or an explicit nonidempotent_approval authorizes a state-changing
    method. In that case a success_signature that sets `status_in` but NO
    independent-content matcher (body_contains / body_regex / similarity_to_baseline)
    can be satisfied by the mutating request's status/redirect alone -- so it cannot
    distinguish a real write from a benign 2xx/302 silent rejection (issue #144).

    Returns a warning string to surface to the caller, or None when not applicable.
    This is ADVISORY only, never a rejection: the signature is still structurally
    valid under UD-3, a status-only oracle is perfectly legitimate for a read-only
    capability, and the CEM method-policy path (legitimately) uses status-only
    signatures for experiments that are not trying to prove a real-world state
    change. The conclusion-side rule is enforced by confirm_state_change() and the
    exploit-agent methodology, not by refusing the signature here.
    """
    m = method.strip().upper() if isinstance(method, str) else ""
    is_state_changing = bool(state_change_authorized) or (bool(m) and m not in _READ_ONLY_METHODS)
    if not is_state_changing or not isinstance(success_signature, dict):
        return None
    has_status = success_signature.get("status_in") is not None
    has_content = any(success_signature.get(k) is not None
                      for k in ("body_contains", "body_regex", "similarity_to_baseline"))
    if has_status and not has_content:
        return (
            "state-changing CEM experiment with a status-only success_signature: a 2xx/302/redirect on "
            "the mutating request cannot independently prove the state changed (a control can return a "
            "benign redirect while silently rejecting the write -- issue #144). Point the oracle at an "
            "independent read-back -- a body_contains/body_regex/similarity match against a RE-FETCH of "
            "the affected resource, or an out-of-band callback -- before concluding the control is "
            "bypassable.")
    return None
