"""Cross-account IDOR/BOLA sweep -- automates the highest-value manual
grind in access-control testing: given a URL template with an `{id}`
placeholder, a list of object ids known to belong to one account (the
"owner"), and a second account's credentials (the "other" identity being
tested for improper access), fetch every id once as each identity and
classify the pair automatically instead of hand-crafting and eyeballing
each curl pair one at a time.

Genuinely generic (works against any REST-shaped endpoint, no per-target
logic) -- what stays per-target and out of scope for this tool is
producing the object ids and the two credentials in the first place
(recon/exploit-agent's own job), and confirming a LEAKED verdict actually
constitutes sensitive data before writing it up (case-mcp's evidence-gate
already requires that for CONFIRMED; this tool feeds candidates into that
gate, it doesn't bypass it).

Auth is seeded the same way browser-mcp's cookie_header/bearer_token
params work (same "name=value; name2=value2" cookie-header string, same
bearer-token convention) -- one shared mental model across every tool in
this repo that needs to act as an authenticated identity, not a third
format to learn.

Uses only the standard library (urllib) -- no new dependency, and no
browser needed since IDOR targets are almost always JSON/REST APIs, not
rendered pages (browser-mcp's cookie/bearer/local_storage seeding is the
tool for when a *rendered page* needs to be diffed across roles instead).
"""

from __future__ import annotations

import difflib
import urllib.error
import urllib.request
from dataclasses import dataclass, field

DEFAULT_TIMEOUT_S = 15

# Thresholds against difflib.SequenceMatcher's ratio() (0.0-1.0) comparing
# the owner's own response body to the other identity's response body for
# the same object id, once both returned 200. Not a security boundary in
# themselves -- a classification aid for a human/agent to prioritize
# manual confirmation, same spirit as case-mcp's confidence bands.
LEAKED_RATIO_THRESHOLD = 0.9
AMBIGUOUS_RATIO_THRESHOLD = 0.5

PROTECTED_STATUSES = {401, 403, 404}

# Fraction of one sweep's verdicts that come back OWNER_BASELINE_FAILED
# above which the failure is almost certainly systemic (a dead/expired
# owner_cookie_header or owner_bearer_token), not N independently
# nonexistent object ids -- see SweepResult.owner_baseline_failure_warning().
OWNER_BASELINE_FAILURE_WARNING_RATIO = 0.8
# Below this many tested ids, a high failure ratio is just as likely to be
# a couple of genuinely bad ids in a small batch as a systemic credential
# problem -- not enough signal to call it out as a warning either way.
OWNER_BASELINE_FAILURE_MIN_SAMPLE = 3


@dataclass
class FetchResult:
    status: int | None
    body: str
    error: str | None = None


@dataclass
class IdVerdict:
    object_id: str
    owner_status: int | None
    other_status: int | None
    verdict: str
    similarity: float | None = None
    detail: str = ""


@dataclass
class SweepResult:
    url_template: str
    verdicts: list[IdVerdict] = field(default_factory=list)

    def summary_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for v in self.verdicts:
            counts[v.verdict] = counts.get(v.verdict, 0) + 1
        return counts

    def owner_baseline_failure_warning(self) -> str | None:
        """None unless OWNER_BASELINE_FAILED verdicts dominate this sweep --
        in which case that's almost certainly one systemic problem (the
        owner credential is dead/expired/invalid), not N separately
        nonexistent object ids, and every other verdict in the sweep is
        untrustworthy until it's fixed. Per-id OWNER_BASELINE_FAILED already
        says this for one id; a caller skimming a long verdict list can
        still miss that the SAME reason repeated across most of the batch,
        so this is a summary-level check, not a duplicate of the per-id one.
        Modeled on the same principle CyberStrike's hackbrowser navigator.ts
        applies to its own crawl planner: a systemic auth failure must
        surface as a hard, specific warning, never blend into an ordinary
        "nothing found here" result."""
        total = len(self.verdicts)
        if total < OWNER_BASELINE_FAILURE_MIN_SAMPLE:
            return None
        failed = sum(1 for v in self.verdicts if v.verdict == "OWNER_BASELINE_FAILED")
        ratio = failed / total
        if ratio < OWNER_BASELINE_FAILURE_WARNING_RATIO:
            return None
        return (
            f"⚠️ {failed}/{total} ({ratio:.0%}) object ids came back OWNER_BASELINE_FAILED. "
            "This pattern is almost always a dead/expired/invalid owner_cookie_header or "
            "owner_bearer_token, not N separately nonexistent object ids -- verify the owner "
            "credential is still valid and re-run before trusting any verdict in this sweep."
        )


def _build_headers(cookie_header: str | None, bearer_token: str | None) -> dict[str, str]:
    headers: dict[str, str] = {}
    if cookie_header:
        headers["Cookie"] = cookie_header
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    return headers


def _fetch(url: str, method: str, headers: dict[str, str], body: str | None,
           timeout_s: float) -> FetchResult:
    data = body.encode() if body else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return FetchResult(status=resp.status, body=resp.read().decode(errors="replace"))
    except urllib.error.HTTPError as e:
        # A 401/403/404 (the exact protected-vs-leaked signal we care
        # about) raises HTTPError in urllib rather than returning
        # normally -- still a real, meaningful response, not a failure.
        return FetchResult(status=e.code, body=e.read().decode(errors="replace"))
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return FetchResult(status=None, body="", error=str(e))


def _classify(owner: FetchResult, other: FetchResult) -> tuple[str, float | None, str]:
    if owner.error:
        return "ERROR", None, f"owner request failed: {owner.error}"
    if owner.status != 200:
        return "OWNER_BASELINE_FAILED", None, (
            f"owner's own request returned {owner.status}, not 200 -- can't use this id as a "
            "baseline (either it isn't really the owner's object, or the owner credential itself "
            "is stale/invalid). Same failure mode as an 'empty test account' -- fix the baseline "
            "before trusting any verdict for this id."
        )
    if not owner.body.strip():
        return "OWNER_BASELINE_FAILED", None, (
            "owner's own request returned 200 but an empty body -- nothing to compare against. "
            "This is the 'empty account, no real data to steal' problem at the tooling level: "
            "provision real data on the owner account before re-running this id."
        )

    if other.error:
        return "ERROR", None, f"other-identity request failed: {other.error}"
    if other.status in PROTECTED_STATUSES:
        return "PROTECTED", None, f"other identity got {other.status} -- access control appears to be working"

    if other.status != 200:
        return "ERROR", None, f"other identity got unexpected status {other.status}, neither 200 nor a protected status"

    ratio = difflib.SequenceMatcher(None, owner.body, other.body).ratio()
    if ratio >= LEAKED_RATIO_THRESHOLD:
        return "LEAKED", ratio, (
            f"other identity got 200 with a body {ratio:.0%} similar to the owner's own view of "
            "the same id -- strong signal of real IDOR/BOLA. Confirm manually (this tool flags "
            "candidates, it doesn't itself decide the data is sensitive) before calling CONFIRMED."
        )
    if ratio >= AMBIGUOUS_RATIO_THRESHOLD:
        return "AMBIGUOUS", ratio, (
            f"other identity got 200 with a body only {ratio:.0%} similar to the owner's -- could "
            "be partial leakage, could be a differently-shaped response for a denied request. "
            "Needs a manual look, not an automatic verdict either way."
        )
    return "DIFFERENT", ratio, (
        f"other identity got 200 but the body is only {ratio:.0%} similar to the owner's -- likely "
        "a generic/soft-404-style page that returns 200 rather than a real access-control bypass, "
        "but confirm rather than assume: some APIs' real per-object payloads are legitimately this "
        "different in size/shape from each other."
    )


def check_one_id(url_template: str, object_id: str, method: str,
                  owner_headers: dict[str, str], other_headers: dict[str, str],
                  body_template: str | None, timeout_s: float) -> IdVerdict:
    """The actual per-id work (2 real HTTP requests -- one per identity),
    factored out of sweep_idor() so a caller that needs to enforce a
    budget/rate-limit PER ID (not once for an entire batch, which would
    undercount how many real requests a large object_ids list actually
    sends -- see idor-mcp/server.py's own comment on this) can call this
    directly in its own loop instead of only getting an all-or-nothing
    batch function."""
    url = url_template.replace("{id}", object_id)
    body = body_template.replace("{id}", object_id) if body_template else None

    owner_resp = _fetch(url, method, owner_headers, body, timeout_s)
    other_resp = _fetch(url, method, other_headers, body, timeout_s)

    verdict, ratio, detail = _classify(owner_resp, other_resp)
    return IdVerdict(
        object_id=object_id,
        owner_status=owner_resp.status,
        other_status=other_resp.status,
        verdict=verdict,
        similarity=ratio,
        detail=detail,
    )


def sweep_idor(url_template: str, object_ids: list[str], method: str = "GET",
               owner_cookie_header: str | None = None, owner_bearer_token: str | None = None,
               other_cookie_header: str | None = None, other_bearer_token: str | None = None,
               body_template: str | None = None,
               timeout_s: float = DEFAULT_TIMEOUT_S) -> SweepResult:
    """Convenience batch wrapper around check_one_id() for direct/test use
    with no budget accounting -- idor-mcp/server.py's actual tool handler
    calls check_one_id() itself in a loop instead, so it can enforce the
    Tier-2 budget once per id (2 real requests) rather than once per
    sweep_idor() call, which would undercount a large object_ids list's
    real request volume. url_template must contain a literal `{id}`
    placeholder (e.g. "https://target.com/api/orders/{id}"). For each id
    in object_ids (each one known to actually belong to the OWNER
    identity), fetches it once as OWNER (the baseline -- confirms the id
    is real and returns actual data) and once as OTHER (the identity
    being tested for improper access to OWNER's object), then classifies
    the pair. Neither credential is required to be both cookie and
    bearer -- pass whichever the target actually uses; omit the other.
    body_template (with the same `{id}` placeholder) is sent as the
    request body for POST/PUT/PATCH; irrelevant for GET/DELETE."""
    owner_headers = _build_headers(owner_cookie_header, owner_bearer_token)
    other_headers = _build_headers(other_cookie_header, other_bearer_token)

    result = SweepResult(url_template=url_template)
    for object_id in object_ids:
        result.verdicts.append(
            check_one_id(url_template, object_id, method, owner_headers, other_headers,
                         body_template, timeout_s)
        )
    return result
