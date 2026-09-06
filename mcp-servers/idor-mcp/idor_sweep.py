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
from dataclasses import dataclass, field

from http_probe import DEFAULT_TIMEOUT_S, FetchResult
from http_probe import build_headers as _build_headers
from http_probe import fetch as _fetch

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


# ---------------------------------------------------------------------------
# Single-credential ID-guess mode -- doesn't need a second identity. Instead
# of diffing owner-vs-other on ids already known to belong to the owner, this
# takes ONE credential and ONE known-good id, then tries ids that plausibly
# DON'T belong to that credential (sequential neighbors, small/admin-like
# ids, the negative variant) and checks whether the same credential can pull
# them anyway. Real for auto-increment integer ids; UUIDs/hashids can't be
# meaningfully sequence-guessed this way, so generate_id_guesses() returns
# nothing for a non-numeric known_id rather than pretending to guess one.
#
# This can only ever report PROTECTED/ACCESSIBLE/EMPTY_RESPONSE/ERROR, never
# sweep_idor()'s LEAKED -- LEAKED requires a second identity's response body
# to diff against as evidence the data really is someone else's. A single
# credential getting 200 on a guessed id is a strong lead, not proof; the
# verdict detail says so explicitly rather than overclaiming confirmation.
# ---------------------------------------------------------------------------

GUESS_ADMIN_LIKE_IDS = (0, 1)


def generate_id_guesses(known_id: str, count: int = 10) -> list[str]:
    """Generate up to `count` candidate ids to guess, given one id already
    known to be real. Returns [] for a non-numeric known_id (UUIDs, hashids,
    ULIDs) -- there's no meaningful "neighbor" of a random-looking identifier,
    unlike a plain auto-increment integer. Order: small/admin-like ids first
    (id=0/1 is very often an admin/system/seed account on auto-increment
    schemes -- cheap, high-value guesses), then the negative variant (some
    frameworks never validate that an id can't be negative because "no real
    id is negative" feels obvious enough not to test), then sequential
    neighbors alternating +/- outward from known_id (closest -- most likely
    to be a real adjacent account/order -- tried first). known_id itself is
    never re-tested."""
    try:
        base = int(known_id)
    except ValueError:
        return []

    seen = {base}
    out: list[int] = []

    def _add(candidate: int) -> None:
        if candidate not in seen:
            seen.add(candidate)
            out.append(candidate)

    for admin_id in GUESS_ADMIN_LIKE_IDS:
        _add(admin_id)
    if base > 0:
        _add(-base)

    offset = 1
    while len(out) < count:
        _add(base + offset)
        if len(out) >= count:
            break
        _add(base - offset)
        offset += 1

    return [str(c) for c in out[:count]]


@dataclass
class GuessVerdict:
    object_id: str
    status: int | None
    verdict: str
    detail: str = ""


@dataclass
class GuessSweepResult:
    url_template: str
    known_id: str
    baseline_ok: bool = True
    baseline_detail: str = ""
    verdicts: list[GuessVerdict] = field(default_factory=list)

    def summary_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for v in self.verdicts:
            counts[v.verdict] = counts.get(v.verdict, 0) + 1
        return counts


def _classify_guess(resp: FetchResult) -> tuple[str, str]:
    if resp.error:
        return "ERROR", f"request failed: {resp.error}"
    if resp.status in PROTECTED_STATUSES:
        return "PROTECTED", f"got {resp.status} -- access control appears to be working for this id"
    if resp.status != 200:
        return "ERROR", f"unexpected status {resp.status}, neither 200 nor a protected status"
    if not resp.body.strip():
        return "EMPTY_RESPONSE", (
            "got 200 but an empty body -- likely not a real object at this id, not a confirmed "
            "access issue either way"
        )
    return "ACCESSIBLE", (
        "got 200 with a non-empty body for an id not already known to belong to this credential -- "
        "verify by hand whether the object actually belongs to the tested account before calling "
        "this an IDOR. Single-credential guessing can't auto-diff against an owner baseline the way "
        "the two-identity sweep_idor() can, so this is a strong lead, not proof."
    )


def check_one_guess(url_template: str, object_id: str, method: str, headers: dict[str, str],
                     body_template: str | None, timeout_s: float) -> GuessVerdict:
    """The actual per-guess work (1 real HTTP request), factored out the same
    way check_one_id() is so a caller enforcing budget per guess can call
    this directly in its own loop."""
    url = url_template.replace("{id}", object_id)
    body = body_template.replace("{id}", object_id) if body_template else None
    resp = _fetch(url, method, headers, body, timeout_s)
    verdict, detail = _classify_guess(resp)
    return GuessVerdict(object_id=object_id, status=resp.status, verdict=verdict, detail=detail)


def sweep_idor_guess(url_template: str, known_id: str, method: str = "GET",
                      cookie_header: str | None = None, bearer_token: str | None = None,
                      guess_count: int = 10, body_template: str | None = None,
                      timeout_s: float = DEFAULT_TIMEOUT_S) -> GuessSweepResult:
    """Convenience batch wrapper (no budget accounting -- idor-mcp/server.py's
    guess_idor tool calls check_one_guess() itself in a loop, same reasoning
    as sweep_idor()/check_one_id()) for single-credential ID-guess testing.
    Confirms known_id itself still works with this credential FIRST -- same
    "don't trust anything built on a dead credential" lesson as
    SweepResult.owner_baseline_failure_warning() above, applied preemptively
    here instead of after the fact: there's no point spending budget on N
    guesses if the one id already known to work doesn't. If that baseline
    check fails, returns immediately with baseline_ok=False and no guesses
    attempted."""
    headers = _build_headers(cookie_header, bearer_token)
    result = GuessSweepResult(url_template=url_template, known_id=known_id)

    baseline_url = url_template.replace("{id}", known_id)
    baseline_body = body_template.replace("{id}", known_id) if body_template else None
    baseline = _fetch(baseline_url, method, headers, baseline_body, timeout_s)
    if baseline.error or baseline.status != 200 or not baseline.body.strip():
        result.baseline_ok = False
        result.baseline_detail = (
            f"known_id baseline check failed (status={baseline.status}, error={baseline.error!r}) -- "
            "the credential may be invalid/expired, or known_id doesn't actually belong to it. "
            "Guessing skipped."
        )
        return result

    for guess_id in generate_id_guesses(known_id, guess_count):
        result.verdicts.append(
            check_one_guess(url_template, guess_id, method, headers, body_template, timeout_s)
        )
    return result
