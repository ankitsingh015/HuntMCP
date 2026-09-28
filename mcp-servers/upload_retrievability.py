"""Uploaded-object non-retrievability check -- turns "I guessed a handful
of paths and they all 404'd" into a bounded, evidence-shaped verdict
instead of an ad-hoc, undocumented sweep.

Why this exists: a negative-result claim like "uploaded content is not
publicly served" was previously bounded only by whatever candidate paths
an agent happened to hand-pick, with no standard primitive to verify
non-retrievability more systematically or to distinguish "genuinely not
found" from "found something odd" -- reported live in an engagement
retrospective (eight hand-picked candidate paths all returned the static
404, but the residual was honestly recorded as "unknown" rather than
"verified negative," since nothing established that all eight responses
were actually the SAME kind of 404 a genuinely nonexistent object gets).

The core idea: a target's real "not found" response has a stable shape
(status + body). This module requires the CALLER to supply an explicit
`baseline_url` known to be genuinely nonexistent (deliberately NOT
auto-derived -- same "no auto-derived success oracle" principle as this
repo's CEM success_signature, PHASE1-EXECUTION-PLAN UD-3: guessing wrong
about what a "clean 404" looks like would produce false confidence, which
is worse than an honest "unknown"). Every candidate is then compared
against that baseline: a candidate matching it is evidence of
non-retrievability; a bare 200 is evidence of retrievability; anything
else (a DIFFERENT non-200 shape, e.g. 403 where the baseline was 404) is
flagged as anomalous rather than silently folded into either verdict.

Generic (works against any storage namespace) -- constructing the
candidate path guesses themselves (which requires target-specific
knowledge of the stack's static-root conventions) stays the caller's job,
same "generic primitive, per-target logic stays out" philosophy as
idor_sweep.py.

Uses only the standard library (via http_probe.py) -- no new dependency.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass, field

from http_probe import DEFAULT_TIMEOUT_S
from http_probe import fetch as _fetch

# Same threshold family/spirit as idor_sweep.py's LEAKED_RATIO_THRESHOLD --
# difflib.SequenceMatcher's ratio() on two response bodies, not a security
# boundary itself, just how "close enough to call it the same 404 shape"
# is drawn.
BASELINE_MATCH_RATIO_THRESHOLD = 0.95


@dataclass
class RetrievabilityCandidate:
    url: str
    status: int | None
    matches_baseline: bool
    error: str | None = None


@dataclass
class RetrievabilityResult:
    baseline_url: str
    baseline_status: int | None
    candidates: list[RetrievabilityCandidate] = field(default_factory=list)
    verdict: str = "unknown_no_candidates"
    retrievable_at: str | None = None


def _bodies_match(a: str, b: str) -> bool:
    if a == b:
        return True
    return difflib.SequenceMatcher(None, a, b).ratio() >= BASELINE_MATCH_RATIO_THRESHOLD


def check_retrievability(candidate_urls: list[str], baseline_url: str, *,
                          cookie_header: str | None = None, bearer_token: str | None = None,
                          timeout_s: float = DEFAULT_TIMEOUT_S) -> RetrievabilityResult:
    """Fetch `baseline_url` (a URL the caller KNOWS is genuinely
    nonexistent under the same storage namespace) once, then fetch every
    `candidate_urls` entry and compare each against it.

    Verdicts:
      "unknown_no_candidates"       -- candidate_urls was empty.
      "unknown_baseline_unreachable" -- the baseline itself couldn't be
                                        fetched; nothing can be compared
                                        against it, so no candidate result
                                        is trustworthy either way.
      "retrievable"                 -- at least one candidate returned 200.
                                        retrievable_at names the first one.
      "unknown_anomalous_response"  -- at least one candidate was neither a
                                        clean 200 NOR a baseline match (a
                                        different status or a differently-
                                        shaped body) -- needs a human look,
                                        not silently folded into either
                                        clean verdict.
      "verified_not_retrievable"    -- every candidate matched the
                                        baseline's status+body shape.
    """
    headers: dict[str, str] = {}
    if cookie_header:
        headers["Cookie"] = cookie_header
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"

    if not candidate_urls:
        return RetrievabilityResult(baseline_url=baseline_url, baseline_status=None)

    baseline = _fetch(baseline_url, "GET", headers, None, timeout_s)
    if baseline.error is not None:
        return RetrievabilityResult(
            baseline_url=baseline_url, baseline_status=None, verdict="unknown_baseline_unreachable",
        )

    candidates: list[RetrievabilityCandidate] = []
    any_retrievable = False
    any_anomalous = False
    retrievable_at: str | None = None

    for url in candidate_urls:
        r = _fetch(url, "GET", headers, None, timeout_s)
        if r.error is not None:
            candidates.append(RetrievabilityCandidate(url=url, status=None, matches_baseline=False, error=r.error))
            any_anomalous = True
            continue
        if r.status == 200:
            candidates.append(RetrievabilityCandidate(url=url, status=r.status, matches_baseline=False))
            any_retrievable = True
            if retrievable_at is None:
                retrievable_at = url
            continue
        matches = r.status == baseline.status and _bodies_match(r.body, baseline.body)
        candidates.append(RetrievabilityCandidate(url=url, status=r.status, matches_baseline=matches))
        if not matches:
            any_anomalous = True

    if any_retrievable:
        verdict = "retrievable"
    elif any_anomalous:
        verdict = "unknown_anomalous_response"
    else:
        verdict = "verified_not_retrievable"

    return RetrievabilityResult(
        baseline_url=baseline_url, baseline_status=baseline.status,
        candidates=candidates, verdict=verdict, retrievable_at=retrievable_at,
    )
