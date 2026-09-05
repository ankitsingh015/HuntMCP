"""Phase-1 Counterfactual Evidence Minimization (CEM) engine -- pure logic, no MCP, no
network, no database. Mirrors how idor-mcp/idor_sweep.py backs idor-mcp/server.py:
this module holds the algorithm, unit-testable on its own; case-mcp/server.py (a later
task) will be the thin MCP wrapper around it.

Task C1: the SuccessSignature contract -- the machine-checkable security-effect oracle a
caller must explicitly supply before CEM can test whether a perturbation "kills the
capability" (PHASE1-PLAN.md D5, UD-3).

Task C2: determinism_gate -- re-runs an unperturbed base_request k times and classifies
the finding STABLE (all-k HIT) or NONDETERMINISTIC (anything else), the literal binary
contract from PHASE1-PLAN.md sec 2.5.1 / PHASE1-EXECUTION-PLAN.md task C2. Still pure
logic: fetch_fn is caller-injected (matching http_probe.fetch's exact signature), so this
module makes no network call itself.

Task C3: classify -- the 3-verdict classifier (necessary / apparently_not_necessary /
inconclusive) over already-observed baseline-arm and perturbed-arm hit sequences
(PHASE1-PLAN.md sec D "Verdict rules"). Pure classification: no fetch, no perturbation
execution. 429/throttle detection is explicitly OUT OF SCOPE (human-approved 2026-09-05,
stopped and asked rather than guessed) -- it's the executor's job (task D3, which
inspects real HTTP status as trials happen), not classify()'s; classify() only ever sees
plain hit/miss bools, matching DeterminismResult.hits' type exactly. Race/TOCTOU ->
`probabilistic` (C4) and interaction detection -> `interacting` (C6) are separate later
tasks, not this 3-verdict classifier.

Task C4: classify_race -- the race/TOCTOU path. PHASE1-PLAN.md sec D lists "finding
flagged race/TOCTOU -> `probabilistic` (report perturbed HIT-rate; never `necessary`)"
but (unlike C1/C2/C3) names no function/signature -- a genuine ambiguity, stopped and
asked rather than guessed (2026-09-05). Resolved: a new, separate pure function rather
than widening classify()'s C3-pinned 3-arg signature. classify_race(perturbed_hits, k)
-> RaceResult always returns VERDICT_PROBABILISTIC (hardcoded, so it structurally can
never return "necessary" regardless of hit pattern) plus the observed perturbed-arm
HIT-rate. No baseline_hits, no boolean race flag -- being routed to this function at
all is the race flag. Still pure: no fetch, no HTTP, no perturbation execution.

Task C5: minimal_condition_sets -- recovers ONE 1-minimal condition set via ddmin
(PHASE1-PLAN.md sec "Multiple minimal sets"). PHASE1-PLAN.md gives the defining
property precisely ("a subset is interesting iff, with all conditions outside it
perturbed to non-triggering, the oracle is unanimously HIT over k") but, unlike
C1/C2/C3, names no concrete pure-function signature at the engine layer -- a genuine
ambiguity, stopped and asked rather than guessed (2026-09-05). Resolved with the
human (of 3 options presented): an injected pure predicate
`is_interesting: Callable[[frozenset[str]], bool]`, matching classic
ddmin(test, circumstances) exactly and mirroring C2's fetch_fn-injection precedent.
Strictly bool -- the plan's own "interesting" definition is already binary, so no
inconclusive/tri-state channel is invented here; a predicate returning anything other
than a real bool is a hard TypeError. Alternates and interaction detection are task
C6, not this function -- minimal_condition_sets finds exactly one 1-minimal set.

Task C6: find_alternate_condition_sets -- alternates + interaction detection, built
strictly ON TOP OF C5's minimal_condition_sets() (reused verbatim via a direct call,
never reimplemented or modified -- "must extend rather than redesign"). Implements
PHASE1-PLAN.md sec 11 ("Multiple minimal sets") literally:
  - Alternates: "for each c in M1, force-exclude c and re-run ddmin -> collect
    distinct minimal sets" -- scoped to M1's own members exactly as written.
  - Interactions, 2 explicit rules, nothing else (never infer an interaction merely
    from co-occurrence): Rule 1 -- "c singly apparently_not_necessary but present in
    every recovered minimal set"; Rule 2 -- "a pair whose joint removal flips the
    oracle while neither single removal does".
  - "Bounded by budget_guard; report sets_found=k, trials_used=n, bounded=True/False"
    -- implemented as an injected `max_trials` cap (never a real budget_guard import;
    C6 stays pure, no network, no DB, mirroring D2's stated "budget via injected
    callback, MCP-free" design), with the 3 named fields reported verbatim.

Two ambiguities were stopped-and-asked rather than guessed (2026-09-05, both
human-approved):

(1) Rule 1's "present in every recovered minimal set" is checked against every
recovered set EXCEPT (a) c's own force-excluded alternate -- which structurally can
never contain c, since c isn't even a candidate in that sub-search -- and (b) M1
itself when c is one of M1's own members, since "c is in M1" merely restates the
Rule-1 precondition rather than independently confirming persistence elsewhere.
Including either would make Rule 1 either vacuously impossible (reading a) or
tautological (reading b). At least one genuinely independent comparison set is
required for the rule to be eligible at all; zero is insufficient evidence, not a
firing (never overclaim from an empty comparison).

(2) The pool of conditions tested for individual droppability (is_interesting(S-{c}),
feeding both rules) is every condition in the ORIGINAL candidate set S, not just M1's
members -- the Alternates SET-FINDING procedure itself stays M1-scoped exactly as
literally written, but interaction-candidate testing is broadened. Reason: ddmin's
greedy single-pass sweep can drop one half of a genuine interacting pair before it
ever reaches M1 (e.g. conditions=[a,b,d], is_interesting = d and (a or b) -- ddmin
drops "a" immediately, landing on M1={b,d}; "a" never becomes an M1 member, yet
is_interesting(S-{a})=True, is_interesting(S-{b})=True, is_interesting(S-{a,b})=False
is a genuine Rule-2 interaction that an M1-only scope would silently miss).

Deliberately NOT here: modifying minimal_condition_sets/classify/classify_race/
evaluate_signature/SuccessSignature (all reused unmodified); a 4th verdict on
classify()'s return value (interacting is a separate flag/result, exactly how
classify_race's `probabilistic` is a separate function/result, not a widened
classify() signature); any claim that an "interacting"-flagged condition is
necessary (interacting and necessary are orthogonal -- C6 never calls classify() or
classify_race() at all); real network/DB/budget_guard/MCP access.

C6 addendum -- mutual AND-necessity detection (retrospective audit fix, human-
approved 2026-09-05, Option 2 of 3 presented): the audit found that Rule 1/Rule 2
above cannot detect a pure "both conditions strictly required together" pattern
(e.g. role_admin AND flag_on) -- PHASE1-PLAN.md's own Rule 2 wording ("a pair whose
joint removal flips the oracle while neither single removal does") is the exact
mathematical signature of OR-REDUNDANCY (either alone still works), not AND-
necessity (neither alone works) -- for a genuine AND, neither condition ever enters
`droppable_singly` in the first place, so Rule 1/Rule 2 structurally cannot fire on
it, by design, not by bug. `find_alternate_condition_sets` itself is UNTOUCHED by
this fix (byte-for-byte unchanged: same Rule 1/Rule 2 logic, same fields, same
tests, same values it always produced) -- AND-necessity is a SEPARATE, additive
detection path: `AndNecessityGroup` + `find_and_necessity_groups()`, a new pure
post-processing function over the SAME `minimal_sets` list `find_alternate_
condition_sets` already returns, needing zero additional `is_interesting` calls
(the signal is already implicit in 1-minimality: any recovered minimal set with
>=2 members means, by ddmin's own termination condition, that removing any single
member -- with everything else already perturbed away -- breaks the effect; that
IS mutual AND-necessity, already proven by the search that found it).

Representation and how it coexists with `necessary` (the exact design decision):
AND-necessity is reported as membership in an `AndNecessityGroup` (a condition-
NAME-only frozenset, mirroring `InteractionEvidence`'s existing pair-evidence
shape, generalized from a pair to an n-ary group) -- a STRUCTURAL annotation
about a *recovered minimal set*, never a verdict string and never a replacement
for one. `classify()` (task C3) is not modified, not called by this addition, and
keeps computing "necessary" for role_admin and flag_on exactly as it always did
under the one-variable-at-a-time protocol (removing either alone, holding the
other fixed at baseline, breaks the capability -- that IS "necessary" under C3's
own literal contract, correctly). A future synthesis layer (not built here) can
present BOTH facts side by side for the same two conditions -- "role_admin:
necessary", "flag_on: necessary", AND "and_necessity_groups: [{role_admin,
flag_on}]" -- without either fact overriding the other. This is deliberately the
narrowest fix that satisfies "detect the signal" without touching classify()'s
verdict vocabulary, the `cem_verdicts` schema's single-`verdict`-column semantics,
or any existing OR-redundancy test/behavior (Option 1 -- rewriting the benchmark's
ground truth to expect two `necessary`s instead of `interacting` -- and Option 3
-- redefining what `interacting` means bundle-wide -- were both presented and NOT
chosen; wiring this new signal into the benchmark's answer key / a bundle field is
explicitly future work, not part of this fix).

Task C7: minimize_poc -- PoC minimization. PHASE1-PLAN.md sec 12: "PoC minimization
reuses the SAME ddmin with the oracle as interestingness" -- so minimize_poc() calls
minimal_condition_sets() (C5) directly, never reimplementing ddmin a second time.
"steps" is not a separate concept anywhere in the plan (checked: it only ever
appears as a loose synonym for "conditions/fields", no dedicated dataclass exists)
-- minimize_poc() operates over the exact same `conditions: list[str]` abstraction
as C5/C6.

Re-validation ("output re-validated through determinism_gate ... guards a DD local
optimum dropping a real step") is an injected `revalidate:
Callable[[frozenset[str]], DeterminismResult]` callable -- kept abstract so this
function stays pure/no-network, exactly how `is_interesting` already stands in for
a real oracle check, reusing C2's own DeterminismResult type unmodified rather than
inventing new determinism vocabulary. Resolved directly from the plan's own text,
not guessed: "ddmin local optimum drops a needed step. Mitigation: re-validate
minimal set/PoC via determinism gate; optional DDMIN* re-iterate" -- the
re-iteration is explicitly marked OPTIONAL, i.e. not part of Phase 1's minimum bar.
So on a NONDETERMINISTIC revalidation, minimize_poc() does not retry/backtrack --
it reports `accepted=False` honestly (poc still returned as evidence, but flagged
as not validated), matching determinism_gate's own established "no majority vote,
no retries beyond exactly k trials" principle.

Deliberately NOT here (any task in this file so far): intervention execution,
perturbation, replication beyond exactly k trials, confounder pinning/Controls, database
writes, model calls, or intelligence routing -- those are later Group C/D/E tasks.

UD-3 (approved, PHASE1-EXECUTION-PLAN.md sec 2): the oracle is explicit and caller-supplied
only. There is no function anywhere in this module that derives a SuccessSignature from a
baseline response, a status code, a finding's vuln_class, or any other heuristic --
SuccessSignature can only be built by a caller passing every matcher value itself, and
construction is refused (ValueError, at both direct-dataclass-construction and from_dict
time) if zero matchers are set. "Zero matchers set" is not the only way to construct a
vacuously always-true oracle, though -- a *set* matcher can still be individually vacuous
(retrospective audit finding, fixed): `body_contains=""` (`"" in body` is True for every
body) and `similarity_to_baseline.threshold<=0.0` (`SequenceMatcher.ratio()` is never
negative) both used to pass construction while always evaluating True regardless of the
target's actual response. Both are now refused at construction (ValueError) for the same
reason as the zero-matchers case: an oracle that always fires is exactly as unable to
distinguish "the capability fired" from "it didn't" as an oracle with nothing to check.

similarity_to_baseline contract note: PHASE1-PLAN.md D5 sketches signatures as a flat
`{status_in:[...], body_contains/body_regex, or similarity_to_baseline >= t}` dict, but
evaluate_signature is documented everywhere else as strictly 2-arg (FetchResult, sig) --
a similarity check needs two bodies to compare, and nothing else in the plan says where a
second body would come from. Resolved with the human (2026-09-05, stopped and asked rather
than guessed): similarity_to_baseline is a nested {body, threshold} object embedded in the
signature itself, so the reference body travels inside `sig` and evaluate_signature stays a
pure, self-contained 2-arg function.

Task C8: assemble_bundle -- the last task in Group C. Assembles the "Triager-Proof
Bundle" (XYZ.md sec 2.8, 11 fields, plus 4 more from PHASE1-PLAN.md: verdict labels,
controls, k, completeness bound -- 15 total) as a single JSON-serializable, redacted
dict. C8's only declared deps are C3..C7, NOT the not-yet-built intervention executor
(D1-D3) or case_store/case-mcp (E1) -- so this is a pure aggregator over already-
computed C1-C7 result types (DeterminismResult, AlternateSetsResult,
PocMinimizationResult) plus raw caller-supplied context, exactly mirroring C2's
injected fetch_fn / C7's injected revalidate precedent: it accepts typed inputs and
never reaches past them (no fetch, no determinism_gate/classify/classify_race/
minimal_condition_sets/find_alternate_condition_sets/minimize_poc call of its own, no
DB, no MCP).

Fields 9 (`minimal_condition_sets`) and 15 (`completeness_bound`) both unpack the
same AlternateSetsResult but are deliberately kept as two distinct top-level keys
(set contents vs. completeness counts), never nested one inside the other, per the
brief. Fields 5/13 (`controlled_pinned_conditions`/`controls`) and 4/14
(`replication_counts`/`k`) are, by contrast, intentional literal duplicates of the
same caller-supplied value under two different key names (PHASE1-PLAN.md's own
separate naming) -- not a bug to collapse. `identified_necessary_conditions` is
derived from `verdict_labels` (sorted keys whose value equals VERDICT_NECESSARY)
rather than accepted as a separate caller-supplied field, so the two can never
silently disagree. `finding_id` is included for bundle identity/traceability but is
not one of the 15 sec-2.8 fields -- a 16th key.

Redaction: `redact_text` (redact.py) operates on one string at a time only; the
recursive dict/list walk that applies it to every string leaf of the assembled
bundle (`_redact_recursive` below) is bundle-assembly logic and stays in this
module rather than redact.py. Applied exactly once, at the end, to the whole
assembled dict, so no field can be assembled after the redaction pass and left
raw. `k` (an int, field 14) is never redacted -- `_redact_recursive` already
leaves every non-string leaf (int/float/bool/None) untouched, so this falls out
for free rather than needing a special case.

Retrospective audit fix: redact_text()'s two name-based rules need the secret's
key NAME embedded in the same string as the value (a flat "Authorization: xyz"
line, or a "token=xyz" pair) -- a dict walk that redacts values in isolation from
their keys can never satisfy that, so only the two VALUE-SHAPE rules (JWT, card
number) ever fired on a dict value. `_redact_recursive` now also checks each
dict KEY against `redact.KNOWN_SECRET_HEADER_NAMES` (the same 4 names
`_HEADER_LINE_RE` already recognizes) before recursing into its value, and
redacts the whole value via the newly-public `redact.redacted()` when it
matches -- exact (case-insensitive) match only, so real CEM condition names
like "session_cookie"/"auth_cookie" (substrings of "cookie"/"auth" but never
equal to them) are never wrongly caught.

Deliberately NOT here: intervention execution, perturbation, replication beyond
what the caller already computed, confounder pinning, database writes, model
calls, "never auto-submitted" draft/review workflow (report-agent / a later
phase) -- only the redaction half of C8's acceptance criterion is this module's
job.
"""

from __future__ import annotations

import difflib
import itertools
import re
from collections.abc import Callable
from dataclasses import dataclass

from http_probe import DEFAULT_TIMEOUT_S, FetchResult
from redact import KNOWN_SECRET_HEADER_NAMES, redact_text, redacted

_VALID_SIGNATURE_KEYS = {"status_in", "body_contains", "body_regex", "similarity_to_baseline"}
_VALID_SIMILARITY_KEYS = {"body", "threshold"}


@dataclass
class SimilarityToBaseline:
    """The reference body a response is diffed against, plus the minimum
    difflib.SequenceMatcher ratio (>0.0-1.0, inclusive of 1.0) required to count as a
    match -- same ratio mechanism idor_sweep.py already uses for owner-vs-other
    comparison. threshold=0.0 is refused (see below), not just "the loosest legal
    value": SequenceMatcher.ratio() is never negative, so a 0.0 threshold would match
    literally any body, silently behaving as an always-true oracle."""
    body: str
    threshold: float

    def __post_init__(self) -> None:
        if not isinstance(self.body, str):
            raise TypeError(f"similarity_to_baseline.body must be a string, got {type(self.body).__name__}")
        if isinstance(self.threshold, bool) or not isinstance(self.threshold, (int, float)):
            raise TypeError(
                f"similarity_to_baseline.threshold must be a number, got {type(self.threshold).__name__}"
            )
        if not (0.0 < self.threshold <= 1.0):
            raise ValueError(
                f"similarity_to_baseline.threshold must be > 0 and <= 1, got {self.threshold!r} -- "
                "a threshold of exactly 0.0 (or below) would always match, since "
                "difflib.SequenceMatcher.ratio() is never negative, silently behaving "
                "as an always-true oracle regardless of the compared body (UD-3 forbids "
                "a vacuous oracle, not just an empty one)"
            )


@dataclass
class SuccessSignature:
    """The explicit, caller-supplied capability oracle (UD-3). Every field is an
    independent matcher against a single FetchResult; whichever fields are set must ALL
    pass for the signature to be satisfied (AND semantics -- each additional field
    narrows the match, it never loosens it). At least one field must be set: a
    signature with nothing to check is rejected at construction, never treated as
    vacuously true or false."""
    status_in: list[int] | None = None
    body_contains: str | None = None
    body_regex: str | None = None
    similarity_to_baseline: SimilarityToBaseline | None = None

    def __post_init__(self) -> None:
        if self.status_in is not None:
            if not isinstance(self.status_in, list) or not all(
                isinstance(s, int) and not isinstance(s, bool) for s in self.status_in
            ):
                raise TypeError(f"status_in must be a list of ints, got {self.status_in!r}")
            if len(self.status_in) == 0:
                raise ValueError("status_in must not be empty")
        if self.body_contains is not None:
            if not isinstance(self.body_contains, str):
                raise TypeError(f"body_contains must be a string, got {type(self.body_contains).__name__}")
            if self.body_contains == "":
                raise ValueError(
                    "body_contains must not be an empty string -- \"\" in result.body is "
                    "True for every possible body, silently behaving as an always-true "
                    "oracle regardless of what the target actually returns (UD-3 forbids "
                    "a vacuous oracle, not just an empty one)"
                )
        if self.body_regex is not None:
            if not isinstance(self.body_regex, str):
                raise TypeError(f"body_regex must be a string, got {type(self.body_regex).__name__}")
            try:
                re.compile(self.body_regex)
            except re.error as e:
                raise ValueError(f"body_regex is not a valid regular expression: {e}") from e
        if self.similarity_to_baseline is not None and not isinstance(self.similarity_to_baseline, SimilarityToBaseline):
            raise TypeError(
                "similarity_to_baseline must be a SimilarityToBaseline instance, got "
                f"{type(self.similarity_to_baseline).__name__}"
            )
        if (self.status_in is None and self.body_contains is None
                and self.body_regex is None and self.similarity_to_baseline is None):
            raise ValueError(
                "success_signature must specify at least one matcher (status_in / body_contains / "
                "body_regex / similarity_to_baseline) -- UD-3 requires an explicit caller-supplied "
                "oracle; there is no default, empty, or auto-derived signature"
            )

    @classmethod
    def from_dict(cls, data: dict) -> SuccessSignature:
        """Build a SuccessSignature from the plain dict shape case_store.cem_define
        accepts and cem_load_state returns (JSON round-tripped through cem_meta.
        success_signature). Rejects anything not shaped exactly like the documented
        contract -- unknown keys, wrong types -- rather than silently ignoring or
        coercing them; every rejection funnels through the same __post_init__
        validation direct construction uses, so there is exactly one place the
        "what counts as a valid oracle" rule lives."""
        if not isinstance(data, dict):
            raise TypeError(f"success_signature must be a dict, got {type(data).__name__}")
        unknown = set(data) - _VALID_SIGNATURE_KEYS
        if unknown:
            raise ValueError(f"unknown success_signature key(s): {sorted(unknown)}")

        similarity_to_baseline = None
        sim = data.get("similarity_to_baseline")
        if sim is not None:
            if not isinstance(sim, dict) or set(sim) != _VALID_SIMILARITY_KEYS:
                raise ValueError(
                    "similarity_to_baseline must be exactly {'body': <str>, 'threshold': <float>}, "
                    f"got {sim!r}"
                )
            similarity_to_baseline = SimilarityToBaseline(body=sim["body"], threshold=sim["threshold"])

        return cls(
            status_in=data.get("status_in"),
            body_contains=data.get("body_contains"),
            body_regex=data.get("body_regex"),
            similarity_to_baseline=similarity_to_baseline,
        )


def evaluate_signature(result: FetchResult, sig: SuccessSignature) -> bool:
    """Deterministically evaluate whether `result` satisfies `sig`. Pure function: no
    network, no I/O, no side effects -- the same (result, sig) pair always returns the
    same bool. A FetchResult with `.error` set (the request itself failed -- connection
    refused, timeout) never satisfies any signature: there is no real HTTP response to
    check a status/body/similarity condition against, so "the capability fired" cannot
    be true. `sig` must already be a validated SuccessSignature -- there is no loose/
    implicit dict form accepted here (call SuccessSignature.from_dict() first)."""
    if not isinstance(sig, SuccessSignature):
        raise TypeError(
            f"evaluate_signature requires a SuccessSignature instance, got {type(sig).__name__} -- "
            "there is no implicit/loose signature format; call SuccessSignature.from_dict() first"
        )
    if result.error is not None:
        return False
    if sig.status_in is not None and result.status not in sig.status_in:
        return False
    if sig.body_contains is not None and sig.body_contains not in result.body:
        return False
    if sig.body_regex is not None and re.search(sig.body_regex, result.body) is None:
        return False
    if sig.similarity_to_baseline is not None:
        ratio = difflib.SequenceMatcher(None, sig.similarity_to_baseline.body, result.body).ratio()
        if ratio < sig.similarity_to_baseline.threshold:
            return False
    return True


# (url, method, headers, body, timeout_s) -> FetchResult, matching http_probe.fetch
# exactly -- Callable[..., X] rather than a fully-spelled arg list since body's
# Optional[str] doesn't round-trip cleanly through Callable's positional-arg syntax.
FetchFn = Callable[..., FetchResult]


@dataclass
class DeterminismResult:
    """Outcome of one determinism_gate run: the binary status, and the raw per-trial
    hit/miss sequence (in trial order) it was computed from, for evidence/inspection.
    No third bucket, no confidence score, no timing data -- exactly PHASE1-PLAN.md's
    stated determinism contract, nothing added."""
    status: str  # "STABLE" | "NONDETERMINISTIC"
    hits: list[bool]
    k: int


def determinism_gate(base_request: dict, k: int, success_signature: SuccessSignature,
                      fetch_fn: FetchFn) -> DeterminismResult:
    """Re-run `base_request` unperturbed, exactly k times, and check each observation
    against `success_signature` (task C2). STABLE iff every one of the k trials is a
    HIT; any other outcome -- one miss, alternating, all miss, fetch errors -- is
    NONDETERMINISTIC. This is the literal Phase-1 binary contract (PHASE1-PLAN.md sec
    2.5.1 / PHASE1-EXECUTION-PLAN.md task C2): no majority vote, no similarity/timing/
    confidence heuristic, no adaptive k, no retries beyond exactly k trials.

    base_request is the same {method, url, headers, body} shape already persisted in
    case_store's cem_meta.base_request (PHASE1-EXECUTION-PLAN.md sec 4).

    fetch_fn is an injected callable matching http_probe.fetch's exact signature
    (url, method, headers, body, timeout_s) -> FetchResult -- reusing the existing
    fetch primitive's contract instead of inventing a new one (UD-1's anti-duplication
    rule): a later task's production wiring can pass http_probe.fetch itself with zero
    adapter code. This function calls fetch_fn exactly k times and nothing else --
    no spacing/controls/confounder-pinning (that's the later Controls/run_intervention
    work), no real network call of its own."""
    if isinstance(k, bool) or not isinstance(k, int):
        raise TypeError(f"k must be an int, got {type(k).__name__}")
    if k < 1:
        raise ValueError(f"k must be >= 1, got {k}")
    if not isinstance(success_signature, SuccessSignature):
        raise TypeError(
            f"determinism_gate requires a SuccessSignature instance, got "
            f"{type(success_signature).__name__}"
        )

    url = base_request["url"]
    method = base_request.get("method", "GET")
    headers = base_request.get("headers") or {}
    body = base_request.get("body")

    hits = [
        evaluate_signature(fetch_fn(url, method, headers, body, DEFAULT_TIMEOUT_S), success_signature)
        for _ in range(k)
    ]

    status = "STABLE" if all(hits) else "NONDETERMINISTIC"
    return DeterminismResult(status=status, hits=hits, k=k)


VERDICT_NECESSARY = "necessary"
VERDICT_APPARENTLY_NOT_NECESSARY = "apparently_not_necessary"
VERDICT_INCONCLUSIVE = "inconclusive"


def _validate_hit_sequence(name: str, hits: list, k: int) -> None:
    if not isinstance(hits, list) or not all(isinstance(h, bool) for h in hits):
        raise TypeError(f"{name} must be a list of bools, got {hits!r}")
    if len(hits) != k:
        raise ValueError(f"{name} must have exactly k={k} entries, got {len(hits)}")


def classify(baseline_hits: list[bool], perturbed_hits: list[bool], k: int) -> str:
    """Classify a condition's necessity verdict from already-observed baseline-arm and
    perturbed-arm trial outcomes (task C3). Exactly one of 3 verdicts
    (PHASE1-PLAN.md sec D "Verdict rules", unanimity, k trials/arm):

    - baseline arm not all-HIT -> `inconclusive` (an unstable baseline can't be
      trusted as the "expected successful behavior" reference for ANY comparison,
      regardless of what the perturbed arm looks like).
    - perturbed all-MISS (baseline all-HIT) -> `necessary`.
    - perturbed all-HIT (baseline all-HIT) -> `apparently_not_necessary`.
    - perturbed mixed (baseline all-HIT) -> `inconclusive`.

    Pure classification only: no HTTP, no fetch, no perturbation execution, no target
    inspection, no DB, no model call -- this function only looks at the two hit
    sequences it's given. 429/throttle detection is out of scope here by design (see
    module docstring); baseline_hits/perturbed_hits are plain bools, matching
    DeterminismResult.hits' type exactly. Race/TOCTOU (`probabilistic`) and
    interaction detection (`interacting`) are separate later tasks (C4/C6) -- this
    function never returns a 4th verdict."""
    if isinstance(k, bool) or not isinstance(k, int):
        raise TypeError(f"k must be an int, got {type(k).__name__}")
    if k < 1:
        raise ValueError(f"k must be >= 1, got {k}")
    _validate_hit_sequence("baseline_hits", baseline_hits, k)
    _validate_hit_sequence("perturbed_hits", perturbed_hits, k)

    if not all(baseline_hits):
        return VERDICT_INCONCLUSIVE
    if all(perturbed_hits):
        return VERDICT_APPARENTLY_NOT_NECESSARY
    if not any(perturbed_hits):
        return VERDICT_NECESSARY
    return VERDICT_INCONCLUSIVE


VERDICT_PROBABILISTIC = "probabilistic"


@dataclass
class RaceResult:
    """Outcome of classify_race: always VERDICT_PROBABILISTIC, plus the observed
    perturbed-arm HIT-rate as evidence. No verdict field can ever read "necessary" --
    reporting the raw rate preserves uncertainty explicitly instead of collapsing a
    race into a false deterministic causal conclusion (PHASE1-PLAN.md sec D)."""
    verdict: str  # always "probabilistic"
    hit_rate: float  # count(True) / k over perturbed_hits
    k: int


def classify_race(perturbed_hits: list[bool], k: int) -> RaceResult:
    """Classify a condition already flagged (by the caller/executor, outside this
    module) as a race/TOCTOU condition (task C4). Unlike classify(), this function is
    only ever invoked once a race is suspected -- being routed here at all IS the race
    flag, mirroring how determinism_gate/classify are already separate pure functions
    per concern rather than one function branching on a mode parameter. Always returns
    VERDICT_PROBABILISTIC, hardcoded: no perturbed-hit pattern -- not even all-MISS,
    the exact pattern that makes classify() return "necessary" -- can make this
    function return "necessary". Reports the perturbed-arm HIT-rate instead, so the
    caller/bundle has evidence of how often the perturbation actually succeeded rather
    than a false binary necessity claim.

    Pure classification only: no HTTP, no fetch, no perturbation execution, no target
    inspection, no DB, no model call, no baseline_hits (PHASE1-PLAN.md's C4 line only
    ever says "report perturbed HIT-rate") -- this function only looks at the one hit
    sequence it's given."""
    if isinstance(k, bool) or not isinstance(k, int):
        raise TypeError(f"k must be an int, got {type(k).__name__}")
    if k < 1:
        raise ValueError(f"k must be >= 1, got {k}")
    _validate_hit_sequence("perturbed_hits", perturbed_hits, k)

    hit_rate = perturbed_hits.count(True) / k
    return RaceResult(verdict=VERDICT_PROBABILISTIC, hit_rate=hit_rate, k=k)


@dataclass
class MinimalSetResult:
    """Outcome of one minimal_condition_sets() run: the recovered 1-minimal
    condition set, plus how many times the injected predicate was consulted
    (evidence/accounting only -- not a causal claim). A condition surviving
    in `minimal_set` means only that removing it (with everything else
    already perturbed away) flipped `is_interesting()` to False for THIS
    predicate's answers; it is NOT itself a "necessary" verdict -- that
    label is classify()'s job (C3), computed from real replicated k-trial
    arms. This function performs pure set minimization over whatever truth
    the caller's predicate encodes; it never asserts causal necessity."""
    minimal_set: frozenset[str]
    predicate_calls: int


def minimal_condition_sets(
    conditions: list[str],
    is_interesting: Callable[[frozenset[str]], bool],
) -> MinimalSetResult:
    """Task C5: recover ONE 1-minimal subset of `conditions` via ddmin
    (PHASE1-PLAN.md sec "Multiple minimal sets"). A subset M is 1-minimal
    iff is_interesting(M) is True and, for every single element e in M,
    is_interesting(M - {e}) is False -- removing any one more condition
    would lose interestingness. Finds exactly one such M; does not search
    for alternates or detect interactions (task C6) and does not itself run
    any experiment -- `is_interesting` is caller-supplied and treated as a
    pure oracle over an already-decided "unanimous HIT over k" truth.

    Contract:
    - `conditions`: a list of distinct condition-name strings -- the
      "present/triggering" condition set S (PHASE1-PLAN.md's own term).
    - `is_interesting(subset)`: called with a frozenset of the condition
      names to KEEP (everything else is implicitly perturbed away); must
      return a real bool. A non-bool return is a hard TypeError, never
      silently treated as truthy/falsy or as "inconclusive" -- the C5
      ddmin contract at this layer is strictly binary.
    - The full set frozenset(conditions) must itself be interesting --
      ddmin cannot minimize a set that doesn't reproduce the effect in the
      first place; violating this is a ValueError.

    Algorithm: deterministic single-element-removal sweep to a fixed point
    -- a correctness-equivalent simplification of classical partition-based
    ddmin, appropriate for the small condition counts Phase-1 CEM operates
    on (a handful of conditions per finding). Repeatedly walks the current
    set in caller-supplied order, removes the first condition whose removal
    keeps is_interesting() True, and restarts the walk on the smaller set;
    stops when a full walk removes nothing. Guarantees 1-minimality on
    termination and is fully deterministic for a deterministic predicate.

    No fetch, no HTTP, no perturbation execution, no DB, no budget/audit, no
    model call, no alternates/interaction search (C6) -- pure logic only."""
    if not isinstance(conditions, list):
        raise TypeError(f"conditions must be a list, got {type(conditions).__name__}")
    if not all(isinstance(c, str) for c in conditions):
        raise TypeError("conditions must be a list of strings")
    if len(set(conditions)) != len(conditions):
        raise ValueError(f"conditions must not contain duplicates, got {conditions!r}")
    if not callable(is_interesting):
        raise TypeError(f"is_interesting must be callable, got {type(is_interesting).__name__}")

    if len(conditions) == 0:
        return MinimalSetResult(minimal_set=frozenset(), predicate_calls=0)

    calls = 0

    def _test(subset: list[str]) -> bool:
        nonlocal calls
        calls += 1
        result = is_interesting(frozenset(subset))
        if not isinstance(result, bool):
            raise TypeError(
                f"is_interesting must return a bool, got {type(result).__name__} -- "
                "the C5 ddmin contract is strictly binary (PHASE1-PLAN.md's own "
                "definition of 'interesting'); there is no inconclusive/unknown "
                "state at this layer"
            )
        return result

    if not _test(conditions):
        raise ValueError(
            "the full condition set must itself be interesting before minimization "
            "can begin -- ddmin cannot minimize a set that does not reproduce the "
            "effect in the first place"
        )

    current = list(conditions)
    changed = True
    while changed:
        changed = False
        for c in current:
            candidate = [x for x in current if x != c]
            if _test(candidate):
                current = candidate
                changed = True
                break

    return MinimalSetResult(minimal_set=frozenset(current), predicate_calls=calls)


VERDICT_INTERACTING = "interacting"


@dataclass
class InteractionEvidence:
    """One verified pairwise joint-removal-flip observation (C6 Rule 2):
    is_interesting(S - {a}) and is_interesting(S - {b}) are both True, but
    is_interesting(S - {a, b}) is False -- individually droppable, but not
    jointly droppable. Evidence only, not a causal necessity claim."""
    pair: frozenset[str]


@dataclass
class AlternateSetsResult:
    """Outcome of one find_alternate_condition_sets() run (task C6): the
    distinct 1-minimal condition sets recovered (minimal_sets[0] is always
    the base M1 from minimal_condition_sets()), which condition names were
    flagged 'interacting' and the pairwise evidence behind any Rule-2
    flags, plus the sets_found/trials_used/bounded completeness-reporting
    triple PHASE1-PLAN.md sec 11 names explicitly. An empty
    interacting/interacting_pairs is NOT proof that no interaction exists
    -- it only means neither of the two explicit C6 rules fired on what
    was actually tested within max_trials; absence of evidence here is
    never treated as evidence of absence. interacting is orthogonal to
    necessary/apparently_not_necessary/inconclusive/probabilistic -- this
    function never calls classify() or classify_race()."""
    minimal_sets: list[frozenset[str]]
    interacting: frozenset[str]
    interacting_pairs: list[InteractionEvidence]
    sets_found: int
    trials_used: int
    bounded: bool


def find_alternate_condition_sets(
    conditions: list[str],
    is_interesting: Callable[[frozenset[str]], bool],
    max_trials: int,
) -> AlternateSetsResult:
    """Task C6: alternates + interaction detection, built strictly on top
    of minimal_condition_sets() (C5, called directly and never
    reimplemented). Implements PHASE1-PLAN.md sec 11 literally:

    - Alternates: "for each c in M1, force-exclude c and re-run ddmin ->
      collect distinct minimal sets" -- scoped to M1's own members exactly
      as written.
    - Rule 1: c is individually droppable (is_interesting(S-{c}) is True)
      but present in every OTHER recovered minimal set. "Other" excludes
      (a) c's own force-excluded alternate, which structurally can never
      contain c, and (b) M1 itself when c is one of M1's own members,
      since "c is in M1" merely restates the premise. At least one
      genuinely independent comparison set is required; zero is
      insufficient evidence, not a firing.
    - Rule 2: a pair whose joint removal flips the oracle while neither
      single removal does.
    - The candidate pool for individual droppability testing (feeding both
      rules) is every condition in the original `conditions`, not just
      M1's members -- ddmin's greedy sweep can drop one half of a genuine
      interacting pair before it ever reaches M1.
    - `max_trials` bounds the total predicate calls beyond the base M1
      computation; if the search is cut short, `bounded` is True and
      whatever was found so far is still returned (never a crash, never a
      claim of exhaustiveness).

    No fetch, no HTTP, no DB, no budget_guard/MCP access, no modification
    of minimal_condition_sets/classify/classify_race/evaluate_signature/
    SuccessSignature (all reused unmodified), no 4th classify() verdict,
    no claim that an interacting condition is necessary."""
    if not isinstance(conditions, list):
        raise TypeError(f"conditions must be a list, got {type(conditions).__name__}")
    if not all(isinstance(c, str) for c in conditions):
        raise TypeError("conditions must be a list of strings")
    if len(set(conditions)) != len(conditions):
        raise ValueError(f"conditions must not contain duplicates, got {conditions!r}")
    if not callable(is_interesting):
        raise TypeError(f"is_interesting must be callable, got {type(is_interesting).__name__}")
    if isinstance(max_trials, bool) or not isinstance(max_trials, int):
        raise TypeError(f"max_trials must be an int, got {type(max_trials).__name__}")
    if max_trials < 1:
        raise ValueError(f"max_trials must be >= 1, got {max_trials}")

    calls = 0

    def _test(subset: list[str]) -> bool:
        nonlocal calls
        calls += 1
        result = is_interesting(frozenset(subset))
        if not isinstance(result, bool):
            raise TypeError(
                f"is_interesting must return a bool, got {type(result).__name__} -- "
                "the C6 ddmin/interaction contract is strictly binary, inherited "
                "unmodified from C5"
            )
        return result

    base = minimal_condition_sets(conditions, is_interesting)
    calls += base.predicate_calls
    minimal_sets: list[frozenset[str]] = [base.minimal_set]
    bounded = False

    # ---- Alternates: for each c in M1, force-exclude c and re-run ddmin.
    alt_by_excluded: dict[str, frozenset[str]] = {}
    for c in sorted(base.minimal_set):
        if calls >= max_trials:
            bounded = True
            break
        reduced = [x for x in conditions if x != c]
        try:
            alt = minimal_condition_sets(reduced, is_interesting)
        except ValueError:
            calls += 1
            continue
        calls += alt.predicate_calls
        alt_by_excluded[c] = alt.minimal_set
        if alt.minimal_set not in minimal_sets:
            minimal_sets.append(alt.minimal_set)

    # ---- Interaction-candidate scan: is_interesting(S-{c}) for EVERY
    # condition in the original candidate set (broadened scope, human-
    # approved 2026-09-05 -- see module docstring).
    droppable_singly: set[str] = set()
    for c in sorted(conditions):
        if calls >= max_trials:
            bounded = True
            break
        reduced = [x for x in conditions if x != c]
        if _test(reduced):
            droppable_singly.add(c)

    interacting: set[str] = set()
    interacting_pairs: list[InteractionEvidence] = []

    # ---- Rule 1.
    for c in droppable_singly:
        self_alt = alt_by_excluded.get(c)
        c_in_base = c in base.minimal_set
        other_sets = [
            s for s in minimal_sets
            if s != self_alt and not (c_in_base and s == base.minimal_set)
        ]
        if other_sets and all(c in s for s in other_sets):
            interacting.add(c)

    # ---- Rule 2.
    for c1, c2 in itertools.combinations(sorted(droppable_singly), 2):
        if calls >= max_trials:
            bounded = True
            break
        joint = [x for x in conditions if x not in (c1, c2)]
        if not _test(joint):
            interacting.add(c1)
            interacting.add(c2)
            interacting_pairs.append(InteractionEvidence(pair=frozenset({c1, c2})))

    return AlternateSetsResult(
        minimal_sets=minimal_sets,
        interacting=frozenset(interacting),
        interacting_pairs=interacting_pairs,
        sets_found=len(minimal_sets),
        trials_used=calls,
        bounded=bounded,
    )


@dataclass
class AndNecessityGroup:
    """One recovered minimal set whose members are mutually AND-necessary
    (C6 addendum, retrospective audit fix): every member was individually
    required to keep the set 1-minimal, so removing ANY single member --
    with everything else already perturbed away -- breaks the effect. Evidence
    only, mirroring InteractionEvidence's existing pair-evidence shape
    (generalized here from a pair to an n-ary group, since a genuine mutual-
    AND relationship is not inherently pairwise -- see ANY_TWO_OF_THREE's
    3-member groups in the test suite). Never a verdict string and never a
    substitute for classify()'s own "necessary" verdict on each member --
    the two facts coexist (see find_and_necessity_groups' docstring)."""
    members: frozenset[str]


def find_and_necessity_groups(minimal_sets: list[frozenset[str]]) -> list[AndNecessityGroup]:
    """C6 addendum (retrospective audit fix, human-approved Option 2 of 3
    presented, 2026-09-05): detect mutual AND-necessity as a signal SEPARATE
    from find_alternate_condition_sets' existing Rule 1/Rule 2 (which detect
    OR-redundancy -- "individually droppable but present in every recovered
    set" / "joint removal flips, neither single removal does"). Neither rule
    can fire on a pure AND-both-required pattern (PHASE1-PLAN.md's own /merge
    example): if role_admin and flag_on are both strictly required, removing
    EITHER alone already breaks the effect, so neither ever enters Rule 1/
    Rule 2's `droppable_singly` candidate pool in the first place -- by
    design, not by bug (confirmed: find_alternate_condition_sets is not
    modified by this addendum, not even by one line; its own pre-existing
    test section is the proof, run unmodified).

    The signal is already implicit in what ddmin's own termination condition
    proves: minimal_condition_sets() (C5) guarantees that for every element e
    of a returned 1-minimal set M, removing e (with everything outside M
    already perturbed away) is NOT interesting -- i.e. every member of an
    M with len(M) >= 2 is, by construction, jointly/mutually required
    together with the rest of M. Detecting this needs ZERO additional
    is_interesting() calls: it is pure post-processing over the `minimal_sets`
    list find_alternate_condition_sets (or minimal_condition_sets) already
    returns -- this function takes exactly that list, nothing else.

    Coexistence with `necessary` (the exact representation decision, see the
    module docstring's "C6 addendum" section for the full rationale): an
    AndNecessityGroup is a structural annotation over condition NAMES only --
    it never calls classify()/classify_race(), never produces or touches a
    verdict string, and is not a replacement for classify()'s own per-
    condition "necessary" verdict (which keeps being computed the same way
    it always was, under the one-variable-at-a-time protocol, and correctly
    still says "necessary" for role_admin and flag_on individually). A single
    -member set (a genuine OR-redundant path, e.g. {"header"} alone) is never
    flagged -- only sets with 2+ members carry a mutual-necessity relationship
    to report. Duplicate groups (the same members appearing more than once in
    the input) are reported once, in first-seen order -- mirroring how
    find_alternate_condition_sets itself already dedupes `minimal_sets`.

    No fetch, no HTTP, no DB, no budget_guard/MCP access, no modification of
    minimal_condition_sets/find_alternate_condition_sets/classify/
    classify_race/evaluate_signature/SuccessSignature (all reused unmodified
    or untouched)."""
    if not isinstance(minimal_sets, list):
        raise TypeError(f"minimal_sets must be a list, got {type(minimal_sets).__name__}")
    for s in minimal_sets:
        if not isinstance(s, frozenset):
            raise TypeError(f"minimal_sets must contain only frozensets, got {type(s).__name__}")
        if not all(isinstance(c, str) for c in s):
            raise TypeError(f"every minimal set must contain only strings, got {s!r}")

    groups: list[AndNecessityGroup] = []
    seen: list[frozenset[str]] = []
    for s in minimal_sets:
        if len(s) >= 2 and s not in seen:
            seen.append(s)
            groups.append(AndNecessityGroup(members=s))
    return groups


@dataclass
class PocMinimizationResult:
    """Outcome of one minimize_poc() run (task C7): the minimal condition
    set found via ddmin (minimal_condition_sets(), reused directly, never
    reimplemented), plus the mandatory re-validation outcome
    (PHASE1-PLAN.md sec 12: "output re-validated through determinism_gate
    ... guards a DD local optimum dropping a real step"). `accepted` is
    True only when `determinism.status == "STABLE"`; a NONDETERMINISTIC
    revalidation means ddmin's greedy minimization likely dropped a
    condition that looked droppable in one predicate call but isn't
    reliably reproducible -- `poc` is still returned for evidence/
    inspection, but `accepted=False` means it must NOT be used as the
    final minimal reproducer. Automatic recovery ("DDMIN* re-iterate") is
    explicitly optional per PHASE1-PLAN.md and is not implemented here --
    Phase 1's minimum bar is honest detection and reporting, not silent
    retry."""
    poc: frozenset[str]
    accepted: bool
    determinism: DeterminismResult
    predicate_calls: int


def minimize_poc(
    conditions: list[str],
    is_interesting: Callable[[frozenset[str]], bool],
    revalidate: Callable[[frozenset[str]], DeterminismResult],
) -> PocMinimizationResult:
    """Task C7: PoC minimization. Reuses minimal_condition_sets() (C5)
    directly for the ddmin search (never reimplemented -- PHASE1-PLAN.md
    sec 12: "PoC minimization reuses the same ddmin with the oracle as
    interestingness"), then re-validates the result via an injected
    `revalidate` callable standing in for the real determinism_gate (C2)
    -- kept abstract so this function stays pure/no-network, exactly like
    is_interesting stands in for a real oracle check.

    `conditions`/`is_interesting` validation is inherited from
    minimal_condition_sets() rather than duplicated -- this function does
    nothing else with them beyond that one delegated call.

    `revalidate(poc)` must return a real DeterminismResult (C2's own
    result type, reused unmodified). accepted = (determinism.status ==
    "STABLE"). No automatic retry/re-iteration on NONDETERMINISTIC --
    PHASE1-PLAN.md explicitly marks that "optional", not part of Phase
    1's minimum bar; this function reports the outcome honestly instead.

    No fetch, no HTTP, no DB, no MCP, no modification of
    minimal_condition_sets/classify/classify_race/determinism_gate/
    evaluate_signature/find_alternate_condition_sets (all reused
    unmodified or untouched)."""
    if not callable(revalidate):
        raise TypeError(f"revalidate must be callable, got {type(revalidate).__name__}")

    base = minimal_condition_sets(conditions, is_interesting)
    determinism = revalidate(base.minimal_set)
    if not isinstance(determinism, DeterminismResult):
        raise TypeError(
            f"revalidate must return a DeterminismResult, got {type(determinism).__name__}"
        )

    return PocMinimizationResult(
        poc=base.minimal_set,
        accepted=determinism.status == "STABLE",
        determinism=determinism,
        predicate_calls=base.predicate_calls,
    )


def _redact_recursive(value):
    """Recursively apply redact_text to every string leaf of a nested
    dict/list/tuple structure (task C8). Dict values are walked, not keys --
    keys are our own field names, never target-controlled data. Lists and
    tuples are walked element-by-element (tuples come back as lists, since
    the assembled bundle must stay JSON-serializable and JSON has no tuple
    type anyway). Ints/floats/bools/None fall through untouched -- there is
    no isinstance(value, str) branch for them, so this is automatic rather
    than a special case. Frozensets are never passed in here directly:
    assemble_bundle already converts every frozenset-derived value to a
    sorted list before handing the assembled dict to this helper.

    Retrospective audit fix: redact_text()'s two name-based rules (header
    line, key=value) both require the secret's KEY NAME to be embedded in
    the SAME STRING as the value -- but a dict walk redacts each VALUE in
    isolation, stripped of its key. That meant only JWT- or card-shaped
    secrets (the two rules keyed on VALUE SHAPE alone) ever actually got
    caught here; an opaque bearer token or API key stored the natural way
    for HTTP headers -- {"Authorization": "Bearer <opaque>"} -- passed
    straight through unredacted, since the value string alone never
    contains "authorization" or "=". Before recursing into a dict value,
    check whether ITS KEY is an exact (case-insensitive) match for one of
    KNOWN_SECRET_HEADER_NAMES -- the same 4 names redact_text()'s own
    _HEADER_LINE_RE already treats as unconditionally secret-by-name in the
    flat-text case -- and if so, redact the value directly via redacted()
    rather than recursing into it. Exact match, not substring: real CEM
    condition names used elsewhere in this codebase (session_cookie,
    auth_cookie) contain "cookie"/"auth" as substrings but are never
    literally equal to "cookie"/"authorization", so they are never wrongly
    caught by this narrower, name-exact check.

    Second-audit fix: a secret-carrying header can legitimately be a LIST of
    values, not just a scalar string -- multiple Set-Cookie lines being the
    realistic case (a dict value shape http.client/requests-style header
    capture can produce). The scalar-only check above missed this: a list
    value fell through to the generic per-element walk below, so an opaque
    (non-JWT, non-"key=value"-shaped) element sitting in that list still
    leaked. When a secret-named key's value is a list/tuple of ALL strings,
    redact each non-empty element the same way the scalar case already does
    (same redacted()/"header-value" convention, so both shapes look uniform
    in the bundle) -- empty elements stay empty, matching the scalar case's
    own "don't mark nothing as redacted" rule. Any other shape under a
    secret-named key (not a plain string, not a list purely of strings --
    e.g. a stray non-string element, or a nested dict) falls back to the
    ordinary recursive walk rather than guessing: this fix covers exactly
    the two realistic header-value shapes, not every conceivable structure."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        result = {}
        for k, v in value.items():
            is_secret_key = isinstance(k, str) and k.lower() in KNOWN_SECRET_HEADER_NAMES
            if is_secret_key and isinstance(v, str) and v:
                result[k] = redacted(v, "header-value")
            elif (is_secret_key and isinstance(v, (list, tuple))
                    and all(isinstance(item, str) for item in v)):
                result[k] = [redacted(item, "header-value") if item else item for item in v]
            else:
                result[k] = _redact_recursive(v)
        return result
    if isinstance(value, (list, tuple)):
        return [_redact_recursive(v) for v in value]
    return value


def assemble_bundle(
    finding_id: int,
    original_baseline: dict,
    baseline_determinism: DeterminismResult,
    intervention_matrix: list[dict],
    controls: dict,
    observed_confounders: list[dict],
    verdict_labels: dict[str, str],
    inconclusive_experiments: dict[str, str],
    alternate_sets: AlternateSetsResult,
    poc: PocMinimizationResult,
    audit_trail: list[dict],
    k: int,
) -> dict:
    """Task C8: assemble the redacted "Triager-Proof Bundle" -- all 15
    sec-2.8 fields (XYZ.md sec 2.8 + PHASE1-PLAN.md's 4 additions) plus
    `finding_id` (a 16th key, for bundle identity/traceability, not one of
    the 15) -- from already-computed C1-C7 result types and raw
    caller-supplied context. Pure aggregation only: never calls
    determinism_gate/classify/classify_race/minimal_condition_sets/
    find_alternate_condition_sets/minimize_poc/http_probe.fetch itself --
    every value it reports was computed by the caller beforehand and handed
    in typed, exactly like C2's injected fetch_fn / C7's injected
    revalidate.

    `identified_necessary_conditions` is derived from `verdict_labels`
    (sorted list of keys whose value equals VERDICT_NECESSARY) rather than
    accepted as a separate parameter, so the two can never silently
    disagree. `minimal_condition_sets`/`completeness_bound` both unpack
    `alternate_sets` but stay two distinct top-level keys (set contents vs.
    completeness counts, never nested). `controlled_pinned_conditions`/
    `controls` and `replication_counts`/`k` are intentional literal
    duplicates of `controls`/`k` under two key names -- not a bug.

    The fully-assembled dict is passed through `_redact_recursive` exactly
    once, at the end, before returning -- every string leaf anywhere in the
    structure (headers, URLs, body text the caller's original_baseline/
    intervention_matrix/audit_trail/controls/observed_confounders/
    inconclusive_experiments may carry) goes through the same
    `redact_text` pass this codebase already uses everywhere else
    (audit_log.py). `k`/ints/bools/None are never touched by this pass.

    `baseline_determinism`/`alternate_sets`/`poc` must already be the real
    C2/C6/C7 result types -- isinstance-checked, not duck-typed, mirroring
    C7's own revalidate-type-check precedent -- since their internal shape
    is read directly (`.status`/`.hits`/`.k`, `.minimal_sets`/`.interacting`/
    `.interacting_pairs`/`.sets_found`/`.trials_used`/`.bounded`,
    `.poc`/`.accepted`/`.determinism`)."""
    if not isinstance(baseline_determinism, DeterminismResult):
        raise TypeError(
            "assemble_bundle requires baseline_determinism to be a DeterminismResult "
            f"instance, got {type(baseline_determinism).__name__}"
        )
    if not isinstance(alternate_sets, AlternateSetsResult):
        raise TypeError(
            "assemble_bundle requires alternate_sets to be an AlternateSetsResult "
            f"instance, got {type(alternate_sets).__name__}"
        )
    if not isinstance(poc, PocMinimizationResult):
        raise TypeError(
            f"assemble_bundle requires poc to be a PocMinimizationResult instance, "
            f"got {type(poc).__name__}"
        )

    identified_necessary_conditions = sorted(
        name for name, verdict in verdict_labels.items() if verdict == VERDICT_NECESSARY
    )

    bundle = {
        "finding_id": finding_id,
        "original_baseline": original_baseline,
        "baseline_replication_results": {
            "status": baseline_determinism.status,
            "hits": baseline_determinism.hits,
            "k": baseline_determinism.k,
        },
        "intervention_matrix": intervention_matrix,
        "replication_counts": k,
        "controlled_pinned_conditions": controls,
        "observed_confounders": observed_confounders,
        "inconclusive_experiments": inconclusive_experiments,
        "identified_necessary_conditions": identified_necessary_conditions,
        "minimal_condition_sets": {
            "minimal_sets": [sorted(s) for s in alternate_sets.minimal_sets],
            "interacting": sorted(alternate_sets.interacting),
            "interacting_pairs": [sorted(ev.pair) for ev in alternate_sets.interacting_pairs],
        },
        "minimized_reproduction_evidence": {
            "poc": sorted(poc.poc),
            "accepted": poc.accepted,
            "determinism": {
                "status": poc.determinism.status,
                "hits": poc.determinism.hits,
                "k": poc.determinism.k,
            },
        },
        "complete_audit_trail": audit_trail,
        "verdict_labels": verdict_labels,
        "controls": controls,
        "k": k,
        "completeness_bound": {
            "sets_found": alternate_sets.sets_found,
            "trials_used": alternate_sets.trials_used,
            "bounded": alternate_sets.bounded,
        },
    }

    return _redact_recursive(bundle)
