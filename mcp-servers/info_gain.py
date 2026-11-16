"""P4-INFOGAIN -- information-gain experiment ORDERING (hints, never skips).

MASTER-ROADMAP-FINAL-v3.md decision matrix "Info-gain experiment selection
(UU-3)" (GATED, dep: telemetry): "uplift; **orders, never hard-blocks a novel
test**".  Section 11-A absolute (zero-tolerance) security invariant:
"allocation/dedupe/negative-knowledge **never hard-block a not-yet-confirmed
novel test** (hints, never skips)".

What this is, and is NOT:
  * It ORDERS a set of candidate experiments by expected information-gain per
    unit cost, so the agent spends effort where it is most likely to learn
    something -- a HINT for the scheduler/agent, consumed by whoever decides
    what to run next.  It is NOT a gate: it never removes, filters, or
    hard-blocks a candidate, and it has no threshold below which a candidate is
    dropped.  `order_experiments()` returns EVERY candidate it was given.
  * NOVELTY IS NEVER PENALIZED.  A candidate whose class has no history ("a
    not-yet-confirmed novel test") is scored with an optimistic prior
    (optimism-under-uncertainty): its expected gain is set to the best gain seen
    among known classes (or a maximal default when there is no history at all),
    so it is never ranked below a known low-yield test purely for lacking a
    track record.  This is the §11-A anti-anchoring guarantee, enforced by
    construction and asserted in tests/test_info_gain.py.

Design posture (same as P4-SIG's causal_signature.py / P2-TEL's telemetry.py):
  * A PURE ranking function over already-collected data.  `history` is injected;
    the core does no I/O, no network, 0 hot-path -- it complements budget_guard,
    never replaces it, and never makes a run/skip decision itself.
  * No new dependency (stdlib only).  Does NOT touch the frozen cem_engine.py.
  * `build_history_from_case_store()` is an optional, read-only, offline helper
    that aggregates per-vuln_class {trials, hits} from the findings table.  It is
    DELIBERATELY fail-safe toward exploration: ANY read error degrades to an
    empty history, which makes every candidate novel -> optimism -> nothing
    penalized -- the safe direction for "never hard-block a novel test".

Information-gain proxy (honest limit): expected gain is the Laplace-smoothed
historical confirmation rate of the candidate's class, (hits + 1) / (trials + 2)
-- a cheap, well-behaved estimate of "how likely is a test of this class to
yield a confirmed finding", NOT a true Bayesian information gain over a belief
state.  It is a prioritization hint, and the optimistic-prior guarantee above is
what keeps the heuristic from anchoring on historically-productive classes.
"""
from __future__ import annotations

# A "hit" = a test of this class PAID OFF: a finding that reached any successful
# terminal status, not only CONFIRMED (an escalated IMPACT_PROVEN/REPORTED finding
# is still a success). Mirrors escalation_value.py's own success notion; all three
# are members of case_store.FINDING_STATUSES.
_HIT_STATUSES = frozenset({"CONFIRMED", "IMPACT_PROVEN", "REPORTED"})

_EPS = 1e-9
# Optimism-under-uncertainty when there is NO history at all: a novel test is
# assumed maximally promising (smoothed gain of a class that always confirms).
_DEFAULT_PRIOR = 1.0


def _key(candidate: dict):
    """The grouping key for history lookup: a candidate's vuln_class (preferred),
    else its tool/class.  A candidate with none is treated as novel."""
    return candidate.get("vuln_class") or candidate.get("tool") or candidate.get("class")


def _smoothed_gain(hits, trials) -> float:
    """Laplace-smoothed confirmation rate: (hits + 1) / (trials + 2).  Bounded in
    (0, 1), defined even at zero trials (=> 0.5), monotone in hits/trials."""
    try:
        h = max(0.0, float(hits))
        n = max(0.0, float(trials))
    except (TypeError, ValueError):
        return 0.5
    return (h + 1.0) / (n + 2.0)


def optimistic_prior(history: dict) -> float:
    """The gain assigned to a novel class: the best smoothed gain among known
    classes, or _DEFAULT_PRIOR when there is no history.  >= every known class's
    gain by construction, so a novel test is never out-ranked on the gain axis
    for lacking history (the §11-A anti-anchoring guarantee)."""
    gains = [_smoothed_gain(h.get("hits", 0), h.get("trials", 0))
             for h in (history or {}).values() if isinstance(h, dict)]
    return max(gains) if gains else _DEFAULT_PRIOR


def order_experiments(candidates, history: dict | None = None, *,
                      prior: float | None = None) -> list[dict]:
    """Return ALL `candidates` re-ordered by descending expected
    information-gain-per-cost.  HINTS, NEVER SKIPS: nothing is removed; a novel
    (no-history) candidate is scored with the optimistic prior so it is never
    ranked below a known low-yield candidate purely for lacking history.

    Each returned item is a shallow COPY of the input candidate annotated with
    `_info_gain` (the gain estimate), `_info_gain_score` (gain / cost), and
    `_novel` (True iff its class had no history).  Deterministic: ties break on
    the original input order.  Pure/offline -- `history` is injected."""
    history = history or {}
    cands = list(candidates)
    if prior is None:
        prior = optimistic_prior(history)

    scored = []
    for i, c in enumerate(cands):
        k = _key(c)
        h = history.get(k) if k is not None else None
        novel = not isinstance(h, dict)
        gain = prior if novel else _smoothed_gain(h.get("hits", 0), h.get("trials", 0))

        cost = c.get("cost")
        if cost is None and isinstance(h, dict):
            cost = h.get("cost_avg")
        try:
            cost = float(cost) if cost is not None else 1.0
        except (TypeError, ValueError):
            cost = 1.0
        cost = max(cost, _EPS)  # clamp: never divide by zero / go infinite

        score = gain / cost
        scored.append((i, c, score, gain, novel))

    # Descending score; on a TIE, a novel test wins (never ranked below a known
    # test it ties with -- the §11-A "never hard-block / never penalize a novel
    # test" guarantee); then stable on original index (deterministic).
    scored.sort(key=lambda t: (-t[2], not t[4], t[0]))

    out = []
    for _i, c, score, gain, novel in scored:
        item = dict(c)  # copy: never mutate the caller's candidate
        item["_info_gain"] = round(gain, 6)
        item["_info_gain_score"] = round(score, 6)
        item["_novel"] = novel
        out.append(item)
    return out


def build_history_from_case_store(db_path: str | None = None) -> dict:
    """Offline, read-only per-vuln_class history {vuln_class: {trials, hits}}
    from the findings table (trials = findings of that class; hits = CONFIRMED).
    Fail-safe toward exploration: ANY error -> {} (every candidate novel ->
    optimism -> nothing penalized), the safe direction for "never hard-block a
    novel test"."""
    try:
        import case_store
        resolved = case_store.resolve_db_path(db_path)
        conn = case_store._get_conn(resolved)
        try:
            rows = conn.execute("SELECT vuln_class, status FROM findings").fetchall()
        finally:
            conn.close()
    except Exception:  # noqa: BLE001 -- fail-safe toward exploration (see docstring)
        return {}

    hist: dict[str, dict] = {}
    for vuln_class, status in rows:
        if not isinstance(vuln_class, str):
            continue
        h = hist.setdefault(vuln_class, {"trials": 0, "hits": 0})
        h["trials"] += 1
        if status in _HIT_STATUSES:
            h["hits"] += 1
    return hist
