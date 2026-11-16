"""P4-M0 -- shallow invariant-model PROTOTYPE (GO/NO-GO probe), high-recall +
CEM-as-precision-gate.

MASTER-ROADMAP-FINAL-v3.md decision matrix row "Invariant model (UU-1)"
(GATED; acceptance gate "P4-M0 GO/NO-GO; invariants remain CEM-provable
hypotheses") and section 5 Phase-4 Group (1): the invariant model passively mines a
hunt's observed request/response corpus into an
actor->action->object->state-transition->invariant model and hands the
*candidate broken invariants* to CEM as HYPOTHESES TO FALSIFY -- never
asserted facts.  The UU research (Opportunity 1 + V.4) flags the shallow
heuristic version as liable to emit "confident false invariants (garbage-in for
CEM)", so it "survives only if gated behind a measured shallow prototype".

Design decision (from code review of the first cut): the probe does NOT try to
be precise on its own -- a `{identity, resource, status, body}`-only heuristic
provably cannot separate an IDOR leak from a legitimately public/shared resource.
Instead the probe is deliberately HIGH RECALL (it flags the public/shared case
too) and annotates each candidate with a cheap negative-control CONFIDENCE
signal; the FROZEN CEM counterfactual is the precision gate (drop the identity /
the replay and see whether the oracle still fires).  GO/NO-GO is therefore
measured on the whole `probe -> CEM` pipeline, not on the probe's standalone
precision.

Scope discipline (same posture as P4-SIG's causal_signature.py):
  * read-only PASSIVE miner over an already-observed corpus. No network,
    no filesystem, no randomness, stdlib only -- no new dependency.
  * it does NOT modify, read, or re-implement the FROZEN cem_engine.py; it
    REUSES authz_diff.py's pure owner-compare helpers for the negative control.
  * an invariant is expressed as a hypothesis RUNNABLE by the existing frozen
    Phase-1 pipeline: a GET base_request whose URL carries the candidate
    condition as a query param, and a `{"drop": true}` perturbation on that
    param (the only perturbation case-mcp.run_counterfactual supports).  No new
    store/table -- "invariants remain CEM-provable hypotheses", via
    case_store's existing log_hypothesis/create_finding/cem_define path.
  * NO MCP server / agent wiring, and NOT the full state-machine model -- that
    is the rest of P4-M1, out of scope for a GO/NO-GO probe.

Corpus shape (one observed request/response exchange):
    {"identity": str,         # which test account issued it (2-account hunt)
     "resource": str,         # the OBJECT-INSTANCE acted on (see contract below)
     "action":   str,         # e.g. "read", "add_coupon", "checkout"
     "args":     dict,        # request parameters
     "status":   int,         # HTTP-like status
     "body":     str,         # observed response body
     "session":  str}         # OPTIONAL in-session boundary (default: one
                              # implicit session). Replays only accumulate
                              # WITHIN a session -- two legitimate re-reads in
                              # different sessions/epochs are not accumulation.

Resource-instance-scoping contract (fix iv): `resource` must identify a single
OBJECT INSTANCE (e.g. "/orders/42"), not a collection or endpoint template
(e.g. "/orders").  A collection legitimately returns 2xx+content to many
identities, so grouping a collection under one `resource` would manufacture a
false ownership candidate for every shared listing.  The probe cannot enforce
this from the corpus alone; it instead SURFACES the risk through the
negative-control confidence: a resource read by multiple identities with NO
denial anywhere and IDENTICAL content across them is marked low confidence
(likely public / a collection), exactly the case CEM then rejects.

Two shallow heuristic invariant templates:
  T1 ownership / horizontal-authz: on one resource, >=2 distinct identities each
     get 2xx + non-empty body for a read-like action -> candidate.  HIGH RECALL:
     the public/shared case is flagged too, annotated low confidence.
  T2 one-time-use / replay: the same (identity, action, args, session) invoked
     >=2 times, all 2xx, bodies not all identical (accumulation) -> candidate.
     A non-2xx in the sequence is recovery, not accumulation (excluded).  ALL
     qualifying replay groups on a resource are emitted (fix iii).
"""
from __future__ import annotations

from urllib.parse import quote, urlencode

READ_ACTIONS = frozenset({"read", "access", "get", "view", "show", "fetch"})
_HOST = "invariant.local"  # placeholder authority for synthesized base requests
_REQUIRED_KEYS = ("identity", "resource", "action", "status", "body")


def _is_success(status) -> bool:
    try:
        return 200 <= int(status) < 300
    except (TypeError, ValueError):
        return False


def _is_denial(status) -> bool:
    try:
        return 400 <= int(status) < 500
    except (TypeError, ValueError):
        return False


def _canon_args(args) -> str:
    import json
    try:
        return json.dumps(args or {}, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return repr(args)


def _trim(body: str, n: int = 120) -> str:
    body = (body or "").strip()
    return body if len(body) <= n else body[:n]


def _valid_row(ex) -> bool:
    """Fix (i): a malformed / partial row degrades (is skipped), never aborts
    the mine -- matches the repo's capture-failure-never-aborts convention."""
    if not isinstance(ex, dict):
        return False
    if any(k not in ex for k in _REQUIRED_KEYS):
        return False
    try:
        int(ex["status"])
    except (TypeError, ValueError):
        return False
    return (isinstance(ex["body"], str) and isinstance(ex["identity"], str)
            and isinstance(ex["resource"], str) and isinstance(ex["action"], str))


def _url(resource, params) -> str:
    return (f"https://{_HOST}/{quote(str(resource), safe='')}?"
            + urlencode({k: str(v) for k, v in params.items()}))


def _by_resource(exchanges):
    groups: dict[str, list[dict]] = {}
    for i, ex in enumerate(exchanges):
        if not _valid_row(ex):
            continue
        groups.setdefault(ex["resource"], []).append({**ex, "_idx": i})
    return groups


def _content_relation(bodies) -> str:
    """REUSE authz_diff's pure owner-compare oracle: are the successful bodies
    the SAME object (identical normalized content -> likely public/shared) or
    DIVERGENT (each identity sees different content)?  When NO body is available
    (real captured corpus -- Burp stores none), the relation is UNKNOWN: the
    cheap content negative control can't run, so the probe stays high-recall and
    leans entirely on the CEM gate for precision."""
    if not any(b and b.strip() for b in bodies):
        return "unknown"
    import authz_diff
    forms = set()
    for b in bodies:
        comp = authz_diff._comparable(b, frozenset())
        forms.add(comp if comp is not None else authz_diff.normalize_body(b))
    return "identical" if len(forms) <= 1 else "divergent"


def _negative_control(rows, success_rows) -> dict:
    denial_seen = any(_is_denial(r["status"]) for r in rows)
    relation = _content_relation([r["body"] for r in success_rows])
    # cheap negative control -> advisory confidence (CEM is the real gate):
    #   denial somewhere on the resource => it IS per-owner protected for some
    #     identity, so a divergent cross-identity 2xx read is more suspicious.
    #   no denial + identical content for all => looks public / a collection.
    if relation == "unknown":
        # no body to compare -> cannot raise confidence on content; cap it.
        confidence = "medium" if denial_seen else "low"
    elif denial_seen:
        confidence = "high"
    elif relation == "identical":
        confidence = "low"
    else:
        confidence = "medium"
    return {"denial_seen": denial_seen, "content_relation": relation,
            "confidence": confidence}


# --------------------------------------------------------------------------- #
# Real-request mapping (P4-M1): a mined candidate's CEM hypothesis fires at the #
# REAL captured request and drops the REAL identity header, when the corpus    #
# row carries one; otherwise the P4-M0 synthesized invariant.local scaffold.   #
# --------------------------------------------------------------------------- #
_IDENTITY_HEADERS = ("authorization", "cookie", "x-api-key", "x-auth-token")


def _identity_header_name(headers) -> str | None:
    """The identity-bearing header actually present in a captured request
    (original-case key), or None.  Must match what case-mcp's _perturbation_for
    can drop (an exact/case-insensitive header name, Authorization alias)."""
    if not isinstance(headers, dict):
        return None
    lowered = {str(k).lower(): k for k in headers}
    for name in _IDENTITY_HEADERS:
        if name in lowered:
            return lowered[name]
    return None


def _cem_spec_for_identity_drop(resource, offender) -> dict:
    """Build the CEM hypothesis for an identity-necessity test on `offender`.
    Real path (row carries a captured request with an identity header): drop
    that header on the real base_request, so run_cem_pipeline fires at the real
    target.  Synthesized path (P4-M0, no base_request): the invariant.local
    query-param scaffold -- unchanged, so existing pipeline tests still pass."""
    br = offender.get("base_request")
    body = offender.get("body") or ""
    hdr = _identity_header_name(br.get("headers") if br else None)
    if br and hdr and br.get("method", "GET").upper() in ("GET", "HEAD", "OPTIONS"):
        sig = {"status_in": [200]}
        if body.strip():
            sig["body_contains"] = _trim(body)
        return {
            "base_request": br,
            "success_signature": sig,
            "conditions": [{"name": hdr, "category": "identity",
                            "baseline_value": br["headers"][hdr],
                            "perturbation": {"drop": True}}],
        }
    return {
        "base_request": {
            "method": "GET",
            "url": _url(resource, {"identity": offender["identity"], "action": "read"}),
            "headers": {}, "body": None},
        "success_signature": {"status_in": [200], "body_contains": _trim(body)},
        "conditions": [{"name": "identity", "category": "identity",
                        "baseline_value": offender["identity"],
                        "perturbation": {"drop": True}}],
    }


# --------------------------------------------------------------------------- #
# T1 -- ownership / horizontal authz                                          #
# --------------------------------------------------------------------------- #
def _mine_ownership(resource, rows):
    reads = [r for r in rows if r["action"] in READ_ACTIONS]
    success = []
    seen_ids: set[str] = set()
    for r in reads:
        # body-optional (high recall): a real captured corpus has no body
        # (Burp stores none), so a 2xx read counts on identity alone; the CEM
        # gate -- not a body check here -- is what rejects a false positive.
        if _is_success(r["status"]) and r["identity"] not in seen_ids:
            seen_ids.add(r["identity"])
            success.append(r)
    if len(seen_ids) < 2:
        return None
    nc = _negative_control(reads, success)
    owner = success[0]["identity"]
    offender = next(r for r in success if r["identity"] != owner)
    return {
        "invariant": "ownership",
        "resource": resource,
        "confidence": nc["confidence"],
        "negative_control": {"denial_seen": nc["denial_seen"],
                             "content_relation": nc["content_relation"]},
        "observation": (
            f"{len(seen_ids)} distinct identities ({', '.join(sorted(seen_ids))}) "
            f"each read '{resource}' successfully (2xx + content); "
            f"negative control: denial_seen={nc['denial_seen']}, "
            f"content={nc['content_relation']} -> confidence {nc['confidence']}."),
        "hypothesis": (
            f"ownership invariant may be violated on '{resource}': identity "
            f"'{offender['identity']}' can read an object owned by '{owner}' "
            f"(candidate -- to be falsified by CEM, not asserted)."),
        "evidence_idx": sorted(r["_idx"] for r in success),
        "cem_spec": _cem_spec_for_identity_drop(resource, offender),
    }


# --------------------------------------------------------------------------- #
# T2 -- one-time-use / replay (ALL qualifying groups; session-bounded)        #
# --------------------------------------------------------------------------- #
def _mine_one_time_use(resource, rows):
    groups: dict[tuple, list[dict]] = {}
    for r in rows:
        key = (r["identity"], r["action"], _canon_args(r.get("args")), r.get("session"))
        groups.setdefault(key, []).append(r)

    candidates = []
    for (identity, action, _args, _session), calls in groups.items():
        if len(calls) < 2:
            continue
        if not all(_is_success(c["status"]) for c in calls):
            continue  # a non-2xx => recovery, not accumulation
        if len({c["body"] for c in calls}) < 2:
            continue  # identical responses => idempotent, invariant holds
        later = [r for r in rows
                 if r["identity"] == identity and r.get("session") == _session
                 and r["_idx"] > calls[-1]["_idx"]]
        effect = later[-1] if later else calls[-1]
        candidates.append({
            "invariant": "one_time_use",
            "resource": resource,
            "identity": identity,
            "confidence": "medium",  # replay accumulation is a behavioural signal
            "negative_control": {"denial_seen": any(_is_denial(r["status"]) for r in rows),
                                 "content_relation": "accumulating"},
            "observation": (
                f"identity '{identity}' replayed action '{action}' {len(calls)} times "
                f"on '{resource}' (same session); all 2xx but the response state "
                f"accumulated on each replay."),
            "hypothesis": (
                f"one-time-use invariant may be violated on '{resource}': replaying "
                f"'{action}' accumulates state instead of applying once (candidate "
                f"-- to be falsified by CEM)."),
            "evidence_idx": sorted([c["_idx"] for c in calls] + [effect["_idx"]]),
            "cem_spec": {
                "base_request": {
                    "method": "GET",
                    "url": _url(resource, {"identity": identity, "replays": len(calls),
                                           "action": action, "final": effect["action"]}),
                    "headers": {}, "body": None},
                "success_signature": {"status_in": [200], "body_contains": _trim(effect["body"])},
                "conditions": [{
                    "name": "replays", "category": "state",
                    "baseline_value": len(calls),
                    "perturbation": {"drop": True}}],
            },
        })
    return candidates


# --------------------------------------------------------------------------- #
# State-transition view (P4-M1): per (object-instance, session) ordered action #
# sequence -- the "state machine" is observable status/content deltas, not an  #
# inferred automaton. Used to FORM candidates; every emitted hypothesis still  #
# reduces to a frozen-CEM droppable-condition test.                            #
# --------------------------------------------------------------------------- #
def _state_class(status) -> str:
    if _is_denial(status):
        return "denied"
    if _is_success(status):
        return "ok"
    return "other"


def _sequence_by_object_session(exchanges):
    seqs: dict[tuple, list[dict]] = {}
    for i, ex in enumerate(exchanges):
        if not _valid_row(ex):
            continue
        key = (ex["resource"], ex.get("session"))
        seqs.setdefault(key, []).append({
            "actor": ex["identity"], "action": ex["action"], "status": ex["status"],
            "state_class": _state_class(ex["status"]), "_idx": ex.get("_idx", i)})
    for key in seqs:
        seqs[key].sort(key=lambda s: s["_idx"])
    return seqs


# --------------------------------------------------------------------------- #
# T3 -- vertical privilege / authz inversion                                  #
#   On one resource, >=1 identity is DENIED (401/403) while a DIFFERENT        #
#   identity SUCCEEDS (2xx). The denial-vs-success differential is the signal  #
#   (class scanners miss it); CEM then tests whether the succeeding identity's #
#   credential was actually necessary.                                         #
# --------------------------------------------------------------------------- #
def _mine_vertical_privilege(resource, rows):
    denied = [r for r in rows if _is_denial(r["status"])]
    if not denied:
        return []
    denied_ids = {r["identity"] for r in denied}
    success, seen = [], set()
    for r in rows:
        if _is_success(r["status"]) and r["identity"] not in seen:
            seen.add(r["identity"])
            success.append(r)
    # vertical privilege is about a privileged OPERATION, not reading someone's
    # object (that is T1 ownership). Scoping to non-read actions keeps correct
    # per-owner read protection (owner 2xx / non-owner 403) out of this template.
    offenders = [r for r in success
                 if r["identity"] not in denied_ids and r["action"] not in READ_ACTIONS]
    if not offenders:
        return []
    offender = offenders[0]
    return [{
        "invariant": "vertical_privilege",
        "resource": resource,
        # a denial-vs-success differential on the same object is a strong signal
        # regardless of whether a body was captured -> high (CEM is precision).
        "confidence": "high",
        "negative_control": {"denial_seen": True,
                             "content_relation": _content_relation([r["body"] for r in success])},
        "observation": (
            f"on '{resource}', identity '{offender['identity']}' succeeded (2xx) at an "
            f"action denied (401/403) to {len(denied_ids)} other identity(ies) "
            f"({', '.join(sorted(denied_ids))}) -- a vertical-privilege differential."),
        "hypothesis": (
            f"vertical-privilege invariant may be violated on '{resource}': identity "
            f"'{offender['identity']}' performs an action others are denied "
            f"(candidate -- to be falsified by CEM, not asserted)."),
        "evidence_idx": sorted([r["_idx"] for r in denied] + [offender["_idx"]]),
        "cem_spec": _cem_spec_for_identity_drop(resource, offender),
    }]


# --------------------------------------------------------------------------- #
# Public API                                                                  #
# --------------------------------------------------------------------------- #
def mine_invariants(exchanges: list[dict]) -> list[dict]:
    """Return candidate broken-invariant records mined from an observed corpus.
    Each record is a hypothesis to falsify (see module docstring and
    `to_cem_hypothesis`), never an assertion of a confirmed finding.  High
    recall: candidates include the public/shared case, annotated with a
    negative-control `confidence`; the frozen CEM counterfactual is the
    precision gate.  Malformed rows are skipped, never fatal."""
    candidates: list[dict] = []
    for resource, rows in _by_resource(exchanges).items():
        own = _mine_ownership(resource, rows)
        if own is not None:
            candidates.append(own)
        candidates.extend(_mine_one_time_use(resource, rows))
        candidates.extend(_mine_vertical_privilege(resource, rows))
    return candidates


def to_cem_hypothesis(candidate: dict, db_path: str | None = None) -> dict:
    """Express one mined candidate as a CEM-provable hypothesis through the
    EXISTING case_store path -- no new store/table.  Returns
    {hypothesis_id, finding_id, condition_ids} or {"error": ...}.  The stored
    base_request + {"drop": true} condition are RUNNABLE by the frozen
    case-mcp.run_cem_pipeline (the probe->CEM precision gate)."""
    import case_store

    spec = candidate["cem_spec"]
    h = case_store.log_hypothesis(candidate["observation"], candidate["hypothesis"],
                                   db_path=db_path)
    if "error" in h:
        return h
    f = case_store.create_finding(
        vuln_class="invariant_violation", endpoint=candidate["resource"],
        parameter=candidate["invariant"], hypothesis_id=h["id"], db_path=db_path)
    if "error" in f:
        return f
    d = case_store.cem_define(
        finding_id=f["id"], base_request=spec["base_request"],
        success_signature=spec["success_signature"], conditions=spec["conditions"],
        db_path=db_path)
    if "error" in d:
        return d
    return {"hypothesis_id": h["id"], "finding_id": f["id"],
            "condition_ids": d["condition_ids"]}
