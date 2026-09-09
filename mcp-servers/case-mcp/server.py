import json
import os
import sys
import time
from contextlib import contextmanager
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import case_store
import cem_engine
import http_probe
import scope_guard
from audit_log import log_call as _log_call
from budget_guard import BudgetExceeded
from budget_guard import enforce as _enforce_budget
from budget_guard import enforce_cem_finding as _enforce_cem_finding
from mcp.server.fastmcp import FastMCP

app = FastMCP("case-mcp")


@app.tool()
def log_hypothesis(observation: str, hypothesis: str) -> str:
    """Record a new hypothesis for this engagement: what you observed, and
    what you think it means (e.g. observation="URL parameter `url=` fetched
    server-side and echoed in the response", hypothesis="server performs an
    unvalidated SSRF-prone fetch"). Starts at status NEW. Call
    update_hypothesis() as you test it. Returns the new hypothesis id --
    use it as hypothesis_id in log_experiment()/add_evidence()/
    create_finding()."""
    return json.dumps(case_store.log_hypothesis(observation, hypothesis))


@app.tool()
def update_hypothesis(hypothesis_id: int, status: str, note: str = "") -> str:
    """Move a hypothesis to a new status: NEW (untested) -> TESTING (a test
    is in flight) -> SUPPORTED/REFUTED/INCONCLUSIVE (test result) ->
    CONFIRMED (verified, ready to become a finding). note is a short
    free-text reason, e.g. why it was REFUTED."""
    return json.dumps(case_store.update_hypothesis(hypothesis_id, status, note))


@app.tool()
def add_evidence(type: str, content: str, hypothesis_id: int = 0, finding_id: int = 0) -> str:
    """Attach immutable evidence (raw request, response body, OOB callback
    log, screenshot description, DNS record, source snippet, or other
    metadata) to a hypothesis and/or a finding. type must be one of:
    request, response, callback, screenshot, dns, source, metadata.
    Content is hashed (SHA-256) and stored content-addressed, so writing
    identical content twice is a safe no-op. Pass hypothesis_id and/or
    finding_id (0 means "not linked" for that one) -- update_finding_status()
    refuses to mark a finding CONFIRMED or IMPACT_PROVEN until it has at
    least one linked evidence row, so call this BEFORE that call, not after."""
    return json.dumps(case_store.add_evidence(
        type, content,
        hypothesis_id=hypothesis_id or None,
        finding_id=finding_id or None,
    ))


@app.tool()
def log_experiment(tool: str, input: str, target: str, result: str = "", cost: int = 0,
                    hypothesis_id: int = 0, finding_id: int = 0, status: str = "done") -> str:
    """Record that a specific test actually ran: which tool, what input
    (e.g. the exact payload or command), against what target, and the
    result. Call this for every test you run, not just successful ones --
    check_experiment_exists() relies on it to stop you re-running a test
    you already tried earlier this engagement."""
    return json.dumps(case_store.log_experiment(
        tool, input, target, result=result, cost=cost,
        hypothesis_id=hypothesis_id or None, finding_id=finding_id or None, status=status,
    ))


@app.tool()
def check_experiment_exists(tool: str, input: str, target: str) -> str:
    """Check whether this exact tool+input+target combination has already
    been run and logged via log_experiment() this engagement -- call this
    BEFORE running a test to avoid repeating work."""
    exists = case_store.check_experiment_exists(tool, input, target)
    return "true" if exists else "false"


@app.tool()
def create_finding(vuln_class: str, endpoint: str, parameter: str = "", hypothesis_id: int = 0) -> str:
    """Register a new finding at status DISCOVERED. Optionally link the
    hypothesis_id that led to it. Returns the new finding id -- use it in
    add_evidence()/update_finding_status()/score_finding_confidence()."""
    return json.dumps(case_store.create_finding(
        vuln_class, endpoint, parameter=parameter, hypothesis_id=hypothesis_id or None,
    ))


@app.tool()
def update_finding_status(finding_id: int, status: str) -> str:
    """Move a finding through its lifecycle: DISCOVERED -> SUSPECTED ->
    VALIDATING -> CONFIRMED -> IMPACT_PROVEN -> REPORTED, or off to
    FALSE_POSITIVE/DUPLICATE/INCONCLUSIVE at any point. Moving to CONFIRMED
    or IMPACT_PROVEN is REJECTED if the finding has zero linked evidence
    rows -- call add_evidence(..., finding_id=...) first."""
    return json.dumps(case_store.update_finding_status(finding_id, status))


@app.tool()
def score_finding_confidence(finding_id: int, signals: str) -> str:
    """Set a finding's confidence from named evidence signals instead of
    self-rating it. signals is a JSON object of {label: points}, e.g.
    '{"endpoint_confirmed": 15, "parameter_confirmed": 15, "reproduction": 25,
    "oob_confirmation": 20}'. Points are summed (clamped 0-100) and banded:
    0-30 LOW, 31-60 MEDIUM, 61-80 HIGH, 81-100 CONFIRMED."""
    try:
        parsed = json.loads(signals)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"signals must be a JSON object: {e}"})
    return json.dumps(case_store.score_finding_confidence(finding_id, parsed))


@app.tool()
def group_root_cause(finding_ids: str, description: str) -> str:
    """Group 2+ findings under one underlying root cause (e.g. IDOR on
    /api/user, /api/orders, and /api/documents are all the same broken
    authorization middleware). finding_ids is a JSON array of ints, e.g.
    '[3, 5, 7]'. Use suggest_root_cause() first to see obvious candidates."""
    try:
        ids = json.loads(finding_ids)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"finding_ids must be a JSON array of ints: {e}"})
    return json.dumps(case_store.group_root_cause(ids, description))


@app.tool()
def suggest_root_cause() -> str:
    """Heuristic suggestion: findings that already share the same
    vuln_class+endpoint signature and aren't grouped under a root cause
    yet. A starting point, not semantic inference -- confirm with your own
    judgment before calling group_root_cause()."""
    return case_store.suggest_root_cause()


@app.tool()
def suggest_next_action() -> str:
    """What to work on next, prioritizing finishing what's already in
    flight (a TESTING hypothesis, an in-progress finding) over starting
    something fresh. Call this when deciding what to test next instead of
    picking arbitrarily."""
    return case_store.suggest_next_action()


@app.tool()
def case_summary() -> str:
    """Current case state: hypothesis/finding counts by status, evidence
    and experiment counts, root causes grouped. Call this to orient before
    deciding what to do next, or before handing off to another agent."""
    return case_store.case_summary()


@app.tool()
def case_export() -> str:
    """Full case state as JSON (all hypotheses, findings, evidence,
    experiments, root causes) -- for report-agent or human review. There
    is no matching case_import(); this engagement's case.db on disk is
    already the durable copy."""
    return case_store.case_export()


# ---------------------------------------------------------------------------
# CEM (Counterfactual Evidence Minimization) tools -- PHASE1-EXECUTION-PLAN.md
# task E1. Thin MCP wrappers over cem_engine.py (the pure algorithm) + the
# case_store CEM CRUD (B2). The two senders (determinism_gate, run_counterfactual)
# send real HTTP via http_probe.fetch and carry a `url` arg so the scope hook can
# gate them once F1 adds "case-mcp" to TIER2_MCP_SERVERS. Budget + audit are
# wired inline in E2; CONFIRMED-state + success_signature guards in E3; content-
# addressed evidence-hash linking + full audit/confounder capture in G1. E1
# persists cem_trials rows as trials happen and one cem_verdicts row per
# run_counterfactual (human-approved "fuller" depth, 2026-09-07 via
# AskUserQuestion). Perturbation vocabulary: the implicit `{"drop": true}` shape
# already in tests/test_cem_case_store.py (human-approved 2026-09-07) -- drop the
# header or query param the condition names.
# ---------------------------------------------------------------------------

_AUTH_HEADER_ALIASES = {
    "auth_cookie": "Cookie",
    "session_cookie": "Cookie",
    "cookie": "Cookie",
    "authorization": "Authorization",
    "bearer_token": "Authorization",
    "bearer": "Authorization",
    "auth_header": "Authorization",
}


def _drop_query_param(url: str, key: str) -> str:
    """Return `url` with every `key=...` pair removed from the query string.
    Scheme/host/path/fragment untouched."""
    parts = urlsplit(url)
    kept = [(k, v) for (k, v) in parse_qsl(parts.query, keep_blank_values=True) if k != key]
    return urlunsplit(parts._replace(query=urlencode(kept)))


def _perturbation_for(condition: dict):
    """Translate a stored cem_conditions row into a Callable[[dict], dict] for
    cem_engine.run_intervention (D2's "the E-layer translates the JSON"). Phase-1
    supports only `perturbation == {"drop": true}`: remove the header or query
    param this condition names (with a couple of auth-header aliases). An
    unsupported shape or an un-locatable target raises ValueError -- never a
    silent no-op (a no-op perturbation would make every condition look
    apparently_not_necessary)."""
    pert = condition.get("perturbation")
    if pert != {"drop": True}:
        raise ValueError(
            f"Phase-1 run_counterfactual only supports perturbation {{\"drop\": true}}, "
            f"got {pert!r} for condition {condition.get('name')!r}"
        )
    name = condition["name"]
    alias = _AUTH_HEADER_ALIASES.get(name.lower())

    def _apply(req: dict) -> dict:
        headers = dict(req.get("headers") or {})
        # 1) an exact (case-insensitive) header match, or a known auth alias
        target_hdr = next(
            (h for h in headers if h.lower() == name.lower()),
            alias if alias and alias in headers else None,
        )
        if target_hdr is not None:
            headers.pop(target_hdr, None)
            return {**req, "headers": headers}
        # 2) a query param currently present in the URL
        url = req.get("url", "")
        if any(k == name for (k, _) in parse_qsl(urlsplit(url).query, keep_blank_values=True)):
            return {**req, "url": _drop_query_param(url, name)}
        raise ValueError(
            f"cannot apply {{\"drop\": true}} for condition {name!r}: no matching header "
            f"or query param in the base request"
        )

    # Fail fast at build time if the target cannot be located in the base request
    # would require the request here; that check happens per-trial inside _apply.
    return _apply


_CONFIRMED_STATES = ("CONFIRMED", "IMPACT_PROVEN")


def _confirmed_or_error(finding_id: int):
    """E3 guard (a): CEM only tests a finding independently confirmed through the
    normal flow (PHASE1-PLAN sec B) -- status CONFIRMED or IMPACT_PROVEN, both of
    which case_store's evidence gate only lets a finding reach with >=1 linked
    evidence row. Returns an error-JSON string if the finding is missing or not
    in a confirmed state, else None. Re-checked on the senders too, so a finding
    demoted to FALSE_POSITIVE/DUPLICATE after define_conditions can't still send
    real requests."""
    f = case_store.get_finding(finding_id)
    if f is None:
        return json.dumps({"error": f"no finding with id {finding_id}"})
    if f["status"] not in _CONFIRMED_STATES:
        return json.dumps({
            "error": f"finding {finding_id} is {f['status']!r}, not CONFIRMED/IMPACT_PROVEN -- "
                     "CEM only tests an independently confirmed finding",
        })
    return None


def _load_cem_or_error(finding_id: int):
    state = case_store.cem_load_state(finding_id)
    if "error" in state:
        return None, json.dumps(state)
    return state, None


def _signature_or_error(meta: dict):
    try:
        return cem_engine.SuccessSignature.from_dict(meta["success_signature"]), None
    except (TypeError, ValueError) as e:
        return None, json.dumps({"error": f"stored success_signature is invalid: {e}"})


def _arm_hits(trials, arm):
    return [t.oracle_hit for t in trials if t.arm == arm]


class ScopeDenied(Exception):
    """F3: raised by the per-trial scope callback (`_make_scope_cb`) when a CEM
    outbound URL, resolved AFTER `controls.pin` and AFTER the perturbation, is not
    in scope (or cannot be evaluated). Caught by `_sender_run` -> a graceful
    `{"error", "incomplete": true}` result, no partial trial/verdict persisted,
    one audit line (`block="scope"`). Not a `ValueError` -- `_sender_run` treats
    those as `block="error"` and re-raises."""


class PerturbationRefused(Exception):
    """F3b / UD-4: raised by the per-trial method callback (`_make_method_cb`) when
    a CEM outbound HTTP method, resolved AFTER `controls.pin` and AFTER the
    perturbation, is a non-idempotent / state-changing verb the finding is not
    explicitly authorized for. Caught by `_sender_run` -> graceful
    `{"error", "incomplete": true, "refused": "nonidempotent_perturbation"}`, no
    partial trial/verdict persisted, one audit line (`block="method"`). Distinct
    exception + distinct block so a state-change refusal is never confused with a
    scope, budget, E3, or malformed-perturbation denial."""


_REFUSED_NONIDEMPOTENT = "nonidempotent_perturbation"


def _resolve_engagement():
    """The active engagement for a scope check, mirroring the PreToolUse hook:
    `NoEngagementFile` -> an empty `Engagement` (a safe test host still passes via
    `is_in_scope`'s `is_safe_test_host` branch; a real host does not). Any other
    resolution failure propagates so the caller fails closed."""
    try:
        return scope_guard.load_engagement()
    except scope_guard.NoEngagementFile:
        return scope_guard.Engagement(target="(no engagement.yaml)")


def _scope_or_error(base_request: dict):
    """SEC-1 (F1): the scope decision must protect the URL
    cem_engine.run_intervention will ACTUALLY fetch -- meta["base_request"]["url"]
    -- not the caller-supplied `url` argument the senders also take (that arg is
    an audit label; the PreToolUse hook early-filters it, but a caller can leave
    it blank or point it elsewhere). Checking base_request["url"] here, right
    before run_intervention, makes that decoupling impossible: the checked value
    IS the fetched value for the baseline arm.

    NOTE (F3): this is a fast fail-fast on the STORED base URL only. The URL a
    perturbed arm actually fetches is resolved per trial inside run_intervention
    (base -> pin -> perturbation) and re-verified there via `_make_scope_cb`;
    this check does not see it.

    Reuses scope_guard -- the exact module scripts/hooks/scope_gate_hook.py and
    scripts/check-scope.sh use -- so there is no second source of truth for scope
    rules. Semantics mirror the hook: a safe test host (loopback / RFC1918 /
    example.* / dev-infra) needs no engagement.yaml; any other host requires an
    active engagement whose in_scope covers it. Fail-closed: a missing/blank
    target, an unreadable engagement, or any evaluation error -> refuse.

    Returns an error-JSON string to hand back to the caller, or None if the send
    is in scope. Runs before _sender_run / run_intervention, so a refusal sends
    no HTTP, enforces no budget, and persists nothing."""
    target = base_request.get("url") if isinstance(base_request, dict) else None
    if not isinstance(target, str) or not target.strip():
        return json.dumps({"error":
            "BLOCKED by scope gate: CEM base_request has no 'url' -- cannot verify "
            "the request destination is in scope; refusing to send."})
    try:
        if scope_guard.is_in_scope(target, _resolve_engagement()):
            return None
    except Exception as e:  # noqa: BLE001 - any resolution/parse failure -> refuse
        return json.dumps({"error":
            f"BLOCKED by scope gate: could not verify CEM target {target!r} is in "
            f"scope ({e.__class__.__name__}: {e}); refusing to send."})
    return json.dumps({"error":
        f"BLOCKED by scope gate: CEM request target {target!r} (base_request['url'], "
        "the URL determinism_gate/run_counterfactual actually fetches) is not in "
        "the active engagement's in_scope list -- refusing to send. The `url` "
        "argument is only an audit label and does not affect this decision."})


def _make_scope_cb(engagement):
    """F3: the authoritative per-trial scope check `cem_engine.run_intervention`
    runs against the FINAL resolved URL of every trial of every arm --
    `perturbation(controls.pin(base_request, i))["url"]`, the exact string handed
    to `http_probe.fetch` on the next statement.

    F1's `_scope_or_error()` only ever sees the stored `base_request["url"]`. A
    perturbation is arbitrary caller code -- today host-preserving ({"drop": true}),
    tomorrow anything -- and can rewrite scheme/host/port AFTER that check. This
    callback closes the gap: it is the boundary for the URL actually contacted,
    and it cannot drift, because run_intervention resolves the request, calls
    this, then fetches, all within one loop iteration.

    `engagement` is resolved ONCE by the sender (one snapshot for the whole run,
    no per-trial file I/O). Reuses `scope_guard.is_in_scope` -- same source of
    truth as F1 and the hook. Raises `ScopeDenied` on an out-of-scope URL, a
    non-string/blank URL, or any evaluation error -- fail closed."""
    def _cb(url) -> None:
        try:
            ok = isinstance(url, str) and bool(url.strip()) and scope_guard.is_in_scope(url, engagement)
        except Exception as e:  # any parse/resolution failure -> refuse (fail closed)
            raise ScopeDenied(
                f"BLOCKED by scope gate: could not verify perturbed CEM target "
                f"{url!r} is in scope ({e.__class__.__name__}: {e}); refusing to send."
            ) from e
        if not ok:
            raise ScopeDenied(
                f"BLOCKED by scope gate: a CEM perturbation resolved the outbound URL "
                f"to {url!r}, which is not in the active engagement's in_scope list -- "
                "refusing to send. (F3: the URL actually fetched is scope-checked "
                "per trial, not just the stored base_request URL.)"
            )
    return _cb


def _scope_cb_or_error():
    """Build the F3 per-trial scope callback for a sender. Returns
    `(cb, None)` on success, or `(None, error_json)` if the engagement cannot be
    resolved at all (fail closed -- never hand run_intervention a no-op check)."""
    try:
        engagement = _resolve_engagement()
    except Exception as e:  # noqa: BLE001 - any resolution failure -> refuse (fail closed)
        return None, json.dumps({"error":
            f"BLOCKED by scope gate: cannot resolve the active engagement to scope-check "
            f"CEM requests ({e.__class__.__name__}: {e}); refusing to send."})
    return _make_scope_cb(engagement), None


# --- F3b / UD-4: non-idempotent / state-changing method policy --------------
# One authoritative decision -- `cem_engine.check_method_allowed(method, approval)`
# -- adapted two ways: a sender FAIL-FAST on the stored base_request method
# (clean early error, no _sender_run) and a per-trial `method_check` callback
# (catches a future perturbation that rewrites the method). Both read the SAME
# persisted `meta["nonidempotent_approval"]`; the approval is never a caller
# argument. Refusal ordering per the plan: E3 -> UD-4 -> F1 scope -> F2 budget.


def _nonidempotent_or_error(meta: dict):
    """UD-4 sender fail-fast: reject before `_sender_run` if the STORED base
    request is not read-only for CEM (a non-idempotent verb, or a method-override
    header) and the finding carries no valid authorization. Returns an error-JSON
    string or None. Covers the common case + the baseline arm; the per-trial
    `method_check` covers a perturbation that changes either."""
    br = meta.get("base_request") if isinstance(meta.get("base_request"), dict) else {}
    reason = cem_engine.check_request_allowed(
        br.get("method", "GET"), br.get("headers") or {}, meta.get("nonidempotent_approval"))
    if reason is None:
        return None
    return json.dumps({
        "error": f"BLOCKED (UD-4 non-idempotent perturbation): {reason}. CEM is read-only by "
                 "default; authorize a specific state-changing method for this finding at "
                 "define_conditions (nonidempotent_approval) if this is intended.",
        "refused": _REFUSED_NONIDEMPOTENT,
    })


def _make_method_cb(approval):
    """F3b per-trial gate: given the FINAL resolved request (after `controls.pin`
    and the perturbation), raise `PerturbationRefused` unless
    `cem_engine.check_request_allowed` clears its verb AND any method-override
    header against this finding's persisted `approval` (captured once per run)."""
    def _cb(req) -> None:
        headers = req.get("headers") if isinstance(req, dict) else None
        method = req.get("method", "GET") if isinstance(req, dict) else None
        reason = cem_engine.check_request_allowed(method, headers or {}, approval)
        if reason is not None:
            raise PerturbationRefused(f"BLOCKED (UD-4 non-idempotent perturbation): {reason}.")
    return _cb


# --- shared Tier-2 sender plumbing (E2; B-1 de-dup) ------------------------
# The two CEM senders (determinism_gate, run_counterfactual) both: enforce the
# Tier-2 budget before every real request, write exactly one audit line per
# invocation, and turn a budget exhaustion into a graceful incomplete result
# without persisting a partial run. That control flow lives here once, not
# copy-pasted per sender -- so F2's per-finding request ceiling is a change to
# `_make_budget_cb` alone.


def _make_budget_cb(finding_id: int):
    """The per-request budget check `cem_engine.run_intervention` calls before
    every real HTTP request (E2 B-1: the single seam -- both senders build their
    callback here, `finding_id` threaded through).

    F2: the callback enforces BOTH budgets, per-finding FIRST:
      1. `budget_guard.enforce_cem_finding(finding_id)` -- the per-finding CEM
         request ceiling (`HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING`). Checked first
         so that once a finding is capped, further denied requests raise here
         and never reach -- never nibble -- the shared engagement counter.
      2. `budget_guard.enforce("case-mcp")` -- the engagement-wide Tier-2 cap
         (E2, unchanged). Every request that actually fetches passes through it.
    Either raising `BudgetExceeded` stops the arm before the next fetch;
    `_sender_run` turns it into a graceful `incomplete` result with no partial
    trial/verdict persisted (E2 T-2)."""
    def _cb() -> None:
        _enforce_cem_finding(finding_id)   # F2: per-finding ceiling (outer-protecting)
        _enforce_budget("case-mcp")        # E2: engagement-wide cap

    return _cb


@contextmanager
def _sender_run(tool_args: list[str]):
    """Wrap a Tier-2 CEM sender's `run_intervention` call(s). Times the block,
    writes exactly ONE `audit_log.log_call("case-mcp", tool_args, …)` on exit
    (`block="budget"` for `BudgetExceeded`, `"scope"` for `ScopeDenied` (F3),
    `"method"` for `PerturbationRefused` (F3b/UD-4), `"error"` for a `ValueError`,
    else `None`), swallows `BudgetExceeded` / `ScopeDenied` / `PerturbationRefused`
    so the sender can emit a graceful `{"error", "incomplete": true}` result, and
    re-raises any `ValueError` (still audited) so the sender's own handler formats
    it. Yields `{"budget_hit", "scope_hit", "method_hit"}` (each str|None) for the
    sender to read after the block."""
    start = time.monotonic()
    outcome = {"budget_hit": None, "scope_hit": None, "method_hit": None}
    block = None
    try:
        yield outcome
    except BudgetExceeded as e:
        outcome["budget_hit"] = str(e)
        block = "budget"
    except ScopeDenied as e:
        outcome["scope_hit"] = str(e)
        block = "scope"
    except PerturbationRefused as e:
        outcome["method_hit"] = str(e)
        block = "method"
    except ValueError:
        block = "error"
        raise
    finally:
        _log_call(
            "case-mcp", tool_args, returncode=None,
            duration_ms=(time.monotonic() - start) * 1000, block=block,
        )


@app.tool()
def define_conditions(finding_id: int, base_request: str, success_signature: str,
                       conditions: str, k: int = 5, nonidempotent_approval: str = "") -> str:
    """Persist the CEM setup for an already-CONFIRMED finding (one-shot): the base
    request, the caller-supplied success_signature oracle (UD-3 -- explicit only,
    never auto-derived), and one row per candidate condition. base_request and
    success_signature are JSON objects; conditions is a JSON array of
    {name, category, baseline_value, perturbation} (perturbation is the implicit
    {"drop": true} shape). Local tool (no host arg).

    `nonidempotent_approval` (F3b/UD-4, OPTIONAL): CEM is read-only by default --
    any outbound method other than GET/HEAD/OPTIONS is refused. To deliberately
    authorize a state-changing CEM experiment for THIS finding, pass a JSON object
    `{"methods": [<POST|PUT|PATCH|DELETE>...], "reason": "<why>",
    "authorized_by": "<who>"}`. It is stored on the finding, applies to every
    determinism_gate / run_counterfactual call for it, and cannot be supplied any
    other way (never a sender argument). Omit it for a normal read-only run."""
    try:
        br = json.loads(base_request)
        sig = json.loads(success_signature)
        conds = json.loads(conditions)
        approval = json.loads(nonidempotent_approval) if nonidempotent_approval.strip() else None
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"base_request/success_signature/conditions/"
                                    f"nonidempotent_approval must be JSON: {e}"})
    err = _confirmed_or_error(finding_id)                     # E3 guard (a)
    if err:
        return err
    try:                                                     # E3 guard (b): UD-3
        cem_engine.SuccessSignature.from_dict(sig)
    except (TypeError, ValueError) as e:
        return json.dumps({
            "error": f"invalid success_signature (UD-3: caller-supplied only, never derived): {e}",
        })
    if approval is not None:                                 # UD-4: validate before persisting
        _, ap_err = cem_engine.validate_nonidempotent_approval(approval)
        if ap_err:
            return json.dumps({"error": f"invalid nonidempotent_approval (UD-4): {ap_err}"})
    return json.dumps(
        case_store.cem_define(finding_id, br, sig, conds, k=k, nonidempotent_approval=approval)
    )


@app.tool()
def determinism_gate(finding_id: int, url: str, k: int = 0) -> str:
    """Sender (Tier-2): re-run the finding's stored base_request k times
    unperturbed and report STABLE (all-k HIT) vs NONDETERMINISTIC.

    SCOPE: the request actually sent targets `meta["base_request"]["url"]`, and
    that is what `_scope_or_error` checks here (before any HTTP) via scope_guard
    -- an out-of-scope stored target is refused regardless of the `url` argument.
    `url` is only an audit/early-filter label for the PreToolUse hook; it does
    not need to (and for security must not be trusted to) match the real target.

    `budget_guard.enforce("case-mcp")` runs before every real request and
    `audit_log.log_call(...)` writes one line per invocation, same as
    idor-mcp/server.py. Records each baseline trial. k defaults to the finding's
    stored k. determinism_status is returned but not yet written to cem_meta
    (deferred)."""
    state, err = _load_cem_or_error(finding_id)
    if err:
        return err
    err = _confirmed_or_error(finding_id)   # E3: re-check current status before sending
    if err:
        return err
    meta = state["meta"]
    k = k or meta["k"]
    sig, err = _signature_or_error(meta)
    if err:
        return err
    err = _nonidempotent_or_error(meta)           # UD-4: fail-fast on the stored base method
    if err:
        return err
    err = _scope_or_error(meta["base_request"])   # F1 SEC-1: fast fail-fast on the stored base URL
    if err:
        return err
    scope_cb, err = _scope_cb_or_error()          # F3: authoritative per-trial check on the ACTUAL fetched URL
    if err:
        return err
    method_cb = _make_method_cb(meta.get("nonidempotent_approval"))   # UD-4: per-trial resolved-method gate

    trials = []
    with _sender_run(["determinism_gate", url, f"finding {finding_id}", f"k={k}"]) as run:
        trials = cem_engine.run_intervention(
            meta["base_request"], cem_engine.Controls(), None, k,
            _make_budget_cb(finding_id), sig, http_probe.fetch,
            scope_check=scope_cb, method_check=method_cb,
        )

    controls_blob = cem_engine.Controls().record()
    for t in trials:
        case_store.cem_record_trial(
            finding_id, t.arm, t.k_index, t.oracle_hit,
            http_status=t.http_status, controls=controls_blob,
        )
    hits = [t.oracle_hit for t in trials]
    throttled = cem_engine.throttled_in(trials)
    stable = (not throttled) and len(hits) == k and all(hits)
    out = {
        "finding_id": finding_id,
        "determinism_status": "STABLE" if stable else "NONDETERMINISTIC",
        "hits": hits,
        "k": k,
        "throttled": throttled,
    }
    if run["budget_hit"]:
        case_store.cem_mark_incomplete(finding_id)   # F2: partial bundle flag
        out["error"] = f"Tier-2 budget exhausted: {run['budget_hit']}"
        out["incomplete"] = True
    elif run["scope_hit"]:
        case_store.cem_mark_incomplete(finding_id)   # F3: perturbation resolved an out-of-scope URL
        out["error"] = run["scope_hit"]
        out["incomplete"] = True
    elif run["method_hit"]:
        case_store.cem_mark_incomplete(finding_id)   # UD-4: perturbation resolved a state-changing method
        out["error"] = run["method_hit"]
        out["incomplete"] = True
        out["refused"] = _REFUSED_NONIDEMPOTENT
    if out.get("incomplete"):
        # G1: a gated/truncated run produced no real determinism observation --
        # do not leave the computed "NONDETERMINISTIC" (from zero trials) in a
        # field a consumer might read on its own.
        out["determinism_status"] = "INCOMPLETE"
    return json.dumps(out)


@app.tool()
def run_counterfactual(finding_id: int, url: str, condition_id: int, k: int = 0) -> str:
    """Sender (Tier-2): test one condition, one variable at a time. Pins a default
    Controls set, runs the baseline arm + the perturbed arm (only this condition
    dropped) k times each, and classifies per PHASE1-PLAN sec D -- forcing
    `inconclusive` on an uncontrolled confounder (apply_control_gate), a 429
    (apply_throttle_gate), or a partial/aborted arm. Records every trial and one
    cem_verdicts row.

    SCOPE (F1 + F3): `_scope_or_error` fail-fasts on the stored base URL; then a
    per-trial `scope_check` (built by `_scope_cb_or_error`) re-verifies the FINAL
    resolved URL of EVERY trial of BOTH arms inside run_intervention -- i.e.
    `perturbation(controls.pin(base, i))["url"]` -- immediately before its fetch.
    So even a future perturbation type that rewrites scheme/host/port is checked
    against its actual destination; an out-of-scope result -> `ScopeDenied` ->
    graceful `incomplete`, nothing sent, nothing persisted. The `url` argument is
    only an audit/early-filter label."""
    state, err = _load_cem_or_error(finding_id)
    if err:
        return err
    err = _confirmed_or_error(finding_id)   # E3: re-check current status before sending
    if err:
        return err
    meta = state["meta"]
    k = k or meta["k"]
    condition = next((c for c in state["conditions"] if c["id"] == condition_id), None)
    if condition is None:
        return json.dumps({"error": f"condition {condition_id} not found for finding {finding_id}"})
    sig, err = _signature_or_error(meta)
    if err:
        return err
    try:
        perturb = _perturbation_for(condition)
    except ValueError as e:
        return json.dumps({"error": str(e)})
    err = _nonidempotent_or_error(meta)           # UD-4: fail-fast on the stored base method
    if err:
        return err
    err = _scope_or_error(meta["base_request"])   # F1 SEC-1: fast fail-fast on the stored base URL
    if err:
        return err
    scope_cb, err = _scope_cb_or_error()          # F3: authoritative per-trial check on the ACTUAL fetched URL
    if err:
        return err
    method_cb = _make_method_cb(meta.get("nonidempotent_approval"))   # UD-4: per-trial resolved-method gate

    controls = cem_engine.Controls()
    tool_args = ["run_counterfactual", url, f"finding {finding_id}",
                 f"condition {condition_id}", f"k={k}"]
    try:
        with _sender_run(tool_args) as run:
            base_trials = cem_engine.run_intervention(
                meta["base_request"], controls, None, k,
                _make_budget_cb(finding_id), sig, http_probe.fetch,
                scope_check=scope_cb, method_check=method_cb,
            )
            pert_trials = cem_engine.run_intervention(
                meta["base_request"], controls, perturb, k,
                _make_budget_cb(finding_id), sig, http_probe.fetch,
                scope_check=scope_cb, method_check=method_cb,
            )
    except ValueError as e:  # perturbation could not be applied to a real trial (already audited)
        return json.dumps({"error": str(e)})
    if run["budget_hit"]:
        case_store.cem_mark_incomplete(finding_id)   # F2: partial bundle flag
        return json.dumps({
            "finding_id": finding_id,
            "condition_id": condition_id,
            "error": f"Tier-2 budget exhausted: {run['budget_hit']}",
            "incomplete": True,
        })
    if run["scope_hit"]:
        case_store.cem_mark_incomplete(finding_id)   # F3: perturbation resolved an out-of-scope URL
        return json.dumps({
            "finding_id": finding_id,
            "condition_id": condition_id,
            "error": run["scope_hit"],
            "incomplete": True,
        })
    if run["method_hit"]:
        case_store.cem_mark_incomplete(finding_id)   # UD-4: perturbation resolved a state-changing method
        return json.dumps({
            "finding_id": finding_id,
            "condition_id": condition_id,
            "error": run["method_hit"],
            "incomplete": True,
            "refused": _REFUSED_NONIDEMPOTENT,
        })

    controls_blob = controls.record()
    for t in (*base_trials, *pert_trials):
        case_store.cem_record_trial(
            finding_id, t.arm, t.k_index, t.oracle_hit,
            condition_id=None if t.arm == cem_engine.ARM_BASELINE else condition_id,
            http_status=t.http_status, controls=controls_blob,
        )

    all_trials = [*base_trials, *pert_trials]
    partial = len(base_trials) < k or len(pert_trials) < k
    if partial or cem_engine.throttled_in(all_trials):
        verdict = cem_engine.VERDICT_INCONCLUSIVE
        detail = "throttled or partial arm -- causal comparison not trustworthy"
    else:
        verdict = cem_engine.classify(
            [t.oracle_hit for t in base_trials], [t.oracle_hit for t in pert_trials], k,
        )
        verdict = cem_engine.apply_control_gate(verdict, controls)
        verdict = cem_engine.apply_throttle_gate(verdict, all_trials)
        detail = f"condition {condition['name']!r}"
    case_store.cem_record_verdict(
        finding_id, verdict, k, controls_blob, condition_id=condition_id, detail=detail,
    )
    return json.dumps({
        "finding_id": finding_id,
        "condition_id": condition_id,
        "condition": condition["name"],
        "verdict": verdict,
        "k": k,
        "baseline_hits": [t.oracle_hit for t in base_trials],
        "perturbed_hits": [t.oracle_hit for t in pert_trials],
    })


def _stored_verdict_map(state: dict) -> dict:
    """condition name -> most-recent stored per-condition verdict string."""
    by_id = {c["id"]: c["name"] for c in state["conditions"]}
    out = {}
    for v in state["verdicts"]:
        name = by_id.get(v["condition_id"])
        if name is not None:
            out[name] = v["verdict"]
    return out


@app.tool()
def minimal_condition_sets(finding_id: int) -> str:
    """Local: from the per-condition verdicts already recorded by
    run_counterfactual, run bounded ddmin (cem_engine.find_alternate_condition_sets)
    over the conditions that classified `necessary` to recover 1-minimal condition
    set(s) + alternates + interactions with a completeness bound. Phase-1 E1 uses a
    stored-verdict predicate (a condition outside a set is droppable iff its
    recorded verdict is `apparently_not_necessary`); live subset re-trials need the
    budget guard (E2) and are deferred."""
    state, err = _load_cem_or_error(finding_id)
    if err:
        return err
    vmap = _stored_verdict_map(state)
    present = sorted(n for n, v in vmap.items() if v == cem_engine.VERDICT_NECESSARY)
    if not present:
        return json.dumps({
            "error": "no condition has a recorded `necessary` verdict yet -- "
                     "run run_counterfactual for each condition first",
        })

    if len(present) == 1:
        # one necessary condition -> the minimal set is trivially itself; ddmin /
        # alternates over a 1-element universe is degenerate.
        return json.dumps({
            "finding_id": finding_id,
            "minimal_sets": [present],
            "interacting": [],
            "sets_found": 1,
            "trials_used": 0,
            "bounded": False,
            "predicate": "stored-verdict (E1); live subset re-trials deferred to E2",
        })

    def is_interesting(subset) -> bool:
        # every condition NOT in `subset` must be individually droppable
        return bool(subset) and all(
            vmap.get(n) == cem_engine.VERDICT_APPARENTLY_NOT_NECESSARY
            for n in present if n not in subset
        )

    result = cem_engine.find_alternate_condition_sets(present, is_interesting, max_trials=64)
    return json.dumps({
        "finding_id": finding_id,
        "minimal_sets": [sorted(s) for s in result.minimal_sets],
        "interacting": sorted(result.interacting),
        "sets_found": result.sets_found,
        "trials_used": result.trials_used,
        "bounded": result.bounded,
        "predicate": "stored-verdict (E1); live subset re-trials deferred to E2",
    })


@app.tool()
def minimize_poc(finding_id: int) -> str:
    """Local: ddmin over the `necessary` conditions using the same stored-verdict
    predicate as minimal_condition_sets, then re-validate the minimal set (E1
    re-validation is derived from the recorded baseline trials, not a fresh
    determinism_gate run -- that wiring lands with G1). Drops any condition that
    was not actually necessary from the reproduction set."""
    state, err = _load_cem_or_error(finding_id)
    if err:
        return err
    vmap = _stored_verdict_map(state)
    present = sorted(n for n, v in vmap.items() if v == cem_engine.VERDICT_NECESSARY)
    if not present:
        return json.dumps({
            "error": "no condition has a recorded `necessary` verdict yet -- "
                     "run run_counterfactual for each condition first",
        })

    def is_interesting(subset) -> bool:
        return bool(subset) and all(
            vmap.get(n) == cem_engine.VERDICT_APPARENTLY_NOT_NECESSARY
            for n in present if n not in subset
        )

    base_hits = _arm_hits(_trials_as_objs(state), cem_engine.ARM_BASELINE)
    k = state["meta"]["k"]
    det_status = "STABLE" if (base_hits and len(base_hits) >= k and all(base_hits)) else "NONDETERMINISTIC"

    def revalidate(subset) -> cem_engine.DeterminismResult:
        return cem_engine.DeterminismResult(status=det_status, hits=list(base_hits), k=k)

    result = cem_engine.minimize_poc(present, is_interesting, revalidate)
    return json.dumps({
        "finding_id": finding_id,
        "poc": sorted(result.poc),
        "accepted": result.accepted,
        "determinism_status": result.determinism.status,
        "revalidation": "derived from recorded baseline trials (E1); fresh determinism_gate re-run deferred to G1",
    })


def _trials_as_objs(state: dict):
    """Rehydrate stored cem_trials rows into cem_engine.Trial objects (response
    left as None -- the raw FetchResult is not persisted until G1)."""
    return [
        cem_engine.Trial(
            arm=r["arm"], k_index=r["k_index"], http_status=r["http_status"],
            oracle_hit=bool(r["oracle_hit"]), request={}, response=None,
        )
        for r in state["trials"]
    ]


@app.tool()
def evidence_bundle(finding_id: int) -> str:
    """Local: assemble the redacted Triager-Proof Bundle
    (cem_engine.assemble_bundle -- all 15 sec-2.8 fields) from the CEM state
    recorded so far. E1 fills what has been persisted (base request, per-condition
    verdicts, baseline determinism from recorded trials); observed_confounders and
    the content-addressed audit trail are populated by G1/E2. report-agent renders
    it; never auto-submitted."""
    state, err = _load_cem_or_error(finding_id)
    if err:
        return err
    meta = state["meta"]
    k = meta["k"]
    trials = _trials_as_objs(state)
    base_hits = _arm_hits(trials, cem_engine.ARM_BASELINE)
    det_status = "STABLE" if (base_hits and len(base_hits) >= k and all(base_hits)) else "NONDETERMINISTIC"
    vmap = _stored_verdict_map(state)

    intervention_matrix = [
        {
            "condition": c["name"],
            "category": c["category"],
            "verdict": vmap.get(c["name"], "untested"),
        }
        for c in state["conditions"]
    ]
    inconclusive = {n: v for n, v in vmap.items() if v == cem_engine.VERDICT_INCONCLUSIVE}
    empty_alternates = cem_engine.AlternateSetsResult(
        minimal_sets=[], interacting=frozenset(), interacting_pairs=[],
        sets_found=0, trials_used=0, bounded=False,
    )
    empty_poc = cem_engine.PocMinimizationResult(
        poc=frozenset(), accepted=False,
        determinism=cem_engine.DeterminismResult(status=det_status, hits=list(base_hits), k=k),
        predicate_calls=0,
    )
    bundle = cem_engine.assemble_bundle(
        finding_id=finding_id,
        original_baseline=meta["base_request"],
        baseline_determinism=cem_engine.DeterminismResult(status=det_status, hits=list(base_hits), k=k),
        intervention_matrix=intervention_matrix,
        controls=cem_engine.Controls().record(),
        observed_confounders=[],
        verdict_labels=vmap,
        inconclusive_experiments=inconclusive,
        alternate_sets=empty_alternates,
        poc=empty_poc,
        audit_trail=[],
        k=k,
    )
    # F2: surface whether a sender stopped this finding's CEM run early on a
    # budget denial -- the bundle is then a partial (incomplete=1) artifact.
    bundle["incomplete"] = bool(meta["incomplete"])
    return json.dumps(bundle)


if __name__ == "__main__":
    print("case-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
