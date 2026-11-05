"""Cross-account IDOR/BOLA sweep MCP server.

See idor_sweep.py's module docstring for the full design rationale --
short version: automates the highest-value manual grind in access-control
testing (hand-crafting a curl pair per object id, per identity, then
eyeballing the diff) into a one-shot sweep across a whole list of ids.

Tier-2 (target-touching, sends real requests to the live target) --
callers MUST run scripts/check-scope.sh <host> first, exactly like every
other Tier-2 tool in this repo. Registered in scripts/hooks/
scope_gate_hook.py's TIER2_MCP_SERVERS. url_template's key name is
literally `url` (not `url_template`) specifically so that hook's existing
HOST_ARG_KEYS-based extraction picks it up automatically -- no new
Python-side scope-checking logic needed for this server.

Uses only the standard library (urllib) -- no Playwright, no browser,
since IDOR targets are almost always JSON/REST APIs. Budget/audit are
enforced directly here (like playwright-mcp's solve_js_challenge), since
a direct urllib call doesn't go through tool_resolver.run_tool()'s
subprocess chokepoint -- and unlike other MCP servers' single-call
semantics, one sweep_idor() call makes 2 x len(object_ids) real requests,
so it's counted against the budget by object id, not once per tool call
(undercounting the real Tier-2 request volume this tool generates would
let a large object_ids list blow past the intended per-engagement request
ceiling without ever tripping the circuit breaker).
"""

import json
import os
import shlex
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 2)[0])

import authz_diff
import idor_sweep
import session_context
import state_change_confirm
from audit_log import log_call as _log_call
from budget_guard import BudgetExceeded
from budget_guard import enforce as _enforce_budget
from mcp.server.fastmcp import FastMCP
from redact import redact_text

app = FastMCP("idor-mcp")


@app.tool()
def sweep_idor(url: str, object_ids: list[str] | None = None, method: str = "GET",
               owner_cookie_header: str = "", owner_bearer_token: str = "",
               other_cookie_header: str = "", other_bearer_token: str = "",
               body_template: str = "") -> str:
    """Cross-account IDOR/BOLA sweep. `url` must contain a literal `{id}`
    placeholder (e.g. "https://target.com/api/orders/{id}"). object_ids is
    now optional: if omitted (or empty), this looks up ids previously
    observed for this exact endpoint via session_context.suggest_object_ids()
    -- populated automatically as recon/browser-mcp tools discover real
    urls for this target -- before falling back to an error asking for an
    explicit list. Pass object_ids explicitly to skip that lookup or when
    testing ids that haven't been observed yet. For each id in object_ids
    -- each one known to actually belong to the OWNER
    identity -- fetches it once as OWNER (the baseline: confirms the id is
    real and returns actual data) and once as OTHER (the identity being
    tested for improper access to OWNER's object), then classifies the
    pair: PROTECTED (other got 401/403/404 -- access control is working),
    LEAKED (other got 200 with a body near-identical to owner's own view --
    strong IDOR signal, confirm manually before calling it CONFIRMED),
    AMBIGUOUS (other got 200, partially similar -- needs a manual look),
    DIFFERENT (other got 200 but the body looks nothing like owner's --
    likely a generic/soft-404 page, not a real bypass, but still worth a
    glance), OWNER_BASELINE_FAILED (owner's own request didn't return real
    data either -- same "empty test account" problem at the tooling
    level, fix the baseline before trusting a verdict for that id), or
    ERROR (a request itself failed). If most of the batch comes back
    OWNER_BASELINE_FAILED, the summary carries a separate warning: that
    pattern almost always means the owner credential itself is dead, not
    that N object ids happen not to exist -- fix the credential and re-run
    rather than trust the verdicts. Pass owner_cookie_header/
    owner_bearer_token for the account that legitimately owns the object
    ids, and other_cookie_header/other_bearer_token for the account being
    tested -- same "name=value; name2=value2" cookie format and bearer
    convention browser-mcp's tools use. Requires scope-gate clearance
    first (Tier-2) -- this sends real requests to the live target, one
    pair per object id. Budget is enforced PER OBJECT ID (2 real requests
    each), not once for the whole call -- a large object_ids list stops
    partway through with partial results (not a hard error) the moment
    the shared Tier-2 budget is exhausted, rather than silently sending
    far more real requests than the circuit breaker was meant to allow."""
    start = time.monotonic()

    if not object_ids:
        object_ids = session_context.suggest_object_ids(url)
        if not object_ids:
            return (
                f"No object_ids given and none previously observed for {url!r} "
                "(session_context has nothing recorded for this endpoint yet). "
                "Pass object_ids explicitly, or run recon/browser-mcp against this "
                "endpoint first so real ids get recorded automatically."
            )

    owner_headers = idor_sweep._build_headers(owner_cookie_header or None, owner_bearer_token or None)
    other_headers = idor_sweep._build_headers(other_cookie_header or None, other_bearer_token or None)

    result = idor_sweep.SweepResult(url_template=url)
    budget_exhausted_at = None
    for object_id in object_ids:
        try:
            _enforce_budget("idor-mcp")
        except BudgetExceeded as e:
            budget_exhausted_at = str(e)
            break
        result.verdicts.append(
            idor_sweep.check_one_id(url, object_id, method, owner_headers, other_headers,
                                     body_template or None, idor_sweep.DEFAULT_TIMEOUT_S)
        )

    duration_ms = (time.monotonic() - start) * 1000
    counts = result.summary_counts()
    _log_call("idor-mcp", [url, f"{len(object_ids)} ids"], returncode=None,
              duration_ms=duration_ms, block=None)

    lines = [f"URL template: {url}", f"Object ids tested: {len(result.verdicts)}/{len(object_ids)}",
             f"Summary: {counts}"]
    baseline_warning = result.owner_baseline_failure_warning()
    if baseline_warning:
        lines.append(baseline_warning)
    if budget_exhausted_at:
        lines.append(f"⚠️ STOPPED EARLY -- Tier-2 budget exhausted: {budget_exhausted_at}")
    lines.append("")
    for v in result.verdicts:
        marker = {"LEAKED": "🔴", "AMBIGUOUS": "🟡", "PROTECTED": "🟢",
                  "DIFFERENT": "⚪", "OWNER_BASELINE_FAILED": "⚠️", "ERROR": "❌"}.get(v.verdict, "")
        sim = f" (similarity {v.similarity:.0%})" if v.similarity is not None else ""
        lines.append(
            f"{marker} {v.object_id}: {v.verdict}{sim} "
            f"[owner={v.owner_status}, other={v.other_status}]"
        )
        lines.append(f"    {v.detail}")
    return "\n".join(lines)


@app.tool()
def guess_idor(url: str, known_id: str, method: str = "GET", cookie_header: str = "",
                bearer_token: str = "", guess_count: int = 10, body_template: str = "") -> str:
    """Single-credential IDOR/BOLA guessing -- for when you only have ONE
    account and don't yet have a second identity to diff against (that case
    is sweep_idor()'s job, and gives a stronger LEAKED/PROTECTED verdict when
    you can set it up). `url` must contain a literal `{id}` placeholder.
    `known_id` is one id already confirmed to belong to this credential (used
    as the baseline AND as the anchor for generating guesses -- sequential
    neighbors, small/admin-like ids like 0/1, and the negative variant).
    Numeric ids only: a UUID/hashid known_id can't be meaningfully
    sequence-guessed, and returns an empty guess list rather than pretending
    to. Checks the baseline FIRST -- if known_id itself doesn't return real
    200 data with this credential, guessing is skipped entirely rather than
    wasting budget on ids anchored to a bad baseline. Each guessed id is
    classified: PROTECTED (401/403/404 -- access control is working),
    ACCESSIBLE (200 with a real body -- a strong lead, but verify by hand
    whether the object actually belongs to the tested account; this mode
    can't auto-diff against an owner baseline the way sweep_idor() can, so
    it never claims LEAKED), EMPTY_RESPONSE (200 but empty -- probably not a
    real object here), or ERROR. Same cookie_header/bearer_token convention
    as sweep_idor()/browser-mcp. Requires scope-gate clearance first
    (Tier-2) -- sends real requests to the live target, one per guess plus
    the baseline check. Budget is enforced per request, same as
    sweep_idor()."""
    start = time.monotonic()
    headers = idor_sweep._build_headers(cookie_header or None, bearer_token or None)

    try:
        _enforce_budget("idor-mcp")
    except BudgetExceeded as e:
        return f"⚠️ Tier-2 budget exhausted before the baseline check could run: {e}"

    baseline_url = url.replace("{id}", known_id)
    baseline_body = body_template.replace("{id}", known_id) if body_template else None
    baseline = idor_sweep._fetch(baseline_url, method, headers, baseline_body, idor_sweep.DEFAULT_TIMEOUT_S)

    if baseline.error or baseline.status != 200 or not baseline.body.strip():
        return (
            f"⚠️ known_id baseline check failed (status={baseline.status}, error={baseline.error!r}) "
            "-- the credential may be invalid/expired, or known_id doesn't actually belong to it. "
            "Guessing skipped."
        )

    guesses = idor_sweep.generate_id_guesses(known_id, guess_count)
    if not guesses:
        return (
            f"known_id '{known_id}' isn't a plain integer -- sequential/admin/negative-id guessing "
            "only applies to numeric ids, not UUIDs/hashids. No guesses generated; use sweep_idor() "
            "with a second identity instead if you have one."
        )

    verdicts: list = []
    budget_exhausted_at = None
    for guess_id in guesses:
        try:
            _enforce_budget("idor-mcp")
        except BudgetExceeded as e:
            budget_exhausted_at = str(e)
            break
        verdicts.append(
            idor_sweep.check_one_guess(url, guess_id, method, headers, body_template or None,
                                        idor_sweep.DEFAULT_TIMEOUT_S)
        )

    duration_ms = (time.monotonic() - start) * 1000
    counts: dict[str, int] = {}
    for v in verdicts:
        counts[v.verdict] = counts.get(v.verdict, 0) + 1
    _log_call("idor-mcp", [url, f"guess from {known_id}", f"{len(guesses)} guesses"],
              returncode=None, duration_ms=duration_ms, block=None)

    lines = [f"URL template: {url}", f"Known id: {known_id} (baseline confirmed OK)",
             f"Guessed ids tested: {len(verdicts)}/{len(guesses)}", f"Summary: {counts}"]
    if budget_exhausted_at:
        lines.append(f"⚠️ STOPPED EARLY -- Tier-2 budget exhausted: {budget_exhausted_at}")
    lines.append("")
    for v in verdicts:
        marker = {"ACCESSIBLE": "🔴", "PROTECTED": "🟢",
                  "EMPTY_RESPONSE": "⚪", "ERROR": "❌"}.get(v.verdict, "")
        lines.append(f"{marker} {v.object_id}: {v.verdict} [status={v.status}]")
        lines.append(f"    {v.detail}")
    return "\n".join(lines)


def _valauthz_enabled() -> bool:
    return os.environ.get("HUNTMCP_VALAUTHZ", "").lower() in ("1", "true", "yes")


def _audit(tool: str, url: str, start: float, requests: int = 0, extra=()) -> None:
    """One audit-log entry per tool call, on EVERY exit path (refusals included)."""
    _log_call("idor-mcp", [url, tool, f"{requests} requests", *extra],
              returncode=None, duration_ms=(time.monotonic() - start) * 1000, block=None)


@app.tool()
def replay_authz_two_step(url: str, carried_path: str, step2_url_template: str,
                          owner_cookie_header: str = "", owner_bearer_token: str = "",
                          other_cookie_header: str = "", other_bearer_token: str = "",
                          step1_method: str = "GET", step2_method: str = "GET",
                          step1_body: str = "", emit_finding: bool = False) -> str:
    """P3-VALAUTHZ two-step authorization replay (feature-flagged: set HUNTMCP_VALAUTHZ=1;
    off by default, in which case use sweep_idor). `url` is step 1, fetched as the OWNER;
    `carried_path` is the dotted JSON path in its response that yields an opaque id (e.g.
    "carts.0.cart_ref"); `step2_url_template` is step 2 with exactly one `{carried}`
    placeholder, same origin as `url`. Step 2 is fetched as the owner (stable baseline,
    twice), then as the OTHER identity carrying the owner's id, then with controls: no
    credentials (public?) and the other identity's own id (authenticated-but-global?). If the
    owner's body itself varies per fetch (timestamps, request ids) those JSON paths are masked
    from every comparison -- but only if at least 2 stable fields remain, else INCONCLUSIVE.
    Verdicts: LEAKED (exact same object, all controls clean -- a CANDIDATE, never CONFIRMED
    here), PROTECTED, PUBLIC, SHARED, DIFFERENT, INCONCLUSIVE, BASELINE_FAILED, ERROR,
    BLOCKED (scope/budget/method gate stopped the run). Read-only by default: a step method
    other than GET/HEAD/OPTIONS is refused before any request unless the HUMAN has confirmed it in
    their own terminal with scripts/confirm-state-change.sh <host> <METHODS> (single-use,
    time-limited, bound to this host and these methods -- you cannot supply an approval yourself).
    An approved state-changing step 2 is sent once per identity only (the stability / unauthenticated
    / own-object controls would each repeat the mutation), so it ends DIFFERENT/INCONCLUSIVE rather
    than LEAKED; an approved state-changing step 1 (create-then-read: e.g. POST /drafts returns the
    new object's id, step 2 GETs it) is sent by the owner, and by the other identity only if the
    controls run. `step1_body` (optional, step 1 only) is a JSON string of at most 4 KiB, sent with
    Content-Type: application/json; it must not contain the carried id, is rejected on a read-only
    step 1, and is never echoed or stored (evidence keeps only a short hash). Scope is checked before EVERY request and Tier-2
    budget is charged per request. emit_finding=True records a LEAKED result as a DISCOVERED
    case_store finding with the candidate CEM conditions (identity, step order, carried id)
    in its evidence. Requires scope-gate clearance first (Tier-2)."""
    start = time.monotonic()

    def _done(text: str, requests: int = 0) -> str:
        _audit("replay_authz_two_step", url, start, requests)
        return text

    if not _valauthz_enabled():
        return _done("replay_authz_two_step is disabled (HUNTMCP_VALAUTHZ is not set) -- "
                     "use sweep_idor for the single-request cross-account sweep.")
    wf = authz_diff.Workflow(step1_url=url, carried_path=carried_path,
                             step2_url_template=step2_url_template,
                             step1_method=step1_method, step2_method=step2_method,
                             step1_body=step1_body or None)
    owner_headers = idor_sweep._build_headers(owner_cookie_header or None, owner_bearer_token or None)
    other_headers = idor_sweep._build_headers(other_cookie_header or None, other_bearer_token or None)

    bad = authz_diff.structural_error(wf, owner_headers, other_headers)
    if bad:  # reject a malformed workflow before it can spend a human-issued approval
        return _done(f"{bad[0]}: {redact_text(bad[1])} -- no request was sent.")
    approval = None
    needed = authz_diff.state_changing_methods(wf)
    if needed:
        refusal = authz_diff.scope_precheck(wf)  # never spend a human approval on an out-of-scope run
        if refusal:
            return _done(f"BLOCKED: {redact_text(refusal)} -- no request was sent.")
        host = authz_diff.approval_host(url)
        fingerprint = authz_diff.workflow_fingerprint(wf, owner_headers, other_headers)
        summary = authz_diff.workflow_summary(wf, owner_headers, other_headers)
        if len(summary) > state_change_confirm.PROMPT_SUMMARY_LIMIT:  # the human could not read all of it
            return _done("ERROR: this workflow's description is too long for a human to confirm in full "
                         "(shorten the URLs) -- no request was sent.")
        # what the human's confirm prompt will show, built here from the real workflow
        state_change_confirm.write_pending(host, needed, fingerprint, summary)
        approval = state_change_confirm.consume_approval(host, needed, fingerprint)
        if approval is None:
            return _done(
                f"BLOCKED: this workflow sends state-changing method(s) {needed}, which need a human's "
                f"single-use confirmation bound to exactly what will be sent: {summary}. "
                "Ask the user to read that, then run in their own "
                f"terminal: scripts/confirm-state-change.sh {shlex.quote(host)} {','.join(needed)} {fingerprint} "
                "-- no request was sent.")
    result = authz_diff.run_two_step(wf, owner_headers, other_headers,
                                     budget_cb=lambda: _enforce_budget("idor-mcp"), approval=approval)
    lines = [f"Workflow: {redact_text(url)} -> {redact_text(step2_url_template)}",
             f"Verdict: {result.verdict}",
             f"Requests sent: {len(result.requests)}", result.detail]
    for r in result.requests:
        lines.append(f"  [{r['role']} step{r['step']}] {r['method']} {r['url']} -> {r['status']}")
    if emit_finding:
        emitted = authz_diff.emit_finding(result, wf)
        if emitted is None:
            lines.append(f"No finding recorded (nothing to record for verdict {result.verdict}).")
        else:
            lines.append(f"Finding recorded: {emitted} (DISCOVERED -- confirm independently before CONFIRMED).")
    return _done("\n".join(lines), len(result.requests))


@app.tool()
def replay_authz_matrix(url: str, carried_path: str, step2_url_template: str,
                        owner_cookie_header: str = "", owner_bearer_token: str = "",
                        identities_json: str = "", emit_finding: bool = False) -> str:
    """P3-VALAUTHZ identity matrix (feature-flagged: HUNTMCP_VALAUTHZ=1; off by default). The same
    owner-fetch-and-compare oracle as replay_authz_two_step, run once per declared identity against the
    OWNER's object: e.g. a same-tenant user, an admin, a user of another tenant. READ-ONLY (GET): a
    state-changing step is refused -- use replay_authz_two_step for that. `identities_json` is a JSON
    list (max 5) of {"name": "bobby", "cookie_header": "...", "bearer_token": "...",
    "should_have_access": false}; name is 1-32 chars [A-Za-z0-9_-]; should_have_access is the access
    POLICY you were given (true for an admin or a same-tenant colleague who is SUPPOSED to read the
    object): such an identity gets EXPECTED_ACCESS instead of LEAKED. Do not guess the policy -- take it
    from the program's rules; the default (false) means "must not have access". Per-identity verdicts
    are the same as replay_authz_two_step's (LEAKED is a CANDIDATE only, never CONFIRMED). A BLOCKED
    identity (scope/budget) stops the rest of the matrix. Scope is checked before EVERY request and
    Tier-2 budget is charged per request. emit_finding=True records one DISCOVERED case_store finding per
    wrongly-allowed identity. Requires scope-gate clearance first (Tier-2)."""
    start = time.monotonic()

    def _done(text: str, requests: int = 0, rows=()) -> str:
        # identity names, the declared policy and each verdict are durable audit facts: a LEAKED
        # that was dismissed as "policy: allowed" must leave a trace
        _audit("replay_authz_matrix", url, start, requests,
               [f"{r.name}={r.verdict}" + ("(policy:allowed)" if r.should_have_access else "") for r in rows])
        return text

    if not _valauthz_enabled():
        return _done("replay_authz_matrix is disabled (HUNTMCP_VALAUTHZ is not set) -- "
                     "use sweep_idor for the single-request cross-account sweep.")
    try:
        raw = json.loads(identities_json)
        if not isinstance(raw, list):
            raise TypeError("identities_json must be a JSON list")
        identities = []
        for entry in raw:
            if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
                raise TypeError("each identity must be an object with a string name")
            headers = idor_sweep._build_headers(entry.get("cookie_header") or None,
                                                entry.get("bearer_token") or None)
            if not headers:
                raise TypeError(f"identity {entry['name'][:32]!r} needs a cookie_header or bearer_token")
            allowed = entry.get("should_have_access", False)
            if not isinstance(allowed, bool):
                raise TypeError(f"should_have_access for {entry['name'][:32]!r} must be true or false")
            identities.append(authz_diff.MatrixIdentity(entry["name"], headers, allowed))
    except (ValueError, TypeError) as e:
        return _done(f"ERROR: invalid identities_json ({redact_text(str(e))}) -- no request was sent.")

    wf = authz_diff.Workflow(step1_url=url, carried_path=carried_path, step2_url_template=step2_url_template)
    owner_headers = idor_sweep._build_headers(owner_cookie_header or None, owner_bearer_token or None)
    try:
        rows = authz_diff.run_matrix(wf, owner_headers, identities,
                                     budget_cb=lambda: _enforce_budget("idor-mcp"))
    except authz_diff.MatrixError as e:
        return _done(f"ERROR: {redact_text(str(e))} -- no request was sent.")

    total = sum(len(r.result.requests) for r in rows)
    lines = [f"Matrix: {redact_text(url)} -> {redact_text(step2_url_template)}",
             f"Identities tested: {len(rows)}/{len(identities)}"]
    for r in rows:
        lines.append(f"{r.name}: {r.verdict} ({len(r.result.requests)} requests)"
                     + (" [policy: should have access]" if r.should_have_access else ""))
        lines.append(f"    {r.result.detail}")
    if emit_finding:
        emitted = authz_diff.emit_matrix_findings(rows, wf)
        lines.append(f"Findings recorded: {emitted} (DISCOVERED -- confirm independently before CONFIRMED)."
                     if emitted else "No finding recorded (no identity was wrongly allowed).")
    return _done("\n".join(lines), total, rows)


if __name__ == "__main__":
    print("idor-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
