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

import sys
import time

sys.path.insert(0, __file__.rsplit("/", 2)[0])

import idor_sweep
from audit_log import log_call as _log_call
from budget_guard import BudgetExceeded
from budget_guard import enforce as _enforce_budget
from mcp.server.fastmcp import FastMCP

app = FastMCP("idor-mcp")


@app.tool()
def sweep_idor(url: str, object_ids: list[str], method: str = "GET",
               owner_cookie_header: str = "", owner_bearer_token: str = "",
               other_cookie_header: str = "", other_bearer_token: str = "",
               body_template: str = "") -> str:
    """Cross-account IDOR/BOLA sweep. `url` must contain a literal `{id}`
    placeholder (e.g. "https://target.com/api/orders/{id}"). For each id
    in object_ids -- each one known to actually belong to the OWNER
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


if __name__ == "__main__":
    print("idor-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
