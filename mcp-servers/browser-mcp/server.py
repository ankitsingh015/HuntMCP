"""Real-browser JS/DOM confirmation MCP server (Phase 2.10-adjacent).

See browser_confirm.py's module docstring for the full design rationale --
short version: exploit-agent's Phase 1.5 rationalizations-to-reject table
already says a payload merely appearing in the raw HTTP response is not
confirmed XSS, it has to execute in a real browser context. This is the
tool that actually checks that, using a real headless Chromium via
Playwright, instead of leaving it to a manual PoC step.

Tier-2 (target-touching) -- callers must run scripts/check-scope.sh <host>
first, exactly like every other Tier-2 tool in this repo. Registered in
scripts/hooks/scope_gate_hook.py's TIER2_MCP_SERVERS so this is also
structurally enforced for Claude Code, not just documented convention.

Setup: pip install -r requirements.txt gets the playwright Python package.
No separate `playwright install chromium` needed if an existing system
Chrome/Chromium is found (see ../browser_launch.SYSTEM_BROWSER_CANDIDATES,
shared with playwright-mcp); otherwise run `playwright install chromium`
once to get Playwright's own bundled browser.

#164 page comprehension: start_ui_walk / check_ui_walk / list_ui_walks walk
an app PAGE-FIRST (every rendered page's real inputs, controls and the UI->API
call each makes; Pass 1 sends nothing state-changing, Pass 2 "canary" needs a
human-written grant file), and run_teardown is the human-gated final step.
screenshot() now saves a viewable JPEG by default (as_base64=True for the old
string). See ui_walk.py and
docs/superpowers/specs/2026-11-19-page-comprehension-ui-walk-design.md.

Every tool here takes four optional, independent, combinable auth-seeding
params (session_file added 2026-08-29, the other three the same day
earlier -- see browser_confirm.py's _new_page() for the full rationale on
why all four, not just one):
- session_file, a path to a Playwright storage_state JSON file. Every
  tool call SAVES its context's current cookies/localStorage back to this
  path when it finishes -- pass the SAME path across multiple calls to
  carry a session between them (log in once, e.g. via fill_and_submit
  with a session_file set, then every later call with that same path
  resumes already-authenticated). Before this, every call launched a
  fresh browser AND a fresh context that both died at the end of that one
  call -- a cookie set mid-flow (a magic-link click, a login submit) was
  gone the instant the call ended, forcing all authenticated work through
  a separate curl+cookie-jar path instead. Use a different path per
  identity for a role-diff check across full rendered pages.
- cookie_header ("name=value; name2=value2", the same shape playwright-
  mcp's solve_js_challenge already outputs a clearance cookie in) for
  traditional cookie-based sessions, applied on top of whatever
  session_file loaded.
- bearer_token, sent as `Authorization: Bearer <token>` on every request,
  for APIs/SPAs that use a bearer token instead of (or alongside)
  cookies. NOT captured by session_file -- pass it on every call that
  needs it.
- session_storage (#164, a dict of key -> value), seeded into the target
  origin's sessionStorage before any page script runs -- for an OIDC SPA that
  keeps its user/token in sessionStorage (e.g. oidc-client's default store).
  sessionStorage is ALSO captured into session_file (sidecar key
  "huntmcp_session_storage", per origin, origin-guarded on restore), which
  Playwright's own storage_state does not do -- the cause of an authenticated
  SPA rendering its logged-out shell from an otherwise-fresh session_file.
- local_storage (a dict of key -> value), seeded into the target origin's
  localStorage before any page script runs, for a modern SPA that reads
  its own session/JWT out of localStorage rather than a cookie or a
  server-sent header. IS captured by session_file, so only needs passing
  once, on the call that establishes the session.
"""

import json
import os
import re
import sys

sys.path.insert(0, __file__.rsplit("/", 2)[0])

import asyncio
from collections import Counter
from urllib.parse import urlsplit

import browser_confirm
import job_runtime
import mutation_runner
import session_capture
import session_keepalive
import session_refresh
import ui_walk
import ui_walk_events
import ui_walk_logic
import ui_walk_store
import ui_walk_teardown
from injection_boundary import quarantine as _quarantine
from mcp.server.fastmcp import FastMCP

app = FastMCP("browser-mcp")


@app.tool()
async def check_js_execution(url: str, marker: str, wait_ms: int = 2000,
                              cookie_header: str = "", bearer_token: str = "",
                              local_storage: dict[str, str] | None = None,
                              session_file: str = "",
        session_storage: dict[str, str] | None = None) -> str:
    """Navigate to url in a real headless browser and check whether marker
    actually executed as JS (a fired alert/confirm/prompt dialog containing
    it, or document.title containing it) vs. merely being present in the
    raw HTML response. Use this to confirm a suspected XSS actually runs in
    a browser context before marking it CONFIRMED -- a payload that shows
    up in raw_html but not in dialog/title is reflection, not proof of
    execution. Pass cookie_header ("name=value; name2=value2"),
    bearer_token, local_storage, and/or session_file to check this in a
    logged-in-only view -- see this server's module docstring for when to
    use which. Requires scope-gate clearance first (Tier-2)."""
    r = await browser_confirm.check_js_execution(
        url, marker, wait_ms=wait_ms,
        cookie_header=cookie_header or None,
        bearer_token=bearer_token or None,
        local_storage=local_storage or None,
        session_file=session_file or None,
        session_storage=session_storage or None,
    )
    if r["error"]:
        return f"Browser error: {r['error']}"
    lines = [f"URL: {url}", f"Marker: {marker!r}"]
    if r["dialog_fired"]:
        lines.append(f"✅ JS DIALOG FIRED containing marker: {r['dialog_text']!r} -- confirmed execution")
    elif r["title_contains_marker"]:
        lines.append("✅ document.title contains marker -- confirmed execution")
    elif r["raw_html_contains_marker"]:
        lines.append("⚠ Marker present in raw HTML but did NOT execute (no dialog, title unchanged) -- reflection only, NOT confirmed")
    else:
        lines.append("✗ Marker not found in raw HTML, dialog, or title")
    if r["console_errors"]:
        lines.append(f"Console errors ({len(r['console_errors'])}): " + "; ".join(r["console_errors"][:5]))
    # C1a: same wire-provenance line as render_dom() -- see its own
    # comment for why this must stay the final line returned.
    provenance = {
        "class": "wire", "captured_by": "browser-mcp", "method": "GET",
        "url": r.get("final_url") or url, "status": r.get("status"),
    }
    lines.append(f"\nProvenance (for case-mcp add_evidence): {json.dumps(provenance)}")
    return "\n".join(lines)


@app.tool()
async def render_dom(url: str, wait_selector: str = "", cookie_header: str = "",
                      bearer_token: str = "", local_storage: dict[str, str] | None = None,
                      session_file: str = "",
        session_storage: dict[str, str] | None = None) -> str:
    """Return the fully rendered (post-JS) HTML for url, for comparison
    against the raw HTTP response -- surfaces client-side-injected content,
    DOM clobbering, and anything a plain curl would never show. Truncated
    to 5000 chars. Pass cookie_header/bearer_token/local_storage/
    session_file to render this as a logged-in user -- also how to do a
    role-diff IDOR check: call this once per role's own session_file (or
    credentials) and compare the two results yourself. Requires scope-gate
    clearance first (Tier-2)."""
    r = await browser_confirm.render_dom(
        url, wait_selector=wait_selector or None,
        cookie_header=cookie_header or None,
        bearer_token=bearer_token or None,
        local_storage=local_storage or None,
        session_file=session_file or None,
        session_storage=session_storage or None,
    )
    if r["error"]:
        return f"Browser error: {r['error']}"
    html = r["html"] or ""
    truncated = html[:5000] + ("... [truncated]" if len(html) > 5000 else "")
    # P2-INJ (UU-7): this is the fully rendered, post-JS page HTML -- per
    # this function's own docstring, deliberately surfaces "client-side-
    # injected content, DOM clobbering, and anything a plain curl would
    # never show." That is fully target-controlled free text reaching
    # agent-visible output -- quarantine it, same as oob-mcp's raw
    # callback-request/response fields.
    output = f"Title: {r['title']}\n\n{_quarantine(truncated, source_label='rendered page HTML')}"
    # C1a: this navigation's real HTTP status + final (post-redirect) URL,
    # shaped exactly as case_store._validate_provenance() requires for
    # class="wire" -- an agent can paste this straight into case-mcp's
    # add_evidence(provenance=...) instead of re-typing it, same pattern
    # as oob-mcp's get_interaction_records().
    provenance = {
        "class": "wire",
        "captured_by": "browser-mcp",
        "method": "GET",
        "url": r.get("final_url") or url,
        "status": r.get("status"),
    }
    # Code-review finding (CONFIRMED): this line MUST stay the final thing
    # this function returns, and `output` MUST stay the only thing before
    # it. The target's own page HTML is attacker-controlled and could
    # contain a forged "Provenance (...):"-shaped decoy line -- but it can
    # only ever land inside `output`'s quarantine boundary (before
    # UNTRUSTED-DATA-END), never after it. A consumer that takes the LAST
    # "Provenance"-prefixed line (not the first) is structurally guaranteed
    # to get this real one, not a decoy -- see
    # tests/test_browser_mcp_provenance.py's decoy test. Appending anything
    # else after this line in the future would break that guarantee.
    return f"{output}\n\nProvenance (for case-mcp add_evidence): {json.dumps(provenance)}"


@app.tool()
async def extract_page_content(url: str, wait_selector: str = "", max_links: int = 200,
                                cookie_header: str = "", bearer_token: str = "",
                                local_storage: dict[str, str] | None = None,
                                session_file: str = "",
        session_storage: dict[str, str] | None = None) -> str:
    """Navigate to url in a real headless browser and return its rendered,
    human-readable text plus every link on the page (text + absolute href,
    deduped, capped at max_links) -- the general "browse this page and see
    what's actually on it" tool, including JS-rendered content a static
    fetch/katana-mcp crawl would miss. Use this to read a single already-
    known page's content or listings, not to discover new URLs across a
    site (that's katana-mcp's job) or to diff rendered vs. raw HTML (that's
    render_dom). Pass cookie_header/bearer_token/local_storage/
    session_file to read a logged-in-only page/listing. Text truncated to
    8000 chars. Requires scope-gate clearance first (Tier-2)."""
    r = await browser_confirm.extract_page_content(
        url, wait_selector=wait_selector or None, max_links=max_links,
        cookie_header=cookie_header or None,
        bearer_token=bearer_token or None,
        local_storage=local_storage or None,
        session_file=session_file or None,
        session_storage=session_storage or None,
    )
    if r["error"]:
        return f"Browser error: {r['error']}"
    text = r["text"] or ""
    truncated = text[:8000] + ("... [truncated]" if len(text) > 8000 else "")
    # P2-INJ (UU-7): rendered, human-readable page TEXT -- fully
    # target-controlled, same reasoning as render_dom()'s own quarantine
    # above.
    lines = [f"Title: {r['title']}", "", "--- Text ---", _quarantine(truncated, source_label="rendered page text")]
    if r["links"]:
        lines.append("")
        lines.append(f"--- Links ({len(r['links'])}) ---")
        for link in r["links"]:
            label = link["text"] or "(no text)"
            lines.append(f"- {label}: {link['href']}")
    # C1a: same wire-provenance line as render_dom() -- must stay the
    # final line. Code-review finding (CONFIRMED): unlike render_dom(),
    # this function has TWO attacker-controlled regions, not one -- the
    # quarantined text above, AND the links section just above this
    # comment (link `text`/`href` are target-controlled and, unlike the
    # page text, NOT quarantined). A decoy "Provenance (...):"-shaped
    # line planted in a link's text would land OUTSIDE the quarantine
    # boundary, unlike render_dom's own decoy. The guarantee that still
    # holds here is narrower: only that THIS line is always the
    # structurally LAST one (nothing is ever appended after it), so a
    # consumer taking the last match is still safe -- see
    # test_extract_page_content_decoy_in_an_unquarantined_link_is_not_authoritative,
    # which exercises exactly this (previously untested) vector.
    provenance = {
        "class": "wire", "captured_by": "browser-mcp", "method": "GET",
        "url": r.get("final_url") or url, "status": r.get("status"),
    }
    lines.append(f"\nProvenance (for case-mcp add_evidence): {json.dumps(provenance)}")
    return "\n".join(lines)


@app.tool()
async def fill_and_submit(url: str, field_values: dict[str, str], submit_selector: str,
                           then_check_marker: str = "", cookie_header: str = "",
                           bearer_token: str = "", local_storage: dict[str, str] | None = None,
                           session_file: str = "",
        session_storage: dict[str, str] | None = None) -> str:
    """Fill form fields (CSS selector -> value) and click submit_selector --
    for stored-XSS or business-logic flows needing a real form submission,
    not just a GET. If then_check_marker is given, checks the resulting
    page for a fired dialog containing it. Pass cookie_header/bearer_token/
    local_storage for a form that only appears once logged in. Pass
    session_file to save whatever session this submission establishes (a
    real login form) for reuse in later calls -- this is the tool that
    actually performs a login flow, so it's the natural place to start a
    session_file for the first time. Requires scope-gate clearance first
    (Tier-2)."""
    r = await browser_confirm.fill_and_submit(
        url, field_values, submit_selector,
        then_check_marker=then_check_marker or None,
        cookie_header=cookie_header or None,
        bearer_token=bearer_token or None,
        local_storage=local_storage or None,
        session_file=session_file or None,
        session_storage=session_storage or None,
    )
    if r["error"]:
        return f"Browser error: {r['error']}"
    lines = [f"Submitted: {r['submitted']}", f"Title after submit: {r['title_after_submit']}"]
    if then_check_marker:
        if r["dialog_fired"]:
            lines.append(f"✅ JS DIALOG FIRED containing marker: {r['dialog_text']!r} -- confirmed execution")
        else:
            lines.append("✗ No dialog containing marker fired after submit")
    # C1a: wire-provenance for the INITIAL (GET) navigation only -- see
    # browser_confirm.fill_and_submit()'s own comment on why the submit's
    # own (possibly POST) response isn't captured here too.
    provenance = {
        "class": "wire", "captured_by": "browser-mcp", "method": "GET",
        "url": r.get("final_url") or url, "status": r.get("status"),
    }
    lines.append(f"\nProvenance (for case-mcp add_evidence): {json.dumps(provenance)}")
    return "\n".join(lines)


@app.tool()
async def screenshot(url: str, wait_ms: int = 1000, cookie_header: str = "",
                      bearer_token: str = "", local_storage: dict[str, str] | None = None,
                      session_file: str = "",
                      session_storage: dict[str, str] | None = None,
                      as_base64: bool = False) -> str:
    """Screenshot url -- visual comprehension of the page AND visual PoC
    evidence for a report's "screenshot + PoC" requirement. Default (#164):
    saves a size-capped JPEG (1280 wide, max 4000px tall) under the
    engagement's screenshots/ dir and returns its PATH -- open it with the
    Read tool to actually look at the page, and attach the path as
    screenshot evidence. as_base64=True returns the old full-page
    `data:image/png;base64,...` string unchanged (too large to view inline;
    kept for existing consumers). Pass cookie_header/bearer_token/
    local_storage/session_storage/session_file for a logged-in-only view.
    Requires scope-gate clearance first (Tier-2)."""
    if as_base64:
        r = await browser_confirm.screenshot_base64(
            url, wait_ms=wait_ms,
            cookie_header=cookie_header or None,
            bearer_token=bearer_token or None,
            local_storage=local_storage or None,
            session_file=session_file or None,
            session_storage=session_storage or None,
        )
        if r["error"]:
            return f"Browser error: {r['error']}"
        return f"data:image/png;base64,{r['screenshot_base64']}"
    r = await browser_confirm.screenshot_to_file(
        url, wait_ms=wait_ms,
        cookie_header=cookie_header or None,
        bearer_token=bearer_token or None,
        local_storage=local_storage or None,
        session_file=session_file or None,
        session_storage=session_storage or None,
    )
    if r["error"]:
        return f"Browser error: {r['error']}"
    provenance = {
        "class": "wire", "captured_by": "browser-mcp", "method": "GET",
        "url": r.get("final_url") or url, "status": r.get("status"),
    }
    return (f"Screenshot saved: {r['path']} ({r['width']}x{r['height']} JPEG). "
            f"View it with Read.\n\nProvenance (for case-mcp add_evidence): {json.dumps(provenance)}")


@app.tool()
async def start_manual_intervention(url: str, session_file: str) -> str:
    """Open a REAL, VISIBLE browser window at url and leave it open -- for
    whatever blocks every other tool in this server: a CAPTCHA, an unusual
    multi-step login, anything that genuinely needs a human's own hands.
    This does NOT solve anything itself; a human does, in the window it
    opens. Requires a real display on whatever machine runs this MCP
    server -- fails in a headless CI/sandbox environment with nowhere to
    show a window; run it from your own machine's session. Call
    finish_manual_intervention(session_file) once the human is done --
    every other browser-mcp/obscura-mcp tool that accepts session_file
    then resumes from whatever state was left behind. Requires scope-gate
    clearance first (Tier-2)."""
    r = await browser_confirm.start_manual_intervention(url, session_file)
    if r.get("error"):
        return f"Error: {r['error']}"
    return r["message"]


@app.tool()
async def finish_manual_intervention(session_file: str) -> str:
    """Capture the session state from a window opened by
    start_manual_intervention(session_file=...), save it to session_file,
    and close the window. Every other browser-mcp/obscura-mcp tool that
    accepts session_file resumes from exactly this state on its next
    call."""
    r = await browser_confirm.finish_manual_intervention(session_file)
    if r.get("error"):
        return f"Error: {r['error']}"
    return f"Closed. Final URL: {r['final_url']!r}, title: {r['final_title']!r}. Session saved to {session_file!r}."


@app.tool()
async def list_open_interventions() -> str:
    """List every manual intervention currently open (started via
    start_manual_intervention, not yet finished) and how long each has
    been open -- so a stale one nobody remembered to finish is
    discoverable instead of silently leaking an open browser window.
    Flags one as likely abandoned once it's been open past
    browser_confirm.INTERVENTION_STALE_AFTER_SECONDS (30 min default) --
    not auto-closed, just surfaced, since a human may genuinely still be
    mid-CAPTCHA/mid-login."""
    items = await browser_confirm.list_open_interventions()
    if not items:
        return "No manual interventions currently open."
    lines = [f"{len(items)} open manual intervention(s):"]
    for it in items:
        if it.get("status") == "starting":
            lines.append(f"  {it['session_file']} -- still starting up")
            continue
        marker = " [LIKELY ABANDONED]" if it["likely_abandoned"] else ""
        lines.append(f"  {it['session_file']} -- open {it['open_seconds']:.0f}s{marker}")
    return "\n".join(lines)


# ----------------------------------------- session capture (#128, #133, #137)
# Human-driven identity/session capture: the human logs in by hand in a real
# window; these tools automate only the EXTRACTION afterwards, and NO secret
# (cookie value, bearer, storage_state, OTP, mailbox password) is ever returned
# to the agent -- see mcp-servers/session_capture.py. Tier-2: run
# scripts/check-scope.sh <host> first (start_capture / capture_oauth_redirect
# also enforce scope in-code via scope_guard, the definitive boundary, since
# their login_url/start_url params are not HOST_ARG_KEYS-extracted by the hook).


@app.tool()
def list_test_identities() -> str:
    """List the configured test-identity labels (the capture allowlist) with
    their human notes and whether a mailbox is configured. Secret-free: never
    includes profile paths or any mailbox credentials. Use this to pick which
    designated test account to capture -- NEVER your personal/company account."""
    return json.dumps(session_capture.list_identities(), indent=2)


@app.tool()
async def start_capture(identity_label: str, login_url: str) -> str:
    """Open a REAL, VISIBLE, DEDICATED-profile browser window at login_url for
    the human to log in BY HAND (captcha/2FA/SSO) -- never automated. Returns a
    non-secret status plus the exact scripts/confirm-capture.sh command the
    HUMAN must run in their own terminal; then call finish_capture. The
    per-identity persistent profile reuses an SSO login across captures.
    Requires scope-gate clearance first (Tier-2)."""
    return json.dumps(await session_capture.start_capture(identity_label, login_url), indent=2)


@app.tool()
async def finish_capture(identity_label: str, whoami_url: str = "") -> str:
    """After the human logged in and confirmed via confirm-capture.sh, extract
    the in-scope cookies (full attributes) + sniffed Authorization header, write
    them to a 0600 identities.json + domain-scoped session file, and return ONLY
    a non-secret summary ({identity, captured, cookie_count, has_bearer,
    whoami}). Pass whoami_url (an in-scope endpoint) to auto-label user_id/role/
    org. Downstream browser-mcp tools consume the capture via session_file path."""
    return json.dumps(await session_capture.finish_capture(identity_label, whoami_url=whoami_url), indent=2)


@app.tool()
async def apply_pending_otp(identity_label: str) -> str:
    """Read the latest OTP/verification code from identity_label's OWN test
    mailbox (IMAP, read-only) and TYPE it into the open capture window -- removes
    the mailbox copy/paste round trip. Returns {otp_applied: bool} only, never
    the code. Requires an open start_capture window and a roster mailbox."""
    return json.dumps(await session_capture.apply_pending_otp(identity_label), indent=2)


@app.tool()
async def open_pending_magic_link(identity_label: str, link_host: str) -> str:
    """Read the latest magic-link for identity_label's OWN test mailbox (IMAP,
    read-only) whose host is link_host, and navigate the open capture window to
    it. Returns {magic_link_opened: bool} only. link_host is host-validated and
    must be in scope. Requires an open start_capture window and a roster mailbox."""
    return json.dumps(await session_capture.open_pending_magic_link(identity_label, link_host), indent=2)


@app.tool()
async def capture_oauth_redirect(identity_label: str, start_url: str, callback_host: str) -> str:
    """Capture an OAuth provider's redirect parameters (e.g. ?code=...) before
    the application consumes them (#133). Opens a fresh, cookie-less window; the
    human completes consent by hand; the tool extracts the callback query params
    to a 0600 file under secrets/oauth/. Returns ONLY {captured_params,
    callback_host} -- never the code. Requires scope-gate clearance first (Tier-2)."""
    return json.dumps(
        await session_capture.capture_oauth_redirect(identity_label, start_url, callback_host), indent=2
    )



# ------------------------------------------ session keep-alive (silent renewal)
# Renews a CAPTURED identity's session without the human: reopens the app
# headless in the identity's dedicated profile (the app renews itself), else
# uses a stored refresh token; only when both fail does it say
# needs_human_login (then start_capture again). Never types a password, never
# touches a CAPTCHA, never returns a token. Login/IdP hosts used: in scope, or
# learned from the human's own capture, or a well-known IdP -- for renewal only.


@app.tool()
async def refresh_session(identity_label: str) -> str:
    """Silently renew identity_label's captured session (writes the fresh
    cookies/localStorage/sessionStorage into its session_file). Returns
    {status, refreshed, layer, needs_human_login, reason, access_expires_in_s}
    -- never a token. On needs_human_login, ask the human to start_capture."""
    return json.dumps(await session_refresh.refresh_session(identity_label), indent=2)


@app.tool()
def session_health(identity_labels: list[str] | None = None) -> str:
    """Per identity: last refresh, layer used, access-token expiry, the
    estimated next forced human login and a warning when it is < 48 h away.
    Non-secret. No labels = every roster identity."""
    return json.dumps(session_keepalive.session_health(identity_labels), indent=2)


@app.tool()
def start_keepalive(identity_labels: list[str], interval_s: int = 7200) -> str:
    """Keep these captured identities logged in in the background: refresh
    ~5 min before the access token expires, else every interval_s (min 1800,
    default 7200). Runs while browser-mcp runs. Replaces a running keep-alive."""
    return json.dumps(session_keepalive.start_keepalive(identity_labels, interval_s), indent=2)


@app.tool()
def stop_keepalive() -> str:
    """Stop the background session keep-alive for the active engagement."""
    return json.dumps(session_keepalive.stop_keepalive(), indent=2)

# ------------------------------------------------- UI-walk (#164)
# Page comprehension: the rendered PAGE + its real inputs + its actions are
# the unit of testing, not the URL. Walks run as background thread jobs (they
# outlast an MCP call). Tier-2: scripts/check-scope.sh <host> first; url is
# scope-checked again in code (and every navigation / sent request inside the
# walk is scope-checked by the walker itself).

_UI_JOBS: dict = {}
_MAX_LISTED_PAGES = 30
_MAX_EVENT_LINES = 20


def _run_walk(**kw) -> dict:
    inv = asyncio.run(ui_walk.walk(**kw))
    path = ui_walk_store.save_inventory(inv)
    nodes = ui_walk_store.emit_nodes(inv) if inv.get("pages") else {}
    return {"kind": "walk", "inventory": inv, "path": path, "nodes": nodes}


def _run_teardown_job(plan: dict, **kw) -> dict:
    r = asyncio.run(ui_walk_teardown.execute(plan, **kw))
    if r.get("inventory"):
        r["path"] = ui_walk_store.save_inventory(r["inventory"])
    return {"kind": "teardown", "result": r}


def _provenance_line(url: str) -> str:
    provenance = {"class": "wire", "captured_by": "browser-mcp", "method": "GET", "url": url, "status": None}
    return f"\nProvenance (for case-mcp add_evidence): {json.dumps(provenance)}"


def _target_detail(inv: dict) -> str:
    """Everything target-derived (titles, URLs, control text, field names) --
    quarantined as one block by the caller."""
    out = []
    listed = (inv.get("pages") or [])[:_MAX_LISTED_PAGES]
    # Candidates live on the inventory, each naming its page: list them under
    # that page (matched on the page URL or its query-stripped form); only the
    # ones whose page matches no listed page stay in the flat list below.
    by_page: dict[int, list[dict]] = {}
    flat: list[dict] = []
    for c in inv.get("candidates") or []:
        cp = c.get("page") if isinstance(c, dict) else None
        idx = None
        if isinstance(cp, str) and cp:
            for n, p in enumerate(listed):
                u = p.get("url") or ""
                if cp in (u, ui_walk_events._strip_url(u)[0], ui_walk._defrag(u)):
                    idx = n
                    break
        if idx is None:
            flat.append(c)
        else:
            by_page.setdefault(idx, []).append(c)
    for n, p in enumerate(listed):
        out.append(f"PAGE {p.get('url')} -- {p.get('title')!r} [{p.get('auth_state', 'ok')}]")
        for i in p.get("inputs") or []:
            rev = f" (revealed by click {i['revealed_by']})" if i.get("revealed_by") else ""
            out.append(f"  input {i.get('name') or i.get('id') or '(unnamed)'} type={i.get('type')} "
                       f"frame={i.get('frame_origin')} form={i.get('form_action')}{rev}")
        for e in p.get("api_edges") or []:
            if (e.get("method") or "GET") != "GET" or not e.get("sent"):
                out.append(f"  edge {e.get('method')} {e.get('url')} sent={e.get('sent')} "
                           f"blocked={e.get('blocked_reason')}")
        evs = p.get("events") or []
        for e in evs[:_MAX_EVENT_LINES]:
            out.append("  event " + json.dumps(e, default=str)[:300])
        if len(evs) > _MAX_EVENT_LINES:
            out.append(f"  ... {len(evs) - _MAX_EVENT_LINES} more event(s) in the inventory file")
        for c in by_page.get(n, []):
            out.append("  candidate " + json.dumps(c, default=str)[:400])
    if len(inv.get("pages") or []) > _MAX_LISTED_PAGES:
        out.append(f"... {len(inv['pages']) - _MAX_LISTED_PAGES} more page(s) in the inventory file")
    for c in flat:
        out.append("CANDIDATE " + json.dumps(c, default=str)[:400])
    out += _sso_detail(inv)
    return "\n".join(out)


def _sso_lines(inv: dict) -> list[str]:
    """Spec 2: SSO counts only -- no target text (hosts, client ids and URLs
    go in the quarantined block)."""
    sso = inv.get("sso") or {}
    flows = sso.get("flows") or []
    if not flows and not sso.get("endpoints") and not sso.get("out_of_scope_idp_redirects"):
        return ["SSO: none"]
    roles = Counter(e.get("role") for e in sso.get("endpoints") or [])
    return [
        (f"SSO: flows={len(flows)} (IdP in scope: {sum(1 for f in flows if f.get('idp_in_scope'))}) "
         f"idp_hosts_in_scope={len(sso.get('idp_hosts') or [])} repeats={sso.get('repeats', 0)} "
         f"discovery_gets={sso.get('discovery_gets', 0)} "
         f"out_of_scope_idp_redirects={len(sso.get('out_of_scope_idp_redirects') or [])}"),
        "SSO endpoints: " + (", ".join(f"{k}={v}" for k, v in sorted(roles.items(), key=lambda kv: str(kv[0])))
                             or "none"),
    ]


def _sso_detail(inv: dict) -> list[str]:
    sso = inv.get("sso") or {}
    out = []
    for f in sso.get("flows") or []:
        a = f.get("authorize") or {}
        flags = []
        for name in ("state", "nonce"):
            ch = f.get(f"{name}_changes_per_request")
            st = (a.get(name) or {}).get("strength")
            flags.append(f"{name} {'static' if ch is False else 'changes' if ch is True else 'unknown'}/{st}")
        out.append(f"SSO FLOW idp={f.get('idp_host')} in_scope={f.get('idp_in_scope')} "
                   f"client_id={a.get('client_id')!r} response_type={a.get('response_type')!r} "
                   f"pkce={a.get('pkce')} {' '.join(flags)} echoed={f.get('state_echoed_on_callback')} "
                   f"page={f.get('page')}")
    for e in sso.get("endpoints") or []:
        extra = f" redirect_params={e['redirect_params']}" if e.get("redirect_params") else ""
        out.append(f"SSO ENDPOINT {e.get('role')} {e.get('method')} {e.get('url')} "
                   f"in_scope={e.get('in_scope')}{extra}")
    for d in sso.get("discovery") or []:
        out.append(f"SSO DISCOVERY {d.get('url')} status={d.get('status')} issuer={d.get('issuer')}")
    for r in sso.get("out_of_scope_idp_redirects") or []:
        out.append(f"SSO OUT-OF-SCOPE REDIRECT followed to {r.get('host')} ({r.get('url')}) from {r.get('page')}")
    return out


_PROXY_ARTIFACT_NOTE = (
    "The block happened only through the proxy, so it is a proxy/tooling artifact (likely the proxy's "
    "outbound connection), not a finding. If the programme's rules allow it, the human may change their "
    "own proxy settings and re-run with the mirror.")


def _event_lines(inv: dict) -> list[str]:
    """Counts only -- no target text. Event/console text itself stays in the quarantined block."""
    pages = inv.get("pages") or []
    types = Counter(e.get("type") for p in pages for e in p.get("events") or [])
    dropped = sum(int(p.get("events_dropped") or 0) for p in pages)
    out = ["Events: " + (", ".join(f"{k}={v}" for k, v in sorted(types.items(), key=lambda kv: str(kv[0])))
                         or "none") + f" (dropped: {dropped})"]
    extra = [f"{k}={inv[f'events_{k}']}" for k in ("forged_dropped", "snapshot_frames_skipped",
                                                  "drains_skipped", "candidate_errors")
             if inv.get(f"events_{k}")]
    if extra:
        out.append("Event recorder: " + ", ".join(extra))
    out.append(f"Pass-2 events: {len(inv.get('pass2_events') or [])}")
    m = inv.get("burp_mirror") or {}
    auto = f" (auto: {m['auto']})" if m.get("auto") else ""
    if not m.get("requested") and m.get("auto"):
        out.append(f"Burp mirror: OFF{auto}")
    if m.get("requested"):
        if m.get("active"):
            out.append(f"Burp mirror: ON via {m.get('proxy')}{auto}")
        else:
            out.append(f"Burp mirror: OFF ({m.get('reason') or 'unknown'})")
            if m.get("detail"):
                out.append("Burp mirror detail: " + json.dumps(str(m["detail"])[:200]))
            if m.get("reason") == "target refused proxied traffic":
                out.append(_PROXY_ARTIFACT_NOTE)
    return out


def _format_walk(value: dict) -> str:
    inv = value["inventory"]
    pages = inv.get("pages") or []
    edges = [e for p in pages for e in p.get("api_edges") or []]
    controls = [c for p in pages for c in p.get("controls") or []]
    cand = Counter(c.get("type") for c in inv.get("candidates") or [])
    lines = [
        f"UI-walk {inv.get('walk_id')} [{inv.get('mode')}] status={inv.get('status')}"
        + (f" error={inv.get('error')}" if inv.get("error") else ""),
        f"Inventory: {value.get('path')}",
        f"Pages: {len(pages)} (logged-out: {sum(1 for p in pages if p.get('auth_state') == 'logged-out')}) | "
        f"Inputs: {sum(len(p.get('inputs') or []) for p in pages)} | Controls: {len(controls)} "
        f"(clicked {sum(1 for c in controls if c.get('clicked'))}, "
        f"never-click {sum(1 for c in controls if c.get('skipped_reason') == 'never-click')})",
        f"UI->API edges: {len(edges)} (intercepted non-GET: "
        f"{sum(1 for e in edges if e.get('method') != 'GET' and not e.get('sent'))}, sent non-GET: "
        f"{sum(1 for e in edges if e.get('method') != 'GET' and e.get('sent'))})",
        f"Real submits: {len(inv.get('real_submits') or [])} | Canaries: {len(inv.get('canaries') or [])} | "
        f"Sinks: {len(inv.get('sinks') or [])} (executing: {sum(1 for s in inv.get('sinks') or [] if s.get('executed'))})",
        "Candidates (leads for exploit-agent, NOT confirmed): "
        + (", ".join(f"{k}={v}" for k, v in sorted(cand.items())) or "none"),
        f"Surface-map nodes: {value.get('nodes') or {}}",
    ]
    lines += _event_lines(inv)
    lines += _sso_lines(inv)
    if inv.get("status") == "auth_lost":
        lines.append("AUTH LOST: the session no longer renders the logged-in view -- refresh the session "
                     "(session_file / session_storage) and re-walk; do NOT treat the logged-out shell as the surface.")
    lines += [f"Honest limit: {h}" for h in inv.get("honest_limits") or []]
    lines.append(_quarantine(_target_detail(inv), source_label="ui-walk inventory"))
    return "\n".join(lines) + "\n" + _provenance_line(inv.get("start_url") or "")


def _format_teardown(r: dict) -> str:
    cand = Counter(c.get("type") for c in r.get("candidates") or [])
    lines = [f"Teardown status={r.get('status')}" + (f" error={r.get('error')}" if r.get("error") else ""),
             f"Steps run: {r.get('steps_run')}", f"Walker objects deleted: {len(r.get('deleted') or [])}",
             "Candidates (leads, NOT confirmed): " + (", ".join(f"{k}={v}" for k, v in sorted(cand.items())) or "none")]
    if r.get("inventory"):
        lines += _event_lines(r["inventory"])
    lines += [f"Note: {n}" for n in r.get("notes") or []]
    if r.get("path"):
        lines.append(f"Inventory: {r['path']}")
    inv = r.get("inventory") or {"candidates": r.get("candidates") or []}
    lines.append(_quarantine(_target_detail(inv), source_label="ui-walk teardown"))
    return "\n".join(lines) + "\n" + _provenance_line((r.get("plan") or {}).get("base_url") or "")


@app.tool()
def start_ui_walk(url: str, mode: str = "map", session_file: str = "", cookie_header: str = "",
                  bearer_token: str = "", local_storage: dict[str, str] | None = None,
                  session_storage: dict[str, str] | None = None, max_pages: int = 50,
                  max_clicks_per_page: int = 40, same_origin_only: bool = True,
                  upstream_proxy: str = "") -> str:
    """PAGE-FIRST comprehension of an app (#164): render every in-scope page
    reachable from url, list its REAL inputs (incl. lazy/third-party iframes,
    modal- and tab-revealed fields, shadow DOM), click every control, and
    record the UI->API call each one makes. Results become page/input/action
    surface-map nodes the coverage gate counts.
    mode="map" (Pass 1, always allowed): NOTHING state-changing is sent --
    every non-GET, payment-provider request, out-of-scope navigation and
    state-changing-looking GET is intercepted and recorded, not sent; logout /
    account-delete / payment controls are never clicked.
    mode="canary" (Pass 2): additionally fills every text input with a unique
    XSS canary, REALLY submits, re-walks to find where each canary renders /
    executes (incl. cross-page stored XSS), and runs create->destroy->verify
    on walker-created objects only (broken delete, delete-IDOR and
    cancel-without-revoke candidates). Refused unless the HUMAN has written
    data/engagements/<slug>/ui-walk-authorized.yaml (`canary_submit: true`) --
    you cannot create that file.
    upstream_proxy (optional, usually leave empty): the Burp mirror -- a copy
    of what the walker really sends shows up in the human's own LOCAL Burp.
    Empty = auto: if a listener on 127.0.0.1:8080 says it is Burp Suite,
    the mirror turns on by itself, otherwise the walk runs direct (the
    result says which; no need to ask anyone). "off" disables it; an explicit
    loopback http URL (e.g. "http://127.0.0.1:8081") or HUNTMCP_UPSTREAM_PROXY
    picks another listener; anything non-loopback is refused before a job
    starts. The mirror never changes what is sent.
    Returns a job id; poll with check_ui_walk. Pass session_file /
    session_storage / cookie_header / bearer_token / local_storage to walk
    the logged-in app. Requires scope-gate clearance first (Tier-2)."""
    if mode not in ("map", "canary"):
        return f"Error: unknown mode {mode!r}; expected 'map' or 'canary'."
    if not ui_walk_logic._default_scope_check(url):
        return f"Refused: {url!r} is out of scope for the active engagement -- no walk started."
    refusal = ui_walk.proxy_refusal(upstream_proxy)
    if refusal:
        return f"Error: {refusal} -- no walk started."
    job = job_runtime.start_thread_job(
        "ui-walk", _run_walk, _UI_JOBS, start_url=url, mode=mode,
        session_file=session_file or None, cookie_header=cookie_header or None,
        bearer_token=bearer_token or None, local_storage=local_storage or None,
        session_storage=session_storage or None, max_pages=max_pages,
        max_clicks_per_page=max_clicks_per_page, same_origin_only=same_origin_only,
        upstream_proxy=upstream_proxy)
    return (f"UI-walk started ({mode}) on {urlsplit(url).hostname}: job_id={job['job_id']}. "
            "Poll with check_ui_walk(job_id).")


@app.tool()
def check_ui_walk(job_id: str) -> str:
    """Poll a start_ui_walk / run_teardown job. When done: the page/input/
    action counts, intercepted vs sent requests, canary sinks, the candidate
    list for exploit-agent, the inventory file path, and surface-map node
    counts. Target-derived text is quarantined."""
    r = job_runtime.poll_thread_job(job_id, _UI_JOBS)
    if r.get("error") and r.get("status") != "error":
        return f"Error: {r['error']}"
    if r["status"] == "running":
        return f"UI-walk job {job_id} still running ({r.get('elapsed_s')}s). Poll again later."
    if r["status"] == "error":
        return f"UI-walk job {job_id} failed: {r.get('error')}"
    value = r["value"]
    return _format_teardown(value["result"]) if value.get("kind") == "teardown" else _format_walk(value)


@app.tool()
def list_ui_walks() -> str:
    """List UI-walk / teardown jobs started in this server session."""
    items = job_runtime.list_thread_jobs(_UI_JOBS)
    if not items:
        return "No UI-walk jobs in this session."
    return "\n".join(json.dumps(i, default=str) for i in items)


# -- spec 3a: Burp-style parameter mutation over the walk's recorded requests --
_SAFE_LABEL_RE = re.compile(r"^[A-Za-z0-9_.:/\-]{1,200}$")


def _safe_label(text) -> str:
    """Route / field names printed OUTSIDE the quarantine (the RESTORE FAILED
    line) must be plain identifiers, never free target text."""
    t = str(text or "")
    return t if _SAFE_LABEL_RE.match(t) else "<non-printable name>"


def _run_mutations_job(plan_id: str, **kw) -> dict:
    res = asyncio.run(mutation_runner.run(plan_id, **kw))
    path = None
    if res.get("run_id") and res.get("walk_id"):
        path = os.path.join(ui_walk_store.walk_dir(), f"{res['walk_id']}.mutations-{res['run_id']}.json")
    return {"kind": "mutations", "result": res, "path": path}


def _format_plan(p: dict) -> str:
    reqs = p.get("requests") or []
    variants = [v for r in reqs for v in r.get("variants") or []]
    why = Counter(v.get("why_not") for v in variants if not v.get("would_send"))
    lines = [f"Mutation plan plan_id={p.get('plan_id')} for walk {p.get('walk_id')}",
             (f"Requests: {len(reqs)} (skipped by max_requests: {p.get('skipped', 0)}) | Variants: {len(variants)} "
              f"(would send now: {sum(1 for v in variants if v.get('would_send'))})"),
             "Not sendable now: " + (", ".join(f"{k}={n}" for k, n in sorted(why.items())) or "none"),
             ("Next: read the reasons, add extra_variants where a request suggests more, then "
              "run_mutations(plan_id, session_file=<the walk's session_file>).")]
    detail = []
    for r in reqs:
        detail.append(f"[{r.get('replay_id')}] {r.get('method')} {r.get('route')} ownership={r.get('ownership')}"
                      + (" NEVER-MUTATED" if r.get("never_mutated") else "")
                      + (f" withheld={r.get('withheld_fields')}" if r.get("withheld_fields") else ""))
        for v in (r.get("variants") or [])[:40]:
            detail.append(f"  {v['variant_id']} {v['family']:<12} score={v['score']:<3} "
                          f"{'SEND' if v.get('would_send') else 'hold:' + str(v.get('why_not'))} | {v['change']} "
                          f"| {v['reason']}")
    lines.append(_quarantine("\n".join(detail) or "(no recorded requests)", source_label="mutation plan"))
    first = reqs[0]["route"] if reqs else ""
    return "\n".join(lines) + "\n" + _provenance_line(first)


def _format_mutations(value: dict) -> str:
    r = value["result"]
    lines = []
    for f in r.get("restore_failures") or []:
        lines.append(f"RESTORE FAILED: {_safe_label(f.get('route'))} field {_safe_label(f.get('field'))} -- the "
                     "test account may still carry the changed value; check and fix it by hand before more runs.")
    left = r.get("left_null_keys") or []
    if left:
        names = sorted({_safe_label(x.get("field")) for x in left})[:20]
        lines.append(f"LEFT AS NULL: {len(left)} field(s) the account did not have before ({', '.join(names)}) "
                     "now exist with a null value -- a write cannot remove a key; check them by hand.")
    results = r.get("results") or []
    why = Counter(x.get("why_not") for x in results if not x.get("sent"))
    cand = Counter(c.get("type") for c in r.get("candidates") or [])
    lines += [f"Mutation run {r.get('run_id')} (plan {r.get('plan_id')}, walk {r.get('walk_id')}) "
              f"status={r.get('status')}" + (f" error={r.get('error')}" if r.get("error") else ""),
              f"Requests sent: {r.get('sent', 0)} | Variants sent: {sum(1 for x in results if x.get('sent'))} | "
              "Not sent: " + (", ".join(f"{k}={n}" for k, n in sorted(why.items(), key=str)) or "none"),
              "Candidates (leads for exploit-agent, NOT confirmed): "
              + (", ".join(f"{k}={n}" for k, n in sorted(cand.items())) or "none"),
              f"Objects created by this run (cleaned up by run_teardown): {len(r.get('created_ids') or [])}",
              f"Burp mirror: {'ON' if (r.get('burp_mirror') or {}).get('active') else 'off'}"]
    if r.get("blocked_hosts"):
        lines.append(f"BLOCKED: stopped on a block signal from {len(r['blocked_hosts'])} host(s); nothing "
                     "tries to get around it.")
    if r.get("status") == "auth_lost":
        lines.append("AUTH LOST: the session stopped being authorized -- refresh it and run again.")
    if r.get("agent_variant_errors"):
        lines.append(f"Rejected extra_variants: {len(r['agent_variant_errors'])}")
    if value.get("path"):
        lines.append(f"Results file: {value['path']}")
    lines += [f"Honest limit: {h}" for h in r.get("honest_limits") or []]
    detail = [json.dumps(c, default=str)[:1500] for c in r.get("candidates") or []]
    detail += [f"rejected extra_variant: {e}" for e in r.get("agent_variant_errors") or []]
    lines.append(_quarantine("\n".join(detail) or "(no candidates)", source_label="mutation results"))
    route = next((x.get("route") for x in results if x.get("route")), "")
    return "\n".join(lines) + "\n" + _provenance_line(route or "")


@app.tool()
def plan_mutations(walk_id: str, request_filter: str = "", max_requests: int = 50) -> str:
    """Spec 3a/3b (Burp-style mutation, NO traffic): profile every request a
    finished UI-walk recorded and return a ranked, request-specific variant
    plan. Parameter level (3a): add a field the UI never sends (mass
    assignment), remove a check field (otp/csrf/old password), duplicate a
    param (HPP), change its type (type juggling), numeric edge values.
    Request level (3b): routing/authz headers (X-Forwarded-For, X-Original-URL,
    ...), method swap/override, content-type switch, JSON parser differentials,
    path/encoding tricks, cache poisoning/deception (always on a unique hmcb=
    URL), GraphQL alias/batch, and races on walker-created objects. Each
    variant has the reason it fits THIS request, whether it needs the human
    Pass-2 grant, and whether it would be sent. Read the reasons; then call run_mutations(plan_id, ...), adding your
    own extra_variants where the request suggests more. Target text is
    quarantined."""
    try:
        p = mutation_runner.make_plan(walk_id, request_filter=request_filter,
                                      max_requests=max(1, min(int(max_requests), 200)))
    except ValueError as e:
        return f"Error: {e}"
    return _format_plan(p)


@app.tool()
def run_mutations(plan_id: str, session_file: str = "", variants: str = "auto",
                  extra_variants: list[dict] | None = None, drop_variants: list[str] | None = None,
                  upstream_proxy: str = "", bearer_token: str = "") -> str:
    """Spec 3a: send a plan_mutations plan as the SAME identity that walked
    (pass the walk's session_file; a different identity is refused). Every
    variant passes code gates: in scope, never a payment host, no
    state-changing-looking GET; GET variants need no grant; non-GET variants
    are sent ONLY with the human-written Pass-2 grant file, only on
    walker-owned objects (walker-created, or the identity's own account), only
    when a read-back GET exists -- each change is read back and RESTORED
    (a failed restore is reported first). The grant's real_submit_cap_per_walk
    is cumulative over all runs. Stops on 429/WAF signals, auth loss, budget.
    variants: "auto" (the plan) or comma-separated variant ids.
    extra_variants: your own additions, one op each:
    {"replay_id", "op": add_param|remove_param|duplicate_param|retype_param|set_param,
     "location": query|form|json|multipart, "path": [...], "value": ..., "reason": "..."}
    or a request-level op: {"replay_id", "op": "set_header", "name", "value"} |
    {"op": "remove_header", "name"} | {"op": "method", "method"|"override",
    "via": swap|header|param} | {"op": "content_type", "to": json|form|text|xml} |
    {"op": "path", "transform": <name>} or {"op": "path", "literal": "/same/host/path"} |
    {"op": "graphql_batch", "n": 2..5, "mode": alias|array}. Never settable:
    Host, Cookie, Authorization, Proxy-*, Content-Length, Transfer-Encoding;
    no CR/LF/NUL; the host never changes; values <= 2 KB. Races are rule-built
    only (grant + a walker-created object; N<=10, create endpoints <=3).
    Cache variants (and path tricks) always go to a unique `hmcb=` URL.
    bearer_token: only for an API that needs one (never stored).
    upstream_proxy: Burp mirror, same rules as start_ui_walk. Results are
    LEADS (mass-assignment / param-removal-bypass / hpp / type-juggling /
    numeric-edge candidates, plus header-authz-bypass / method-override /
    content-type-confusion / json-parser-differential / path-normalization /
    cache-poisoning / cache-deception / graphql-batching / race candidates),
    never confirmed. Poll with check_mutations."""
    if mutation_runner.load_plan(plan_id) is None and not ui_walk.proxy_refusal(upstream_proxy):
        return f"Error: unknown plan_id {plan_id!r} -- run plan_mutations(walk_id) first."
    refusal = ui_walk.proxy_refusal(upstream_proxy)
    if refusal:
        return f"Error: {refusal} -- no run started."
    job = job_runtime.start_thread_job(
        "ui-walk-mutations", _run_mutations_job, _UI_JOBS, plan_id, session_file=session_file,
        variants=variants or "auto", extra_variants=extra_variants or None,
        drop_variants=drop_variants or None, upstream_proxy=upstream_proxy, bearer_token=bearer_token)
    return f"Mutation run started for {plan_id}: job_id={job['job_id']}. Poll with check_mutations(job_id)."


@app.tool()
def check_mutations(job_id: str) -> str:
    """Poll a run_mutations job: status (RESTORE FAILED first), sent / not-sent
    counts with reasons, candidates for exploit-agent (leads, quarantined),
    the results file path."""
    r = job_runtime.poll_thread_job(job_id, _UI_JOBS)
    if r.get("error") and r.get("status") != "error":
        return f"Error: {r['error']}"
    if r["status"] == "running":
        return f"Mutation job {job_id} still running ({r.get('elapsed_s')}s). Poll again later."
    if r["status"] == "error":
        return f"Mutation job {job_id} failed: {r.get('error')}"
    value = r["value"]
    if value.get("kind") != "mutations":
        return f"Job {job_id} is not a mutation run -- use check_ui_walk."
    return _format_mutations(value)


@app.tool()
def list_mutation_runs() -> str:
    """List run_mutations jobs started in this server session."""
    items = [i for i in job_runtime.list_thread_jobs(_UI_JOBS) if i.get("tool") == "ui-walk-mutations"]
    if not items:
        return "No mutation runs in this session."
    return "\n".join(json.dumps(i, default=str) for i in items)


@app.tool()
def run_teardown(url: str, identity_label: str, session_file: str = "", cookie_header: str = "",
                 steps: list[str] | None = None, upstream_proxy: str = "") -> str:
    """FINAL, human-gated engagement step (#164) -- only when the HUMAN says the
    engagement is done (ideally after triage, so findings stay reproducible).
    Never on your own initiative. Steps: cleanup (delete every walker-created
    canary object, with broken-delete checks), logout (real logout, then
    replay the old session -> logout-session-survives candidate),
    account_delete (ONLY for a roster identity marked disposable: true).
    Without a fresh confirmation this returns BLOCKED with the exact
    scripts/confirm-state-change.sh command the HUMAN must run in their own
    terminal (bound to this exact cleanup set + identity); then call again.
    Returns a job id to poll with check_ui_walk. Requires scope-gate clearance
    first (Tier-2). upstream_proxy: optional local Burp mirror, same rules as
    start_ui_walk (loopback http only, "off" disables)."""
    refusal = ui_walk.proxy_refusal(upstream_proxy)
    if refusal:
        return f"Error: {refusal} -- no teardown started."
    try:
        plan, stop = ui_walk_teardown.gate(url, identity_label, steps,
                                           session=ui_walk_teardown.session_ref(session_file or None,
                                                                                cookie_header or None))
    except ValueError as e:
        return f"Error: {e}"
    if stop is not None:
        if stop["status"] == "blocked":
            return ("BLOCKED: teardown changes state and needs a human confirmation for exactly this plan.\n"
                    f"Plan: {stop['summary']}\nThe HUMAN runs, in their own terminal:\n  {stop['command']}\n"
                    "then call run_teardown again with the same arguments.")
        return f"Refused: {stop.get('error')}"
    job = job_runtime.start_thread_job("ui-walk-teardown", _run_teardown_job, _UI_JOBS, plan,
                                       session_file=session_file or None, cookie_header=cookie_header or None,
                                       upstream_proxy=upstream_proxy)
    return f"Teardown started: job_id={job['job_id']}. Poll with check_ui_walk(job_id)."



if __name__ == "__main__":
    print("browser-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
