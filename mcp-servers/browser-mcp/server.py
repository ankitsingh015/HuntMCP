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
- local_storage (a dict of key -> value), seeded into the target origin's
  localStorage before any page script runs, for a modern SPA that reads
  its own session/JWT out of localStorage rather than a cookie or a
  server-sent header. IS captured by session_file, so only needs passing
  once, on the call that establishes the session.
"""

import sys

sys.path.insert(0, __file__.rsplit("/", 2)[0])

import browser_confirm
from mcp.server.fastmcp import FastMCP

app = FastMCP("browser-mcp")


@app.tool()
async def check_js_execution(url: str, marker: str, wait_ms: int = 2000,
                              cookie_header: str = "", bearer_token: str = "",
                              local_storage: dict[str, str] | None = None,
                              session_file: str = "") -> str:
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
    return "\n".join(lines)


@app.tool()
async def render_dom(url: str, wait_selector: str = "", cookie_header: str = "",
                      bearer_token: str = "", local_storage: dict[str, str] | None = None,
                      session_file: str = "") -> str:
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
    )
    if r["error"]:
        return f"Browser error: {r['error']}"
    html = r["html"] or ""
    truncated = html[:5000] + ("... [truncated]" if len(html) > 5000 else "")
    return f"Title: {r['title']}\n\n{truncated}"


@app.tool()
async def extract_page_content(url: str, wait_selector: str = "", max_links: int = 200,
                                cookie_header: str = "", bearer_token: str = "",
                                local_storage: dict[str, str] | None = None,
                                session_file: str = "") -> str:
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
    )
    if r["error"]:
        return f"Browser error: {r['error']}"
    text = r["text"] or ""
    truncated = text[:8000] + ("... [truncated]" if len(text) > 8000 else "")
    lines = [f"Title: {r['title']}", "", "--- Text ---", truncated]
    if r["links"]:
        lines.append("")
        lines.append(f"--- Links ({len(r['links'])}) ---")
        for link in r["links"]:
            label = link["text"] or "(no text)"
            lines.append(f"- {label}: {link['href']}")
    return "\n".join(lines)


@app.tool()
async def fill_and_submit(url: str, field_values: dict[str, str], submit_selector: str,
                           then_check_marker: str = "", cookie_header: str = "",
                           bearer_token: str = "", local_storage: dict[str, str] | None = None,
                           session_file: str = "") -> str:
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
    )
    if r["error"]:
        return f"Browser error: {r['error']}"
    lines = [f"Submitted: {r['submitted']}", f"Title after submit: {r['title_after_submit']}"]
    if then_check_marker:
        if r["dialog_fired"]:
            lines.append(f"✅ JS DIALOG FIRED containing marker: {r['dialog_text']!r} -- confirmed execution")
        else:
            lines.append("✗ No dialog containing marker fired after submit")
    return "\n".join(lines)


@app.tool()
async def screenshot(url: str, wait_ms: int = 1000, cookie_header: str = "",
                      bearer_token: str = "", local_storage: dict[str, str] | None = None,
                      session_file: str = "") -> str:
    """Full-page screenshot of url as a base64-encoded PNG -- visual PoC
    evidence for a report's "screenshot + PoC" requirement. Pass
    cookie_header/bearer_token/local_storage/session_file for a screenshot
    of a logged-in-only view. Requires scope-gate clearance first (Tier-2)."""
    r = await browser_confirm.screenshot_base64(
        url, wait_ms=wait_ms,
        cookie_header=cookie_header or None,
        bearer_token=bearer_token or None,
        local_storage=local_storage or None,
        session_file=session_file or None,
    )
    if r["error"]:
        return f"Browser error: {r['error']}"
    return f"data:image/png;base64,{r['screenshot_base64']}"


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


if __name__ == "__main__":
    print("browser-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
