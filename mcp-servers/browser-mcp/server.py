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
Chrome/Chromium is found (see browser_confirm.SYSTEM_BROWSER_CANDIDATES);
otherwise run `playwright install chromium` once to get Playwright's own
bundled browser.
"""

import sys

sys.path.insert(0, __file__.rsplit("/", 2)[0])

import browser_confirm
from mcp.server.fastmcp import FastMCP

app = FastMCP("browser-mcp")


@app.tool()
def check_js_execution(url: str, marker: str, wait_ms: int = 2000) -> str:
    """Navigate to url in a real headless browser and check whether marker
    actually executed as JS (a fired alert/confirm/prompt dialog containing
    it, or document.title containing it) vs. merely being present in the
    raw HTML response. Use this to confirm a suspected XSS actually runs in
    a browser context before marking it CONFIRMED -- a payload that shows
    up in raw_html but not in dialog/title is reflection, not proof of
    execution. Requires scope-gate clearance first (Tier-2)."""
    r = browser_confirm.check_js_execution(url, marker, wait_ms=wait_ms)
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
def render_dom(url: str, wait_selector: str = "") -> str:
    """Return the fully rendered (post-JS) HTML for url, for comparison
    against the raw HTTP response -- surfaces client-side-injected content,
    DOM clobbering, and anything a plain curl would never show. Truncated
    to 5000 chars. Requires scope-gate clearance first (Tier-2)."""
    r = browser_confirm.render_dom(url, wait_selector=wait_selector or None)
    if r["error"]:
        return f"Browser error: {r['error']}"
    html = r["html"] or ""
    truncated = html[:5000] + ("... [truncated]" if len(html) > 5000 else "")
    return f"Title: {r['title']}\n\n{truncated}"


@app.tool()
def fill_and_submit(url: str, field_values: dict[str, str], submit_selector: str,
                     then_check_marker: str = "") -> str:
    """Fill form fields (CSS selector -> value) and click submit_selector --
    for stored-XSS or business-logic flows needing a real form submission,
    not just a GET. If then_check_marker is given, checks the resulting
    page for a fired dialog containing it. Requires scope-gate clearance
    first (Tier-2)."""
    r = browser_confirm.fill_and_submit(url, field_values, submit_selector,
                                         then_check_marker=then_check_marker or None)
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
def screenshot(url: str, wait_ms: int = 1000) -> str:
    """Full-page screenshot of url as a base64-encoded PNG -- visual PoC
    evidence for a report's "screenshot + PoC" requirement. Requires
    scope-gate clearance first (Tier-2)."""
    r = browser_confirm.screenshot_base64(url, wait_ms=wait_ms)
    if r["error"]:
        return f"Browser error: {r['error']}"
    return f"data:image/png;base64,{r['screenshot_base64']}"


if __name__ == "__main__":
    print("browser-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
