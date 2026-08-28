"""Real-browser JS-challenge-solving MCP server (WAF/bot-detection bypass,
the Playwright tool ARCHITECTURE.md's WAF/bot-detection block note has
long flagged as planned but unbuilt).

See challenge_solver.py's module docstring for the full design rationale
and the important scope caveat: WAF/anti-bot challenges are frequently
explicitly out-of-scope in bug bounty programs, so this solves a challenge
once to confirm reachability, not to grind through it repeatedly.

Tier-2 (target-touching) -- callers must run scripts/check-scope.sh <host>
first, exactly like every other Tier-2 tool in this repo. Registered in
scripts/hooks/scope_gate_hook.py's TIER2_MCP_SERVERS so this is also
structurally enforced for Claude Code (and, via .opencode/plugin/
scope-gate.ts shelling out to that same script, for OpenCode too).

Setup: pip install -r requirements.txt gets the playwright Python package.
No separate `playwright install chromium` needed if an existing system
Chrome/Chromium is found (see ../browser_launch.SYSTEM_BROWSER_CANDIDATES,
shared with browser-mcp); otherwise run `playwright install chromium`
once to get Playwright's own bundled browser.
"""

import sys

sys.path.insert(0, __file__.rsplit("/", 2)[0])

import challenge_solver
from mcp.server.fastmcp import FastMCP

app = FastMCP("playwright-mcp")

_SCOPE_REMINDER = (
    "\n\nReminder: WAF/anti-bot presence is often explicitly out-of-scope "
    "per program policy (e.g. Cloudflare's own HackerOne baseline "
    "excludes bot-score/challenge disputes) -- check this engagement's "
    "AGENT-BRIEF.md before treating a solved challenge as authorization "
    "to continue past it. Reporting 'target is behind <vendor>, "
    "JS-challenge-protected' as an informational finding is itself a "
    "complete, valid outcome -- this tool is not meant to be used as a "
    "repeated bypass-grinder against a program that has excluded this."
)


@app.tool()
async def solve_js_challenge(url: str) -> str:
    """Navigate to url in a real headless browser and check for a JS-based
    bot-detection challenge (Cloudflare, Akamai, Imperva, DataDome,
    PerimeterX) that waf-bypass-mcp's curl-based Tier 1-4 can't beat.
    Makes a single attempt to let Playwright's real browser execute the
    challenge JS -- not a retry loop. If solved, returns the clearance
    cookie so you can inject it into a subsequent curl/tool_resolver
    request's Cookie header to continue testing the application behind
    it. Requires scope-gate clearance first (Tier-2). Use this after
    waf-bypass-mcp's attempt_bypass() reports "still WAF-protected" and
    the block looks JS-challenge-shaped, not for a generic 403/rate-limit
    block that the curl-based tiers should handle first."""
    r = await challenge_solver.solve_js_challenge(url)

    if r["error"]:
        return f"Browser error: {r['error']}"

    if not r["challenge_type"]:
        return f"No JS challenge detected at {url} -- page loaded normally."

    lines = [f"Detected challenge type: {r['challenge_type']} at {url}"]
    if r["solved"]:
        lines.append(
            f"✅ Solved. Clearance cookie: {r['clearance_cookie_name']}="
            f"{r['clearance_cookie_value']}"
        )
        lines.append(
            "Inject this cookie into subsequent requests via -H "
            f"\"Cookie: {r['clearance_cookie_name']}={r['clearance_cookie_value']}\" "
            "to continue testing -- reuse window varies by vendor (Cloudflare "
            "cf_clearance is typically config-dependent, ~15min-hours; Akamai/"
            "Imperva/DataDome/PerimeterX cookies are often shorter-lived and "
            "bound to the originating browser's TLS/UA fingerprint)."
        )
    else:
        lines.append(
            "⚠ Still challenged after one attempt -- not retrying further. "
            "Document as WAF/anti-bot-protected and move on."
        )

    return "\n".join(lines) + _SCOPE_REMINDER


if __name__ == "__main__":
    print("playwright-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
