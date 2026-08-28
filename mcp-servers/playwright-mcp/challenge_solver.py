"""Real-browser JS-challenge solving for WAF/bot-detection bypass (Phase
0.6 Tier 5-adjacent -- see ARCHITECTURE.md's WAF/bot-detection block note).

waf-bypass-mcp's Tier 1-4 (header/path/method/HTTP-version curl variants)
can beat a rule-based WAF, but not a JS-based bot-detection challenge
(Cloudflare "Just a moment...", Akamai Bot Manager, Imperva/Incapsula,
DataDome, PerimeterX) -- those require executing real challenge JS in an
actual browser. This drives one via Playwright, reusing browser-mcp's
launch pattern (../browser_launch.py, shared, not duplicated).

Deliberately a SINGLE attempt, not a retry/grind loop: WAF/anti-bot
challenges are frequently explicitly out-of-scope in bug bounty programs
(e.g. Cloudflare's own HackerOne program policy lists CAPTCHA/Turnstile
automation and bot-score disputes as out of scope -- the anti-bot layer is
infrastructure the customer chose to deploy, not attack surface, unless a
program's scope says otherwise). This tool solves a challenge once, to
confirm the application behind it is reachable for further *authorized*
testing -- "target is behind an unsolvable/out-of-scope WAF" is itself a
complete, valid, reportable outcome, not a failure to keep grinding at.

Tier-2 (target-touching) -- callers must run scripts/check-scope.sh <host>
first, exactly like every other Tier-2 tool in this repo. Registered in
scripts/hooks/scope_gate_hook.py's TIER2_MCP_SERVERS, inherited
automatically by .opencode/plugin/scope-gate.ts (shells out to that same
script). Budget AND audit are both enforced directly here (unlike
browser-mcp, which only enforces budget) since this is a direct Playwright
call, not a subprocess through tool_resolver.run_tool()'s chokepoint --
audit matters more here than for browser-mcp given the scope-ambiguity
noted above.

Uses Playwright's ASYNC API, not sync_playwright -- see browser_confirm.py's
module docstring for why: FastMCP dispatches tool handlers on its own
already-running asyncio event loop, and sync_playwright() cannot start a
second one inside it. Confirmed live 2026-08-28 that this tool failed
identically to browser-mcp's the moment it was actually invoked through a
real MCP call, despite passing its own (Playwright-free) unit tests.
"""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from audit_log import log_call as _log_call
from browser_launch import DEFAULT_TIMEOUT_MS, launch_kwargs
from budget_guard import enforce as _enforce_budget

# Signatures researched against each vendor's actual, documented challenge
# behavior (Cloudflare's own developer docs; independent write-ups for the
# others, since none publish a formal spec) -- not guessed. Checked against
# both response headers and page content, since either alone can be spoofed
# or absent depending on challenge stage.
_CHALLENGE_SIGNATURES = {
    "cloudflare": {
        "headers": {"cf-mitigated": "challenge"},
        "body_markers": ["Just a moment...", "cf_chl_opt", "/cdn-cgi/challenge-platform/"],
        "clearance_cookie": "cf_clearance",
    },
    "akamai": {
        # NOT "_abck"/"sensor_data"/"ak_bmsc" -- Akamai's sensor/telemetry JS
        # and _abck cookie are present on essentially every page load on an
        # Akamai-fronted site, challenged or not, so those would false-positive
        # on ordinary traffic. The interstitial block/challenge page itself
        # carries distinct copy -- match that instead.
        "headers": {},
        "body_markers": ["Pardon Our Interruption", "Reference #", "_sec/cp_challenge"],
        "clearance_cookie": "_abck",
    },
    "imperva": {
        "headers": {"x-iinfo": None},  # presence alone is the signal, any value
        "body_markers": ["incap_ses_", "visid_incap_"],
        "clearance_cookie": "visid_incap",
    },
    "datadome": {
        "headers": {},
        "body_markers": ["geo.captcha-delivery.com", "datadome"],
        "clearance_cookie": "datadome",
    },
    "perimeterx": {
        "headers": {},
        "body_markers": ["_px3", "_pxvid", "Press & Hold", "px-cdn.net"],
        "clearance_cookie": "_px3",
    },
}


def _detect_challenge_type(html: str, headers: dict[str, str]) -> str | None:
    """Identify which vendor's JS challenge (if any) a page is showing, by
    checking response headers and body content against each vendor's known
    signatures. Returns the vendor key or None if no challenge is
    detected -- a normal page (even one that later turns out to have some
    other WAF rule) is not a JS challenge and this correctly returns None
    for it, distinct from waf-bypass-mcp's classify_block()."""
    lower_headers = {k.lower(): v for k, v in headers.items()}
    lower_html = html.lower() if html else ""

    for vendor, sig in _CHALLENGE_SIGNATURES.items():
        for header_name, expected in sig["headers"].items():
            actual = lower_headers.get(header_name.lower())
            if actual is not None and (expected is None or expected.lower() in actual.lower()):
                return vendor
        for marker in sig["body_markers"]:
            if marker.lower() in lower_html:
                return vendor
    return None


def _body_still_shows_challenge(html: str, vendor: str) -> bool:
    """Post-wait recheck for one already-identified vendor. Deliberately
    body-markers-only, not a second _detect_challenge_type() call with an
    empty headers dict: the original headers came from the initial
    navigation response and are stale by the time any client-side JS has
    run, so re-using them (or silently passing {} through the same header-
    aware code path) would either wrongly keep flagging a since-cleared
    header-based signature (cloudflare/imperva) as still active, or wrongly
    treat "we didn't refetch headers" as "headers are absent". Body content
    is the one signal that actually reflects post-wait DOM state."""
    lower_html = html.lower() if html else ""
    return any(marker.lower() in lower_html for marker in _CHALLENGE_SIGNATURES[vendor]["body_markers"])


async def solve_js_challenge(url: str, timeout_ms: int = DEFAULT_TIMEOUT_MS) -> dict:
    """Navigate to url in a real headless browser, detect whether a
    JS-based bot-detection challenge is present, and (if so) wait once for
    Playwright's own navigation to settle past it -- a single attempt, not
    a retry loop. Returns the detected challenge type (or None), whether
    it was solved, and the resulting clearance cookie if one was issued,
    so the calling agent can inject it into a subsequent curl/tool_resolver
    request's Cookie header for further testing."""
    _enforce_budget("playwright-mcp")
    start = time.monotonic()
    from playwright.async_api import async_playwright

    result = {
        "url": url, "challenge_type": None, "solved": False,
        "clearance_cookie_name": None, "clearance_cookie_value": None,
        "error": None,
    }

    async with async_playwright() as p:
        browser = None
        try:
            browser = await p.chromium.launch(**launch_kwargs())
            context = await browser.new_context()
            page = await context.new_page()

            response = await page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
            headers = response.headers if response else {}
            html = await page.content()
            challenge = _detect_challenge_type(html, headers)
            result["challenge_type"] = challenge

            if challenge:
                # One bounded wait for the challenge to clear -- not a
                # retry loop. Poll for the clearance cookie instead of
                # page.wait_for_load_state("networkidle", ...): these
                # vendors' challenge pages poll/beacon continuously by
                # design (that's how they keep verifying the client), so
                # network-idle is structurally unlikely to ever fire here
                # and would burn the full timeout on every call regardless
                # of how fast the challenge actually cleared.
                cookie_name = _CHALLENGE_SIGNATURES[challenge]["clearance_cookie"]
                deadline = time.monotonic() + (timeout_ms / 1000)
                matched = None
                while time.monotonic() < deadline:
                    cookies = {c["name"]: c["value"] for c in await context.cookies()}
                    matched = next((n for n in cookies if n.lower().startswith(cookie_name.lower())), None)
                    if matched:
                        break
                    await page.wait_for_timeout(250)

                still_challenged = _body_still_shows_challenge(await page.content(), challenge)

                if matched and not still_challenged:
                    result["solved"] = True
                    result["clearance_cookie_name"] = matched
                    result["clearance_cookie_value"] = cookies[matched]
        except Exception as e:
            result["error"] = str(e)
        finally:
            if browser is not None:
                await browser.close()

    duration_ms = (time.monotonic() - start) * 1000
    _log_call("playwright-mcp", [url], returncode=None, duration_ms=duration_ms,
              block=result["challenge_type"])
    return result
