"""Shared Playwright browser-launch helpers, extracted from
browser-mcp/browser_confirm.py so playwright-mcp can reuse the exact same
system-Chrome-detection and launch-args logic without a second, drifting
copy. Pure extraction -- no behavior change for browser-mcp.

Prefers an existing system Chrome/Chromium/Edge install over Playwright's
own bundled browser download -- lighter setup, most machines already have
one. Falls back to Playwright's default (its own installed browser, if
`playwright install chromium` was run) when no system browser is found.
"""

from __future__ import annotations

import os
from urllib.parse import urlsplit

SYSTEM_BROWSER_CANDIDATES = [
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/bin/microsoft-edge",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
]

DEFAULT_TIMEOUT_MS = 15_000

# Cheap, well-known Chromium launch flags that reduce the odds of tripping
# basic bot-detection during an ordinary confirmation call (check_js_execution/
# render_dom/extract_page_content/solve_js_challenge) -- NOT a claim of full
# fingerprint spoofing (no canvas/WebGL/font masking here, none of that is
# needed for what this module does). --disable-blink-features=
# AutomationControlled is the one that actually matters: without it, Chromium
# sets navigator.webdriver=true and a handful of other automation-only
# properties that even simple bot-detection JS checks for -- a page that
# would otherwise render normally can instead serve a challenge/block page
# purely because the browser announced itself as automated, which would look
# identical to a real WAF block to everything downstream (classify_block(),
# a human reading the result) without ever being one. The other two are
# low-risk companions with the same intent: --disable-features=IsolateOrigins,
# site-per-process avoids a site-isolation quirk some bot-detection scripts
# key off, --no-first-run suppresses first-run UI noise that has no reason to
# ever show up in a headless run anyway. playwright-mcp's solve_js_challenge
# already handles the case where a target's challenge is unavoidable even
# with these flags -- this is about not walking into one that a real visitor
# wouldn't have hit at all.
STEALTH_ARGS = [
    "--disable-blink-features=AutomationControlled",
    "--disable-features=IsolateOrigins,site-per-process",
    "--no-first-run",
]


def find_browser_executable() -> str | None:
    for path in SYSTEM_BROWSER_CANDIDATES:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def launch_kwargs(headless: bool = True) -> dict:
    # headless=False is for browser_confirm.py's start_manual_intervention()
    # only -- a real, visible window a human can actually see and click in,
    # for whatever blocks scripted automation entirely (a CAPTCHA, an
    # unusual login flow). Every other caller in this repo wants headless
    # (no display needed, and the default), so this stays True unless a
    # caller explicitly asks otherwise.
    executable = find_browser_executable()
    kwargs: dict = {
        "headless": headless,
        "args": ["--no-sandbox", "--disable-dev-shm-usage", *STEALTH_ARGS],
    }
    if executable:
        kwargs["executable_path"] = executable
    return kwargs


def parse_cookie_header(cookie_header: str, url: str) -> list[dict]:
    """Parse a raw HTTP `Cookie:` header string (e.g. "session=abc;
    csrftoken=xyz", the exact shape playwright-mcp's solve_js_challenge
    already tells callers to inject via `-H "Cookie: ..."`) into
    Playwright's `context.add_cookies()` list-of-dicts format, scoped to
    url's own host -- this is what lets browser-mcp's tools drive a page
    as an already-authenticated user instead of only ever seeing the
    logged-out view. Deliberately reuses the same "Cookie: name=value;
    name2=value2" convention already established by solve_js_challenge's
    own output, rather than inventing a second cookie format -- a
    clearance cookie from a solved WAF challenge and a session cookie from
    a real login are both just "one string to paste into the next call,"
    and should look the same to whoever's copying it between tool calls.
    Silently skips a malformed segment (no `=`) rather than raising --
    a stray `;` or trailing whitespace in a hand-typed header shouldn't
    abort the whole navigation."""
    host = urlsplit(url).hostname or ""
    cookies = []
    for segment in cookie_header.split(";"):
        segment = segment.strip()
        if not segment or "=" not in segment:
            continue
        name, value = segment.split("=", 1)
        name = name.strip()
        value = value.strip()
        if not name:
            continue
        cookies.append({"name": name, "value": value, "domain": host, "path": "/"})
    return cookies
