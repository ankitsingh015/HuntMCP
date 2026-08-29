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


def find_browser_executable() -> str | None:
    for path in SYSTEM_BROWSER_CANDIDATES:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def launch_kwargs() -> dict:
    executable = find_browser_executable()
    kwargs: dict = {"headless": True, "args": ["--no-sandbox", "--disable-dev-shm-usage"]}
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
