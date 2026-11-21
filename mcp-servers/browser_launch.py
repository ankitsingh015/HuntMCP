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


# Mirror mode only (launch_kwargs(proxy=...)): keep Chromium's own background
# networking off the user's proxy.
MIRROR_QUIET_ARGS = ("--disable-background-networking", "--disable-component-update",
                     "--disable-domain-reliability")


def find_browser_executable() -> str | None:
    for path in SYSTEM_BROWSER_CANDIDATES:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def launch_kwargs(headless: bool = True, proxy: str | None = None) -> dict:
    # headless=False is for browser_confirm.py's start_manual_intervention()
    # only -- a real, visible window a human can actually see and click in,
    # for whatever blocks scripted automation entirely (a CAPTCHA, an
    # unusual login flow). Every other caller in this repo wants headless
    # (no display needed, and the default), so this stays True unless a
    # caller explicitly asks otherwise.
    #
    # proxy is for the #164 UI-walk's optional Burp mirror only, and the
    # caller has already checked it is a loopback URL. Chromium skips the
    # proxy for loopback targets by default; --proxy-bypass-list=<-loopback>
    # turns that off so a locally served target shows up in Burp too, and
    # MIRROR_QUIET_ARGS keep Chromium's own background traffic out of it. With
    # proxy=None the result is exactly what every other browser tool gets.
    executable = find_browser_executable()
    kwargs: dict = {
        "headless": headless,
        "args": ["--no-sandbox", "--disable-dev-shm-usage", *STEALTH_ARGS],
    }
    if executable:
        kwargs["executable_path"] = executable
    if proxy:
        kwargs["proxy"] = {"server": proxy}
        # Chromium's own background traffic (component updates, safe-browsing /
        # variations fetches to Google) must not go through the human's proxy:
        # only the target's traffic belongs in Burp.
        kwargs["args"].extend(MIRROR_QUIET_ARGS)
        kwargs["args"].append("--proxy-bypass-list=<-loopback>")
    return kwargs


# OS-default browser profile roots (#128). A capture window must NEVER open
# the operator's personal/company Chrome profile; it uses a dedicated
# per-identity user-data-dir instead. assert_dedicated_profile_dir() refuses
# any path equal to or nested within one of these.
DEFAULT_PROFILE_ROOTS = [
    "~/.config/google-chrome",
    "~/.config/chromium",
    "~/.config/microsoft-edge",
    "~/Library/Application Support/Google/Chrome",
    "~/Library/Application Support/Chromium",
    "~/AppData/Local/Google/Chrome/User Data",
    "~/AppData/Local/Chromium/User Data",
]


def assert_dedicated_profile_dir(profile_dir: str) -> str:
    """Return the absolute real path of profile_dir, or raise ValueError if it
    is equal to or nested within any OS-default browser profile root (#128).

    This is the hard, code-level guarantee that capture never drives the
    operator's personal/company browser profile -- it always uses a dedicated
    per-identity user-data-dir. Convention is not enough here: a mistyped or
    agent-chosen default-profile path would silently expose real accounts.
    """
    resolved = os.path.realpath(os.path.expanduser(profile_dir))
    for root in DEFAULT_PROFILE_ROOTS:
        r = os.path.realpath(os.path.expanduser(root))
        if resolved == r or resolved.startswith(r + os.sep):
            raise ValueError(
                f"refusing to use the OS-default browser profile dir "
                f"({profile_dir!r}) -- capture must use a dedicated per-identity "
                f"profile, never your personal/company browser profile"
            )
    return resolved


def resolve_executable_or_raise() -> str:
    """Return a Chrome/Chromium executable path for a capture launch, or raise
    RuntimeError with an actionable message (#137).

    Order: $HUNTMCP_CHROME_PATH (if an existing executable) > a detected system
    browser > raise. We require an explicit, resolvable binary for the headed
    persistent-context capture flow rather than letting Playwright resolve its
    own bundled revision, because a package/browser revision drift makes that
    fail with a cryptic mid-launch error instead of a clear instruction.
    """
    override = os.getenv("HUNTMCP_CHROME_PATH")
    if override and os.path.isfile(override) and os.access(override, os.X_OK):
        return override
    found = find_browser_executable()
    if found:
        return found
    raise RuntimeError(
        "No Chrome/Chromium executable found for capture. Install a system "
        "Chrome/Chromium, or run `playwright install chromium`, or set "
        "HUNTMCP_CHROME_PATH to the browser binary."
    )


def persistent_context_kwargs(user_data_dir: str, headless: bool = False) -> dict:
    """kwargs for `chromium.launch_persistent_context(**kwargs)` for a
    dedicated per-identity capture profile (#128). Reuses STEALTH_ARGS and the
    system-browser executable_path when one is found. headless defaults to
    False -- a capture window must be visible for the human to log in."""
    kwargs: dict = {
        "user_data_dir": user_data_dir,
        "headless": headless,
        "args": ["--no-sandbox", "--disable-dev-shm-usage", *STEALTH_ARGS],
    }
    executable = find_browser_executable()
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
