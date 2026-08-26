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
