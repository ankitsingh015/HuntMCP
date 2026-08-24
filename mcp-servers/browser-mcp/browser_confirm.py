"""Real-browser JS/DOM confirmation for exploit-agent -- closes a gap that
existed as a documented rationalization-to-reject with no actual tool
behind it: exploit-agent.md's Phase 1.5 says "the payload appears in the
raw HTTP response" is NOT confirmed XSS -- it has to execute in an actual
browser context. Until now there was no way to check that other than
manual PoC. This drives a real Chromium (via Playwright) to check.

Idea taken (not code -- this is a from-scratch Python/Playwright
implementation, not a port) from bugbase/pentest-copilot's
backend/src/tools/handlers/magnitude-browser.ts, which wraps the
magnitude-core TS library as a single natural-language-"goal"-driven tool
with its own nested LLM loop. Deliberately NOT that shape here: HuntMCP's
calling agent (exploit-agent, already an LLM) is the reasoning layer:
these tools are low-level, deterministic primitives it drives itself
(navigate, check-marker, screenshot) -- consistent with every other
MCP server in this repo (subprocess/API wrappers, no nested agent loop),
not a second LLM hidden inside the tool.

Prefers an existing system Chrome/Chromium install (checked via
_find_browser_executable) over Playwright's own bundled browser download
-- lighter setup, most machines already have one. Falls back to
Playwright's default (its own installed browser, if `playwright install
chromium` was run) when no system browser is found.

This is Tier-2 (target-touching, actually loads and executes a live
target's JS) -- callers MUST run scripts/check-scope.sh <host> first,
exactly like every other Tier-2 tool in this repo. Not enforced inside
this module itself (consistent with how other MCP servers work -- the
calling agent enforces scope, tool_resolver.run_tool()'s subprocess
callers enforce budget); budget IS enforced here directly since these
calls don't go through run_tool()'s subprocess chokepoint.
"""

from __future__ import annotations

import base64
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from budget_guard import enforce as _enforce_budget

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


def _find_browser_executable() -> str | None:
    for path in SYSTEM_BROWSER_CANDIDATES:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def _launch_kwargs() -> dict:
    executable = _find_browser_executable()
    kwargs: dict = {"headless": True, "args": ["--no-sandbox", "--disable-dev-shm-usage"]}
    if executable:
        kwargs["executable_path"] = executable
    return kwargs


def check_js_execution(url: str, marker: str, wait_ms: int = 2000,
                        timeout_ms: int = DEFAULT_TIMEOUT_MS) -> dict:
    """Navigate to url in a real headless browser and check whether marker
    actually executed as JS, vs. merely appearing in the raw response body.
    Checks three signals: (1) any JS dialog (alert/confirm/prompt) whose
    text contains marker -- the classic XSS PoC signal, (2) document.title
    containing marker, (3) marker present in the raw HTML source at all
    (reflection, not proof of execution on its own). A payload that is
    present in raw_html_contains_marker but NOT in dialog_fired/
    title_contains_marker is exactly the "reflected but not confirmed"
    case exploit-agent's rationalizations-to-reject table warns about."""
    _enforce_budget("browser-mcp")
    from playwright.sync_api import sync_playwright

    result = {
        "url": url, "marker": marker,
        "dialog_fired": False, "dialog_text": None,
        "title_contains_marker": False, "raw_html_contains_marker": False,
        "console_errors": [], "error": None,
    }

    with sync_playwright() as p:
        browser = p.chromium.launch(**_launch_kwargs())
        try:
            page = browser.new_page()

            def _on_dialog(dialog):
                if marker in (dialog.message or ""):
                    result["dialog_fired"] = True
                    result["dialog_text"] = dialog.message
                dialog.dismiss()

            page.on("dialog", _on_dialog)
            page.on("console", lambda msg: result["console_errors"].append(msg.text)
                     if msg.type == "error" else None)

            try:
                response = page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
                page.wait_for_timeout(wait_ms)
                result["raw_html_contains_marker"] = marker in (response.text() if response else "")
            except Exception:
                # response.text() can fail for non-text content types; fall
                # back to the rendered content, which still tells us about
                # execution even if we can't diff against the raw body
                pass

            result["title_contains_marker"] = marker in page.title()
        except Exception as e:
            result["error"] = str(e)
        finally:
            browser.close()

    return result


def render_dom(url: str, wait_selector: str | None = None,
                timeout_ms: int = DEFAULT_TIMEOUT_MS) -> dict:
    """Return the fully rendered (post-JS) HTML for comparison against the
    raw HTTP response -- surfaces client-side-injected content, DOM
    clobbering, and anything a raw curl request would never show."""
    _enforce_budget("browser-mcp")
    from playwright.sync_api import sync_playwright

    result = {"url": url, "html": None, "title": None, "error": None}
    with sync_playwright() as p:
        browser = p.chromium.launch(**_launch_kwargs())
        try:
            page = browser.new_page()
            page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
            if wait_selector:
                page.wait_for_selector(wait_selector, timeout=timeout_ms)
            result["html"] = page.content()
            result["title"] = page.title()
        except Exception as e:
            result["error"] = str(e)
        finally:
            browser.close()
    return result


def fill_and_submit(url: str, field_values: dict[str, str], submit_selector: str,
                     then_check_marker: str | None = None,
                     timeout_ms: int = DEFAULT_TIMEOUT_MS) -> dict:
    """Fill form fields (selector -> value) and click submit_selector --
    for stored-XSS/business-logic confirmation flows that need a real
    submission, not just a GET request. If then_check_marker is given,
    checks the resulting page the same way check_js_execution does
    (dialog fired / title contains marker) after the submit completes."""
    _enforce_budget("browser-mcp")
    from playwright.sync_api import sync_playwright

    result = {"url": url, "submitted": False, "dialog_fired": False,
              "dialog_text": None, "title_after_submit": None, "error": None}

    with sync_playwright() as p:
        browser = p.chromium.launch(**_launch_kwargs())
        try:
            page = browser.new_page()

            def _on_dialog(dialog):
                if then_check_marker and then_check_marker in (dialog.message or ""):
                    result["dialog_fired"] = True
                    result["dialog_text"] = dialog.message
                dialog.dismiss()

            page.on("dialog", _on_dialog)
            page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")

            for selector, value in field_values.items():
                page.fill(selector, value, timeout=timeout_ms)

            page.click(submit_selector, timeout=timeout_ms)
            page.wait_for_load_state("domcontentloaded", timeout=timeout_ms)
            result["submitted"] = True
            result["title_after_submit"] = page.title()
        except Exception as e:
            result["error"] = str(e)
        finally:
            browser.close()
    return result


def screenshot_base64(url: str, wait_ms: int = 1000,
                       timeout_ms: int = DEFAULT_TIMEOUT_MS) -> dict:
    """Full-page screenshot as base64 PNG -- visual PoC evidence for the
    report's "screenshot + PoC" requirement."""
    _enforce_budget("browser-mcp")
    from playwright.sync_api import sync_playwright

    result = {"url": url, "screenshot_base64": None, "error": None}
    with sync_playwright() as p:
        browser = p.chromium.launch(**_launch_kwargs())
        try:
            page = browser.new_page()
            page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
            page.wait_for_timeout(wait_ms)
            png_bytes = page.screenshot(full_page=True)
            result["screenshot_base64"] = base64.b64encode(png_bytes).decode()
        except Exception as e:
            result["error"] = str(e)
        finally:
            browser.close()
    return result
