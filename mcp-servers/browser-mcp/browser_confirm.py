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

Prefers an existing system Chrome/Chromium install (via
../browser_launch.find_browser_executable, shared with playwright-mcp)
over Playwright's own bundled browser download -- lighter setup, most
machines already have one. Falls back to Playwright's default (its own
installed browser, if `playwright install chromium` was run) when no
system browser is found.

This is Tier-2 (target-touching, actually loads and executes a live
target's JS) -- callers MUST run scripts/check-scope.sh <host> first,
exactly like every other Tier-2 tool in this repo. Not enforced inside
this module itself (consistent with how other MCP servers work -- the
calling agent enforces scope, tool_resolver.run_tool()'s subprocess
callers enforce budget); budget IS enforced here directly since these
calls don't go through run_tool()'s subprocess chokepoint.

Uses Playwright's ASYNC API (async_playwright), not sync_playwright --
deliberately, and not optional. FastMCP dispatches tool handlers on the
already-running asyncio event loop (this server's own `app.run(...)`);
sync_playwright() tries to start/manage its own event loop internally and
raises "It looks like you are using Playwright Sync API inside the
asyncio loop. Please use the Async API instead." the moment it's actually
invoked through a live MCP tool call -- confirmed live 2026-08-28 (every
tool in this file, not just a new one, failed identically). This bug was
invisible to `tests/test_playwright_mcp.py`'s pure-logic unit tests
because they never actually invoke Playwright at all, only the
`_detect_challenge_type`/`_body_still_shows_challenge` helpers -- a real
end-to-end MCP tool call was the only thing that caught it.
"""

from __future__ import annotations

import base64
import json
import os
import sys
from urllib.parse import urljoin

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from browser_launch import DEFAULT_TIMEOUT_MS
from browser_launch import launch_kwargs as _launch_kwargs
from browser_launch import parse_cookie_header as _parse_cookie_header
from budget_guard import enforce as _enforce_budget


async def _new_page(browser, url: str, cookie_header: str | None,
                     bearer_token: str | None = None,
                     local_storage: dict[str, str] | None = None,
                     session_file: str | None = None):
    """Shared context/page setup for every function below -- an explicit
    BrowserContext (not the implicit one `browser.new_page()` creates) is
    required to seed cookies/headers at all, since Playwright's
    add_cookies()/set_extra_http_headers() are context-level, not
    page-level, APIs. Without this, every tool in this module could only
    ever drive a page as a logged-out visitor -- no way to exercise an
    authenticated SPA flow, a role-diff IDOR check (load the same page as
    two different sessions and compare), or anything behind a login.

    Four independent, combinable auth-seeding mechanisms, because real
    targets split across all of them:
    - session_file -- a path to a Playwright storage_state JSON file
      (cookies + localStorage/origins together). If it already exists,
      the context resumes from it instead of starting logged-out. Added
      2026-08-29: previously every browser-mcp call launched a fresh
      browser AND a fresh context, so a cookie set mid-flow (a magic-
      link click, a login form submit) was gone the instant that one
      call ended -- the next call started logged-out again, no way to
      carry a session across separate tool calls at all. Every function
      below saves the context's current storage_state back to this same
      path in its `finally` block (if session_file was given), so
      passing the SAME path across multiple calls makes them share one
      continuously-updated session -- log in once (e.g. via
      fill_and_submit with a session_file set), then every later call
      with that same session_file resumes already-authenticated. Use a
      different path per identity (e.g. one file per test account) for
      a role-diff check across full rendered pages, not just raw HTTP
      (idor-mcp's owner/other credentials cover the raw-HTTP case).
    - cookie_header ("name=value; name2=value2") -- traditional
      cookie-based sessions, applied on top of whatever session_file
      loaded (or standalone if no session_file is used at all). Same
      shape playwright-mcp's solve_js_challenge already outputs a
      clearance cookie in.
    - bearer_token -- sent as `Authorization: Bearer <token>` on every
      request via set_extra_http_headers(). Covers APIs/SPAs that use a
      bearer token instead of (or alongside) cookies. NOT captured by
      session_file (Playwright's storage_state only covers cookies/
      localStorage, not custom extra headers) -- pass it again on every
      call that needs it, same as before session_file existed.
    - local_storage -- a modern SPA storing its own session/JWT in
      localStorage (not a cookie, not a header the browser sends
      automatically) needs the token to already be *in* localStorage
      before the app's own JS runs and reads it. add_init_script() runs
      before any page script on every new document in this context, so
      the values are there the instant the app boots, on the correct
      origin, without needing a real login flow first. This was the
      gap cookie_header alone didn't close: a target authenticating via
      "JWT in localStorage read by the SPA's own fetch() calls" (common
      in modern Vue/React apps) has no cookie and no server-set header
      to seed -- localStorage is the only place the credential lives.
      IS captured by session_file (Playwright includes localStorage in
      storage_state), so this only needs to be passed once, on the
      first call that establishes the session."""
    context_kwargs = {}
    if session_file and os.path.isfile(session_file):
        context_kwargs["storage_state"] = session_file
    context = await browser.new_context(**context_kwargs)
    if cookie_header:
        await context.add_cookies(_parse_cookie_header(cookie_header, url))
    if bearer_token:
        await context.set_extra_http_headers({"Authorization": f"Bearer {bearer_token}"})
    if local_storage:
        script = "".join(
            f"localStorage.setItem({json.dumps(k)}, {json.dumps(v)});"
            for k, v in local_storage.items()
        )
        await context.add_init_script(script)
    return context, await context.new_page()


async def _save_session(context, session_file: str | None) -> None:
    """Persist the context's current cookies/localStorage back to
    session_file, if one was given -- called from every function's
    `finally` block, right before the browser (and therefore the
    context) closes, so the NEXT call with the same session_file resumes
    from whatever state this call left the session in (a fresh login, a
    session that rotated, a logout). Silently does nothing if
    session_file wasn't provided -- session persistence is opt-in per
    call, not a hidden default."""
    if session_file:
        os.makedirs(os.path.dirname(os.path.abspath(session_file)) or ".", exist_ok=True)
        await context.storage_state(path=session_file)


async def check_js_execution(url: str, marker: str, wait_ms: int = 2000,
                              timeout_ms: int = DEFAULT_TIMEOUT_MS,
                              cookie_header: str | None = None,
                              bearer_token: str | None = None,
                              local_storage: dict[str, str] | None = None,
                              session_file: str | None = None) -> dict:
    """Navigate to url in a real headless browser and check whether marker
    actually executed as JS, vs. merely appearing in the raw response body.
    Checks three signals: (1) any JS dialog (alert/confirm/prompt) whose
    text contains marker -- the classic XSS PoC signal, (2) document.title
    containing marker, (3) marker present in the raw HTML source at all
    (reflection, not proof of execution on its own). A payload that is
    present in raw_html_contains_marker but NOT in dialog_fired/
    title_contains_marker is exactly the "reflected but not confirmed"
    case exploit-agent's rationalizations-to-reject table warns about.
    cookie_header/bearer_token/local_storage/session_file (see _new_page()) seed an authenticated
    session before navigating, for confirming XSS in a logged-in-only
    view."""
    _enforce_budget("browser-mcp")
    from playwright.async_api import async_playwright

    result = {
        "url": url, "marker": marker,
        "dialog_fired": False, "dialog_text": None,
        "title_contains_marker": False, "raw_html_contains_marker": False,
        "console_errors": [], "error": None,
    }

    async with async_playwright() as p:
        browser = await p.chromium.launch(**_launch_kwargs())
        try:
            context, page = await _new_page(browser, url, cookie_header, bearer_token, local_storage, session_file)

            async def _on_dialog(dialog):
                if marker in (dialog.message or ""):
                    result["dialog_fired"] = True
                    result["dialog_text"] = dialog.message
                await dialog.dismiss()

            page.on("dialog", _on_dialog)
            page.on("console", lambda msg: result["console_errors"].append(msg.text)
                     if msg.type == "error" else None)

            try:
                response = await page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
                await page.wait_for_timeout(wait_ms)
                result["raw_html_contains_marker"] = marker in (await response.text() if response else "")
            except Exception:
                # response.text() can fail for non-text content types; fall
                # back to the rendered content, which still tells us about
                # execution even if we can't diff against the raw body
                pass

            result["title_contains_marker"] = marker in await page.title()
        except Exception as e:
            result["error"] = str(e)
        finally:
            await _save_session(context, session_file)
            await browser.close()

    return result


async def render_dom(url: str, wait_selector: str | None = None,
                      timeout_ms: int = DEFAULT_TIMEOUT_MS,
                      cookie_header: str | None = None,
                      bearer_token: str | None = None,
                      local_storage: dict[str, str] | None = None,
                      session_file: str | None = None) -> dict:
    """Return the fully rendered (post-JS) HTML for comparison against the
    raw HTTP response -- surfaces client-side-injected content, DOM
    clobbering, and anything a raw curl request would never show.
    cookie_header/bearer_token/local_storage/session_file (see _new_page()) seed an authenticated
    session before navigating -- also what makes a role-diff IDOR check
    possible: render_dom the same url once per role's cookie_header and
    compare the two results yourself."""
    _enforce_budget("browser-mcp")
    from playwright.async_api import async_playwright

    result = {"url": url, "html": None, "title": None, "error": None}
    async with async_playwright() as p:
        browser = await p.chromium.launch(**_launch_kwargs())
        try:
            context, page = await _new_page(browser, url, cookie_header, bearer_token, local_storage, session_file)
            await page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
            if wait_selector:
                await page.wait_for_selector(wait_selector, timeout=timeout_ms)
            result["html"] = await page.content()
            result["title"] = await page.title()
        except Exception as e:
            result["error"] = str(e)
        finally:
            await _save_session(context, session_file)
            await browser.close()
    return result


def _normalize_links(base_url: str, raw_links: list[dict], max_links: int) -> list[dict]:
    """Resolve relative hrefs against base_url, drop non-navigable ones
    (javascript:/mailto:/tel:/bare-fragment anchors -- not real listing
    entries), dedupe by (text, href), and cap the count so a page with
    thousands of anchors doesn't blow out the tool's return size."""
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []
    for link in raw_links:
        href = (link.get("href") or "").strip()
        text = (link.get("text") or "").strip()
        if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
            continue
        absolute = urljoin(base_url, href)
        key = (text, absolute)
        if key in seen:
            continue
        seen.add(key)
        out.append({"text": text, "href": absolute})
        if len(out) >= max_links:
            break
    return out


async def extract_page_content(url: str, wait_selector: str | None = None,
                                max_links: int = 200,
                                timeout_ms: int = DEFAULT_TIMEOUT_MS,
                                cookie_header: str | None = None,
                                bearer_token: str | None = None,
                                local_storage: dict[str, str] | None = None,
                                session_file: str | None = None) -> dict:
    """Navigate to url in a real headless browser and return its rendered,
    human-readable text plus every link on the page -- the general-purpose
    "browse this page and tell me what's actually on it" primitive that
    render_dom's raw HTML doesn't give you directly (raw HTML still needs a
    parser to get to plain text/listings, and render_dom is meant for
    diffing against the unrendered response, not reading content). Distinct
    from katana-mcp's crawl(), which discovers URLs/params across a site but
    never returns a single page's actual text -- this is for reading one
    already-known page's content, including anything only JS rendering
    produces (a static fetch/curl would miss it). Requires scope-gate
    clearance first (Tier-2), same as every other tool in this module.
    cookie_header/bearer_token/local_storage/session_file (see _new_page()) seed an authenticated
    session before navigating, for reading a logged-in-only page/listing."""
    _enforce_budget("browser-mcp")
    from playwright.async_api import async_playwright

    result = {"url": url, "title": None, "text": None, "links": [], "error": None}
    async with async_playwright() as p:
        browser = await p.chromium.launch(**_launch_kwargs())
        try:
            context, page = await _new_page(browser, url, cookie_header, bearer_token, local_storage, session_file)
            await page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
            if wait_selector:
                await page.wait_for_selector(wait_selector, timeout=timeout_ms)
            result["title"] = await page.title()
            result["text"] = await page.inner_text("body")
            raw_links = await page.eval_on_selector_all(
                "a[href]",
                "els => els.map(e => ({text: e.innerText.trim(), href: e.getAttribute('href')}))",
            )
            result["links"] = _normalize_links(url, raw_links, max_links)
        except Exception as e:
            result["error"] = str(e)
        finally:
            await _save_session(context, session_file)
            await browser.close()
    return result


async def fill_and_submit(url: str, field_values: dict[str, str], submit_selector: str,
                           then_check_marker: str | None = None,
                           timeout_ms: int = DEFAULT_TIMEOUT_MS,
                           cookie_header: str | None = None,
                           bearer_token: str | None = None,
                           local_storage: dict[str, str] | None = None,
                           session_file: str | None = None) -> dict:
    """Fill form fields (selector -> value) and click submit_selector --
    for stored-XSS/business-logic confirmation flows that need a real
    submission, not just a GET request. If then_check_marker is given,
    checks the resulting page the same way check_js_execution does
    (dialog fired / title contains marker) after the submit completes.
    cookie_header/bearer_token/local_storage/session_file (see _new_page()) seed an authenticated
    session before navigating, for a form that only appears once logged in."""
    _enforce_budget("browser-mcp")
    from playwright.async_api import async_playwright

    result = {"url": url, "submitted": False, "dialog_fired": False,
              "dialog_text": None, "title_after_submit": None, "error": None}

    async with async_playwright() as p:
        browser = await p.chromium.launch(**_launch_kwargs())
        try:
            context, page = await _new_page(browser, url, cookie_header, bearer_token, local_storage, session_file)

            async def _on_dialog(dialog):
                if then_check_marker and then_check_marker in (dialog.message or ""):
                    result["dialog_fired"] = True
                    result["dialog_text"] = dialog.message
                await dialog.dismiss()

            page.on("dialog", _on_dialog)
            await page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")

            for selector, value in field_values.items():
                await page.fill(selector, value, timeout=timeout_ms)

            await page.click(submit_selector, timeout=timeout_ms)
            await page.wait_for_load_state("domcontentloaded", timeout=timeout_ms)
            result["submitted"] = True
            result["title_after_submit"] = await page.title()
        except Exception as e:
            result["error"] = str(e)
        finally:
            await _save_session(context, session_file)
            await browser.close()
    return result


async def screenshot_base64(url: str, wait_ms: int = 1000,
                             timeout_ms: int = DEFAULT_TIMEOUT_MS,
                             cookie_header: str | None = None,
                             bearer_token: str | None = None,
                             local_storage: dict[str, str] | None = None,
                             session_file: str | None = None) -> dict:
    """Full-page screenshot as base64 PNG -- visual PoC evidence for the
    report's "screenshot + PoC" requirement.
    cookie_header/bearer_token/local_storage/session_file (see _new_page()) seed an
    authenticated session before navigating, for
    a screenshot of a logged-in-only view."""
    _enforce_budget("browser-mcp")
    from playwright.async_api import async_playwright

    result = {"url": url, "screenshot_base64": None, "error": None}
    async with async_playwright() as p:
        browser = await p.chromium.launch(**_launch_kwargs())
        try:
            context, page = await _new_page(browser, url, cookie_header, bearer_token, local_storage, session_file)
            await page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
            await page.wait_for_timeout(wait_ms)
            png_bytes = await page.screenshot(full_page=True)
            result["screenshot_base64"] = base64.b64encode(png_bytes).decode()
        except Exception as e:
            result["error"] = str(e)
        finally:
            await _save_session(context, session_file)
            await browser.close()
    return result
