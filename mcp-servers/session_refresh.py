"""Session keep-alive: silently renew a captured identity's session.

Design: docs/superpowers/specs/2026-11-20-session-keepalive-design.md

Layers, in order (stop at the first that yields a VERIFIED logged-in session):
  1. app renews itself -- reopen the app headless in the identity's dedicated
     persistent profile (which holds the IdP's long-lived SSO cookie); the app's
     own code does its silent renew / refresh call; re-extract the session.
  2. tool refresh_token grant -- for a recognised SPA token cache holding a
     refresh token, POST grant_type=refresh_token to the issuer's token endpoint.
  3. human -- report needs_human_login; the human re-captures via start_capture.

SECURITY invariants:
- Never types, clicks, or submits a form. A document (form) POST aborts the
  layer; a login form, password field or CAPTCHA means "renewal failed".
- No secret is returned to the agent: summaries carry allow-listed keys only.
- Hosts: in scope (scope_guard), or learned from the human's own login
  (renewal_hosts), or a built-in well-known IdP -- usable ONLY by this module,
  scope_guard.is_in_scope is untouched. engagement.out_of_scope always wins.
- session_file keeps only in-scope cookies/origins (IdP cookies stay in the
  dedicated profile only).
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import tempfile
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import engagement_paths
import file_lock
import scope_guard
import session_capture
from audit_log import log_call as _log_call
from budget_guard import BudgetExceeded, enforce

SESSION_STORAGE_KEY = "huntmcp_session_storage"  # == browser_confirm.SESSION_STORAGE_KEY
_RESTORED_FLAG = "__huntmcp_restored"

BUILTIN_IDP_PATTERNS: tuple[str, ...] = (
    "*.auth0.com", "*.okta.com", "*.oktapreview.com", "login.microsoftonline.com",
    "login.live.com", "*.b2clogin.com", "accounts.google.com", "*.amazoncognito.com",
    "*.onelogin.com", "*.pingidentity.com", "*.pingone.com",
)

# A renewal-shaped in-scope call (POST only): token/refresh/renew/silent endpoints.
_TOKEN_PATH_RE = re.compile(r"/(oauth2?/|connect/)?(token|refresh|renew|silent[-_]?renew|silent)\b",
                            re.IGNORECASE)
# Same as ui_walk_logic._LOGIN_PATH_RE (kept local: this module lives outside browser-mcp/).
_LOGIN_PATH_RE = re.compile(r"/(login|signin|sign-in|auth)\b", re.IGNORECASE)
_CAPTCHA_SELECTOR = (".g-recaptcha, .h-captcha, .cf-turnstile, iframe[src*='recaptcha'], "
                     "iframe[src*='hcaptcha'], iframe[src*='turnstile']")


# ------------------------------------------------------------------ policy

def _host(url_or_host: str) -> str:
    return (scope_guard._host_of(url_or_host) or "").lower()


def _ip_non_public(addr: str) -> bool:
    import ipaddress

    try:
        ip = ipaddress.ip_address(addr.split("%", 1)[0])
    except ValueError:
        return True  # unparseable -> treat as unsafe
    return not ip.is_global


def _is_ip_literal(host: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _resolves_non_public(host: str) -> bool:
    """True if host is (or resolves to any) loopback/private/link-local/
    reserved address, or does not resolve at all."""
    import socket

    host = host.strip("[]")
    if _is_ip_literal(host):
        return _ip_non_public(host)
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return True
    return not infos or any(_ip_non_public(i[4][0]) for i in infos)


@dataclass
class RenewalPolicy:
    """The ONLY hosts a silent renewal may touch. Deliberately does NOT use
    scope_guard.is_in_scope: its safe-test-host shortcut treats loopback,
    RFC1918, link-local (cloud metadata) and some real TLDs as always in
    scope, which must never become reachable from a target-controlled page
    (documents are fetched via Playwright, outside Chromium's Local Network
    Access check). Rules:
    - out_of_scope always wins;
    - in scope = an explicit engagement.in_scope pattern match;
    - learned (from the human's own capture) or builtin IdP = renewal host;
    - a host that is / resolves to a non-public address is allowed only when
      engagement.in_scope names it explicitly (a deliberate internal or lab
      target), never as a learned/builtin host."""
    engagement: scope_guard.Engagement
    learned: list[str] = field(default_factory=list)
    builtin: tuple[str, ...] = BUILTIN_IDP_PATTERNS
    resolver: object = None  # host -> non-public?; default _resolves_non_public (tests inject)

    def _excluded(self, host: str) -> bool:
        exact_in = host in self.engagement.in_scope
        for p in self.engagement.out_of_scope:
            if scope_guard._matches(host, p) and not (exact_in and "*" in p):
                return True
        return False

    def _explicit_in_scope(self, host: str) -> bool:
        return any(scope_guard._matches(host, p) for p in self.engagement.in_scope)

    def _non_public(self, host: str) -> bool:
        return (self.resolver or _resolves_non_public)(host)

    def in_scope(self, url_or_host: str) -> bool:
        host = _host(url_or_host)
        return bool(host) and not self._excluded(host) and self._explicit_in_scope(host)

    def is_renewal_host(self, url_or_host: str) -> bool:
        host = _host(url_or_host)
        if not host or self._excluded(host) or _is_ip_literal(host):
            return False
        named = host in {h.lower() for h in self.learned} or any(
            scope_guard._matches(host, p) for p in self.builtin)
        return named and not self._non_public(host)

    def is_builtin(self, url_or_host: str) -> bool:
        host = _host(url_or_host)
        return bool(host) and not self._excluded(host) and not _is_ip_literal(host) and any(
            scope_guard._matches(host, p) for p in self.builtin) and not self._non_public(host)

    def allowed(self, url_or_host: str) -> bool:
        return self.in_scope(url_or_host) or self.is_renewal_host(url_or_host)


def route_decision(method: str, url: str, resource_type: str, is_main_frame: bool,
                   policy: RenewalPolicy) -> tuple[str, str | None]:
    method = method.upper()
    if resource_type == "document":
        if not policy.allowed(url):
            return "abort", f"blocked_host:{_host(url)}"
        if method != "GET":
            return "abort", "form_post"
        return "continue", None
    if method in ("GET", "HEAD", "OPTIONS"):
        return "continue", None
    if method == "POST":
        if policy.is_renewal_host(url):
            return "continue", None
        if policy.in_scope(url) and _TOKEN_PATH_RE.search(urlsplit(url).path):
            return "continue", None
    return "abort", "mutating_call"


# ------------------------------------------------------------------ files

def _load_state(path: str) -> dict:
    try:
        with open(path) as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_private_json(path: str, data: dict) -> None:
    """Atomic 0600 write (same contract as browser_confirm._write_private_json)."""
    d = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _filter_state(storage: dict, policy: RenewalPolicy) -> dict:
    """Only explicitly in-scope cookies/origins, with the capture's cookie
    attributes (IdP cookies stay in the dedicated profile only)."""
    cookies = [{k: c.get(k) for k in session_capture._COOKIE_KEYS} for c in storage.get("cookies") or []
               if policy.in_scope(c.get("domain", "").lstrip("."))]
    origins = [o for o in storage.get("origins") or [] if policy.in_scope(o.get("origin", ""))]
    return {"cookies": cookies, "origins": origins}


def _restore_script(state: dict, policy: RenewalPolicy) -> str:
    """Init script putting the session_file's in-scope localStorage +
    sessionStorage back -- ONCE per origin per tab (flag in sessionStorage), so
    a later same-origin navigation never clobbers a token the app just renewed."""
    per_origin: dict[str, dict] = {}
    for o in state.get("origins") or []:
        origin = o.get("origin", "")
        if policy.in_scope(origin):
            per_origin.setdefault(origin, {"local": {}, "session": {}})["local"].update(
                {i["name"]: i["value"] for i in o.get("localStorage") or []
                 if isinstance(i, dict) and "name" in i and "value" in i})
    for origin, kv in (state.get(SESSION_STORAGE_KEY) or {}).items():
        if policy.in_scope(origin) and isinstance(kv, dict):
            per_origin.setdefault(origin, {"local": {}, "session": {}})["session"].update(
                {k: v for k, v in kv.items() if k != _RESTORED_FLAG})
    return (
        "(() => { const D = " + json.dumps(per_origin) + "; const o = D[location.origin];"
        " if (!o) return; try { if (sessionStorage.getItem(" + json.dumps(_RESTORED_FLAG) + ")) return;"
        " sessionStorage.setItem(" + json.dumps(_RESTORED_FLAG) + ", '1');"
        " for (const [k, v] of Object.entries(o.local)) localStorage.setItem(k, v);"
        " for (const [k, v] of Object.entries(o.session)) sessionStorage.setItem(k, v);"
        " } catch (e) {} })();"
    )


# ------------------------------------------------------------------ layer 1

@dataclass
class LayerResult:
    ok: bool
    reason: str | None = None
    state: dict | None = None
    authorization: str | None = None
    sso_expiry: float | None = None


# Empty in production. Loopback-only tests append
# "--disable-features=LocalNetworkAccessChecks": a route-fulfilled document has
# no address space, so Chromium treats a 127.0.0.1 page as public and blocks its
# fetch to a loopback IdP. Real targets are public; keeping the check ON in
# production stops a target page from reaching the operator's localhost.
_EXTRA_LAUNCH_ARGS: tuple[str, ...] = ()


async def _launch_headless(profile_dir: str):
    """(playwright, persistent context) for the identity's dedicated profile,
    headless. Isolated for test injection."""
    from browser_launch import persistent_context_kwargs
    from playwright.async_api import async_playwright

    kwargs = persistent_context_kwargs(profile_dir, headless=True)
    kwargs["args"] = [*kwargs["args"], *_EXTRA_LAUNCH_ARGS]
    p = await async_playwright().start()
    try:
        context = await p.chromium.launch_persistent_context(**kwargs)
    except BaseException:
        await p.stop()
        raise
    return p, context


def _whoami_ok(url: str, cookies: list[dict], authorization: str | None) -> bool:
    from http_probe import fetch

    headers: dict[str, str] = {}
    cookie_header = "; ".join(f"{c['name']}={c['value']}" for c in cookies if c.get("name"))
    if cookie_header:
        headers["Cookie"] = cookie_header
    if authorization:
        headers["Authorization"] = authorization
    r = fetch(url, "GET", headers, None, 10.0, allow_redirects=False)
    return r.error is None and r.status is not None and 200 <= r.status < 300


async def verify_logged_in(page, policy: RenewalPolicy, whoami_url: str | None,
                           cookies: list[dict], authorization: str | None) -> str | None:
    """None if the page is a logged-in app view; else the failure reason."""
    try:
        if await page.locator(_CAPTCHA_SELECTOR).count():
            return "captcha"
        if await page.locator("input[type=password]").count():
            return "password_field"
    except Exception:  # noqa: BLE001 -- page gone mid-check
        return "login_page"
    url = page.url or ""
    if not policy.in_scope(url) or _LOGIN_PATH_RE.search(urlsplit(url).path):
        return "login_page"
    if whoami_url:
        if not policy.in_scope(whoami_url):
            return "whoami_failed"
        if not await asyncio.to_thread(_whoami_ok, whoami_url, cookies, authorization):
            return "whoami_failed"
    return None


_TRAMPOLINE = "<!doctype html><meta name=robots content=noindex><script>location.replace({loc})</script>"


async def _route_document(route, req, main: bool, policy: RenewalPolicy, blocked: dict) -> None:
    """Fetch a document ourselves WITHOUT following redirects, so every hop's
    Location is policy-checked BEFORE the browser goes there. Playwright's
    route handler only ever sees the first URL of a redirect chain; an allowed
    IdP that 302s onward to an unknown host would otherwise be followed
    unchecked. An allowed hop is handed back as a tiny same-URL page that
    script-navigates to the Location (a fresh, routed navigation); its
    Set-Cookie headers are passed through so the redirect's cookies still land."""
    from urllib.parse import urljoin

    try:
        resp = await route.fetch(max_redirects=0)
    except Exception:  # noqa: BLE001 -- network error: let the page see a failed load
        await route.abort()
        return
    loc = resp.headers.get("location")
    if 300 <= resp.status < 400 and loc:
        loc = urljoin(req.url, loc)
        if not policy.allowed(loc) or urlsplit(loc).scheme not in ("http", "https"):
            if main:
                blocked.setdefault("reason", f"blocked_host:{_host(loc)}")
            await route.abort()
            return
        headers = {k: v for k, v in resp.headers.items() if k.lower() == "set-cookie"}
        headers["content-type"] = "text/html; charset=utf-8"
        headers["cache-control"] = "no-store"
        await route.fulfill(status=200, headers=headers, body=_TRAMPOLINE.format(loc=json.dumps(loc).replace("<", "\\u003c")))
        return
    await route.fulfill(response=resp)


_FRESH_MARGIN_S = 30


def _auth_evidence(state: dict, api_statuses: list[int], now: float,
                   origin_ok=None) -> str | None:
    """Positive evidence the session is really renewed (None = ok). A page
    shell that merely stayed on an in-scope URL is not enough:
    - if the state holds recognised SPA token entries, the earliest access
      token must now be fresh (else the stale restored token is all we have);
    - an in-scope API call that ended 401/403 with no later 2xx means the
      app is not authenticated, whatever the page looks like."""
    import session_tokens

    entries = [e for e in session_tokens.find_token_entries(state) if origin_ok is None or origin_ok(e.origin)]
    if entries:
        # at least ONE entry must be fresh: an app may keep a stale entry for a
        # second, unused client that never renews
        exps = [e.access_exp for e in entries if e.access_exp is not None]
        if not exps or max(exps) <= now + _FRESH_MARGIN_S:
            return "token_not_renewed"
    last_denied = max((i for i, st in enumerate(api_statuses) if st in (401, 403)), default=-1)
    if last_denied >= 0 and not any(200 <= st < 300 for st in api_statuses[last_denied + 1:]):
        return "unauthorized_api"
    return None


async def _settle(page, timeout_ms: int) -> None:
    for _ in range(2):
        try:
            await page.wait_for_load_state("networkidle", timeout=timeout_ms)
        except Exception:  # noqa: BLE001 -- a chatty page never idles; verify decides
            pass
        await page.wait_for_timeout(400)


async def _session_storage_sidecar(context, policy: RenewalPolicy, saved: dict) -> dict:
    side = {o: kv for o, kv in (saved.get(SESSION_STORAGE_KEY) or {}).items()
            if policy.in_scope(o) and isinstance(kv, dict)}
    for pg in context.pages:
        try:
            origin = await pg.evaluate("location.origin")
            entries = await pg.evaluate("Object.fromEntries(Object.entries(sessionStorage))")
        except Exception:  # noqa: BLE001
            continue
        if origin and origin != "null" and policy.in_scope(origin) and isinstance(entries, dict):
            entries.pop(_RESTORED_FLAG, None)
            side[origin] = entries
    for kv in side.values():
        kv.pop(_RESTORED_FLAG, None)
    return side


async def layer1_app_renew(profile_dir: str, app_url: str, session_file: str, policy: RenewalPolicy,
                           whoami_url: str | None, timeout_ms: int = 20000) -> LayerResult:
    saved = _load_state(session_file)
    p, context = await _launch_headless(profile_dir)
    blocked: dict = {}
    auth_by_host: dict = {}
    api_statuses: list[int] = []

    def on_response(resp) -> None:
        try:
            if resp.request.resource_type in ("xhr", "fetch") and policy.in_scope(resp.url):
                api_statuses.append(resp.status)
        except Exception:  # noqa: BLE001
            pass
    try:
        async def on_route(route):
            req = route.request
            try:
                main = req.is_navigation_request() and req.frame.parent_frame is None
            except Exception:  # noqa: BLE001 -- detached frame
                main = False
            action, reason = route_decision(req.method, req.url, req.resource_type, main, policy)
            if action == "abort":
                if reason == "form_post" or main:
                    blocked.setdefault("reason", reason)
                await route.abort()
            elif req.resource_type == "document":
                await _route_document(route, req, main, policy, blocked)
            else:
                await route.continue_()

        await context.route("**/*", on_route)
        def on_request(req) -> None:
            try:
                auth = req.headers.get("authorization")
                if auth and policy.in_scope(req.url):
                    auth_by_host[_host(req.url)] = auth
            except Exception:  # noqa: BLE001
                pass

        context.on("request", on_request)
        context.on("response", on_response)
        await context.add_init_script(_restore_script(saved, policy))
        page = context.pages[0] if context.pages else await context.new_page()
        try:
            await page.goto(app_url, timeout=timeout_ms, wait_until="domcontentloaded")
        except Exception as e:  # noqa: BLE001
            if not blocked:
                return LayerResult(False, f"navigation_failed:{type(e).__name__}")
        await _settle(page, timeout_ms)
        if blocked:
            return LayerResult(False, blocked["reason"])
        storage = await context.storage_state()
        filtered = _filter_state(storage, policy)
        authorization = next(iter(auth_by_host.values()), None)
        reason = await verify_logged_in(page, policy, whoami_url, filtered["cookies"], authorization)
        if reason:
            return LayerResult(False, reason)
        side = await _session_storage_sidecar(context, policy, saved)
        state = dict(filtered)
        if side:
            state[SESSION_STORAGE_KEY] = side
        reason = _auth_evidence(state, list(api_statuses), time.time(), policy.in_scope)
        if reason:
            return LayerResult(False, reason)
        sso = [c.get("expires") for c in storage.get("cookies") or []
               if isinstance(c.get("expires"), (int, float)) and c["expires"] > 0
               and policy.is_renewal_host(c.get("domain", "").lstrip("."))]
        return LayerResult(True, None, state, authorization, max(sso) if sso else None)
    finally:
        try:
            await context.close()
        finally:
            await p.stop()


# ------------------------------------------------------------------ layer 2

def _discover_token_endpoint(issuer: str) -> str | None:
    """token_endpoint from the issuer's OIDC discovery doc (no redirects)."""
    import http_probe

    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    r = http_probe.fetch(url, "GET", {"Accept": "application/json"}, None, 10.0, allow_redirects=False)
    if r.error or r.status != 200:
        return None
    try:
        endpoint = json.loads(r.body).get("token_endpoint")
    except (ValueError, AttributeError):
        return None
    return endpoint if isinstance(endpoint, str) else None


def layer2_refresh_grant(state: dict, policy: RenewalPolicy, app_origin: str) -> LayerResult:
    """POST grant_type=refresh_token for the first recognised token entry that
    holds a refresh token; on success return a new state with that entry
    patched (rotation-safe). Every host touched must pass policy.allowed()."""
    from urllib.parse import urlencode

    import http_probe
    import session_tokens

    entries = [e for e in session_tokens.find_token_entries(state)
               if e.refresh_token and e.issuer and e.client_id and policy.in_scope(e.origin)]
    if not entries:
        return LayerResult(False, "no_refresh_token")
    reason = "token_refused"
    for entry in entries:
        if not policy.allowed(entry.issuer) or urlsplit(entry.issuer).scheme not in ("http", "https"):
            reason = "token_endpoint_not_allowed"
            continue
        endpoint = _discover_token_endpoint(entry.issuer)
        # the discovery doc is IdP-controlled: its token endpoint must be on the
        # issuer's own host, or explicitly in scope, or a builtin IdP -- never
        # merely "learned", and never a non-public address (strict policy).
        same_host = bool(endpoint) and _host(endpoint) == _host(entry.issuer)
        if (not endpoint or urlsplit(endpoint).scheme not in ("http", "https")
                or not policy.allowed(endpoint)
                or not (same_host or policy.in_scope(endpoint) or policy.is_builtin(endpoint))):
            reason = "token_endpoint_not_allowed"
            continue
        body = urlencode({"grant_type": "refresh_token", "refresh_token": entry.refresh_token,
                          "client_id": entry.client_id})
        r = http_probe.fetch(endpoint, "POST", {"Content-Type": "application/x-www-form-urlencoded",
                                                "Accept": "application/json", "Origin": app_origin},
                             body, 15.0, allow_redirects=False)
        if r.error or r.status is None or not 200 <= r.status < 300:
            reason = "token_refused"
            continue
        try:
            resp = json.loads(r.body)
        except ValueError:
            reason = "token_refused"
            continue
        if not isinstance(resp, dict) or not isinstance(resp.get("access_token"), str):
            reason = "token_refused"
            continue
        return LayerResult(True, None, session_tokens.apply_token_response(state, entry, resp, time.time()))
    return LayerResult(False, reason)


# ------------------------------------------------------------ orchestration


MAX_RENEWALS_PER_DAY = 48

ALLOWED_SUMMARY_KEYS = frozenset({
    "identity", "status", "refreshed", "layer", "needs_human_login", "reason",
    "access_expires_in_s", "renewal_hosts", "last_refresh", "estimated_next_human_login",
    "warning", "message", "error",
})

_label_locks: dict = {}
_label_locks_guard = threading.Lock()


def _summary(label: str, **facts) -> dict:
    out: dict = {"identity": label}
    for key, value in facts.items():
        assert key in ALLOWED_SUMMARY_KEYS, f"non-allowed summary key: {key!r}"
        out[key] = value
    return out


def _today() -> str:
    return time.strftime("%Y-%m-%d", time.gmtime())


def session_file_for(label: str) -> str:
    session_capture._safe_label(label)
    return engagement_paths.resolve(f"secrets/sessions/{label}.json")


def refresh_state_path(label: str) -> str:
    session_capture._safe_label(label)
    return engagement_paths.resolve(f"session-refresh/{label}.json")


def _load_refresh_state(label: str) -> dict:
    return _load_state(refresh_state_path(label))


def _save_refresh_state(label: str, state: dict) -> None:
    _write_private_json(refresh_state_path(label), state)


def label_for_session_file(path: str, slug: str | None = None) -> str | None:
    """The roster label whose captured session_file is `path`, else None."""
    if not path:
        return None
    label = os.path.basename(path)[:-5] if path.endswith(".json") else ""
    try:
        expected = session_file_for(label)
    except ValueError:
        return None
    return label if os.path.realpath(expected) == os.path.realpath(path) else None


def notify(title: str, body: str) -> None:
    """Best-effort desktop notification (no-op without notify-send). Callers
    pass non-secret text only."""
    import shutil
    import subprocess

    exe = shutil.which("notify-send")
    if not exe:
        return
    try:
        subprocess.run([exe, "--app-name=HuntMCP", title, body], timeout=5, check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:  # noqa: BLE001
        pass


def _load_identity(label: str) -> dict | None:
    data = _load_state(engagement_paths.resolve("secrets/identities.json"))
    entry = data.get(label)
    return entry if isinstance(entry, dict) else None


def _update_identity(label: str, state: dict, authorization: str | None) -> None:
    ipath = engagement_paths.resolve("secrets/identities.json")
    with file_lock.locked(ipath):
        data = _load_state(ipath)
        entry = data.get(label) if isinstance(data.get(label), dict) else {}
        entry["cookies"] = [{k: c.get(k) for k in session_capture._COOKIE_KEYS}
                            for c in state.get("cookies") or []]
        if authorization:
            entry["authorization"] = authorization
        entry["refreshed_at"] = time.time()
        data[label] = entry
        _write_private_json(ipath, data)


def _is_profile_locked(err: BaseException) -> bool:
    text = str(err).lower()
    return any(s in text for s in ("processsingleton", "singletonlock", "already in use",
                                   "profile appears to be in use"))


def _rt_expiry(state: dict) -> float | None:
    import session_tokens

    exps = [session_tokens.jwt_exp(e.refresh_token) for e in session_tokens.find_token_entries(state)
            if e.refresh_token]
    exps = [e for e in exps if e]
    return max(exps) if exps else None


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


async def refresh_session(identity_label: str, slug: str | None = None) -> dict:
    """Renew identity_label's captured session without the human (layers 1 ->
    2), or report needs_human_login. Returns a non-secret summary only."""
    import session_tokens

    label = identity_label
    try:
        session_capture._safe_label(label)
    except ValueError as e:
        return _summary("invalid", error=str(e))
    try:
        roster = session_capture.roster_entry(label)
    except KeyError:
        return _summary(label, error=f"unknown identity label {label!r} -- not on the test-identity roster")
    try:
        from browser_launch import assert_dedicated_profile_dir

        profile_dir = assert_dedicated_profile_dir(roster.get("profile_dir", ""))
    except ValueError as e:
        return _summary(label, error=str(e))
    try:
        engagement = session_capture._load_engagement()
    except scope_guard.NoEngagementFile as e:
        return _summary(label, error=f"no active engagement: {e}")
    slug = session_capture._slug(slug)

    def human(reason: str, **extra) -> dict:
        st = _load_refresh_state(label)
        already = st.get("needs_human_login") and st.get("last_reason") == reason
        st.update(needs_human_login=True, last_reason=reason)
        _save_refresh_state(label, st)
        if not already:
            notify("HuntMCP: login needed", f"{label}: session renewal failed ({reason}). "
                                           "Log in again via start_capture.")
        _log_call("browser-mcp", ["refresh_session", label, "none", reason], returncode=None,
                  duration_ms=0.0, block=None)
        return _summary(label, status="needs_human_login", refreshed=False, layer="none",
                        needs_human_login=True, reason=reason, **extra)

    ident = _load_identity(label)
    if ident is None:
        return human("not_captured")
    app_url = ident.get("app_url") or ident.get("source_login_url") or ""
    policy = RenewalPolicy(engagement, list(ident.get("renewal_hosts") or []))
    if not app_url or not policy.in_scope(app_url):
        return human("no_app_url")
    if (slug, label) in session_capture._live_captures:
        return _summary(label, status="busy", refreshed=False, needs_human_login=False,
                        message="a capture window is open for this identity")
    rstate = _load_refresh_state(label)
    now = time.time()
    if rstate.get("day") == _today() and rstate.get("count", 0) >= MAX_RENEWALS_PER_DAY:
        return _summary(label, status="capped", refreshed=False, needs_human_login=False,
                        message=f"daily renewal cap ({MAX_RENEWALS_PER_DAY}) reached")
    interval = float(getattr(engagement, "min_request_interval_s", 0.0) or 0.0)
    if interval and now - float(rstate.get("last_attempt") or 0) < interval:
        return _summary(label, status="rate_limited", refreshed=False, needs_human_login=False)

    with _label_locks_guard:
        lock = _label_locks.setdefault((slug, label), threading.Lock())
    if not lock.acquire(blocking=False):
        return _summary(label, status="busy", refreshed=False, needs_human_login=False,
                        message="a refresh for this identity is already running")
    try:
        try:
            enforce("browser-mcp")
        except BudgetExceeded as e:
            return _summary(label, error=f"budget exhausted: {e}")
        rstate = _load_refresh_state(label)
        if rstate.get("day") != _today():
            rstate.update(day=_today(), count=0)
        rstate.update(count=int(rstate.get("count", 0)) + 1, last_attempt=now)
        _save_refresh_state(label, rstate)

        session_file = session_file_for(label)
        whoami_url = ident.get("whoami_url") or None
        with file_lock.locked(session_file):
            layer = "app"
            try:
                res = await layer1_app_renew(profile_dir, app_url, session_file, policy, whoami_url)
            except Exception as e:  # noqa: BLE001
                if _is_profile_locked(e):
                    return _summary(label, status="busy", refreshed=False, needs_human_login=False,
                                    message="the identity's browser profile is in use")
                res = LayerResult(False, f"browser_error:{type(e).__name__}")
            if not res.ok:
                first_reason = res.reason
                l2 = await asyncio.to_thread(layer2_refresh_grant, _load_state(session_file), policy,
                                             _origin(app_url))
                if not l2.ok:
                    return human(first_reason or l2.reason or "unknown")
                # persist FIRST: a rotated refresh token must never be lost
                _write_private_json(session_file, l2.state)
                layer = "refresh_token"
                try:
                    res = await layer1_app_renew(profile_dir, app_url, session_file, policy, whoami_url)
                except Exception as e:  # noqa: BLE001
                    res = LayerResult(False, f"browser_error:{type(e).__name__}")
                if not res.ok:
                    return human(res.reason or "unknown")
            _write_private_json(session_file, res.state)
            _update_identity(label, res.state, res.authorization)
        exp = session_tokens.earliest_access_exp(res.state, res.authorization, after=time.time())
        rstate = _load_refresh_state(label)
        rstate.update(last_refresh=time.time(), last_layer=layer, needs_human_login=False,
                      last_reason=None)
        if res.sso_expiry:
            rstate["sso_expiry"] = res.sso_expiry
        rt_exp = _rt_expiry(res.state)
        if rt_exp:
            rstate["rt_expiry"] = rt_exp
        if exp:
            rstate["access_exp"] = exp
        _save_refresh_state(label, rstate)
        _log_call("browser-mcp", ["refresh_session", label, layer, "ok"], returncode=None,
                  duration_ms=0.0, block=None)
        return _summary(label, status="refreshed", refreshed=True, layer=layer, needs_human_login=False,
                        access_expires_in_s=int(exp - time.time()) if exp else None)
    finally:
        lock.release()


__all__ = ["BUILTIN_IDP_PATTERNS", "RenewalPolicy", "route_decision", "LayerResult",
           "layer1_app_renew", "verify_logged_in"]
