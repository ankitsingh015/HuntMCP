"""Session keep-alive local fixture: a tiny SPA app + a mini OIDC IdP (loopback,
stdlib http.server). NOT a protected benchmark -- an ordinary test fixture.

Hosts (Chromium resolves *.localhost to loopback):
- app:   http://127.0.0.1:<app_port>/         (in scope in tests)
- IdP:   http://idp.localhost:<idp_port>       (NOT in scope -- a renewal host)
- rogue: http://rogue.localhost:<idp_port>     (never allowed; same server, Host-dispatched)

The SPA keeps its tokens in sessionStorage in oidc-client-ts shape under
`oidc.user:<authority>:<client_id>` and renews them like a real app:
valid token -> /api/me; expired + refresh_token (app_uses_rt) -> refresh grant;
expired + app_silent_renew -> hidden iframe /authorize?prompt=none using the
IdP's SSO cookie, code exchanged with PKCE; otherwise -> /login.
After a renewal it reloads the page once (reload_after_renew), which is what
catches a session-restore script that clobbers the fresh token.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

LOOPBACK = "127.0.0.1"
SESSION_STORAGE_KEY = "huntmcp_session_storage"  # mirrors browser_confirm.SESSION_STORAGE_KEY


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _jwt(claims: dict) -> str:
    return f"{_b64(json.dumps({'alg': 'none', 'typ': 'JWT'}).encode())}.{_b64(json.dumps(claims).encode())}."


class OidcFixture:
    def __init__(self, *, access_ttl: int = 60, sso_valid: bool = True, app_silent_renew: bool = True,
                 app_uses_rt: bool = True, reload_after_renew: bool = True,
                 authorize_mode: str = "normal", client_id: str = "spa", fail_mode: str = "login"):
        self.access_ttl = access_ttl
        self.sso_valid = sso_valid
        self.app_silent_renew = app_silent_renew
        self.app_uses_rt = app_uses_rt
        self.reload_after_renew = reload_after_renew
        self.authorize_mode = authorize_mode
        self.client_id = client_id
        self.fail_mode = fail_mode  # "login" -> location=/login on failure; "stay" -> do nothing
        self.requests: list[tuple[str, str, str]] = []
        self.touch_count = 0
        self.used_refresh_tokens: set[str] = set()
        self._access: dict[str, float] = {}
        self._refresh: set[str] = set()
        self._codes: dict[str, dict] = {}
        self._sso: set[str] = set()
        self._lock = threading.Lock()
        self._idp = ThreadingHTTPServer((LOOPBACK, 0), _make_idp_handler(self))
        self.idp_port = self._idp.server_address[1]
        self._app = ThreadingHTTPServer((LOOPBACK, 0), _make_app_handler(self))
        self.app_port = self._app.server_address[1]
        self.app_origin = f"http://{LOOPBACK}:{self.app_port}"
        self.app_url = self.app_origin + "/"
        self.idp_base = f"http://idp.localhost:{self.idp_port}"
        self.rogue_base = f"http://rogue.localhost:{self.idp_port}"
        self.storage_key = f"oidc.user:{self.idp_base}:{self.client_id}"
        for srv in (self._idp, self._app):
            threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    # -- token issuing ----------------------------------------------------
    def _issue(self) -> dict:
        now = time.time()
        exp = now + self.access_ttl
        access = _jwt({"iss": self.idp_base, "sub": "user-A", "aud": self.client_id, "exp": exp,
                       "jti": secrets.token_hex(6)})
        rt = "rt-" + secrets.token_hex(12)
        with self._lock:
            self._access[access] = exp
            self._refresh.add(rt)
        id_token = _jwt({"iss": self.idp_base, "sub": "user-A", "aud": self.client_id, "exp": exp})
        return {"access_token": access, "id_token": id_token, "refresh_token": rt,
                "token_type": "Bearer", "expires_in": self.access_ttl, "scope": "openid"}

    def valid_access(self, token: str) -> bool:
        with self._lock:
            exp = self._access.get(token)
        return exp is not None and exp > time.time()

    # -- test helpers -----------------------------------------------------
    def sso_cookie(self) -> dict:
        value = secrets.token_hex(12)
        with self._lock:
            self._sso.add(value)
        return {"name": "idp_sso", "value": value, "domain": "idp.localhost", "path": "/",
                "expires": time.time() + 5 * 86400, "httpOnly": True, "secure": True, "sameSite": "None"}

    def seed_state(self, access_valid: bool, with_rt: bool) -> dict:
        """A session_file-shaped storage_state for the app origin whose
        sessionStorage sidecar holds an oidc-client-ts user entry."""
        tok = self._issue()
        if not access_valid:
            # an issued-but-expired token (exp in the past)
            expired = _jwt({"iss": self.idp_base, "sub": "user-A", "aud": self.client_id,
                            "exp": time.time() - 30, "jti": secrets.token_hex(6)})
            with self._lock:
                self._access[expired] = time.time() - 30
            tok["access_token"] = expired
        user = {"id_token": tok["id_token"], "access_token": tok["access_token"],
                "token_type": "Bearer", "scope": "openid", "profile": {"sub": "user-A"},
                "expires_at": int(_claims(tok["access_token"])["exp"])}
        if with_rt:
            user["refresh_token"] = tok["refresh_token"]
        return {"cookies": [], "origins": [],
                SESSION_STORAGE_KEY: {self.app_origin: {self.storage_key: json.dumps(user)}}}

    def close(self) -> None:
        for srv in (self._idp, self._app):
            srv.shutdown()
            srv.server_close()


def _claims(jwt: str) -> dict:
    part = jwt.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def serve(**opts) -> OidcFixture:
    return OidcFixture(**opts)


async def seed_profile(profile_dir: str, cookies: list[dict]) -> None:
    """Stand-in for the human's earlier login: put the IdP SSO cookie into a
    dedicated persistent profile (headless), then close it."""
    import os as _os
    import sys as _sys

    _sys.path.insert(0, _os.path.join(_os.path.dirname(__file__), "..", "..", "..", "mcp-servers"))
    import browser_launch
    from playwright.async_api import async_playwright

    async with async_playwright() as p:
        ctx = await p.chromium.launch_persistent_context(
            **browser_launch.persistent_context_kwargs(profile_dir, headless=True))
        await ctx.add_cookies(cookies)
        await ctx.close()


# ------------------------------------------------------------------ IdP
_LOGIN_HTML = """<!doctype html><html><body><h1>Sign in</h1>
<form method="post" action="/login"><input name="user"><input type="password" name="pw">
<button>Sign in</button></form></body></html>"""
_CAPTCHA_HTML = """<!doctype html><html><body><h1>Are you human?</h1>
<div class="g-recaptcha" data-sitekey="x"></div></body></html>"""


def _make_idp_handler(fx: OidcFixture):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _host(self) -> str:
            return (self.headers.get("Host") or "").split(":")[0]

        def _send(self, code, body=b"", ctype="text/html", headers=None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Access-Control-Allow-Origin", fx.app_origin)
            for k, v in (headers or {}).items():
                for one in (v if isinstance(v, list) else [v]):
                    self.send_header(k, one)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code, obj):
            self._send(code, json.dumps(obj).encode(), "application/json")

        def _sso_ok(self) -> bool:
            jar = SimpleCookie(self.headers.get("Cookie") or "")
            m = jar.get("idp_sso")
            with fx._lock:
                return fx.sso_valid and m is not None and m.value in fx._sso

        def do_GET(self):
            u = urlsplit(self.path)
            fx.requests.append(("GET", self._host(), u.path))
            if self._host() != "idp.localhost":
                return self._send(200, b"<html><body>rogue</body></html>")
            if u.path == "/.well-known/openid-configuration":
                return self._json(200, {"issuer": fx.idp_base,
                                        "authorization_endpoint": fx.idp_base + "/authorize",
                                        "token_endpoint": fx.idp_base + "/token"})
            if u.path == "/authorize":
                q = {k: v[0] for k, v in parse_qs(u.query).items()}
                redirect = q.get("redirect_uri", "")
                if fx.authorize_mode == "redirect_rogue":
                    return self._send(302, headers={"Location": fx.rogue_base + "/x"})
                if fx.authorize_mode == "captcha":
                    return self._send(200, _CAPTCHA_HTML.encode())
                if not self._sso_ok():
                    if q.get("prompt") == "none":
                        loc = redirect + "?" + urlencode({"error": "login_required", "state": q.get("state", "")})
                        return self._send(302, headers={"Location": loc})
                    return self._send(200, _LOGIN_HTML.encode())
                code = secrets.token_hex(8)
                with fx._lock:
                    fx._codes[code] = {"challenge": q.get("code_challenge", ""), "redirect_uri": redirect}
                loc = redirect + "?" + urlencode({"code": code, "state": q.get("state", "")})
                # sliding SSO session: every successful authorize re-issues a cookie
                fx.touch_count += 1
                touch = f"idp_touch={fx.touch_count}; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=None"
                csrf = "idp_csrf=c; Path=/; Max-Age=86400; Secure; SameSite=None"
                return self._send(302, headers={"Location": loc, "Set-Cookie": [touch, csrf]})
            return self._send(404, b"not found")

        def do_POST(self):
            u = urlsplit(self.path)
            fx.requests.append(("POST", self._host(), u.path))
            n = int(self.headers.get("Content-Length") or 0)
            form = {k: v[0] for k, v in parse_qs(self.rfile.read(n).decode()).items()}
            if self._host() != "idp.localhost" or u.path != "/token":
                return self._send(404, b"not found")
            grant = form.get("grant_type")
            if grant == "authorization_code":
                with fx._lock:
                    rec = fx._codes.pop(form.get("code", ""), None)
                verifier = form.get("code_verifier", "")
                ok = rec and rec["challenge"] == _b64(hashlib.sha256(verifier.encode()).digest()) \
                    and rec["redirect_uri"] == form.get("redirect_uri")
                if not ok:
                    return self._json(400, {"error": "invalid_grant"})
                return self._json(200, fx._issue())
            if grant == "refresh_token":
                rt = form.get("refresh_token", "")
                with fx._lock:
                    live = rt in fx._refresh
                    if live:
                        fx._refresh.discard(rt)
                        fx.used_refresh_tokens.add(rt)
                if not live:
                    return self._json(400, {"error": "invalid_grant"})
                return self._json(200, fx._issue())
            return self._json(400, {"error": "unsupported_grant_type"})

    return H


# ------------------------------------------------------------------ app
_SPA = """<!doctype html><html><head><meta charset="utf-8"><title>App</title></head><body>
<div id="me">loading</div><script>
const KEY = __KEY__, IDP = __IDP__, CLIENT = __CLIENT__;
const SILENT = __SILENT__, USES_RT = __USES_RT__, RELOAD = __RELOAD__, STAY = __STAY__;
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
function store(t){ const exp = JSON.parse(atob(t.access_token.split('.')[1].replace(/-/g,'+').replace(/_/g,'/'))).exp;
  sessionStorage.setItem(KEY, JSON.stringify({id_token:t.id_token, access_token:t.access_token,
    refresh_token:t.refresh_token, token_type:'Bearer', scope:t.scope, profile:{sub:'user-A'}, expires_at:Math.floor(exp)})); }
function done(){ if (RELOAD && !location.search.includes('renewed=1')) { location.replace('/?renewed=1'); return true; } return false; }
async function showMe(u){
  const r = await fetch('/api/me', {headers:{Authorization:'Bearer '+u.access_token}});
  if (r.status !== 200) { location = '/login'; return; }
  document.getElementById('me').textContent = (await r.json()).sub;
}
async function token(form){
  const r = await fetch(IDP + '/token', {method:'POST', body:new URLSearchParams(form)});
  return r.status === 200 ? r.json() : null;
}
async function silent(){
  const ver = b64(crypto.getRandomValues(new Uint8Array(32)));
  const chal = b64(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(ver)));
  const redirect = location.origin + '/callback';
  window.addEventListener('message', async (e) => {
    if (e.origin !== location.origin) return;
    if (!e.data.code) { location = '/login'; return; }
    const t = await token({grant_type:'authorization_code', code:e.data.code, client_id:CLIENT,
                           redirect_uri:redirect, code_verifier:ver});
    if (!t) { location = '/login'; return; }
    store(t); if (!done()) showMe(JSON.parse(sessionStorage.getItem(KEY)));
  });
  const f = document.createElement('iframe'); f.style.display = 'none';
  f.src = IDP + '/authorize?' + new URLSearchParams({client_id:CLIENT, redirect_uri:redirect,
    response_type:'code', scope:'openid', prompt:'none', state:'s', code_challenge:chal,
    code_challenge_method:'S256'});
  document.body.appendChild(f);
}
(async () => {
  const raw = sessionStorage.getItem(KEY); const u = raw ? JSON.parse(raw) : null;
  if (u && u.expires_at > Date.now()/1000 + 5) return showMe(u);
  if (location.search.includes('renewed=1')) { location = '/login'; return; }
  if (u && u.refresh_token && USES_RT) {
    const t = await token({grant_type:'refresh_token', refresh_token:u.refresh_token, client_id:CLIENT});
    if (t) { store(t); if (!done()) showMe(JSON.parse(sessionStorage.getItem(KEY))); return; }
  }
  if (SILENT) return silent();
  if (!STAY) location = '/login';
})();
</script></body></html>"""

_CALLBACK = """<!doctype html><html><body><script>
const q = new URLSearchParams(location.search);
parent.postMessage({code: q.get('code'), error: q.get('error')}, location.origin);
</script></body></html>"""

_APP_LOGIN = """<!doctype html><html><body><h1>Log in</h1><a href="/">Sign in</a></body></html>"""


def _make_app_handler(fx: OidcFixture):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body: bytes, ctype="text/html"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            u = urlsplit(self.path)
            fx.requests.append(("GET", LOOPBACK, u.path))
            if u.path == "/":
                page = (_SPA.replace("__KEY__", json.dumps(fx.storage_key))
                        .replace("__IDP__", json.dumps(fx.idp_base))
                        .replace("__CLIENT__", json.dumps(fx.client_id))
                        .replace("__SILENT__", json.dumps(fx.app_silent_renew))
                        .replace("__USES_RT__", json.dumps(fx.app_uses_rt))
                        .replace("__RELOAD__", json.dumps(fx.reload_after_renew))
                        .replace("__STAY__", json.dumps(fx.fail_mode == "stay")))
                return self._send(200, page.encode())
            if u.path == "/callback":
                return self._send(200, _CALLBACK.encode())
            if u.path == "/login":
                return self._send(200, _APP_LOGIN.encode())
            if u.path == "/api/me":
                auth = self.headers.get("Authorization") or ""
                tok = auth[7:] if auth.startswith("Bearer ") else ""
                if fx.valid_access(tok):
                    return self._send(200, json.dumps({"sub": "user-A"}).encode(), "application/json")
                return self._send(401, b'{"error":"unauthorized"}', "application/json")
            return self._send(404, b"not found")

        def do_POST(self):
            fx.requests.append(("POST", LOOPBACK, urlsplit(self.path).path))
            self._send(404, b"not found")

    return H
