"""#164 local fixture app for the UI-walk (loopback only, stdlib http.server).

Exhibits, in one small app, every UI-only surface the walker must handle:
lazy-loaded third-party-origin iframe form (the Marketo case), modal- and
tab-revealed inputs, a cross-page stored-XSS render sink, a soft delete
(object still reachable after delete), a logout that does not invalidate the
server session, a sessionStorage-token SPA, a payment button, an out-of-scope
link, an icon-only and a non-English destructive button, a popup that POSTs
on load, an unbounded calendar URL space, and a very tall page.

Spec 2 (SSO): `/sso/*` makes this app a relying party for a real local test
IdP (mock_idp.py, mock-oauth2-server container): static vs fresh state/nonce,
no PKCE vs S256, an implicit-flow link, a baked-state authorize href, an SPA
button, an IdP logout link, and a callback.

`vulnerable=False` serves the PATCHED variant (escaped renders, hard delete,
invalidating logout and account deletion) so tests can check the walker
distinguishes the two.

NOT a protected benchmark -- an ordinary test fixture.
"""

from __future__ import annotations

import html
import json
import os
import secrets
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

LOOPBACK = "127.0.0.1"


def _browser_available() -> bool:
    try:
        import playwright  # noqa: F401
    except ImportError:
        return False
    import sys

    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "mcp-servers"))
    import browser_launch

    if browser_launch.find_browser_executable():
        return True
    cache = os.path.expanduser("~/.cache/ms-playwright")
    return os.path.isdir(cache) and any(n.startswith("chromium") for n in os.listdir(cache))


requires_browser = pytest.mark.skipif(not _browser_available(),
                                      reason="needs Playwright + a Chromium executable")

_PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>{title}</title></head>
<body><nav><a href="/">Home</a></nav><main>{body}</main>{script}</body></html>"""


def _render(title: str, body: str, script: str = "") -> bytes:
    return _PAGE.format(title=title, body=body,
                        script=f"<script>{script}</script>" if script else "").encode()


_WAF_BODY = _render("Access denied", "<h1>Access denied</h1><p>Request blocked by the edge firewall.</p>")


class FixtureApp:
    def __init__(self, vulnerable: bool = True, refuse_proxied: bool = False,
                 refuse_proxied_after: int | None = None, refuse_all: bool = False,
                 sso_login_issuer: str | None = None, sso_session_issuer: str | None = None):
        self.vulnerable = vulnerable
        # Spec 2 (SSO): issuer URLs of the local test IdPs (tests/fixtures/
        # ui_walk_target/mock_idp.py) -- one showing its login page, one with
        # an "existing session" that bounces straight back. This app is only
        # the relying party (RP): its /sso pages start flows and take callbacks.
        self.sso_login_issuer = sso_login_issuer
        self.sso_session_issuer = sso_session_issuer
        self.issued_secrets: list[str] = []          # every state/nonce/challenge/code this RP saw or made
        self.host_requests: list[tuple[str, str, str]] = []   # (method, host, path?query)
        # Burp-mirror tests: answer requests carrying a `Via` header (i.e. that
        # came through the stand-in proxy) with a WAF-looking 403 -- always
        # (refuse_proxied), or once more than N requests were received
        # (refuse_proxied_after=N, the mid-walk case).
        self.refuse_proxied = refuse_proxied
        self.refuse_proxied_after = refuse_proxied_after
        self.refuse_all = refuse_all   # the same 403 for every request, proxied or direct (a real block)
        self.requests: list[tuple[str, str]] = []
        self.cookie_headers: list[str] = []
        self.items: dict[str, dict] = {}
        self.valid_sids: set[str] = set()
        self.account_deleted = False
        # Spec 3a (request mutation): the test identity's own account record
        # (GET /api/v3/me), its email-change OTP and a promo code. The patched
        # app ignores unknown profile keys, requires the OTP, rejects duplicate
        # `to` params and array-form `code`.
        self.v3_me = {"id": "u-1001", "display_name": "Tester", "role": "user",
                      "email": "tester@example.invalid", "plan": "free"}
        self.v3_otp = "%06d" % secrets.randbelow(10 ** 6)
        while self.v3_otp == "000000":
            self.v3_otp = "%06d" % secrets.randbelow(10 ** 6)
        self.v3_promo = "PROMO" + secrets.token_hex(3).upper()
        # Runner tests: a second identity (its sids see u-2002's record), a
        # "sticky" mode where a changed role can no longer be put back (restore
        # failure), session expiry after N v3 requests and a 429 after N.
        self.v3_other = {"id": "u-2002", "display_name": "Other", "role": "user",
                         "email": "other@example.invalid", "plan": "free"}
        self.other_sids: set[str] = set()
        self.v3_sticky_role = False
        self.v3_expire_after: int | None = None
        self.v3_rate_limit_after: int | None = None
        self.v3_requests = 0
        self._next_id = 1
        self._lock = threading.Lock()
        self._server = ThreadingHTTPServer((LOOPBACK, 0), _make_handler(self))
        self.port = self._server.server_address[1]
        self.base_url = f"http://{LOOPBACK}:{self.port}"
        self.alt_base_url = f"http://localhost:{self.port}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    # -- test helpers -------------------------------------------------------
    def login_cookie(self) -> str:
        sid = secrets.token_hex(8)
        self.valid_sids.add(sid)
        return f"sid={sid}"

    def seed_item(self, name: str, description: str = "") -> str:
        with self._lock:
            iid = str(self._next_id)
            self._next_id += 1
            self.items[iid] = {"id": iid, "name": name, "description": description, "deleted": False}
        return iid

    def write_session_file(self, path: str, other: bool = False) -> None:
        """A Playwright storage_state file holding a valid RP `sid` cookie
        (other=True: the second identity, u-2002)."""
        sid = self.login_cookie().split("=", 1)[1]
        if other:
            self.other_sids.add(sid)
        state = {"cookies": [{"name": "sid", "value": sid, "domain": LOOPBACK, "path": "/",
                              "expires": -1, "httpOnly": False, "secure": False, "sameSite": "Lax"}],
                 "origins": []}
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(state, fh)

    def _sso_secret(self, static: str) -> str:
        v = static if self.vulnerable else secrets.token_urlsafe(24)
        self.issued_secrets.append(v)
        return v

    def sso_authorize_url(self, issuer: str, *, implicit: bool = False, prompt: str | None = None,
                          client_id: str = "fixture-app") -> str:
        """An authorize request as this RP builds it. Vulnerable: static
        state and nonce, no PKCE, implicit link without nonce. Patched: fresh
        values every time, PKCE S256, implicit link downgraded to code."""
        from urllib.parse import urlencode

        q = {"client_id": client_id, "redirect_uri": self.base_url + "/sso/callback",
             "scope": "openid profile", "state": self._sso_secret("FIXSTATESTATIC01")}
        if implicit and self.vulnerable:
            q["response_type"] = "id_token token"
        else:
            q["response_type"] = "code"
            q["nonce"] = self._sso_secret("FIXNONCESTATIC01")
        if not self.vulnerable:
            q["code_challenge"] = self._sso_secret("")
            q["code_challenge_method"] = "S256"
        if prompt:
            q["prompt"] = prompt
        return f"{issuer}/authorize?{urlencode(q)}"

    def non_get_requests(self) -> list[tuple[str, str]]:
        return [(m, p) for m, p in self.requests if m not in ("GET", "HEAD", "OPTIONS")]

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def serve(vulnerable: bool = True, **kw) -> FixtureApp:
    return FixtureApp(vulnerable=vulnerable, **kw)


def _make_handler(app: FixtureApp):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # quiet
            pass

        # -- plumbing -------------------------------------------------------
        def _sid(self) -> str | None:
            raw = self.headers.get("Cookie") or ""
            c = SimpleCookie()
            try:
                c.load(raw)
            except Exception:
                return None
            return c["sid"].value if "sid" in c else None

        def _authed(self) -> bool:
            return self._sid() in app.valid_sids

        def _send(self, status: int, body: bytes, ctype: str = "text/html", headers=None):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            if (not app.vulnerable and ctype == "text/html"
                    and (self.headers.get("Host") or "").startswith(LOOPBACK)):
                self.send_header("X-Frame-Options", "SAMEORIGIN")   # patched: pages cannot be framed cross-origin
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, status: int, obj):
            self._send(status, json.dumps(obj).encode(), "application/json")

        def _redirect(self, loc: str, headers=None):
            h = {"Location": loc}
            h.update(headers or {})
            self._send(302, b"", headers=h)

        def _body(self) -> bytes:
            n = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(n) if n else b""

        def _log(self):
            app.requests.append((self.command, self.path))
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0]
            app.host_requests.append((self.command, host, self.path))
            app.cookie_headers.append(self.headers.get("Cookie") or "")

        def _refused_proxied(self) -> bool:
            """Burp-mirror tests: a WAF-style 403 for proxied (Via) requests,
            or for every request when refuse_all is set."""
            if app.refuse_all:
                self._send(403, _WAF_BODY)
                return True
            if not self.headers.get("Via"):
                return False
            after = app.refuse_proxied_after
            if not (app.refuse_proxied or (after is not None and len(app.requests) > after)):
                return False
            self._send(403, _WAF_BODY)
            return True

        # -- verbs ----------------------------------------------------------
        def do_HEAD(self):
            self._log()
            self._send(200, b"")

        def do_OPTIONS(self):
            self._log()
            self._send(204, b"")

        def do_GET(self):
            self._log()
            if self._refused_proxied():
                return
            u = urlsplit(self.path)
            path, q = u.path, parse_qs(u.query)
            protected = path in ("/items", "/settings", "/activity") or path.startswith(("/items/", "/api/items"))
            if protected and not self._authed():
                if path.startswith("/api/"):
                    return self._json(401, {"error": "unauthenticated"})
                return self._redirect("/login")
            route = getattr(self, "_get_" + (path.strip("/").split("/")[0] or "index").replace("-", "_"), None)
            if route is None:
                return self._send(404, _render("Not found", "<p>not found</p>"))
            return route(path, q)

        def do_POST(self):
            self._log()
            self._mutate("POST")

        def do_PUT(self):
            self._log()
            self._mutate("PUT")

        def do_PATCH(self):
            self._log()
            self._mutate("PATCH")

        def do_DELETE(self):
            self._log()
            self._mutate("DELETE")

        # -- pages ----------------------------------------------------------
        def _get_index(self, path, q):
            body = f"""
<h1>Fixture</h1>
<ul>
 <li><a href="/items">Items</a></li><li><a href="/contact">Contact</a></li>
 <li><a href="/settings">Settings</a></li><li><a href="/checkout">Checkout</a></li>
 <li><a href="/activity">Activity</a></li><li><a href="/app">App</a></li>
 <li><a href="/cal?d=1">Calendar</a></li><li><a href="/tall">Tall</a></li>
 <li><a href="/sso-protected">Reports</a></li><li><a href="/danger">Account options</a></li>
 <li><a href="/profile2">Profile 2</a></li><li><a href="/cards">Cards</a></li>
 <li><a href="/logout">Sign out</a></li>
 <li><a href="{app.alt_base_url}/elsewhere">Partner site</a></li>
 <li><a href="/popup" target="_blank">Open popup</a></li>
</ul>
<button id="open-win">Open window</button>
<button aria-label="" id="icon-del">&#128465;</button>
<button id="loeschen">L&ouml;schen</button>"""
            script = """
document.getElementById('open-win').onclick=()=>window.open('/popup?w=1');
document.getElementById('icon-del').onclick=()=>fetch('/api/purge',{method:'POST'});
document.getElementById('loeschen').onclick=()=>fetch('/api/purge',{method:'POST'});"""
            self._send(200, _render("Home", body, script))

        def _get_login(self, path, q):
            if q.get("go"):
                sid = secrets.token_hex(8)
                app.valid_sids.add(sid)
                return self._redirect("/", {"Set-Cookie": f"sid={sid}; Path=/"})
            self._send(200, _render("Login", '<a href="/login?go=1"><button>Sign in</button></a>'))

        def _get_logout(self, path, q):
            sid = self._sid()
            if not app.vulnerable and sid:
                app.valid_sids.discard(sid)
            self._redirect("/login", {"Set-Cookie": "sid=; Path=/; Max-Age=0"})

        def _render_names_js(self, target_id: str) -> str:
            sink = "innerHTML" if app.vulnerable else "textContent"
            return f"""
fetch('/api/items').then(r=>r.json()).then(items=>{{
  const el=document.getElementById('{target_id}');
  for(const it of items){{ const s=document.createElement('div'); s.{sink}=it.name; el.appendChild(s); }}
}});"""

        def _get_items(self, path, q):
            parts = [p for p in path.split("/") if p]
            if len(parts) == 2:  # detail
                iid = parts[1]
                script = f"""
fetch('/api/items/{iid}').then(r=>r.ok?r.json():null).then(it=>{{
  document.getElementById('detail').textContent = it ? it.name : 'gone';
}});"""
                return self._send(200, _render("Item", '<div id="detail"></div>', script))
            sink = "innerHTML" if app.vulnerable else "textContent"
            body = """
<button id="new">New item</button>
<div id="modal" style="display:none">
 <form id="create"><label>Name <input name="name"></label>
 <label>Description <textarea name="description"></textarea></label>
 <button type="submit">Create</button></form>
</div>
<table id="rows"></table>"""
            script = f"""
document.getElementById('new').onclick=()=>{{document.getElementById('modal').style.display='block';}};
document.getElementById('create').onsubmit=(e)=>{{e.preventDefault();
  const f=new FormData(e.target);
  fetch('/api/items',{{method:'POST',headers:{{'Content-Type':'application/json'}},
    body:JSON.stringify({{name:f.get('name'),description:f.get('description')}})}}).then(()=>location.reload());}};
fetch('/api/items').then(r=>r.json()).then(items=>{{
  const t=document.getElementById('rows');
  for(const it of items){{
    const tr=document.createElement('tr'); tr.setAttribute('data-id', it.id);
    const n=document.createElement('td'); n.{sink}=it.name; tr.appendChild(n);
    const a=document.createElement('td');
    const v=document.createElement('a'); v.href='/items/'+it.id; v.textContent='View'; a.appendChild(v);
    const d=document.createElement('button'); d.textContent='Delete';
    d.onclick=()=>{{ if(confirm('Are you sure?')) fetch('/api/items/'+it.id,{{method:'DELETE'}}).then(()=>location.reload()); }};
    a.appendChild(d); tr.appendChild(a); t.appendChild(tr);
  }}
}});"""
            self._send(200, _render("Items", body, script))

        def _get_activity(self, path, q):
            self._send(200, _render("Activity", '<h2>Latest</h2><div id="latest"></div>',
                                    self._render_names_js("latest")))

        def _get_contact(self, path, q):
            script = f"""
document.getElementById('slot').textContent='Loading form...';
setTimeout(()=>{{const f=document.createElement('iframe'); f.src='{app.alt_base_url}/embed/form';
  const s=document.getElementById('slot'); s.textContent=''; s.appendChild(f);}},300);"""
            self._send(200, _render("Contact", '<div id="slot"></div>', script))

        def _get_p2contact(self, path, q):
            # unlinked: an in-scope (same-origin) contact form, for Pass-2 cookie-event tests
            body = """<form action="/api/contact" method="post">
<label>Your name <input name="name"></label><label>Message <textarea name="message"></textarea></label>
<button type="submit">Send</button></form>"""
            self._send(200, _render("Contact form", body))

        def _get_embed(self, path, q):
            body = """<form action="/api/contact" method="post">
<label>Your name <input name="name"></label><label>Message <textarea name="message"></textarea></label>
<button type="submit">Send</button></form>"""
            self._send(200, _render("Embedded form", body))

        def _get_settings(self, path, q):
            body = """
<div role="tablist"><button role="tab" id="t-profile">Profile</button>
<button role="tab" id="t-keys">API keys</button></div>
<section id="p-profile"><form id="profile"><label>Display name <input name="display_name"></label>
<button type="submit">Save</button></form></section>
<section id="p-keys" style="display:none"><form id="keys"><label>Key label <input name="key_label"></label>
<button type="submit">Generate</button></form></section>
<button id="del-account">Delete account</button>"""
            script = """
const show=(a,b)=>{document.getElementById(a).style.display='block';document.getElementById(b).style.display='none';};
document.getElementById('t-profile').onclick=()=>show('p-profile','p-keys');
document.getElementById('t-keys').onclick=()=>show('p-keys','p-profile');
document.getElementById('profile').onsubmit=(e)=>{e.preventDefault();
  fetch('/api/profile',{method:'PUT',body:new URLSearchParams(new FormData(e.target))});};
document.getElementById('keys').onsubmit=(e)=>{e.preventDefault();
  fetch('/api/keys',{method:'POST',body:new URLSearchParams(new FormData(e.target))});};
document.getElementById('del-account').onclick=()=>{ if(confirm('Delete your account?'))
  fetch('/api/account/delete',{method:'POST'}).then(()=>location.href='/login'); };"""
            self._send(200, _render("Settings", body, script))

        def _get_checkout(self, path, q):
            script = """document.getElementById('pay').onclick=()=>fetch('https://api.stripe.com/v1/charges',{method:'POST',body:'amount=100'});"""
            self._send(200, _render("Checkout", '<p>Total: $1.00</p><button id="pay">Pay now</button>', script))

        def _get_popup(self, path, q):
            self._send(200, _render("Popup", "<p>popup</p>",
                                    "fetch('/api/popup-post',{method:'POST'});"))

        def _get_cal(self, path, q):
            d = int((q.get("d") or ["1"])[0])
            self._send(200, _render("Calendar", f'<p>Day {d}</p><a href="/cal?d={d + 1}">Next day</a>'))

        def _get_mx(self, path, q):
            # Burp-mirror R12 hubs (no nav bar, so the BFS order is exactly the
            # hub's links): /mx/deny/N is the app's OWN "Access denied" 403
            # (with or without a proxy), /mx/ok/N a normal page.
            hubs = {"a": ["deny/1", "deny/2", "ok/1", "deny/3"],   # never 3 block pages in a row
                    "b": ["deny/1", "deny/2", "deny/3", "ok/1"],   # 3 in a row
                    "c": ["ok/1", "ok/2", "ok/3"]}                 # all fine (refuse_proxied_after tests)
            parts = [x for x in path.split("/") if x]
            if len(parts) == 2 and parts[1] == "e":
                # fix-wave R12 hub: a BUTTON whose click navigates to deny/2 (a block
                # page at a different URL), then the hub's own re-load (the walker's
                # way back) is the app's 403 too. Links: deny/1, ok/1.
                if sum(1 for _m, pth in app.requests if pth == "/mx/e") > 1:
                    return self._send(403, _WAF_BODY)
                return self._send(200, b"<!doctype html><html><head><title>MX e</title></head><body>"
                                       b'<a href="/mx/deny/1">deny/1</a> <a href="/mx/ok/1">ok/1</a> '
                                       b'<button id="go" onclick="location.href=\'/mx/deny/2\'">Go</button>'
                                       b"</body></html>")
            if len(parts) == 2 and parts[1] in hubs:
                links = "".join(f'<a href="/mx/{h}">{h}</a> ' for h in hubs[parts[1]])
                return self._send(200, f"<!doctype html><html><head><title>MX {parts[1]}</title></head>"
                                       f"<body>{links}</body></html>".encode())
            if len(parts) == 3 and parts[1] == "deny":
                return self._send(403, _WAF_BODY)
            if len(parts) == 3 and parts[1] == "ok":
                return self._send(200, f"<!doctype html><html><head><title>OK {parts[2]}</title></head>"
                                       "<body><p>ok</p></body></html>".encode())
            return self._send(404, _render("Not found", "<p>not found</p>"))

        def _get_tall(self, path, q):
            self._send(200, _render("Tall", '<div style="height:10000px;background:#eee">tall</div>'))

        def _get_sso_protected(self, path, q):
            # an in-scope page that bounces to a third-party SSO host
            self._redirect(f"{app.alt_base_url}/login?next=/sso-protected")

        def _get_danger(self, path, q):
            body = """
<form id="close" action="/api/account/close" method="post"><label>Why are you leaving? <textarea name="reason"></textarea></label>
<button type="submit">Close account</button></form>
<form id="order" action="/api/orders" method="post"><label>Order notes <input name="notes"></label>
<button type="submit">Place order</button></form>"""
            self._send(200, _render("Account options", body))

        def _get_profile2(self, path, q):
            body = """
<form id="f1"><label>Nickname <input name="nickname"></label><button type="submit">Save nickname</button></form>
<form id="f2"><label>Bio <input name="bio"></label><button type="submit">Save bio</button></form>"""
            script = """
document.getElementById('f1').onsubmit=(e)=>{e.preventDefault();
  fetch('/api/items/1',{method:'DELETE'});
  fetch('/api/p1',{method:'PUT',body:new URLSearchParams(new FormData(e.target))});};
document.getElementById('f2').onsubmit=(e)=>{e.preventDefault();
  fetch('/api/p2',{method:'PUT',body:new URLSearchParams(new FormData(e.target))});};"""
            self._send(200, _render("Profile 2", body, script))

        def _get_cards(self, path, q):
            script = """
fetch('/api/items').then(r=>r.json()).then(items=>{
  const list=document.getElementById('list');
  for(const it of items){ const row=document.createElement('div'); row.className='row';
    const n=document.createElement('span'); n.textContent=it.name; row.appendChild(n);
    const b=document.createElement('button'); b.textContent='Remove';
    b.onclick=()=>fetch('/api/items/'+it.id,{method:'DELETE'}).then(()=>location.reload());
    row.appendChild(b); list.appendChild(row); }
});"""
            self._send(200, _render("Cards", '<div class="card" id="list"></div>', script))

        def _get_elsewhere(self, path, q):
            self._send(200, _render("Partner", "<p>partner</p>"))

        def _get_app(self, path, q):
            if path.rstrip("/") == "/app/login":
                script = """sessionStorage.setItem('oidc.user', JSON.stringify({name:'alice'})); location.href='/app';"""
                return self._send(200, _render("App login", "<p>signing in</p>", script))
            script = """
const u=sessionStorage.getItem('oidc.user'); const m=document.getElementById('spa');
if(!u){ const b=document.createElement('button'); b.textContent='Sign in'; b.onclick=()=>location.href='/app/login'; m.appendChild(b); }
else { const n=JSON.parse(u).name; const p=document.createElement('p'); p.textContent='Welcome, '+n; m.appendChild(p);
  const i=document.createElement('input'); i.name='nickname'; m.appendChild(i); }"""
            self._send(200, _render("App", '<div id="spa"></div>', script))

        # -- /sso/*: spec 2 relying-party pages (IdP = local mock container) --
        def _get_sso(self, path, q):
            sub = path.rstrip("/")
            login, sess = app.sso_login_issuer, app.sso_session_issuer
            if not (login and sess):
                return self._send(404, _render("Not found", "<p>no IdP configured</p>"))
            if sub == "/sso":
                spa = app.sso_authorize_url(login, client_id="fixture-spa")   # its own flow: repeat by re-click
                body = f"""<h1>SSO</h1><p>Account linking (you are signed in to this app)</p><ul>
<li><a href="/sso/login">SSO with login prompt</a></li>
<li><a href="/sso/login-silent">Silent SSO</a></li>
<li><a href="/sso/login-implicit">Implicit SSO</a></li>
<li><a id="link-signin" href="{html.escape(app.sso_authorize_url(login))}">SSO direct link</a></li>
<li><a href="{html.escape(sess)}/endsession?post_logout_redirect_uri={app.base_url}/sso&amp;id_token_hint=FIXIDTOKENHINT">Log out of IdP</a></li>
</ul><button id="spa-signin">SPA SSO</button>"""
                script = f"document.getElementById('spa-signin').onclick=()=>{{location.href={json.dumps(spa)};}};"
                return self._send(200, _render("SSO", body, script))
            if sub == "/sso/login":
                return self._redirect(app.sso_authorize_url(login, prompt="login"))
            if sub == "/sso/login-silent":
                return self._redirect(app.sso_authorize_url(sess))
            if sub == "/sso/login-implicit":
                return self._redirect(app.sso_authorize_url(sess, implicit=True))
            if sub == "/sso/callback":
                for k in ("code", "state"):
                    app.issued_secrets.extend(q.get(k) or [])
                return self._redirect("/sso/home")
            if sub == "/sso/home":
                return self._send(200, _render("Signed in", "<p>signed in via SSO</p>"))
            return self._send(404, _render("Not found", "<p>not found</p>"))

        # -- /ev/*: event-recorder surfaces (cookies, redirects, console, WS, CORS) --
        def _get_ev(self, path, q):
            sub = path.strip("/").split("/")[1:]
            name = sub[0] if sub else ""
            if name == "":
                body = """<h1>Events</h1><ul>
<li><a href="/ev/cookies">Cookies</a></li>
<li><a href="/ev/redirect?next=/ev/landed">Redirecting</a></li>
<li><a href="/ev/console">Console</a></li><li><a href="/ev/delayed">Delayed</a></li>
<li><a href="/ev/ws">Socket</a></li><li><a href="/ev/noisy">Noisy</a></li>
<li><a href="/ev/redirect-out">Out two</a></li><li><a href="/ev/redirect-out1">Out one</a></li>
<li><a href="/ev/redirect-dead">Dead two</a></li><li><a href="/ev/redirect-dead1">Dead one</a></li><li><a href="/ev/cors">Cors</a></li>
<li><a href="/ev/pm-send">Pm send</a></li><li><a href="/ev/pm-listen">Pm listen</a></li>
<li><a href="/ev/pm-listen-safe">Pm listen safe</a></li><li><a href="/ev/jscookie">Js cookie</a></li>
<li><a href="/ev/idb">Idb</a></li><li><a href="/ev/storage">Storage</a></li>
<li><a href="/ev/blank">Blank</a></li><li><a href="/ev/sw">Sw</a></li>
<li><a href="/ev/forge">Forge</a></li><li><a href="/ev/overwrite">Overwrite</a></li><li><a href="/ev/flood">Flood</a></li>
<li><a href="/ev/hook-a">Hook a</a></li><li><a href="/ev/hook-b">Hook b</a></li></ul>"""
                return self._send(200, _render("Events", body))
            if name == "cookies":
                flags = "" if app.vulnerable else "; Secure; HttpOnly; SameSite=Lax"
                self.send_response(200)
                body = _render("Cookies", "<p>cookies set</p>")
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Set-Cookie", f"SID=FIXTURESECRET; Path=/{flags}")
                self.send_header("Set-Cookie", "theme=dark; Path=/")
                self.end_headers()
                self.wfile.write(body)
                return
            if name == "redirect":
                nxt = (q.get("next") or ["/ev/landed"])[0]
                # patched: the destination is fixed server-side, no redirect parameter
                return self._redirect("/ev/hop2?next=" + nxt if app.vulnerable else "/ev/hop2")
            if name == "redirect-out":
                return self._redirect("/ev/hop2-out")
            if name == "redirect-dead":
                return self._redirect("/ev/hop2-dead")
            if name == "hop2-dead":
                return self._redirect("http://127.0.0.1:1/dead")  # nothing listens: network failure
            if name == "redirect-dead1":
                return self._redirect("http://127.0.0.1:1/dead")
            if name == "hop2-out":
                return self._redirect(f"{app.alt_base_url}/elsewhere")
            if name == "redirect-out1":
                return self._redirect(f"{app.alt_base_url}/elsewhere")
            if name == "hop2":
                return self._redirect((q.get("next") or ["/ev/landed"])[0])
            if name == "landed":
                return self._send(200, _render("Landed", "<p>landed</p>"))
            if name == "console":
                script = """document.getElementById('boom').onclick=()=>{
  console.error('fixture console failure code 42'); throw new Error('fixture click error'); };"""
                return self._send(200, _render("Console", '<button id="boom">Trigger fault</button>', script))
            if name == "noisy":
                script = """document.getElementById('spam').onclick=()=>{
  for(let i=0;i<25;i++) console.error('noisy failure '+i); };"""
                return self._send(200, _render("Noisy", '<button id="spam">Make noise</button>', script))
            if name == "delayed":
                script = """document.getElementById('late').onclick=()=>{ fetch('/ev/delayed-set'); };"""
                return self._send(200, _render("Delayed", '<button id="late">Load later</button>', script))
            if name == "delayed-set":
                time.sleep(0.4)
                return self._send(200, b"ok", "text/plain",
                                  {"Set-Cookie": "late=FIXTURESECRET; Path=/"})
            if name == "ws":
                script = """const ws=new WebSocket('ws://'+location.host+'/ev/socket');
document.getElementById('sub').onclick=()=>{ ws.send(JSON.stringify({op:'sub',token:'FIXTURESECRET'})); };"""
                return self._send(200, _render("Socket", '<button id="sub">Open channel</button>', script))
            if name == "cors":
                script = """fetch('/api/cors').then(r=>r.json()).then(j=>{document.getElementById('o').textContent=j.ok;});"""
                return self._send(200, _render("Cors", '<p id="o"></p>', script))
            if name == "pm-send":
                script = """document.getElementById('pm').onclick=()=>{ window.postMessage({op:'sync',token:'FIXTURESECRET'}, TARGET); };"""
                script = script.replace("TARGET", "'*'" if app.vulnerable else "location.origin")
                return self._send(200, _render("Pm send", '<button id="pm">Send message</button>', script))
            if name == "pm-listen":
                guard = "" if app.vulnerable else "if(e.origin!==location.origin) return; "
                script = ("window.addEventListener('message', e=>{ " + guard + "document.title = String(e.data); });")
                return self._send(200, _render("Pm listen", '<p>listener</p><iframe src="/ev/pm-listen-safe"></iframe>', script))
            if name == "pm-listen-safe":
                script = """window.addEventListener('message', e=>{ if(e.origin!==location.origin) return; document.title='ok'; });"""
                return self._send(200, _render("Pm listen safe", "<p>safe listener</p>", script))
            if name == "jscookie":
                script = """document.getElementById('jc').onclick=()=>{ document.cookie='jsid=FIXTURESECRET; Path=/; SameSite=Lax'; };
document.getElementById('jn').onclick=()=>{ document.cookie='FIXTURESECRET'; };"""
                return self._send(200, _render("Js cookie", '<button id="jc">Remember me</button><button id="jn">Nameless cookie</button>', script))
            if name == "idb":
                script = """const rq=indexedDB.open('fixturedb',1);
rq.onupgradeneeded=()=>{ rq.result.createObjectStore('notes'); rq.result.createObjectStore('drafts'); };"""
                return self._send(200, _render("Idb", "<p>idb</p>", script))
            if name == "storage":
                script = """document.getElementById('st').onclick=()=>{ localStorage.setItem('authToken','FIXTURESECRET'); };"""
                return self._send(200, _render("Storage", '<button id="st">Keep me signed in</button>', script))
            if name == "tabnab":   # unlinked: an out-of-scope target=_blank link without noopener
                return self._send(200, _render("Tabnab", f'<a href="{app.alt_base_url}/ev/landed" target="_blank">Partner</a>'))
            if name == "blank":
                body = """<a href="/ev/landed" target="_blank" rel="noopener">Safe link</a>
<a href="/ev/landed?x=1" target="_blank">Unsafe link</a>
<a href="/ev/landed?ANCHORSECRET=1" target="_blank">Tracked link</a>
<button id="pop">Open popup</button>"""
                script = """document.getElementById('pop').onclick=()=>{ window.open('/ev/landed?p=1&access_token=POPUPSECRET#POPUPSECRET','_blank','noopener'); };"""
                return self._send(200, _render("Blank", body, script))
            if name == "sw":
                script = """navigator.serviceWorker.register('/ev/sw.js?token=FIXTURESECRET').then(
()=>fetch('/ev/sw-state?r=registered'), ()=>fetch('/ev/sw-state?r=blocked'));"""
                return self._send(200, _render("Sw", "<p>sw</p>", script))
            _find = """const names=Object.getOwnPropertyNames(window).filter(k=>k.startsWith('__hm')&&typeof window[k]==='function');"""
            if name == "forge":
                script = _find + """const forge=()=>{ for(const n of names){ for(const o of [
 {k:'wopen',url:'http://forged.invalid/x',noopener:false}, {k:'wopen',url:'http://forged.invalid/y',noopener:false,n:'guess'}]){
 try{ window[n](JSON.stringify(o)); }catch(e){} } } };
forge(); document.getElementById('fg').onclick=forge;"""
                return self._send(200, _render("Forge", '<button id="fg">Forge events</button>', script))
            if name == "overwrite":
                script = _find + """for(const n of names){ try{ window[n]=function(){ window.__intercepted=true; }; }catch(e){}
 try{ Object.defineProperty(window,n,{value:function(){ window.__intercepted=true; }}); }catch(e){} }
document.getElementById('ow').onclick=()=>{ window.postMessage({after:'overwrite'}, '*'); };"""
                return self._send(200, _render("Overwrite", '<button id="ow">Send after overwrite</button>', script))
            if name == "flood":
                script = """document.getElementById('fl').onclick=()=>{ for(let i=0;i<100;i++) window.postMessage({i:i}, '*'); };"""
                return self._send(200, _render("Flood", '<button id="fl">Flood messages</button>', script))
            if name in ("hook-a", "hook-b"):
                install = ("Object.defineProperty(Object.prototype,'n',{configurable:true,set(v){ window.__leak=v; }});"
                           if name == "hook-a" else
                           "Object.defineProperty(Object.prototype,'toJSON',{configurable:true,value:function(){ if(this&&this.n) window.__leak=this.n; return this; }});")
                script = _find + install + """document.getElementById('hk').onclick=()=>{
 window.postMessage({real:1}, '*'); window.open('/ev/landed','_blank','noopener');
 const lk=window.__leak; for(const n of names){ for(const p of [
  JSON.stringify({k:'wopen',url:'http://forged.invalid/z',noopener:false,n:lk}),
  String(lk)+'|'+JSON.stringify({k:'wopen',url:'http://forged.invalid/z',noopener:false})]){
  try{ window[n](p); }catch(e){} } } };"""
                return self._send(200, _render("Hook", '<button id="hk">Fire real events</button>', script))
            # -- DOM-XSS sources/sinks + postMessage probe (Task 4); own index so
            #    the /ev walk of test_ui_walk_events stays as it was --
            if name == "dom":
                body = """<h1>DOM</h1><ul>
<li><a href="/ev/dom-hash">Dom hash</a></li><li><a href="/ev/dom-hash-raw">Dom hash raw</a></li>
<li><a href="/ev/dom-name">Dom name</a></li><li><a href="/ev/pm-dom">Pm dom</a></li>
<li><a href="/ev/pm-oos">Pm oos</a></li><li><a href="/ev/spa">Spa</a></li>
<li><a href="/ev/dom-leak">Dom leak</a></li><li><a href="/ev/dom-cookie">Dom cookie</a></li>
<li><a href="/ev/dom-alert">Dom alert</a></li><li><a href="/ev/dom-store">Dom store</a></li>
<li><a href="/ev/redirect-secret">Redirect secret</a></li><li><a href="/ev/q-secret">Query secret</a></li>
<li><a href="/ev">All events</a></li></ul>"""
                return self._send(200, _render("DOM", body))
            sink = "innerHTML" if app.vulnerable else "textContent"
            if name == "dom-hash":
                script = f"""const render=()=>{{ const h=decodeURIComponent(location.hash.slice(1));
  document.getElementById('out').{sink}='Section: '+h; }};
window.addEventListener('hashchange', render); render();"""
                return self._send(200, _render("Dom hash", '<p id="out"></p>', script))
            if name == "dom-hash-raw":
                # undecoded hash: the token reaches the sink, the payload stays percent-encoded
                script = f"""window.addEventListener('hashchange', ()=>{{
  document.getElementById('out').{sink}='Raw: '+location.hash.slice(1); }});"""
                return self._send(200, _render("Dom hash raw", '<p id="out"></p>', script))
            if name == "dom-name":
                script = ("document.write('<p>Hello '+window.name+'</p>');" if app.vulnerable else
                          "const p=document.createElement('p'); p.textContent='Hello '+window.name; document.body.appendChild(p);")
                return self._send(200, _render("Dom name", "<p>name</p>", script))
            if name == "pm-dom":
                check = "" if app.vulnerable else "if(e.origin!==location.origin) return; "
                script = f"""window.addEventListener('message', e=>{{ {check}const d=e.data;
  document.getElementById('out').innerHTML='Got: '+(d && d.type!==undefined ? d.type : d); }});"""
                return self._send(200, _render("Pm dom", '<div id="out"></div>', script))
            if name == "pm-oos":
                return self._send(200, _render("Pm oos", f'<p>oos</p><iframe src="{app.alt_base_url}/ev/pm-oos-frame"></iframe>'))
            if name == "pm-oos-frame":
                script = """window.addEventListener('message', e=>{ fetch('/ev/pm-oos-hit'); document.title='hit'; });"""
                return self._send(200, _render("Pm oos frame", "<p>third-party listener</p>", script))
            if name == "pm-oos-hit":
                return self._send(200, b"ok", "text/plain")
            if name == "spa":
                script = """const ROUTES={'/route':'Route view: /route'};
const route=()=>{ const h=location.hash; if(h===''||h==='#'){ location.replace('#/route'); return; }
  const r=h.startsWith('#/') ? h.slice(1).split('?')[0] : '';
  document.getElementById('view').textContent=ROUTES[r]||'Not found'; };
window.addEventListener('hashchange', route); route();"""
                return self._send(200, _render("Spa", '<div id="view"></div>', script))
            if name == "dom-leak":
                # the page forwards its hash to the server: the walker must never let a canary out
                script = """window.addEventListener('hashchange', ()=>{ fetch('/ev/leak?d='+encodeURIComponent(location.hash.slice(1))); });"""
                return self._send(200, _render("Dom leak", "<p>leak</p>", script))
            if name == "dom-cookie":
                # the page copies its hash into a cookie, then makes a request (the cookie rides along)
                script = """window.addEventListener('hashchange', ()=>{
  document.cookie='lastsection='+encodeURIComponent(location.hash.slice(1))+'; path=/';
  fetch('/ev/landed?after=cookie'); });"""
                return self._send(200, _render("Dom cookie", "<p>cookie</p>", script))
            if name == "dom-alert":
                # echoes the decoded hash in a dialog: the payload is shown, never executed
                script = """window.addEventListener('hashchange', ()=>{
  alert('Bad route: '+decodeURIComponent(location.hash)); });"""
                return self._send(200, _render("Dom alert", "<p>alert</p>", script))
            if name == "dom-store":
                # copies the hash into web storage (it would persist into a saved session file)
                script = """window.addEventListener('hashchange', ()=>{
  localStorage.setItem('lastSection', location.hash.slice(1));
  sessionStorage.setItem('lastSection', location.hash.slice(1));
  localStorage.setItem('keep', 'kept-value'); });"""
                return self._send(200, _render("Dom store", "<p>store</p>", script))
            if name == "dom-store-key":
                # unlinked (fix wave): copies the hash into web-storage KEYS, which the
                # in-browser value scrub does not look at; only the post-save scrub can
                script = """window.addEventListener('hashchange', ()=>{
  localStorage.setItem('sec_'+location.hash.slice(1), '1');
  sessionStorage.setItem('ss_'+location.hash.slice(1), '1');
  localStorage.setItem('val', location.hash.slice(1));
  localStorage.setItem('keep', 'kept-value'); });"""
                return self._send(200, _render("Dom store key", "<p>store key</p>", script))
            if name == "leak":
                return self._send(200, b"ok", "text/plain")
            if name == "redirect-secret":
                return self._redirect("/ev/hop2?next=/ev/landed&code=FIXTURESECRET" if app.vulnerable
                                      else "/ev/hop2?code=FIXTURESECRET")
            if name == "q-secret":
                return self._send(200, _render("Query secret",
                                               '<iframe src="/ev/cookies?code=FIXTURESECRET"></iframe>'))
            if name == "sw-state":
                return self._send(200, b"ok", "text/plain")
            if name == "sw.js":
                return self._send(200, b"self.addEventListener('fetch',()=>{});", "application/javascript")
            return self._send(404, _render("Not found", "<p>not found</p>"))

        def _get_acct(self, path, q):
            if not self._authed():
                return self._redirect("/login")
            body = """
<h1>Account</h1><p id="who"></p>
<form id="pf"><label>Display name <input name="display_name" id="dn" value="Tester"></label>
<button type="button" id="save">Save</button></form>
<form id="ef"><label>New email <input name="new_email" id="ne" type="email" value="new@example.invalid"></label>
<label>Code <input name="otp" id="otp" value=""></label>
<button type="button" id="chg">Change email</button></form>
<a href="/api/v3/transfer-preview?to=u-1001">Transfer preview</a>
<a href="/api/v3/promo-check?promo=WELCOME0">Check promo</a>"""
            script = """
fetch('/api/v3/me').then(r=>r.json()).then(m=>{document.getElementById('who').textContent=m.display_name;});
document.getElementById('save').onclick=()=>fetch('/api/v3/profile',{method:'PUT',
  headers:{'Content-Type':'application/json'},body:JSON.stringify({display_name:document.getElementById('dn').value})});
document.getElementById('chg').onclick=()=>fetch('/api/v3/account/change-email',{method:'POST',
  headers:{'Content-Type':'application/json'},
  body:JSON.stringify({email:document.getElementById('ne').value,otp:document.getElementById('otp').value})});"""
            self._send(200, _render("Account", body, script))

        def _get_qsink(self, path, q):
            sink = "innerHTML" if app.vulnerable else "textContent"
            script = ("const m=new URLSearchParams(location.search).get('msg')||'';"
                      f"document.getElementById('out').{sink}=m;")
            self._send(200, _render("Message", '<div id="out"></div>', script))

        def _v3_gate(self):
            """None to go on, else the response already sent (401 / 429)."""
            with app._lock:
                app.v3_requests += 1
                n = app.v3_requests
            if app.v3_rate_limit_after is not None and n > app.v3_rate_limit_after:
                return self._json(429, {"error": "Too Many Requests"}) or True
            if app.v3_expire_after is not None and n > app.v3_expire_after:
                app.valid_sids.clear()
            if not self._authed():
                return self._json(401, {"error": "unauthenticated"}) or True
            return None

        def _me(self):
            return app.v3_other if self._sid() in app.other_sids else app.v3_me

        def _get_api_v3(self, parts, q):
            if self._v3_gate():
                return
            if parts == ["api", "v3", "me"]:
                return self._json(200, dict(self._me()))
            if parts == ["api", "v3", "transfer-preview"]:
                to = q.get("to") or []
                if not to:
                    return self._json(400, {"error": "to required"})
                if len(to) > 1 and not app.vulnerable:
                    return self._json(400, {"error": "duplicate to"})
                if to[0] != self._me()["id"]:
                    return self._json(403, {"error": "not your account"})
                return self._json(200, {"preview_for": to[-1], "amount": 0})
            if parts == ["api", "v3", "promo-check"]:
                if "promo[]" in q:
                    if app.vulnerable:   # emulates a loose (array) comparison
                        return self._json(200, {"valid": True})
                    return self._json(400, {"error": "bad code"})
                if (q.get("promo") or [""])[0] == app.v3_promo:
                    return self._json(200, {"valid": True})
                return self._json(403, {"valid": False})
            return self._json(404, {"error": "not found"})

        def _mutate_v3(self, method, parts, raw):
            if self._v3_gate():
                return
            me = self._me()
            try:
                data = json.loads(raw or b"{}")
            except ValueError:
                return self._json(400, {"error": "bad json"})
            if not isinstance(data, dict):
                return self._json(400, {"error": "bad json"})
            if parts == ["api", "v3", "profile"] and method in ("PUT", "PATCH"):
                keys = list(data) if app.vulnerable else [k for k in data if k == "display_name"]
                for k in keys:
                    if k == "id" or (k == "role" and app.v3_sticky_role and me.get("role") != "user"):
                        continue
                    me[k] = data[k]
                return self._json(200, {"ok": True})
            if parts == ["api", "v3", "account", "change-email"] and method == "POST":
                if "otp" in data or not app.vulnerable:
                    if data.get("otp") != app.v3_otp:
                        return self._json(403, {"error": "bad code"})
                if not isinstance(data.get("email"), str) or "@" not in data["email"]:
                    return self._json(400, {"error": "bad email"})
                me["email"] = data["email"]
                return self._json(200, {"ok": True})
            return self._json(404, {"error": "not found"})

        def _get_api(self, path, q):
            parts = [p for p in path.split("/") if p]
            if parts[:2] == ["api", "v3"]:
                return self._get_api_v3(parts, q)
            if parts[:2] == ["api", "items"]:
                if len(parts) == 2:
                    live = [dict(it) for it in app.items.values() if not it["deleted"]]
                    return self._json(200, live)
                it = app.items.get(parts[2])
                if it is None or (it["deleted"] and not app.vulnerable):
                    return self._json(404, {"error": "not found"})
                return self._json(200, it)
            if parts == ["api", "cors"]:
                origin = (self.headers.get("Origin") or f"http://{self.headers.get('Host')}"
                          if app.vulnerable else "http://allowed.test")
                return self._send(200, b'{"ok": "cors"}', "application/json",
                                  {"Access-Control-Allow-Origin": origin,
                                   "Access-Control-Allow-Credentials": "true"})
            return self._json(404, {"error": "not found"})

        # -- mutations ------------------------------------------------------
        def _mutate(self, method: str):
            if self._refused_proxied():
                return
            path = urlsplit(self.path).path
            raw = self._body()
            parts = [p for p in path.split("/") if p]
            if path == "/api/contact" and method == "POST":
                # vulnerable: rotates a session cookie on an unauthenticated POST
                hdr = {"Set-Cookie": "SID=FIXTURESECRET; Path=/"} if app.vulnerable else None
                return self._send(200, _render("Thanks", "<p>thanks</p>"), headers=hdr)
            if not self._authed():
                return self._json(401, {"error": "unauthenticated"})
            if parts[:2] == ["api", "v3"]:
                return self._mutate_v3(method, parts, raw)
            if parts[:2] == ["api", "items"]:
                if method == "POST" and len(parts) == 2:
                    try:
                        data = json.loads(raw or b"{}")
                    except ValueError:
                        data = {}
                    iid = app.seed_item(str(data.get("name") or ""), str(data.get("description") or ""))
                    return self._json(201, {"id": iid})
                if method == "DELETE" and len(parts) == 3:
                    it = app.items.get(parts[2])
                    if it is None:
                        return self._json(404, {"error": "not found"})
                    if app.vulnerable:
                        it["deleted"] = True
                    else:
                        del app.items[parts[2]]
                    return self._json(200, {"deleted": parts[2]})
            if path == "/api/account/delete" and method == "POST":
                app.account_deleted = True
                if not app.vulnerable:
                    app.valid_sids.clear()
                return self._json(200, {"deleted": True})
            if path in ("/api/profile", "/api/keys", "/api/purge", "/api/popup-post",
                        "/api/account/close", "/api/orders", "/api/p1", "/api/p2"):
                if path == "/api/purge":
                    for it in app.items.values():
                        it["deleted"] = True
                return self._json(200, {"ok": True})
            return self._json(404, {"error": "not found"})

    return Handler
