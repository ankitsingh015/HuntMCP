"""#164 local fixture app for the UI-walk (loopback only, stdlib http.server).

Exhibits, in one small app, every UI-only surface the walker must handle:
lazy-loaded third-party-origin iframe form (the Marketo case), modal- and
tab-revealed inputs, a cross-page stored-XSS render sink, a soft delete
(object still reachable after delete), a logout that does not invalidate the
server session, a sessionStorage-token SPA, a payment button, an out-of-scope
link, an icon-only and a non-English destructive button, a popup that POSTs
on load, an unbounded calendar URL space, and a very tall page.

`vulnerable=False` serves the PATCHED variant (escaped renders, hard delete,
invalidating logout and account deletion) so tests can check the walker
distinguishes the two.

NOT a protected benchmark -- an ordinary test fixture.
"""

from __future__ import annotations

import json
import os
import secrets
import threading
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


class FixtureApp:
    def __init__(self, vulnerable: bool = True):
        self.vulnerable = vulnerable
        self.requests: list[tuple[str, str]] = []
        self.items: dict[str, dict] = {}
        self.valid_sids: set[str] = set()
        self.account_deleted = False
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

    def non_get_requests(self) -> list[tuple[str, str]]:
        return [(m, p) for m, p in self.requests if m not in ("GET", "HEAD", "OPTIONS")]

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def serve(vulnerable: bool = True) -> FixtureApp:
    return FixtureApp(vulnerable=vulnerable)


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

        # -- verbs ----------------------------------------------------------
        def do_HEAD(self):
            self._log()
            self._send(200, b"")

        def do_OPTIONS(self):
            self._log()
            self._send(204, b"")

        def do_GET(self):
            self._log()
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

        def _get_api(self, path, q):
            parts = [p for p in path.split("/") if p]
            if parts[:2] == ["api", "items"]:
                if len(parts) == 2:
                    live = [dict(it) for it in app.items.values() if not it["deleted"]]
                    return self._json(200, live)
                it = app.items.get(parts[2])
                if it is None or (it["deleted"] and not app.vulnerable):
                    return self._json(404, {"error": "not found"})
                return self._json(200, it)
            return self._json(404, {"error": "not found"})

        # -- mutations ------------------------------------------------------
        def _mutate(self, method: str):
            path = urlsplit(self.path).path
            raw = self._body()
            parts = [p for p in path.split("/") if p]
            if path == "/api/contact" and method == "POST":
                return self._send(200, _render("Thanks", "<p>thanks</p>"))
            if not self._authed():
                return self._json(401, {"error": "unauthenticated"})
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
