"""Session keep-alive Task 3: the human's own login teaches which login hosts a
later silent renewal may pass through (learned renewal_hosts) + app_url."""

import asyncio
import json
import os
import time

import capture_confirm
import engagement_paths
import scope_guard
import session_capture

SENTINEL = "S3NTINEL_COOKIE_VALUE"
ENG = scope_guard.Engagement(target="t.com", in_scope=["*.t.com", "t.com"], out_of_scope=["evil.t.com", "blocked.idp.net"])


class _Frame:
    def __init__(self, parent=None):
        self.parent_frame = parent


class _Req:
    def __init__(self, url, nav=True, main=True):
        self.url = url
        self._nav = nav
        self.frame = _Frame(None if main else _Frame())

    def is_navigation_request(self):
        return self._nav


class _Page:
    def __init__(self, url):
        self.url = url


class _Ctx:
    async def cookies(self):
        return [{"name": "sid", "value": SENTINEL, "domain": "app.t.com", "path": "/", "httpOnly": True,
                 "secure": True, "sameSite": "Lax", "expires": -1}]

    async def storage_state(self):
        return {"cookies": await self.cookies(), "origins": []}

    async def close(self):
        pass


class _P:
    async def stop(self):
        pass


def test_record_nav_only_main_frame_navigations():
    hosts = []
    session_capture._record_nav(hosts, _Req("https://t.auth0.com/authorize"))
    session_capture._record_nav(hosts, _Req("https://t.auth0.com/u/login"))  # same host twice -> once
    session_capture._record_nav(hosts, _Req("https://cdn.x.net/app.js", nav=False))
    session_capture._record_nav(hosts, _Req("https://ads.x.net/frame", main=False))
    session_capture._record_nav(hosts, object())  # broken request object: swallowed
    assert hosts == ["t.auth0.com"]


def test_record_nav_ignores_popups():
    class Pg:
        main_frame = object()

    hosts = []
    session_capture._record_nav(hosts, _Req("https://popup.x.net/"), Pg())  # another page's main frame
    assert hosts == []


def test_learned_hosts_exclude_in_scope_and_out_of_scope():
    nav = ["app.t.com", "evil.t.com", "blocked.idp.net", "t.auth0.com", "login.microsoftonline.com",
           "10.0.0.9", "app.t.com"]
    assert session_capture.learned_renewal_hosts(nav, ENG) == ["login.microsoftonline.com", "t.auth0.com"]


def test_learned_hosts_only_before_last_app_landing():
    # hosts browsed AFTER returning to the app are not part of the login
    nav = ["app.t.com", "t.auth0.com", "app.t.com", "docs.google.com", "news.example.org"]
    assert session_capture.learned_renewal_hosts(nav, ENG) == ["t.auth0.com"]
    assert session_capture.learned_renewal_hosts(["t.auth0.com", "x.y.net"], ENG) == []  # never came back


def test_learned_hosts_capped():
    nav = [f"h{i}.idp.net" for i in range(9)] + ["app.t.com"]
    assert len(session_capture.learned_renewal_hosts(nav, ENG)) == session_capture.MAX_LEARNED_HOSTS


def test_app_url_requires_explicit_scope():
    class P:
        url = "http://evil.sh/x"

    assert session_capture._app_url(P(), "https://app.t.com/login", ENG) == "https://app.t.com/login"


def _seed(page_url, nav_hosts):
    slug = engagement_paths.get_active_target()
    live = session_capture._LiveCapture(_P(), _Ctx(), _Page(page_url) if page_url else None, "fp", {}, ENG,
                                        "https://app.t.com/login", slug, "xyz", 0.0)
    live.nav_hosts.extend(nav_hosts)
    session_capture._live_captures[(slug, "xyz")] = live
    tpath = capture_confirm.confirmation_token_path(slug, "xyz")
    os.makedirs(os.path.dirname(tpath), exist_ok=True)
    with open(tpath, "w") as f:
        json.dump({"slug": slug, "label": "xyz", "fingerprint": "fp", "ts": time.time()}, f)


def _identity():
    with open(engagement_paths.resolve("secrets/identities.json")) as fh:
        return json.load(fh)["xyz"]


def test_finish_capture_writes_renewal_hosts_app_url_and_summary():
    session_capture._live_captures.clear()
    _seed("https://app.t.com/dashboard", ["app.t.com", "t.auth0.com", "app.t.com"])
    out = asyncio.run(session_capture.finish_capture("xyz", whoami_url="https://api.t.com/me"))
    assert SENTINEL not in json.dumps(out)
    assert out["renewal_hosts"] == ["t.auth0.com"]
    entry = _identity()
    assert entry["renewal_hosts"] == ["t.auth0.com"]
    assert entry["app_url"] == "https://app.t.com/dashboard"
    assert entry["whoami_url"] == "https://api.t.com/me"


def test_finish_capture_app_url_falls_back_when_page_left_scope_or_missing():
    session_capture._live_captures.clear()
    _seed("https://t.auth0.com/u/login", [])
    asyncio.run(session_capture.finish_capture("xyz"))
    assert _identity()["app_url"] == "https://app.t.com/login"
    session_capture._live_captures.clear()
    _seed(None, [])
    asyncio.run(session_capture.finish_capture("xyz"))
    entry = _identity()
    assert entry["app_url"] == "https://app.t.com/login" and entry["renewal_hosts"] == []
