"""Spec 2 (in-scope SSO / auth flows as surface): the per-walk SSO tracker.

The walker feeds every URL it already sees (interceptor, redirect chains,
control hrefs) into SsoTracker. `data` becomes inv["sso"] and holds only
non-secret facts (ui_walk_sso_logic Values policy). The first state/nonce of
each flow is kept in `_first` -- memory only, for the one repeat comparison --
and dropped by finish_repeat()/drop_secrets(); it is never part of `data`.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ui_walk_sso_logic as S  # noqa: E402
from endpoint_template import endpoint_template  # noqa: E402

MAX_CHAIN_HOPS = 20


def _netloc(url: str) -> str:
    try:
        return (urlsplit(url).netloc or "").lower()
    except ValueError:
        return ""


class SsoTracker:
    def __init__(self, scope: Callable[[str], bool]):
        self._scope = scope
        self.data: dict = {"flows": [], "endpoints": [], "discovery": [], "idp_hosts": [],
                           "repeats": 0, "discovery_gets": 0, "out_of_scope_idp_redirects": []}
        self._flows: dict[str, dict] = {}
        self._endpoint_keys: set = set()
        self._first: dict[str, dict] = {}        # flow key -> {"state", "nonce"}  (MEMORY ONLY)
        self._source: dict[str, dict] = {}       # flow key -> repeat source
        self._authorize_url: dict[str, str] = {}  # idp netloc -> one authorize URL (stripped) for discovery
        self._expect: str | None = None          # repeat kind c: flow key whose next authorize URL is wanted
        self._second: dict[str, str] = {}        # flow key -> that URL (MEMORY ONLY)

    # -- helpers -----------------------------------------------------------
    def _in_scope(self, url: str) -> bool:
        try:
            return bool(self._scope(url))
        except Exception:  # noqa: BLE001 -- a scope error is "not in scope"
            return False

    def is_idp_host(self, netloc: str) -> bool:
        return (netloc or "").lower() in self.data["idp_hosts"]

    def is_idp_url(self, url: str) -> bool:
        return self.is_idp_host(_netloc(url))

    @staticmethod
    def chain_has_authorize(urls) -> bool:
        return any(isinstance(u, str) and S.classify_url(u) in ("authorize", "saml-request")
                   for u in list(urls or [])[:MAX_CHAIN_HOPS])

    def authorize_url_for(self, netloc: str) -> str | None:
        return self._authorize_url.get(netloc)

    def flow(self, key: str) -> dict | None:
        return self._flows.get(key)

    # -- observation ---------------------------------------------------------
    def observe_url(self, url, *, method: str = "GET", seen_via: str, page, control_signature,
                    body_fields=None) -> str | None:
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            return None
        role = S.classify_url(url, method, body_fields)
        if role is None:
            return None
        in_scope = self._in_scope(url)
        netloc = _netloc(url)
        method = (method or "GET").upper()
        try:
            tmpl = endpoint_template(S._clean_url(url))
        except Exception:  # noqa: BLE001
            tmpl = S._clean_url(url)
        self._endpoint(role, url, method, tmpl, in_scope, seen_via, page, control_signature)
        if role in ("authorize", "saml-request") and in_scope and netloc not in self.data["idp_hosts"]:
            self.data["idp_hosts"].append(netloc)
        if role == "authorize":
            self._observe_authorize(url, netloc, in_scope, seen_via, page, control_signature)
        return role

    def _endpoint(self, role, url, method, tmpl, in_scope, seen_via, page, ctl) -> None:
        ekey = (role, method, tmpl)   # one record (one node) per endpoint; the first page seen is its parent
        if ekey in self._endpoint_keys:
            return
        self._endpoint_keys.add(ekey)
        ep = {"role": role, "method": method, "url": S._clean_url(url), "in_scope": in_scope,
              "param_names": sorted({k.lower() for k, _ in S.all_params(url)})[:30],
              "seen_via": seen_via, "page": page, "control_signature": ctl}
        if role == "logout":
            lf = S.logout_flags(url)
            ep["redirect_params"] = lf["redirect_params"]
            ep["post_logout_redirect_uri"] = lf["post_logout_redirect_uri"]
        self.data["endpoints"].append(ep)

    def record_discovery(self, netloc: str, url: str, status, parsed: dict | None, *, page) -> None:
        """One discovery GET. Endpoints it lists are recorded with the role the
        document gives them (their paths need not look like OAuth paths)."""
        entry = {"host": netloc, "url": S._clean_url(url), "status": status,
                 "issuer": (parsed or {}).get("issuer"), "endpoints": (parsed or {}).get("endpoints") or [],
                 "supported": (parsed or {}).get("supported") or {}}
        self.data["discovery"].append(entry)
        if parsed is None:
            return
        self._endpoint("discovery", url, "GET", S._clean_url(url), True, "discovery", page, None)
        for ep in entry["endpoints"]:
            try:
                tmpl = endpoint_template(ep["url"])
            except Exception:  # noqa: BLE001
                tmpl = ep["url"]
            self._endpoint(ep["role"], ep["url"], S.ENDPOINT_METHOD.get(ep["role"], "GET"), tmpl,
                           ep["in_scope"], "discovery", page, None)

    def page_for_host(self, netloc: str):
        return next((f["page"] for f in self.data["flows"] if f["idp_host"] == netloc), None)

    def expect_authorize(self, key: str | None) -> None:
        self._expect = key

    def take_second(self, key: str) -> str | None:
        return self._second.pop(key, None)

    def _observe_authorize(self, url, netloc, in_scope, seen_via, page, ctl) -> None:
        key = S.flow_key(url)
        if self._expect == key and key in self._flows:
            self._second[key] = url
        if in_scope:
            self._authorize_url.setdefault(netloc, S._clean_url(url))
        flow = self._flows.get(key)
        if flow is None:
            flow = {"key": key, "authorize": S.authorize_flags(url), "idp_host": netloc,
                    "idp_in_scope": in_scope, "page": page, "control_signature": ctl, "seen_via": seen_via,
                    "state_changes_per_request": "unknown", "nonce_changes_per_request": "unknown",
                    "state_echoed_on_callback": "unknown", "repeat": None}
            self._flows[key] = flow
            self.data["flows"].append(flow)
            self._first[key] = S.secrets_of(url)
        if key not in self._source and flow["repeat"] is None:
            if seen_via == "href":
                self._source[key] = {"kind": "b", "page": page, "control_signature": ctl}
            elif seen_via in ("request", "aborted") and ctl is not None:
                self._source[key] = {"kind": "c", "page": page, "control_signature": ctl}

    def observe_chain(self, urls, *, page, control_signature) -> None:
        """One navigation's redirect chain (full URLs, in memory). Never raises."""
        try:
            hops = [u for u in list(urls or [])[:MAX_CHAIN_HOPS] if isinstance(u, str)]
        except Exception:  # noqa: BLE001
            return
        last_key, last_state, first_hop = None, None, None
        for u in hops:
            try:
                role = self.observe_url(u, seen_via="redirect-hop", page=page,
                                        control_signature=control_signature)
            except Exception:  # noqa: BLE001
                continue
            if role == "authorize":
                last_key = S.flow_key(u)
                last_state = S.secrets_of(u).get("state")
                if first_hop and last_key not in self._source and self._flows[last_key]["repeat"] is None:
                    self._source[last_key] = {"kind": "a", "url": first_hop}
            elif role == "callback" and last_key is not None:
                cb_state = S.secrets_of(u).get("state")
                if last_state:
                    self._flows[last_key]["state_echoed_on_callback"] = cb_state == last_state
            elif role is None and last_key is None and self._in_scope(u) and not S.is_callback_url(u):
                first_hop = u   # the LAST in-scope app hop before the authorize: its Location is the authorize URL

    def note_out_of_scope_redirect(self, url: str, *, page, control_signature) -> None:
        rec = {"host": _netloc(url), "url": S._clean_url(url), "page": page,
               "control_signature": control_signature}
        if rec not in self.data["out_of_scope_idp_redirects"]:   # the walker and the recorder both report a chain
            self.data["out_of_scope_idp_redirects"].append(rec)

    # -- the repeat ------------------------------------------------------------
    def pending_repeats(self) -> list[tuple[str, dict]]:
        return [(k, dict(src)) for k, src in self._source.items()
                if self._flows.get(k, {}).get("repeat") is None]

    def finish_repeat(self, key: str, second_url: str | None, kind: str, *, result: str | None = None) -> None:
        flow = self._flows.get(key)
        if flow is None:
            return
        second = S.secrets_of(second_url) if second_url else None
        cmp = S.compare_secrets(self._first.get(key) or {}, second)
        flow.update(cmp)
        compared = second is not None and any(v != "unknown" for v in cmp.values())
        flow["repeat"] = {"kind": kind, "result": result or ("compared" if compared else "unknown")}
        self._first.pop(key, None)
        self._source.pop(key, None)

    def drop_secrets(self) -> None:
        self._first.clear()
        self._second.clear()
        self._expect = None
        self._source.clear()   # kind-a sources hold raw URLs
