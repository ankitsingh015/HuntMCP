"""Constructed authorization-differential benchmark target (TEST FIXTURE ONLY).

P3-VALAUTHZ's own ground-truth range. Loopback-only (127.0.0.1, ephemeral
port), zero outbound calls, two behavior modes ("vulnerable"/"patched"),
bearer-token identities (synthetic fixture tokens only). Keeps an
independent in-process request log and mutation counter so a test can verify
what the tool under test actually sent, from the target's own side.

Does NOT import authz_scenarios/authz_answer_key/authz_evaluator -- this app
has no path to its own expected answers (benchmarks.md blindness rule).

Planted behaviors (labels live ONLY in authz_answer_key.py):
  - an opaque per-identity id carried from step 1 (/authz/refs) into a
    step-2 object endpoint whose ownership check is missing in "vulnerable"
  - a single-step by-id object endpoint (what the existing sweep covers)
  - three look-alikes that must NEVER be reported in either mode: a public
    resource, an endpoint that ignores the id and returns the caller's own
    view, and an endpoint that denies with HTTP 200 + an error body
  - one state-changing POST, used to prove the human gate sends nothing
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

LOOPBACK = "127.0.0.1"

ALICE = "tok-alice-authz-fixture"
BOB = "tok-bobby-authz-fixture"
CAROL = "tok-carol-authz-fixture"   # a user of ANOTHER tenant (t2)
ROOT = "tok-root-authz-fixture"     # an administrator of tenant t1
_IDENTITIES = {ALICE: "alice", BOB: "bobby", CAROL: "carol", ROOT: "root"}
_TENANT = {"alice": "t1", "bobby": "t1", "carol": "t2", "root": "t1"}
_ADMINS = frozenset({"root"})

_REFS = {
    "alice": {"cart_ref": "ck-7f3a91", "order_id": "42", "profile_ref": "pr-a11ce0",
              "note_ref": "nt-5c20e1", "catalog_ref": "sku-100",
              "report_ref": "rp-31c4e2", "stmt_ref": "st-6be2f0"},
    "bobby": {"cart_ref": "ck-2b8d04", "order_id": "43", "profile_ref": "pr-b0bb70",
              "note_ref": "nt-91d4aa", "catalog_ref": "sku-100",
              "report_ref": "rp-8a07dd", "stmt_ref": "st-19c7a4"},
    "carol": {"cart_ref": "ck-c4a901", "order_id": "44", "profile_ref": "pr-ca0100",
              "note_ref": "nt-c4a902", "catalog_ref": "sku-100",
              "report_ref": "rp-c4a903", "stmt_ref": "st-c4a904"},
    "root": {"cart_ref": "ck-r00t01", "order_id": "45", "profile_ref": "pr-r00t02",
             "note_ref": "nt-r00t03", "catalog_ref": "sku-100",
             "report_ref": "rp-r00t04", "stmt_ref": "st-r00t05"},
}
_REFS["alice"].update({"ledger_ref": "lg-5d11aa", "doc_ref": "td-90c3b2"})
_REFS["bobby"].update({"ledger_ref": "lg-2e7c40", "doc_ref": "td-a1b2c3"})
_REFS["carol"].update({"ledger_ref": "lg-77aa10", "doc_ref": "td-c0ffee"})
_REFS["root"].update({"ledger_ref": "lg-00r001", "doc_ref": "td-00r002"})


def _owner_of(kind: str, ref: str) -> str | None:
    for user, refs in _REFS.items():
        if refs.get(kind) == ref:
            return user
    return None


class _State:
    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.lock = threading.Lock()
        self.request_log: list[dict] = []
        self.mutation_count = 0
        self.volatile_counter = 0
        self.created: dict[str, dict] = {}  # ref -> {"kind", "owner", "title"} for create-then-read cases
        self.create_counter = 0

    def volatile_fields(self) -> dict:
        """Per-request fields (a timestamp-like value and a request id) that differ on EVERY
        response, even for the same object and caller."""
        with self.lock:
            self.volatile_counter += 1
            n = self.volatile_counter
        return {"generated_at": f"T{n:06d}", "request_id": f"req-{n}"}


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a, **k) -> None:
        return

    def _send(self, status: int, payload) -> None:
        body = (payload if isinstance(payload, str) else json.dumps(payload)).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _caller(self) -> str | None:
        auth = self.headers.get("Authorization", "")
        return _IDENTITIES.get(auth[7:]) if auth.startswith("Bearer ") else None

    def _record(self, method: str, path: str, qs: dict, body: str = "") -> None:
        st: _State = self.server.state  # type: ignore[attr-defined]
        with st.lock:
            st.request_log.append({
                "method": method, "path": path, "query": qs, "body": body[:500],
                "authorization": self.headers.get("Authorization", ""),
                "headers": dict(self.headers.items()),
            })

    def _owned_or_refused(self, caller: str, owner: str) -> bool:
        st: _State = self.server.state  # type: ignore[attr-defined]
        return st.mode == "vulnerable" or caller == owner

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        self._record("GET", path, parse_qs(parsed.query))
        caller = self._caller()

        if path.startswith("/authz/catalog/"):  # public: no auth needed
            self._send(200, {"sku": path.rsplit("/", 1)[-1], "name": "Widget", "price": "9.99"})
            return

        if caller is None:
            self._send(401, {"error": "unauthenticated"})
            return

        if path == "/authz/refs":
            self._send(200, _REFS[caller])
            return

        if path.startswith("/authz/carts/") and path.endswith("/invoice"):
            ref = path.split("/")[3]
            owner = _owner_of("cart_ref", ref)
            if owner is None:
                self._send(404, {"error": "no such cart"})
            elif self._owned_or_refused(caller, owner):
                self._send(200, {"cart": ref, "owner": owner, "total": "149.00",
                                 "currency": "EUR", "items": ["widget", "gadget"]})
            else:
                self._send(403, {"error": "forbidden"})
            return

        if path.startswith("/authz/orders/"):
            oid = path.rsplit("/", 1)[-1]
            owner = _owner_of("order_id", oid)
            if owner is None:
                self._send(404, {"error": "no such order"})
            elif self._owned_or_refused(caller, owner):
                self._send(200, {"order": oid, "owner": owner, "status": "shipped", "total": "59.90"})
            else:
                self._send(403, {"error": "forbidden"})
            return

        st: _State = self.server.state  # type: ignore[attr-defined]

        if path.startswith("/authz/reports/"):  # ownership check missing in "vulnerable"; volatile fields
            ref = path.rsplit("/", 1)[-1]
            owner = _owner_of("report_ref", ref)
            if owner is None:
                self._send(404, {"error": "no such report"})
            elif self._owned_or_refused(caller, owner):
                self._send(200, {"report": ref, "owner": owner, "period": "2026-Q3", "total": "88.10",
                                 "currency": "EUR", **st.volatile_fields()})
            else:
                self._send(403, {"error": "forbidden"})
            return

        if path.startswith("/authz/statements/"):  # soft-deny (HTTP 200) with volatile fields, BOTH modes
            ref = path.rsplit("/", 1)[-1]
            owner = _owner_of("stmt_ref", ref)
            if owner is None:
                self._send(404, {"error": "no such statement"})
            elif caller == owner:
                self._send(200, {"statement": ref, "owner": owner, "balance": "12.00",
                                 "currency": "EUR", **st.volatile_fields()})
            else:
                self._send(200, {"error": "not_yours", **st.volatile_fields()})
            return

        for kind in ("draft", "receipt"):  # create-then-read objects made by POST /authz/<kind>s
            if path.startswith(f"/authz/{kind}s/"):
                ref = path.rsplit("/", 1)[-1]
                item = st.created.get(ref)
                if item is None or item["kind"] != kind:
                    self._send(404, {"error": f"no such {kind}"})
                    return
                # drafts: ownership check missing in "vulnerable"; receipts: enforced in BOTH modes
                allowed = self._owned_or_refused(caller, item["owner"]) if kind == "draft" else caller == item["owner"]
                if allowed:
                    self._send(200, {kind: ref, "owner": item["owner"], "title": item["title"],
                                     "status": "open", "version": 1})
                else:
                    self._send(403, {"error": "forbidden"})
                return

        if path.startswith("/authz/ledger/"):  # vulnerable: no ownership check; patched: owner or an admin
            ref = path.rsplit("/", 1)[-1]
            owner = _owner_of("ledger_ref", ref)
            if owner is None:
                self._send(404, {"error": "no such ledger"})
            elif st.mode == "vulnerable" or caller == owner or caller in _ADMINS:
                self._send(200, {"ledger": ref, "owner": owner, "balance": "1200.50",
                                 "currency": "EUR", "entries": 3})
            else:
                self._send(403, {"error": "forbidden"})
            return

        if path.startswith("/authz/teamdocs/"):  # vulnerable: no tenant isolation; patched: same tenant only
            ref = path.rsplit("/", 1)[-1]
            owner = _owner_of("doc_ref", ref)
            if owner is None:
                self._send(404, {"error": "no such document"})
            elif st.mode == "vulnerable" or _TENANT[caller] == _TENANT[owner]:
                self._send(200, {"doc": ref, "owner": owner, "tenant": _TENANT[owner],
                                 "title": "Q3 roadmap", "classification": "internal"})
            else:
                self._send(403, {"error": "forbidden"})
            return

        if path.startswith("/authz/profiles/"):  # ignores the id: always the caller's own view
            self._send(200, {"owner": caller, "email": f"{caller}@authz.test", "plan": "basic",
                             "region": "eu-west", "tier": "standard", "locale": "en-GB"})
            return

        if path.startswith("/authz/notes/"):  # soft-deny: HTTP 200 + error body, in BOTH modes
            ref = path.rsplit("/", 1)[-1]
            owner = _owner_of("note_ref", ref)
            if owner is None:
                self._send(404, {"error": "no such note"})
            elif caller == owner:
                self._send(200, {"note": ref, "owner": owner, "text": "private note body"})
            else:
                self._send(200, {"error": "not_yours"})
            return

        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        st: _State = self.server.state  # type: ignore[attr-defined]
        parsed = urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode(errors="replace") if length else ""
        self._record("POST", path, parse_qs(parsed.query), raw)
        caller = self._caller()
        if caller is None:
            self._send(401, {"error": "unauthenticated"})
            return
        if path in ("/authz/drafts", "/authz/receipts"):
            kind = "draft" if path.endswith("drafts") else "receipt"
            try:
                title = str(json.loads(raw).get("title", "untitled"))[:60] if raw else "untitled"
            except (ValueError, AttributeError):
                title = "untitled"
            with st.lock:
                st.create_counter += 1
                ref = f"{kind[:2]}-{st.create_counter:04d}-{caller[:1]}"
                st.created[ref] = {"kind": kind, "owner": caller, "title": title}
                st.mutation_count += 1
            self._send(201, {f"{kind}_ref": ref})
            return
        if path.startswith("/authz/carts/") and path.endswith("/cancel"):
            ref = path.split("/")[3]
            owner = _owner_of("cart_ref", ref)
            if owner is None:
                self._send(404, {"error": "no such cart"})
            elif self._owned_or_refused(caller, owner):
                with st.lock:
                    st.mutation_count += 1
                self._send(200, {"cart": ref, "status": "cancelled"})
            else:
                self._send(403, {"error": "forbidden"})
            return
        self._send(404, {"error": "not found"})


def _make_server(mode: str, bind: str = LOOPBACK, port: int = 0) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((bind, port), _Handler)
    server.state = _State(mode)  # type: ignore[attr-defined]
    return server


class AuthzApp:
    def __init__(self, mode: str) -> None:
        assert mode in ("vulnerable", "patched")
        self.mode = mode
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> "AuthzApp":
        self._server = _make_server(self.mode)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()

    @property
    def base_url(self) -> str:
        _host, port = self._server.server_address  # type: ignore[union-attr]
        return f"http://{LOOPBACK}:{port}"

    @property
    def request_log(self) -> list[dict]:
        return self._server.state.request_log  # type: ignore[attr-defined]

    @property
    def mutation_count(self) -> int:
        return self._server.state.mutation_count  # type: ignore[attr-defined]
