"""#164 UI-walk TEARDOWN: the last, human-gated step of an engagement.

Never run by an agent on its own initiative -- huntbrain only offers it once
the human says the engagement is done (ideally after triage, so findings stay
reproducible). Each run needs a FRESH human terminal confirmation via the
existing scripts/confirm-state-change.sh, bound by state_change_confirm to the
host, the methods {POST,PUT,PATCH,DELETE} and a fingerprint of
{engagement, identity, base URL, the exact set of walker canaries to clean
up, the steps} -- so a token cannot be replayed for a different object set or
identity. Steps, in order:

1. cleanup        -- destroy every walker-owned (canary-tagged) object still
                     present, running the full create->destroy->verify checks
                     (ui_walk_destroy) on each, which also stops walker-created
                     content/invites from generating mail.
2. logout         -- snapshot the session, use the real logout control (the
                     ONLY place it is ever used), replay authenticated GETs
                     with the OLD session: still authorized -> candidate
                     "logout-session-survives". The old session is restored
                     afterwards for the next step.
3. account_delete -- ONLY for a roster identity marked `disposable: true`:
                     delete the account via the UI, replay the old session ->
                     candidate "account-deleted-session-survives"; always emit
                     "reregistration-candidate" (re-signup needs a new account,
                     so it is never automated).

Payment controls/hosts stay blocked here too. Candidates are leads for
exploit-agent, never confirmed bugs.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from urllib.parse import urlsplit

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.dirname(_HERE))

import browser_confirm  # noqa: E402
import engagement_paths  # noqa: E402
import session_capture  # noqa: E402
import state_change_confirm  # noqa: E402
import ui_walk  # noqa: E402
import ui_walk_destroy  # noqa: E402
import ui_walk_logic as L  # noqa: E402
import ui_walk_pass2  # noqa: E402
import ui_walk_store  # noqa: E402

TEARDOWN_STEPS = ("cleanup", "logout", "account_delete")
TEARDOWN_METHODS = ["POST", "PUT", "PATCH", "DELETE"]
TEARDOWN_SUBMIT_CAP = 200
MAX_AUTH_PROBES = 10


def session_ref(session_file: str | None, cookie_header: str | None) -> str:
    """A non-secret reference to the session teardown will act as -- bound into
    the fingerprint and shown to the human, so an approval for "identity X"
    cannot be replayed with some other account's session."""
    if session_file:
        return os.path.abspath(session_file)
    if cookie_header:
        return "cookie-header:sha256:" + hashlib.sha256(cookie_header.encode()).hexdigest()[:12]
    return "(no session)"


def teardown_fingerprint(slug: str, identity_label: str, base_url: str,
                         cleanup_tokens: list[str], steps: list[str], session_ref: str = "") -> str:
    blob = json.dumps({"slug": slug, "identity": identity_label, "base_url": base_url,
                       "tokens": sorted(cleanup_tokens), "steps": list(steps),
                       "session": session_ref}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:32]


def plan_teardown(base_url: str, identity_label: str, steps: list[str] | None = None,
                  session: str = "(no session)") -> dict:
    wanted = list(steps) if steps else list(TEARDOWN_STEPS)
    unknown = [s for s in wanted if s not in TEARDOWN_STEPS]
    if unknown:
        raise ValueError(f"unknown teardown step(s) {unknown}; expected a subset of {list(TEARDOWN_STEPS)}")
    ordered = [s for s in TEARDOWN_STEPS if s in wanted]
    notes = []
    if "account_delete" in ordered and not session_capture.is_disposable(identity_label):
        ordered.remove("account_delete")
        notes.append(f"account_delete skipped: identity {identity_label!r} is not marked "
                     "`disposable: true` in the test-identity roster")
    tokens = sorted(ui_walk_store.load_cleanup_canaries())   # never a DOM-source token
    host = (urlsplit(base_url).hostname or "").lower()
    fp = teardown_fingerprint(engagement_paths.get_active_target() or "", identity_label, base_url, tokens,
                              ordered, session)
    return {"host": host, "base_url": base_url, "identity": identity_label, "steps": ordered,
            "notes": notes, "cleanup_tokens": tokens, "session": session, "fingerprint": fp}


def _summary(plan: dict) -> str:
    return (f"UI-walk TEARDOWN on {plan['base_url']} as {plan['identity']} using session "
            f"{plan.get('session')}: steps={plan['steps']}; "
            f"destroys {len(plan['cleanup_tokens'])} walker-created canary object(s) (only objects whose "
            "row/card shows a walker canary or whose id a walker create returned); logout test; "
            + ("ACCOUNT DELETION (irreversible); " if "account_delete" in plan["steps"] else "")
            + "never payment. " + " ".join(plan["notes"]))


class TeardownWalker(ui_walk_pass2.CanaryWalker):
    def configure(self, grant=None, cleanup_tokens: list[str] | None = None) -> None:
        super().configure(ui_walk_pass2.ui_walk_grant.Grant(True, [], TEARDOWN_SUBMIT_CAP))
        # ONLY the canaries the human confirmed (the fingerprinted set), never
        # tokens registered after the confirmation.
        # A DOM-source canary is never a cleanup token / ownership proof, even
        # if one ended up in the confirmed set.
        reg = ui_walk_store.load_canaries()
        confirmed = set(cleanup_tokens or []) - {t for t, r in reg.items() if ui_walk_store.is_dom_source(r)}
        self.tokens = {t: r for t, r in reg.items() if t in confirmed}
        self.created_ids = {i for i, t in ui_walk_store.load_created_ids().items() if t in confirmed}
        self.steps: list[str] = []
        self.steps_run: list[str] = []
        self.notes: list[str] = []
        self._allowed_get: str | None = None

    def permit_mutating_get(self, url: str) -> bool:
        return self._allowed_get is not None and ui_walk._defrag(url) == self._allowed_get

    async def after_map(self) -> None:
        pages = [p for p in self.inv["pages"] if p.get("auth_state", "ok") == "ok"]
        if "cleanup" in self.steps:
            await ui_walk_destroy.run(self, pages)
            self.steps_run.append("cleanup")
        if "logout" in self.steps:
            await self._logout(pages)
        if "account_delete" in self.steps:
            await self._account_delete(pages)

    # -- helpers ----------------------------------------------------------------
    def _find(self, pages, classification):
        for prec in pages:
            for c in prec.get("controls") or []:
                if c.get("classification") == classification:
                    return prec, c
        return None

    async def _auth_probes(self, pages) -> list[str]:
        urls = []
        for u in [e["url"] for e in self.get_log] + [p["url"] for p in pages]:
            u = ui_walk._defrag(u)
            if u not in urls and self.scope(u) and not L.is_mutating_get_url(u):
                urls.append(u)
        ok = []
        for u in urls:
            if len(ok) >= MAX_AUTH_PROBES:
                break
            r = await self._replay(u, None)
            if r and 200 <= r[0] < 300:
                ok.append(u)
        return ok

    async def _replay(self, url: str, cookie_header: str | None):
        if not self.scope(url):
            return None
        await self._budget()
        try:
            headers = {"Cookie": cookie_header} if cookie_header is not None else None
            resp = await self.context.request.get(url, headers=headers, max_redirects=0, timeout=10000)
            return resp.status, await resp.text()
        except Exception:  # noqa: BLE001
            return None

    async def _cookie_header(self) -> tuple[list, str]:
        cookies = await self.context.cookies()
        host = urlsplit(self.start_url).hostname or ""
        mine = [c for c in cookies if host.endswith(c["domain"].lstrip(".")) or c["domain"].lstrip(".") == host]
        return cookies, "; ".join(f"{c['name']}={c['value']}" for c in mine)

    async def _use_control(self, prec, crec, classification) -> bool:
        """Use a logout/account-delete control for real. Returns whether it ran."""
        href = crec.get("href") or ""
        if href and not href.lower().startswith("javascript:"):
            if not self.scope(href):
                return False
            self._allowed_get = ui_walk._defrag(href)
            try:
                await self._budget()
                await self.page.goto(href, wait_until="domcontentloaded")
                await self._settle(self.page)
            finally:
                self._allowed_get = None
            return True
        await self._open_page(prec["url"])
        for frame, d in await self._snapshot(self.page):
            for c in d["controls"]:
                if L.classify_control(c) == classification:
                    before = self.sent
                    self.window = "teardown-control"
                    try:
                        await self._click(frame, c, L.control_signature(c, prec["template"]), {})
                    finally:
                        self.window = None
                    return self.sent > before
        return False

    # -- steps ------------------------------------------------------------------
    async def _logout(self, pages) -> None:
        found = self._find(pages, "logout")
        if not found:
            self.notes.append("logout test skipped: no logout control found on the mapped pages")
            return
        probes = await self._auth_probes(pages)
        old_cookies, old_hdr = await self._cookie_header()
        if not await self._use_control(*found, "logout"):
            self.notes.append("logout test skipped: logout control could not be used")
            return
        self.steps_run.append("logout")
        for u in probes:
            old = await self._replay(u, old_hdr)
            now = await self._replay(u, None)
            if old and 200 <= old[0] < 300 and not (now and 200 <= now[0] < 300):
                self.inv["candidates"].append({
                    "type": "logout-session-survives", "url": u, "status_with_old_session": old[0],
                    "status_logged_out": now[0] if now else None,
                    "next_step": "confirm manually: the pre-logout session cookie still authorizes this request"})
        await self.context.add_cookies(old_cookies)

    async def _account_delete(self, pages) -> None:
        found = self._find(pages, "account-delete")
        if not found:
            self.notes.append("account_delete skipped: no account-deletion control found")
            return
        probes = await self._auth_probes(pages)
        if not probes:
            self.notes.append("account_delete skipped: session is no longer valid (e.g. logout invalidated "
                              "it) -- re-capture the session and run teardown with steps=['account_delete']")
            return
        _cookies, old_hdr = await self._cookie_header()
        if not await self._use_control(*found, "account-delete"):
            self.notes.append("account_delete: the deletion request was not sent")
            return
        self.steps_run.append("account_delete")
        for u in probes:
            old = await self._replay(u, old_hdr)
            if old and 200 <= old[0] < 300:
                self.inv["candidates"].append({
                    "type": "account-deleted-session-survives", "url": u, "status": old[0],
                    "next_step": "confirm manually: the deleted account's session still authorizes this request"})
        self.inv["candidates"].append({
            "type": "reregistration-candidate", "identity": self.auth.get("identity_label"),
            "next_step": "human: re-register the same email and check whether old data/permissions reattach"})


def gate(base_url: str, identity_label: str, steps: list[str] | None = None, scope_check=None,
         session: str = "(no session)") -> tuple[dict | None, dict | None]:
    """(plan, None) when a fresh human confirmation for exactly this plan was
    consumed; (None, refusal_or_blocked) otherwise. Synchronous and cheap, so
    the MCP tool can answer "blocked: run this command" immediately."""
    scope = scope_check or L._default_scope_check
    if not scope(base_url):
        return None, {"status": "refused", "error": "base URL is out of scope", "candidates": []}
    plan = plan_teardown(base_url, identity_label, steps, session)
    if state_change_confirm.consume_approval(plan["host"], TEARDOWN_METHODS, plan["fingerprint"]) is None:
        summary = _summary(plan)
        state_change_confirm.write_pending(plan["host"], TEARDOWN_METHODS, plan["fingerprint"], summary)
        return None, {"status": "blocked", "plan": plan, "summary": summary, "candidates": [],
                      "command": (f"scripts/confirm-state-change.sh {plan['host']} "
                                  f"{','.join(TEARDOWN_METHODS)} {plan['fingerprint']}")}
    return plan, None


async def execute(plan: dict, session_file: str | None = None, *, cookie_header: str | None = None,
                  bearer_token: str | None = None, scope_check=None, screenshot_dir: str | None = None,
                  max_pages: int = 50, upstream_proxy: str = "") -> dict:
    """Run an already-approved plan (see gate()). upstream_proxy: the optional
    Burp mirror, same rules and launch path as ui_walk.walk()."""
    scope = scope_check or L._default_scope_check
    base_url, identity_label = plan["base_url"], plan["identity"]
    start = time.monotonic()
    auth = {"session_file": session_file, "cookie_header": cookie_header, "bearer_token": bearer_token,
            "local_storage": None, "session_storage": None}
    w = TeardownWalker(base_url, "teardown", scope=scope, max_pages=max_pages, max_clicks_per_page=40,
                       same_origin_only=True, wall_clock_s=1200, action_delay_s=ui_walk._default_delay(),
                       screenshot_dir=screenshot_dir, had_session=True, session_file=session_file,
                       auth={**auth, "identity_label": identity_label}, walk_id=os.urandom(6).hex())
    if session_ref(session_file, cookie_header) != plan.get("session"):
        return {"status": "refused", "error": "session differs from the one the human confirmed", "candidates": []}
    proxy, mirror_err = ui_walk.resolve_mirror(upstream_proxy)
    if mirror_err:
        return {"status": "refused", "error": mirror_err, "candidates": []}
    await w.setup_mirror(proxy)
    w.configure(cleanup_tokens=plan["cleanup_tokens"])
    w.steps = plan["steps"]
    inv = await w.run(**auth)
    browser_confirm._log_call("browser-mcp:ui-walk-teardown", [base_url, identity_label, ",".join(plan["steps"])],
                              returncode=0 if inv["status"] == "complete" else 1,
                              duration_ms=(time.monotonic() - start) * 1000, block=None)
    deleted = [d for d in inv.get("destroy_log", []) if d["owned"] and not d["skipped_reason"]]
    return {"status": inv["status"], "error": inv["error"], "plan": plan, "steps_run": w.steps_run,
            "notes": plan["notes"] + w.notes, "candidates": inv["candidates"], "deleted": deleted,
            "walk_id": inv["walk_id"], "inventory": inv}


async def run_teardown(base_url: str, identity_label: str, session_file: str | None = None,
                       steps: list[str] | None = None, *, cookie_header: str | None = None,
                       bearer_token: str | None = None, scope_check=None,
                       screenshot_dir: str | None = None, max_pages: int = 50, upstream_proxy: str = "") -> dict:
    mirror_err = ui_walk.proxy_refusal(upstream_proxy)
    if mirror_err:   # refused before gate(), so a bad proxy URL never uses up the human's approval
        return {"status": "refused", "error": mirror_err, "candidates": []}
    plan, stop = gate(base_url, identity_label, steps, scope_check, session_ref(session_file, cookie_header))
    if stop is not None:
        return stop
    return await execute(plan, session_file, cookie_header=cookie_header, bearer_token=bearer_token,
                         scope_check=scope_check, screenshot_dir=screenshot_dir, max_pages=max_pages,
                         upstream_proxy=upstream_proxy)
