"""#164 create -> destroy -> verify, on WALKER-OWNED objects only.

For every destructive control (delete/remove/revoke/cancel/...) on a mapped
page, inside the canary pass (browser still open):

1. DRY click it first: the interceptor aborts the request it fires, which we
   capture -- that request (URL/body) is the control's "control_request".
2. Ownership (hard rule, ui_walk_logic.is_walker_owned): an id our own Pass-2
   create returned appears exactly in that request, OR a walker canary token is
   in the control's row/card container. Otherwise -> map-only,
   destroy_log skipped_reason="ownership-unproven". Pre-existing data is
   never deleted.
3. Snapshot reach-paths: links in the object's container plus GET/XHR seen
   while opening them; keep those that return 2xx containing the token BEFORE
   the delete (so they provably reach the object).
4. Delete for real through the UI control (confirm() accepted), counted against
   the grant's submit cap + budget.
5. Re-request every reach-path with the same session: still 2xx + token ->
   candidate "broken-delete"; origin page still renders the token ->
   "delete-leftover". Always emit "delete-idor-candidate" (exploit-agent
   replays the recorded delete as account B via idor-mcp) and, for
   revoke/cancel/unshare controls, "cancel-without-revoke-candidate".

All candidates are leads for exploit-agent, not confirmed bugs. Response
excerpts are redacted (redact.redact_text) before they enter the inventory.
"""

from __future__ import annotations

import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.dirname(_HERE))

import ui_walk  # noqa: E402
import ui_walk_logic as L  # noqa: E402
from redact import redact_text  # noqa: E402

MAX_REACH_PATHS = 20
_REVOKE_RE = re.compile(r"\b(revoke|cancel|unshare|disconnect|unlink|leave|disable|deactivate)\b", re.IGNORECASE)

# The ownership container is the control's OWN row/card: the nearest of
# tr/li/[role=row]/article/.card/[data-id] -- but only if it holds no other
# control with the same label (otherwise it is a list wrapper, e.g. a .card
# around every row, and one canary inside it would make every row "owned");
# then fall back to the control's own parent element.
_CONTAINER_JS = r"""
(e) => { const label = (e.innerText || e.value || '').trim();
  const sameLabel = c => [...c.querySelectorAll('button, a, [role=button], input[type=submit]')]
      .filter(x => (x.innerText || x.value || '').trim() === label).length;
  let c = e.closest('tr, li, [role=row], article, .card, [data-id]');
  if (c && sameLabel(c) > 1) c = null;
  if (!c) c = e.parentElement;
  return {text: c ? (c.innerText || '') : '', links: c ? [...c.querySelectorAll('a[href]')].map(a => a.href) : []}; }
"""


def _mentions_id(url: str, ids: set[str]) -> bool:
    """An id appears as an exact path segment / query value (never a substring:
    id "1" must not match /items/10)."""
    return any(L.url_has_segment(url, i) for i in ids)


def _excerpt(text: str) -> str:
    return redact_text((text or "")[:300])


async def _get(walker, url: str):
    """Replay a GET with the walk's own session (APIRequestContext shares the
    browser context's cookies). Scope-checked and budget-counted."""
    if not walker.scope(url) or L.is_mutating_get_url(url):
        return None
    await walker._budget()
    try:
        resp = await walker.context.request.get(url, max_redirects=0, timeout=10000)
        return resp.status, await resp.text()
    except Exception:  # noqa: BLE001 -- unreachable path: no evidence either way
        return None


async def _destructive_controls(walker, tmpl: str):
    out = []
    for frame, d in await walker._snapshot(walker.page):
        for c in d["controls"]:
            if L.classify_control(c) == "destructive":
                out.append((frame, c))
    return out


async def _container(frame, c) -> dict:
    try:
        return await frame.locator(f'[data-hm-idx="{c["idx"]}"]').first.evaluate(_CONTAINER_JS)
    except Exception:  # noqa: BLE001
        return {"text": "", "links": []}


async def run(walker, pages: list[dict]) -> None:
    tokens = set(walker.tokens)
    for prec in pages:
        if not any(c.get("classification") == "destructive" for c in prec.get("controls") or []):
            continue
        await walker._open_page(prec["url"])
        handled: set[str] = set()
        # Re-snapshot after every real delete (the list re-renders).
        while True:
            target = None
            for frame, c in await _destructive_controls(walker, prec["template"]):
                cont = await _container(frame, c)
                key = (c["text"], cont["text"][:200])
                if repr(key) in handled:
                    continue
                handled.add(repr(key))
                target = (frame, c, cont)
                break
            if target is None:
                break
            await _one(walker, prec, tokens, *target)
            if walker.budget_hit or walker.sent >= walker.cap:
                return


async def _one(walker, prec, tokens, frame, c, cont) -> None:
    log = {"page": prec["url"], "control_text": c["text"] or c["aria_label"], "owned": False,
           "skipped_reason": None, "request": None}
    walker.inv["destroy_log"].append(log)
    page_url = ui_walk._defrag(walker.page.url)
    # 1. dry click -> capture the request the control would send.
    walker.last_aborted = None
    await walker._click(frame, c, L.control_signature(c, prec["template"]), {})
    req = walker.last_aborted
    if ui_walk._defrag(walker.page.url) != page_url:
        await walker._open_page(page_url)
    log["request"] = {"method": req["method"], "url": req["url"]} if req else None
    tok_here = {t for t in tokens if t in (cont["text"] or "")}
    # 2. ownership.
    if not L.is_walker_owned(req, walker.created_ids, cont["text"], tokens):
        log["skipped_reason"] = "ownership-unproven"
        return
    log["owned"] = True
    log["ownership_basis"] = "created-id" if (req and any(
        L.is_walker_owned(req, {i}, "", set()) for i in walker.created_ids)) else "canary-in-row"
    if req is None:
        # No request captured on the dry run: nothing to pin the real click to.
        log["skipped_reason"] = "no-request-captured"
        return
    ids_here = {i for i in walker.created_ids if req and L.is_walker_owned(req, {i}, "", set())}
    # 3. reach paths, proven BEFORE the delete.
    candidates = []
    for link in cont["links"]:
        link = ui_walk._defrag(link)
        if link not in candidates and walker.scope(link) and not L.is_mutating_get_url(link):
            candidates.append(link)
    before = len(walker.get_log)
    for link in candidates[:]:
        await walker._open_page(link)
    for entry in walker.get_log[before:] + walker.get_log[:before]:
        u = entry["url"]
        if u not in candidates and (_mentions_id(u, ids_here) or any(t in u for t in tok_here)):
            candidates.append(u)
    reach = []
    for u in candidates[:MAX_REACH_PATHS]:
        r = await _get(walker, u)
        if r and 200 <= r[0] < 300 and (not tok_here or any(t in r[1] for t in tok_here)):
            reach.append(u)
    # 4. real delete through the UI control (re-located: the page re-rendered).
    await walker._open_page(prec["url"])
    live = None
    for f2, c2 in await _destructive_controls(walker, prec["template"]):
        cont2 = await _container(f2, c2)
        if (tok_here and any(t in cont2["text"] for t in tok_here)) or (not tok_here and cont2["text"] == cont["text"]):
            live = (f2, c2)
            break
    if live is None:
        log["skipped_reason"] = "control-not-relocated"
        return
    sent_before = walker.sent
    # Only the exact request the dry run captured (and proved ownership with)
    # may be sent -- a mis-located control firing a different delete is aborted.
    walker.window = ("exact", req["method"], req["url"])
    try:
        await walker._click(live[0], live[1], L.control_signature(live[1], prec["template"]), {})
    finally:
        walker.window = None
    if walker.sent == sent_before:
        log["skipped_reason"] = "delete-not-sent"
        return
    # 5. verify it is gone.
    for u in reach:
        r = await _get(walker, u)
        if r and 200 <= r[0] < 300 and (not tok_here or any(t in r[1] for t in tok_here)):
            walker.inv["candidates"].append({
                "type": "broken-delete", "reach_path": u, "status": r[0], "page": prec["url"],
                "control_text": log["control_text"], "evidence": _excerpt(r[1])})
    await walker._open_page(prec["url"])
    try:
        html = await walker.page.content()
    except Exception:  # noqa: BLE001
        html = ""
    if tok_here and any(t in html for t in tok_here):
        walker.inv["candidates"].append({"type": "delete-leftover", "page": prec["url"],
                                         "control_text": log["control_text"]})
    if req:
        walker.inv["candidates"].append({
            "type": "delete-idor-candidate", "page": prec["url"], "control_text": log["control_text"],
            "request": {"method": req["method"], "url": req["url"], "body_shape": ui_walk._body_shape(req.get("body"))},
            "next_step": "replay as account B against a fresh account-A object (idor-mcp replay_authz_matrix)"})
    if _REVOKE_RE.search(log["control_text"] or ""):
        walker.inv["candidates"].append({
            "type": "cancel-without-revoke-candidate", "page": prec["url"], "control_text": log["control_text"],
            "reach_paths": reach,
            "next_step": "replay the revoked link/key/invite/session and confirm it no longer works"})
