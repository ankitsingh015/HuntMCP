"""#164 UI-walk persistence: inventories, the canary registry, and emission of
page/input/action nodes into the per-engagement surface map (so the coverage
gate counts every rendered page's inputs and actions, not just URLs).

Storage: data/engagements/<slug>/ui-walk/ (engagement_paths.resolve_dir),
overridable with HUNTMCP_UI_WALK_DIR for tests.
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))

import engagement_paths  # noqa: E402
import file_lock  # noqa: E402
import surface_map  # noqa: E402
from endpoint_template import endpoint_template  # noqa: E402

CANARY_REGISTRY = "canaries.json"
_WALK_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _unscoped(name: str) -> str:
    """Where engagement-scoped output goes when NO engagement is active: still
    under the (gitignored) engagements root, never a bare path relative to the
    process cwd (which is usually the repo root)."""
    return os.path.join(engagement_paths.ENGAGEMENTS_ROOT, "_no-active-engagement", name)


def walk_dir() -> str:
    return engagement_paths.resolve_dir("ui-walk", override_env="HUNTMCP_UI_WALK_DIR",
                                        legacy_default=_unscoped("ui-walk"))


def _atomic_write_json(path: str, data) -> None:
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh, indent=1)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def save_inventory(inv: dict) -> str:
    walk_id = str(inv.get("walk_id") or "")
    if not _WALK_ID_RE.match(walk_id):
        raise ValueError(f"invalid walk_id {walk_id!r}")
    path = os.path.join(walk_dir(), f"{walk_id}.json")
    _atomic_write_json(path, inv)
    return path


def load_inventory(walk_id: str) -> dict | None:
    if not _WALK_ID_RE.match(walk_id or ""):
        return None
    path = os.path.join(walk_dir(), f"{walk_id}.json")
    try:
        with open(path) as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def _registry_path() -> str:
    return os.path.join(walk_dir(), CANARY_REGISTRY)


def load_canaries() -> dict[str, dict]:
    try:
        with open(_registry_path()) as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


DOM_SOURCE_KIND = "dom-source"


def is_dom_source(record) -> bool:
    """A Pass-1 DOM-source canary (registered on a sink hit, never submitted):
    never a teardown cleanup token and never proof that a walker created an object."""
    return isinstance(record, dict) and record.get("kind") == DOM_SOURCE_KIND


def load_cleanup_canaries() -> dict[str, dict]:
    """load_canaries() without the DOM-source tokens."""
    return {t: r for t, r in load_canaries().items() if not is_dom_source(r)}


CREATED_IDS = "created-ids.json"


def _created_path() -> str:
    return os.path.join(walk_dir(), CREATED_IDS)


def load_created_ids() -> dict[str, str]:
    """{created object id: canary token of the submit that created it}."""
    try:
        with open(_created_path()) as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def register_created_id(token: str, created_id: str) -> None:
    """Persist an id a walker create returned, so a later teardown can prove
    ownership by id (the strong basis), not only by a canary in the row."""
    path = _created_path()
    with file_lock.locked(path):
        reg = load_created_ids()
        reg[str(created_id)] = token
        _atomic_write_json(path, reg)


def register_canary(token: str, record: dict) -> None:
    path = _registry_path()
    with file_lock.locked(path):
        reg = load_canaries()
        reg[token] = record
        _atomic_write_json(path, reg)


def emit_nodes(inv: dict, map_path: str | None = None) -> dict[str, int]:
    """Add one `page` node per mapped page, one `input` node per input and one
    `action` node per state-changing UI->API edge (children of the page).
    Dedup comes from surface_map.add_node (kind+signature+parent), so re-running
    a walk never bloats the map. Logged-out pages are not the authenticated
    surface and emit nothing."""
    counts = {"page": 0, "input": 0, "action": 0}
    walk_id = inv.get("walk_id")
    for page in inv.get("pages") or []:
        if page.get("auth_state", "ok") != "ok":
            continue
        tmpl = page.get("template") or endpoint_template(page["url"])
        pid = surface_map.add_node("page", page.get("title") or page["url"], f"page:{tmpl}",
                                   meta={"endpoint": page["url"], "walk_id": walk_id}, path=map_path)
        counts["page"] += 1
        for inp in page.get("inputs") or []:
            name = inp.get("name") or inp.get("id") or "(unnamed)"
            action = inp.get("form_action") or page["url"]
            surface_map.add_node("input", f"{name} @ {page['url']}",
                                 f"input:{endpoint_template(action)}:{name}", parent_id=pid,
                                 meta={"endpoint": action, "type": inp.get("type"),
                                       "frame_origin": inp.get("frame_origin"),
                                       "revealed_by": inp.get("revealed_by"), "walk_id": walk_id},
                                 path=map_path)
            counts["input"] += 1
        controls = {c.get("signature"): c for c in page.get("controls") or []}
        seen: set[str] = set()
        for edge in page.get("api_edges") or []:
            method = (edge.get("method") or "").upper()
            if method in ("GET", "HEAD", "OPTIONS"):
                continue
            sig = f"action:{method} {endpoint_template(edge['url'])}"
            if sig in seen:
                continue
            seen.add(sig)
            ctrl = controls.get(edge.get("control_signature")) or {}
            surface_map.add_node("action", f"{method} {edge['url']}", sig, parent_id=pid,
                                 meta={"endpoint": edge["url"], "classification": ctrl.get("classification"),
                                       "control_text": ctrl.get("text"), "blocked_reason": edge.get("blocked_reason"),
                                       "walk_id": walk_id},
                                 path=map_path)
            counts["action"] += 1
    return counts
