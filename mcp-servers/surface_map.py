"""Isolated per-engagement surface map for the knowledge-map layer.

A living model of the target grown during an engagement: domains -> subdomains
-> features -> flows -> tech, each node carrying its test state, bound precedent
and findings. Stored as one JSON file per engagement, resolved through
engagement_paths (data/engagements/<slug>/surface-map.json) -- so switching or
pausing targets never mixes maps, and case-mcp's own store is never touched.

Design guarantees (see docs/superpowers/specs/2026-11-17-knowledge-map-layer-design.md):
- Absent/corrupt file -> empty map (never raises on read), so "empty == behaves
  like today" holds and a half-built layer cannot brick a run.
- Atomic writes (temp file + os.replace).
- No network, no scope/budget interaction -- pure local state.

Node shape:
  {id, kind, label, signature, parent_id, state, precedent, findings, meta}
state in {discovered, precedent-bound, testing, tested}.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import tempfile

import engagement_paths

_OVERRIDE_ENV = "HUNTMCP_SURFACE_MAP_PATH"
_STATES = ("discovered", "precedent-bound", "testing", "tested")


def _resolve(path: str | None) -> str:
    if path is not None:
        return path
    return engagement_paths.resolve("surface-map.json", override_env=_OVERRIDE_ENV)


@contextlib.contextmanager
def _lock(path: str | None):
    """Serialize a read-modify-write across concurrent agent processes. Multiple
    sub-agents write the same per-engagement map; without this an interleaved
    load->save loses the other's node/state change (last write wins)."""
    p = _resolve(path)
    os.makedirs(os.path.dirname(os.path.abspath(p)), exist_ok=True)
    fh = open(os.path.abspath(p) + ".lock", "w")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fh, fcntl.LOCK_UN)
        fh.close()


def load_map(path: str | None = None) -> dict:
    """Return the map ({"nodes": [...]}). Missing or corrupt file -> empty map;
    never raises, so a bad file never aborts an agent."""
    p = _resolve(path)
    try:
        with open(p) as fh:
            data = json.load(fh)
        if isinstance(data, dict) and isinstance(data.get("nodes"), list):
            return data
        return {"nodes": []}
    except (OSError, ValueError):
        return {"nodes": []}


def _save_map(data: dict, path: str | None = None) -> None:
    p = _resolve(path)
    os.makedirs(os.path.dirname(os.path.abspath(p)), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(p)), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, p)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def add_node(kind: str, label: str, signature: str, parent_id: int | None = None,
             meta: dict | None = None, path: str | None = None) -> int:
    """Add a node, or return the existing id if (kind, signature, parent_id)
    already exists (dedup, so recon re-runs don't bloat the map)."""
    with _lock(path):
        data = load_map(path)
        key = (kind, signature, parent_id)
        for n in data["nodes"]:
            if (n["kind"], n["signature"], n.get("parent_id")) == key:
                return n["id"]
        nid = 1 + max((n["id"] for n in data["nodes"]), default=0)
        data["nodes"].append({
            "id": nid, "kind": kind, "label": label, "signature": signature,
            "parent_id": parent_id, "state": "discovered",
            "precedent": None, "findings": [], "meta": meta or {},
        })
        _save_map(data, path)
        return nid


def get_node(node_id: int, path: str | None = None) -> dict | None:
    for n in load_map(path)["nodes"]:
        if n["id"] == node_id:
            return n
    return None


def _update(node_id: int, path: str | None, mutate) -> bool:
    with _lock(path):
        data = load_map(path)
        for n in data["nodes"]:
            if n["id"] == node_id:
                mutate(n)
                _save_map(data, path)
                return True
        return False


def set_state(node_id: int, state: str, path: str | None = None) -> bool:
    if state not in _STATES:
        raise ValueError(f"invalid state {state!r}; expected one of {_STATES}")
    return _update(node_id, path, lambda n: n.__setitem__("state", state))


def set_precedent(node_id: int, precedent, path: str | None = None) -> bool:
    def _m(n):
        n["precedent"] = precedent
        if n["state"] == "discovered":
            n["state"] = "precedent-bound"
    return _update(node_id, path, _m)


def attach_finding(node_id: int, finding_id: int, path: str | None = None) -> bool:
    def _m(n):
        if finding_id not in n["findings"]:
            n["findings"].append(finding_id)
    return _update(node_id, path, _m)


def iter_untested(kind: str | None = None, path: str | None = None) -> list[dict]:
    """Nodes not yet in state 'tested', optionally filtered by kind."""
    out = []
    for n in load_map(path)["nodes"]:
        if n["state"] == "tested":
            continue
        if kind and n["kind"] != kind:
            continue
        out.append(n)
    return out
