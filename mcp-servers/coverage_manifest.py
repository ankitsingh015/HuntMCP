"""#159 coverage manifest: surface x vuln-class breadth gate.

Bridges the surface-map node inventory (surface_map.py -- "what exists") with
case_store's evidence-backed findings (coverage_signal.evidence_backed_findings
-- "what we tried, with evidence") to answer, per (discovered node x its
required vuln-class): covered / N-A / open. And a gate: a surface is not
"exhausted" while any cell is open.

Design + honest limits:
docs/superpowers/specs/2026-11-19-coverage-manifest-design.md

- Covered-ness is DERIVED from evidence (never a stored/self-written flag), so
  it cannot be gamed by empty finding declarations.
- The required battery is a fixed per-kind FLOOR unioned with classes the
  node's bound precedent surfaces -- the floor guarantees breadth even when
  precedent retrieval is thin; precedent only widens, never narrows.
- Class/endpoint matching is CONSERVATIVE: when unsure a finding maps to a
  battery class, it does NOT count covered -- a false "open" (re-check) is
  safe; a false "covered" would hide a real gap.
- Offline, read-only; no network/scope/budget interaction.
"""

from __future__ import annotations

import os
import sys

try:
    import coverage_signal
    import surface_map
except ImportError:  # pragma: no cover - path shim for direct execution
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import coverage_signal
    import surface_map

# Canonical required-class FLOOR per surface-map node kind. Names are canonical
# battery keys; _class_matches maps free-form finding vuln_class values onto
# them. Reviewable + extendable in this one place.
BATTERY_BY_KIND: dict[str, set[str]] = {
    "endpoint": {"xss", "sqli", "idor", "access-control", "ssrf", "open-redirect", "csrf"},
    "feature": {"access-control", "business-logic", "auth", "idor"},
    "flow": {"access-control", "business-logic", "auth", "idor"},
    "host": {"info-disclosure", "security-misconfig", "subdomain-takeover"},
    "tech": {"known-cve"},
}

# Alias groups: canonical key -> the surface forms (normalized) that mean it.
# Used both to match a finding's free-form vuln_class to a battery class and to
# detect classes named in precedent text. Conservative: only explicit members
# match, never a loose substring.
_ALIASES: dict[str, set[str]] = {
    "xss": {"xss", "cross-site-scripting", "reflected-xss", "stored-xss", "dom-xss", "xss-js-confirmation"},
    "sqli": {"sqli", "sql-injection", "sqlinjection"},
    "idor": {"idor", "idor-bola", "bola", "insecure-direct-object-reference"},
    "access-control": {"access-control", "broken-access-control", "authz", "authorization", "privilege-escalation", "privesc"},
    "ssrf": {"ssrf", "server-side-request-forgery", "blind-ssrf-oob"},
    "open-redirect": {"open-redirect", "openredirect"},
    "csrf": {"csrf", "cross-site-request-forgery"},
    "auth": {"auth", "authentication", "session", "mfa", "oauth", "saml", "jwt"},
    "business-logic": {"business-logic", "logic-flaw", "race-condition", "race"},
    "info-disclosure": {"info-disclosure", "information-disclosure", "exposed-secrets", "source-leak-github"},
    "security-misconfig": {"security-misconfig", "misconfiguration", "cve-misconfig-nuclei"},
    "subdomain-takeover": {"subdomain-takeover", "subdomain-takeover"},
    "known-cve": {"known-cve", "cve", "cve-misconfig-nuclei"},
    "prototype-pollution": {"prototype-pollution", "prototype-pollution-xss"},
    "ssti": {"ssti", "server-side-template-injection", "template-injection"},
    "xxe": {"xxe", "xml-external-entity"},
    "rce": {"rce", "remote-code-execution", "command-injection"},
}


def _normalize_class(s: str) -> str:
    return s.strip().lower().replace("_", "-").replace(" ", "-")


def _canonical_class(s: str) -> str | None:
    """The canonical battery key a free-form class string maps to, or None."""
    norm = _normalize_class(s)
    for canon, forms in _ALIASES.items():
        if norm == canon or norm in forms:
            return canon
    return None


def _class_matches(finding_class: str, battery_class: str) -> bool:
    """Conservative: a finding's free-form vuln_class covers a battery class
    only if both resolve to the same canonical key, or they are exactly equal
    once normalized. No loose substring matching."""
    fnorm = _normalize_class(finding_class)
    bnorm = _normalize_class(battery_class)
    if fnorm == bnorm:
        return True
    fcanon = _canonical_class(finding_class)
    bcanon = _canonical_class(battery_class)
    return fcanon is not None and fcanon == bcanon


def _classes_in_text(text: str | None) -> set[str]:
    """Canonical classes explicitly named in precedent text (token match on an
    alias). Used to widen a node's required battery from its bound precedent."""
    if not text:
        return set()
    norm = _normalize_class(text)
    found: set[str] = set()
    for canon, forms in _ALIASES.items():
        if canon in norm or any(f in norm for f in forms):
            found.add(canon)
    return found


def required_classes(node: dict) -> set[str]:
    """The required vuln-class battery for one surface node: the fixed per-kind
    FLOOR, UNIONed with classes the node's bound precedent surfaces. A node with
    no precedent still gets the floor; precedent only widens it."""
    floor = set(BATTERY_BY_KIND.get(node.get("kind", ""), set()))
    return floor | _classes_in_text(node.get("precedent"))


def _normalize_endpoint(s: str) -> str:
    """Normalize an endpoint for joining: lowercase scheme+host, strip default
    ports (:80/:443), drop trailing slash, drop query+fragment. Keeps path
    case (paths can be case-sensitive)."""
    from urllib.parse import urlsplit

    s = (s or "").strip()
    parts = urlsplit(s)
    if parts.scheme or parts.netloc:
        scheme = parts.scheme.lower()
        host = parts.hostname or ""
        host = host.lower()
        port = parts.port
        if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
            host = f"{host}:{port}"
        path = parts.path.rstrip("/")
        return f"{scheme}://{host}{path}" if scheme or host else path
    # bare path (no scheme/host)
    return s.split("?", 1)[0].split("#", 1)[0].rstrip("/")


def _node_endpoint(node: dict) -> str:
    """The endpoint a node joins on: meta['endpoint'] if set, else its label,
    normalized. Empty string for nodes that carry no endpoint."""
    meta = node.get("meta") or {}
    return _normalize_endpoint(meta.get("endpoint") or node.get("label") or "")


def compute_manifest(db_path: str | None = None, map_path: str | None = None) -> dict:
    """Join the surface-map node inventory with case_store's evidence-backed
    findings into a per-(node x required-class) coverage manifest + exhaustion
    verdict. Offline, read-only.

    A cell (node, class) is:
      - na      iff the node records an N/A for a matching class WITH a
                non-empty reason;
      - covered iff some evidence-backed finding F matches the class AND is
                linked to the node -- either F.id is in node['findings']
                (an explicit attach_finding link, the robust join) OR F's
                normalized endpoint equals the node's (the fallback join);
      - open    otherwise.
    exhausted = no open cell across all nodes (vacuously True for an empty map).
    """
    nodes_in = surface_map.load_map(map_path).get("nodes", [])
    ebf = coverage_signal.evidence_backed_findings(db_path)

    out_nodes: list[dict] = []
    counts = {"covered": 0, "na": 0, "open": 0}
    open_cells: list[dict] = []

    for node in nodes_in:
        nep = _node_endpoint(node)
        fids = set(node.get("findings") or [])
        na = node.get("na") or {}
        cells = []
        for cls in sorted(required_classes(node)):
            reason = next(
                (r for k, r in na.items() if isinstance(r, str) and r.strip() and _class_matches(k, cls)),
                None,
            )
            if reason is not None:
                state, extra = "na", {"reason": reason}
            else:
                covered = any(
                    _class_matches(f["vuln_class"], cls)
                    and (f["id"] in fids or (nep and _normalize_endpoint(f["endpoint"]) == nep))
                    for f in ebf
                )
                state, extra = ("covered" if covered else "open"), {}
            counts[state] += 1
            cells.append({"vuln_class": cls, "state": state, **extra})
            if state == "open":
                open_cells.append({"node_id": node["id"], "vuln_class": cls})
        out_nodes.append({
            "node_id": node["id"], "kind": node["kind"], "label": node["label"], "cells": cells,
        })

    return {
        "nodes": out_nodes,
        "open_cells": open_cells,
        "counts": counts,
        "exhausted": not open_cells,
    }
