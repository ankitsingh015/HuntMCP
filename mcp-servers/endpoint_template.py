"""Endpoint-template deduplication -- recognizes that /items/1, /items/2,
... /items/55 are all instances of the SAME templated endpoint
(/items/{id}), so testing every single instance a crawl found wastes
Tier-2 budget for close to zero additional signal once a handful of
representatives are covered.

Design confirmed by reading a competitor project's actual source during a
broader research pass (see gitignored RESEARCH-TODO.md's CyberStrike
deep-dive): its own crawler explicitly caps representatives kept per
numbered-label cluster at a small constant rather than keeping every
instance, for exactly this reason. This module is HuntMCP's own
from-scratch equivalent of that idea (no code ported -- CyberStrike is
AGPL, HuntMCP is MIT), plumbing straight into what already needs it:
idor-mcp's sweep_idor()/guess_idor() take an explicit object_ids list
today, hand-collected by whoever calls them. Feeding
sample_representatives()'s output (with extract_last_id() pulling the
varying id out of each kept URL) turns that into "here's every distinct
templated endpoint a crawl found, sampled down to a manageable, still-
covering set" instead of requiring the id list to already be known.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit

_NUMERIC_RE = re.compile(r"^\d+$")
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
# Opaque hashid/short-url-style tokens: long, mixed alphanumeric, no
# separators. Requires BOTH a letter and a digit so an ordinary path word
# ("login", "dashboard") never matches -- real hashids mix cases/digits,
# real words don't.
_HASHID_RE = re.compile(r"^[A-Za-z0-9_-]{10,}$")


def _is_id_like(segment: str) -> bool:
    if not segment:
        return False
    if _NUMERIC_RE.match(segment):
        return True
    if _UUID_RE.match(segment):
        return True
    if _HASHID_RE.match(segment) and any(c.isdigit() for c in segment) and any(c.isalpha() for c in segment):
        return True
    return False


def endpoint_template(url: str) -> str:
    """Replace every id-shaped path segment with `{id}`, producing a
    template string that groups instances of the same endpoint together.
    Query string and fragment are dropped -- they don't define the
    endpoint's SHAPE for this purpose (two requests differing only in
    ?page=2 are the same endpoint; two differing in /orders/41 vs
    /orders/42 are the same endpoint TEMPLATE but different instances)."""
    parts = urlsplit(url)
    segments = parts.path.split("/")
    templated = ["{id}" if _is_id_like(seg) else seg for seg in segments]
    return urlunsplit((parts.scheme, parts.netloc, "/".join(templated), "", ""))


def group_by_template(urls: list[str]) -> dict[str, list[str]]:
    """Every url bucketed by its endpoint_template(), preserving each
    bucket's original relative order."""
    groups: dict[str, list[str]] = {}
    for url in urls:
        groups.setdefault(endpoint_template(url), []).append(url)
    return groups


def sample_representatives(urls: list[str], max_per_template: int = 5) -> list[str]:
    """Cap each distinct template at `max_per_template` representative
    URLs, first-encountered order, deterministic -- a crawl that found 200
    instances of /orders/{id} contributes at most max_per_template of them
    to whatever consumes this list, instead of all 200. Order of the
    INPUT list is preserved for whichever URLs are kept; this does not
    reorder or otherwise favor any particular instance."""
    counts: dict[str, int] = {}
    out: list[str] = []
    for url in urls:
        template = endpoint_template(url)
        seen = counts.get(template, 0)
        if seen < max_per_template:
            out.append(url)
        counts[template] = seen + 1
    return out


def extract_last_id(url: str) -> str | None:
    """The single id most tools mean when they say "this endpoint's id",
    even when a path has multiple id-shaped segments -- the LAST one is
    what identifies the actual resource (e.g. /v2/users/42/orders/1001 --
    the order id, not the user id, identifies THIS resource). Returns None
    if no path segment looks id-like at all."""
    segments = urlsplit(url).path.split("/")
    id_segments = [s for s in segments if _is_id_like(s)]
    return id_segments[-1] if id_segments else None
