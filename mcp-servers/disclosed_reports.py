"""Structured lookup over a public catalog of disclosed vulnerability
reports, sourced from bug-bounty-disclosures.vercel.app -- 11k+ real
disclosed reports (platform, program, researcher, vulnerability class,
severity, bounty, CVEs) as one static JSON dataset (its "API" is actually
a client-fetched static data file, not a queryable REST endpoint -- see
the note in fetch() below).

Why this exists: the "cite real disclosed reports as precedent" pattern
already used in several `.claude/skills/*/SKILL.md` files (auth-and-session,
access-control-and-idor, injection-and-rce) was built by hand, one ad-hoc
WebSearch per skill. This gives scan-agent/exploit-agent/report-agent (and
whoever writes the next skill) a fast, structured, offline-after-first-fetch
way to pull real citations by vuln class or platform instead.

This is precedent/citation material only -- it does not imply authorization
to test anything. A report showing up here says a technique paid out
somewhere once; it says nothing about the current target's scope.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

CACHE_DIR = os.getenv(
    "DISCLOSED_REPORTS_CACHE_DIR",
    os.path.join(os.path.dirname(__file__), "../data/disclosed-reports-cache"),
)
CACHE_PATH = os.path.join(CACHE_DIR, "catalog.json")
LAST_REFRESH_PATH = os.path.join(CACHE_DIR, ".last_refresh")
SOURCE_URL = "https://bug-bounty-disclosures.vercel.app/data/catalog.js"
REFRESH_TTL_SECONDS = 24 * 60 * 60  # this dataset moves slowly; daily is plenty
JS_PREFIX = "window.DISCLOSURE_REPORTS="


def needs_refresh(ttl_seconds: int = REFRESH_TTL_SECONDS) -> bool:
    if not os.path.isfile(LAST_REFRESH_PATH):
        return True
    with open(LAST_REFRESH_PATH) as f:
        try:
            last = float(f.read().strip())
        except ValueError:
            return True
    return (time.time() - last) > ttl_seconds


def refresh(force: bool = False) -> dict:
    """Download and cache the catalog. The site serves its dataset as a
    plain JS file assigning a JSON array to window.DISCLOSURE_REPORTS --
    not a REST API despite the site's own '#api' section suggesting one;
    strip that JS wrapper and store the raw array as JSON."""
    if not force and not needs_refresh():
        return {"refreshed": False, "reason": "cache still fresh", "count": _cached_count()}

    req = urllib.request.Request(SOURCE_URL, headers={"User-Agent": "HuntMCP-disclosed-reports/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read().decode(errors="replace")
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as e:
        return {"refreshed": False, "reason": f"fetch failed: {e}", "count": _cached_count()}

    if not raw.startswith(JS_PREFIX):
        return {"refreshed": False, "reason": "unexpected source format (site may have changed)", "count": _cached_count()}

    try:
        data = json.loads(raw[len(JS_PREFIX):].rstrip().rstrip(";"))
    except ValueError as e:
        return {"refreshed": False, "reason": f"parse failed: {e}", "count": _cached_count()}

    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(CACHE_PATH, "w") as f:
        json.dump(data, f)
    with open(LAST_REFRESH_PATH, "w") as f:
        f.write(str(time.time()))

    return {"refreshed": True, "count": len(data)}


def _cached_count() -> int:
    data = _load_cache()
    return len(data)


def _load_cache() -> list[dict]:
    if not os.path.isfile(CACHE_PATH):
        return []
    with open(CACHE_PATH) as f:
        return json.load(f)


def search(vuln_class: str = "", platform: str = "", keyword: str = "", limit: int = 10) -> list[dict]:
    """Filter the cached catalog. vuln_class/platform match case-insensitively
    against the record's own field; keyword substring-matches against title
    + program. Does not auto-refresh -- call refresh() first."""
    data = _load_cache()
    vuln_class_l = vuln_class.strip().lower()
    platform_l = platform.strip().lower()
    keyword_l = keyword.strip().lower()

    out = []
    for r in data:
        if vuln_class_l and vuln_class_l not in (r.get("vulnerabilityClass") or "").lower():
            continue
        if platform_l and platform_l != (r.get("platform") or "").lower():
            continue
        if keyword_l and keyword_l not in (r.get("title") or "").lower() and keyword_l not in (r.get("program") or "").lower():
            continue
        out.append(r)
        if len(out) >= limit:
            break
    return out
