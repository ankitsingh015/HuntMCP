"""Disclosure-channel lookup, sourced from lissy93/bug-bounties
(github.com/lissy93/bug-bounties, MIT, 415+ stars) -- complements
bounty_scope.py, doesn't duplicate it.

bounty_scope.py aggregates the 5 major platforms' (HackerOne/Bugcrowd/
Intigriti/Federacy/YesWeHack) OWN published scope, sourced from
arkadiyt/bounty-targets-data -- cleanly domain-keyed, exact-match/
wildcard lookup. This module covers a different, complementary slice:
lissy93/bug-bounties' own two source files answer a different question
("how do I report this, not just is it in scope") from a different data
shape (company/url/contact-centric, not domain-keyed):
  - platform-programs.yml (~25k lines) -- auto-populated from public
    sources by the upstream repo's own populate-bounties.py script.
  - independent-programs.yml (~3k lines) -- manually community-submitted
    standalone VDPs not managed on ANY platform (a company's own
    disclosure page) -- the same gap target-discovery-mcp's live
    security.txt probing targets, but as a pre-aggregated list instead
    of a live per-domain check. A real, useful second signal: a domain
    whose security.txt is temporarily unreachable, or that never
    published one but is still listed here by a contributor, is only
    caught by this half.

Both files share the same `companies:` schema (company, url, contact,
rewards, safe_harbor, program_type, status, domains, ...) -- genuinely
useful fields (`contact`, `safe_harbor`, `rewards`) neither
bounty_scope.py's H1/Bugcrowd/etc. data nor target-discovery-mcp's own
security.txt parsing surface today.

Domain matching here is deliberately LOOSER than bounty_scope.py's exact
wildcard-domain matching -- this dataset's `domains` field is free-text,
human-written ("www.example.com (Main website)", "All subdomains
(*.example.com)"), not a clean structured list. Matching against the
program's own `url` hostname plus a substring check against `domains`
entries is the honest ceiling of precision this data shape supports; a
caller should treat a match as "a program exists that plausibly covers
this domain, go read the url" rather than a definitive in-scope
determination the way bounty_scope.py's matches are.

Cached locally with a much longer TTL than bounty_scope.py's 20 minutes
-- this is a mostly-static, community-curated file (contributors submit
PRs, not a live-synced feed), so refreshing every 20 min would just be
needless GitHub traffic for data that rarely changes hour to hour.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import yaml

CACHE_DIR = os.getenv(
    "DISCLOSURE_LOOKUP_CACHE_DIR",
    os.path.join(os.path.dirname(__file__), "../data/disclosure-lookup-cache"),
)
BASE_URL = "https://raw.githubusercontent.com/lissy93/bug-bounties/main"
SOURCE_FILES = {
    "platform": "platform-programs.yml",
    "independent": "independent-programs.yml",
}
# Community-curated, PR-submitted data, not a live-synced feed -- refreshing
# far less often than bounty_scope.py's 20-minute TTL is honest about how
# often this actually changes, and avoids needless GitHub raw-content pulls.
REFRESH_TTL_SECONDS = 24 * 60 * 60

CACHE_PATH = os.path.join(CACHE_DIR, "companies.json")
LAST_REFRESH_PATH = os.path.join(CACHE_DIR, ".last_refresh")


def _fetch_yaml(filename: str) -> list[dict]:
    url = f"{BASE_URL}/{filename}"
    req = urllib.request.Request(url, headers={"User-Agent": "HuntMCP-disclosure-lookup/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read().decode()
    data = yaml.safe_load(raw) or {}
    return data.get("companies", []) or []


def _cache_fresh() -> bool:
    if not os.path.isfile(LAST_REFRESH_PATH):
        return False
    try:
        last = float(open(LAST_REFRESH_PATH).read().strip())
    except (ValueError, OSError):
        return False
    return (time.time() - last) < REFRESH_TTL_SECONDS


def refresh(force: bool = False) -> dict:
    """Fetch both source files and cache the merged, source-tagged company
    list. Skips the download if the cache is still fresh unless force=True.
    Returns {"refreshed": bool, "reason": str|None, "companies": int,
    "failed_sources": [...]}. A single source failing (e.g. GitHub rate
    limit) does not block the other -- partial data beats none, with the
    failure named explicitly rather than silently returning a stale/empty
    result."""
    if not force and _cache_fresh() and os.path.isfile(CACHE_PATH):
        with open(CACHE_PATH) as f:
            return {"refreshed": False, "reason": "cache still fresh",
                     "companies": len(json.load(f)), "failed_sources": []}

    os.makedirs(CACHE_DIR, exist_ok=True)
    merged: list[dict] = []
    failed: list[str] = []
    # Fetched concurrently -- two independent HTTP calls that don't depend
    # on each other, previously run one after another (worst case ~60s if
    # both are slow) for no reason; same fix as bounty_scope.py's refresh().
    with ThreadPoolExecutor(max_workers=len(SOURCE_FILES)) as pool:
        futures = {
            source: pool.submit(_fetch_yaml, filename)
            for source, filename in SOURCE_FILES.items()
        }
        for source, future in futures.items():
            try:
                companies = future.result()
            except (urllib.error.HTTPError, urllib.error.URLError, yaml.YAMLError, TimeoutError) as e:
                failed.append(f"{source} ({e})")
                continue
            for c in companies:
                c["_source"] = source
            merged.extend(companies)

    if not merged:
        return {"refreshed": False, "reason": f"all sources failed: {failed}",
                 "companies": 0, "failed_sources": failed}

    with open(CACHE_PATH, "w") as f:
        json.dump(merged, f)
    with open(LAST_REFRESH_PATH, "w") as f:
        f.write(str(time.time()))

    return {"refreshed": True, "reason": None, "companies": len(merged), "failed_sources": failed}


def _load_cache() -> list[dict]:
    if not os.path.isfile(CACHE_PATH):
        return []
    with open(CACHE_PATH) as f:
        return json.load(f)


def _hostname(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _matches(entry: dict, domain: str) -> bool:
    domain = domain.lower().lstrip("*.")
    url_host = _hostname(entry.get("url", ""))
    if url_host and (domain == url_host or url_host.endswith("." + domain) or domain.endswith("." + url_host)):
        return True
    for d in entry.get("domains", []) or []:
        if domain in str(d).lower():
            return True
    return False


def lookup(domain: str) -> list[dict]:
    """Companies whose program plausibly covers `domain`, from the cached
    data -- call refresh() first if it might be stale. See this module's
    own docstring for why matching is loose (substring/hostname-suffix,
    not exact wildcard) -- treat a match as "read the url, a program
    likely exists" rather than a confirmed in-scope determination."""
    matches = []
    for entry in _load_cache():
        if _matches(entry, domain):
            matches.append({
                "company": entry.get("company"),
                "url": entry.get("url"),
                "contact": entry.get("contact"),
                "rewards": entry.get("rewards", []),
                "safe_harbor": entry.get("safe_harbor"),
                "program_type": entry.get("program_type"),
                "status": entry.get("status"),
                "source": entry.get("_source"),
            })
    return matches
