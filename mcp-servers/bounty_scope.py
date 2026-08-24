"""Aggregated bounty-program scope lookup, sourced from arkadiyt/bounty-targets-data
(github.com/arkadiyt/bounty-targets-data) -- a well-known, actively-maintained
(synced every 30 min) public aggregation of HackerOne, Bugcrowd, Intigriti,
Federacy, and YesWeHack's own published program scopes.

Why this exists alongside hackerone-mcp: sync_program_scope() there needs a
live HackerOne account + API credentials and only covers HackerOne. This
needs neither -- zero credentials, all 5 major platforms in one place -- at
the cost of being a third-party aggregation rather than a direct API call
(if that repo ever goes dark or falls behind, hackerone-mcp's direct-API
path still works for HackerOne specifically; keep both, don't replace
either).

Two distinct jobs:
1. lookup_domain(): "is this domain already covered by a published program,
   and on which platform" -- the Phase 0 auto-discovery use case, so a user
   naming a target doesn't have to already know/paste which program it's
   under.
2. diff_since_last_refresh(): the cheap half of "24/7 scanning" -- refreshing
   and diffing this feed costs a handful of small JSON downloads, nothing
   target-touching. NEW scope (a domain added to an existing program, or a
   brand-new program) is logged to scope_log.jsonl as it's detected. This is
   deliberately the ONLY thing safe to run unattended/frequently -- actually
   recon'ing or scanning newly-discovered scope is a separate, deliberate,
   budget-gated decision (see ARCHITECTURE.md's "Continuous bounty-scope
   discovery" section), not something this module triggers on its own.
"""

from __future__ import annotations

import calendar
import json
import os
import re
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

CACHE_DIR = os.getenv(
    "BOUNTY_SCOPE_CACHE_DIR",
    os.path.join(os.path.dirname(__file__), "../data/bounty-scope-cache"),
)
BASE_URL = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data"
PLATFORMS = ["hackerone", "bugcrowd", "intigriti", "federacy", "yeswehack"]
REFRESH_TTL_SECONDS = 20 * 60  # source updates every 30 min; refresh a bit more often than that
DOMAIN_LIKE_FIELDS = ("asset_identifier", "target", "uri", "endpoint", "identifier", "value")
DOMAIN_RE = re.compile(r"^\*?\.?[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$")
# HackerOne (and similarly-shaped platform data) tags each entry with an
# asset_type -- these are dotted-label identifiers that pass DOMAIN_RE's
# shape check but are NOT domains (a Play Store app ID like
# "com.example.app" is syntactically identical to a hostname).
NON_DOMAIN_ASSET_TYPES = {
    "GOOGLE_PLAY_APP_ID", "APPLE_STORE_APP_ID", "OTHER_APK", "OTHER_IPA",
    "SOURCE_CODE", "EXECUTABLE", "DOWNLOADABLE_EXECUTABLES", "HARDWARE",
    "CIDR", "OTHER",
}

DOMAIN_INDEX_PATH = os.path.join(CACHE_DIR, "domain_index.json")
SCOPE_LOG_PATH = os.path.join(CACHE_DIR, "scope_log.jsonl")
LAST_REFRESH_PATH = os.path.join(CACHE_DIR, ".last_refresh")


def _fetch_json(url: str) -> list | None:
    req = urllib.request.Request(url, headers={"User-Agent": "HuntMCP-bounty-scope/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, ValueError):
        return None


def _extract_domain(entry: dict) -> str | None:
    """Pull a plausible domain/wildcard out of a scope entry, tolerant of
    the different field names each platform uses. Returns None for entries
    that clearly aren't a domain (mobile app IDs, source repos, IP ranges,
    free-text descriptions) -- this tool is domain-scope lookup only."""
    if not isinstance(entry, dict):
        return None
    asset_type = entry.get("asset_type") or entry.get("type")
    if isinstance(asset_type, str) and asset_type.strip().upper() in NON_DOMAIN_ASSET_TYPES:
        return None
    raw = None
    for field in DOMAIN_LIKE_FIELDS:
        val = entry.get(field)
        if isinstance(val, str) and val.strip():
            raw = val.strip()
            break
    if not raw:
        return None

    if "://" in raw:
        try:
            host = urlparse(raw).hostname
        except ValueError:
            return None
        if not host:
            return None
        raw = host

    raw = raw.strip().rstrip("/")
    if DOMAIN_RE.match(raw):
        return raw.lower()
    return None


def _program_identity(program: dict) -> tuple[str, str]:
    name = program.get("name") or program.get("handle") or "unknown"
    url = program.get("url") or program.get("website") or ""
    return name, url


def _normalize_platform(platform: str, programs: list) -> list[dict]:
    """Flatten one platform's raw program list into
    {domain, platform, program, program_url, eligible_for_bounty, max_severity,
    submission_state} rows -- one row per (domain, program) pair."""
    rows = []
    for program in programs:
        if not isinstance(program, dict):
            continue
        targets = program.get("targets")
        if not isinstance(targets, dict):
            continue
        in_scope = targets.get("in_scope") or []
        if not isinstance(in_scope, list):
            continue
        name, url = _program_identity(program)
        offers_bounties = bool(program.get("offers_bounties", True))
        for entry in in_scope:
            domain = _extract_domain(entry)
            if not domain:
                continue
            eligible = entry.get("eligible_for_bounty") if isinstance(entry, dict) else None
            rows.append({
                "domain": domain,
                "platform": platform,
                "program": name,
                "program_url": url,
                "offers_bounties": offers_bounties,
                "eligible_for_bounty": eligible if eligible is not None else offers_bounties,
                "max_severity": entry.get("max_severity") if isinstance(entry, dict) else None,
                "submission_state": program.get("submission_state"),
            })
    return rows


def _load_domain_index() -> dict[str, list[dict]]:
    if not os.path.isfile(DOMAIN_INDEX_PATH):
        return {}
    with open(DOMAIN_INDEX_PATH) as f:
        return json.load(f)


def _save_domain_index(index: dict[str, list[dict]]) -> None:
    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(DOMAIN_INDEX_PATH, "w") as f:
        json.dump(index, f)


def _append_scope_log(events: list[dict]) -> None:
    if not events:
        return
    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(SCOPE_LOG_PATH, "a") as f:
        f.writelines(json.dumps(event) + "\n" for event in events)


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
    """Download all 5 platforms, rebuild the flattened domain index, and
    diff against the previous index to log newly-added/removed
    (domain, platform, program) pairs. Returns a summary dict. Safe to call
    repeatedly -- skips the actual downloads if the cache is still fresh
    (within REFRESH_TTL_SECONDS) unless force=True."""
    if not force and not needs_refresh():
        index = _load_domain_index()
        return {"refreshed": False, "reason": "cache still fresh", "domains": len(index)}

    previous = _load_domain_index()
    previous_pairs = {
        (row["domain"], row["platform"], row["program"])
        for rows in previous.values() for row in rows
    }

    new_index: dict[str, list[dict]] = {}
    failed_platforms = []
    for platform in PLATFORMS:
        data = _fetch_json(f"{BASE_URL}/{platform}_data.json")
        if data is None:
            failed_platforms.append(platform)
            continue
        for row in _normalize_platform(platform, data):
            new_index.setdefault(row["domain"], []).append(row)

    if not new_index and failed_platforms:
        # every platform failed -- don't overwrite a good cache with an empty one
        return {"refreshed": False, "reason": "all platform fetches failed", "failed": failed_platforms}

    current_pairs = {
        (row["domain"], row["platform"], row["program"])
        for rows in new_index.values() for row in rows
    }

    added = current_pairs - previous_pairs
    removed = previous_pairs - current_pairs
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    events = (
        [{"ts": now, "event": "added", "domain": d, "platform": p, "program": prog} for d, p, prog in added]
        + [{"ts": now, "event": "removed", "domain": d, "platform": p, "program": prog} for d, p, prog in removed]
    )
    _append_scope_log(events)
    _save_domain_index(new_index)
    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(LAST_REFRESH_PATH, "w") as f:
        f.write(str(time.time()))

    return {
        "refreshed": True,
        "domains": len(new_index),
        "added": len(added),
        "removed": len(removed),
        "failed_platforms": failed_platforms,
    }


def lookup_domain(domain: str) -> list[dict]:
    """Exact + wildcard-suffix match against the cached index. Does NOT
    auto-refresh -- call refresh() first (or rely on a scheduled refresh) so
    lookups stay fast and don't each trigger 5 downloads."""
    domain = domain.strip().lower().rstrip("/")
    if domain.startswith(("http://", "https://")):
        try:
            domain = urlparse(domain).hostname or domain
        except ValueError:
            pass

    index = _load_domain_index()
    matches = []
    if domain in index:
        matches.extend(index[domain])
    for candidate, rows in index.items():
        if candidate == domain:
            continue
        if candidate.startswith("*.") and (domain == candidate[2:] or domain.endswith("." + candidate[2:])):
            matches.extend(rows)
    return matches


def list_new_scope(since_hours: int = 24) -> list[dict]:
    """Read scope_log.jsonl for 'added' events within the given window."""
    if not os.path.isfile(SCOPE_LOG_PATH):
        return []
    cutoff = time.time() - since_hours * 3600
    out = []
    with open(SCOPE_LOG_PATH) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if event.get("event") != "added":
                continue
            try:
                ts = calendar.timegm(time.strptime(event["ts"], "%Y-%m-%dT%H:%M:%SZ"))
            except (ValueError, KeyError):
                continue
            if ts >= cutoff:
                out.append(event)
    return out
