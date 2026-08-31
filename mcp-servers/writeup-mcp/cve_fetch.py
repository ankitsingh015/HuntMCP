"""Fetch CVEs from the NVD REST API and write them as writeup-shaped markdown.

Deliberately reuses the existing writeup pipeline instead of building a
parallel storage system: each CVE becomes a data/writeups/*.md file with the
same frontmatter shape (title, url, vuln_class, tech) as any other writeup,
so it flows through chunk_writeup() -> embed() -> ChromaDB unchanged, and is
retrievable via the same query_rag() every agent already uses.
"""

from __future__ import annotations

import argparse
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
WRITEUP_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data", "writeups")


def _best_cvss(metrics: dict) -> tuple[str, str]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0]["cvssData"]
            score = str(data.get("baseScore", "?"))
            severity = str(entries[0].get("baseSeverity", data.get("baseSeverity", "?")))
            return score, severity
    return "?", "?"


def _cwe(weaknesses: list | None) -> str:
    for w in weaknesses or []:
        for d in w.get("description", []):
            if d.get("value", "").startswith("CWE-"):
                return d["value"]
    return "N/A"


def _fetch_epss_scores(cve_ids: list[str]) -> dict[str, str]:
    """Batch-fetch EPSS (exploit prediction) scores for a list of CVE IDs
    in one API call. Returns {cve_id: score_str}; missing entries just
    aren't in the dict (EPSS doesn't score every CVE, e.g. very new ones)."""
    if not cve_ids:
        return {}
    url = f"{EPSS_API}?cve={','.join(cve_ids)}"
    try:
        data = _fetch_json(url, {"User-Agent": "HuntMCP-cve-fetch/1.0"}, retries=1)
    except (urllib.error.URLError, RuntimeError):
        return {}
    return {row["cve"]: row["epss"] for row in data.get("data", [])}


def _fetch_kev_set() -> set[str]:
    """CISA's Known Exploited Vulnerabilities catalog -- CVEs confirmed
    actively exploited in the wild, not just theoretically scorable.
    Best-effort: an empty set (not an exception) if CISA's feed is
    unreachable, since KEV is a priority signal, not a hard requirement."""
    try:
        data = _fetch_json(KEV_URL, {"User-Agent": "HuntMCP-cve-fetch/1.0"}, retries=1)
    except (urllib.error.URLError, RuntimeError):
        return set()
    return {v["cveID"] for v in data.get("vulnerabilities", [])}


def _cve_to_markdown(cve: dict, keyword: str, epss_score: str | None, in_kev: bool) -> str:
    cve_id = cve["id"]
    descriptions = cve.get("descriptions", [])
    desc = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        "No description available.",
    )
    score, severity = _best_cvss(cve.get("metrics", {}))
    cwe = _cwe(cve.get("weaknesses"))
    published = cve.get("published", "")[:10]
    epss_line = f"{float(epss_score):.1%} probability of exploitation in the next 30 days" if epss_score else "not scored"
    kev_line = "**YES -- actively exploited, per CISA KEV**" if in_kev else "not listed"

    return f"""---
title: "{cve_id} -- {keyword}"
url: "https://nvd.nist.gov/vuln/detail/{cve_id}"
vuln_class: CVE
tech: {keyword}
---

# {cve_id}

- **CVSS**: {score} ({severity})
- **CWE**: {cwe}
- **Published**: {published}
- **EPSS**: {epss_line}
- **CISA KEV**: {kev_line}
- **NVD**: https://nvd.nist.gov/vuln/detail/{cve_id}

## Description

{desc}
"""


def _fetch_json(url: str, headers: dict, retries: int = 3) -> dict:
    last_err: Exception | None = None
    for attempt in range(retries):
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            last_err = e
            # NVD's public rate limit (no API key) is 5 requests / 30s.
            if e.code in (403, 429) and attempt < retries - 1:
                time.sleep(6)
                continue
            raise
        except (urllib.error.URLError, TimeoutError, ConnectionResetError) as e:
            # Transient network failure (timeout, connection reset, DNS
            # hiccup) -- NOT an HTTPError, so the branch above never caught
            # it: a single dropped connection used to propagate immediately
            # with zero retries despite the `retries` param implying
            # otherwise. Short backoff, same attempt budget as the rate-limit
            # case above.
            last_err = e
            if attempt < retries - 1:
                time.sleep(2)
                continue
            raise
    raise RuntimeError(f"Failed to fetch {url} after {retries} attempts") from last_err


def fetch_cves(
    keyword: str,
    limit: int = 20,
    api_key: str | None = None,
    writeup_dir: str | None = None,
) -> list[str]:
    """Fetch up to `limit` CVEs matching `keyword` from NVD, write one
    writeup-shaped .md file per new CVE into `writeup_dir` (defaults to the
    module-level WRITEUP_DIR), and return the filenames actually written.
    CVEs already present on disk are skipped, so re-running with the same
    keyword is cheap and idempotent.
    """
    target_dir = writeup_dir or WRITEUP_DIR
    params = {"keywordSearch": keyword, "resultsPerPage": str(min(limit, 200))}
    url = f"{NVD_API}?{urllib.parse.urlencode(params)}"
    headers = {"User-Agent": "HuntMCP-cve-fetch/1.0"}
    if api_key:
        headers["apiKey"] = api_key

    data = _fetch_json(url, headers)

    os.makedirs(target_dir, exist_ok=True)
    new_cves = []
    for vuln in data.get("vulnerabilities", [])[:limit]:
        cve = vuln["cve"]
        fpath = os.path.join(target_dir, f"{cve['id'].lower()}.md")
        if not os.path.exists(fpath):
            new_cves.append(cve)

    if not new_cves:
        return []

    # EPSS + KEV are prioritization signals (which of these CVEs actually
    # matters), fetched once for the whole new batch rather than per-CVE.
    epss_scores = _fetch_epss_scores([c["id"] for c in new_cves])
    kev_set = _fetch_kev_set()

    written = []
    for cve in new_cves:
        fname = f"{cve['id'].lower()}.md"
        fpath = os.path.join(target_dir, fname)
        with open(fpath, "w") as f:
            f.write(_cve_to_markdown(
                cve, keyword,
                epss_score=epss_scores.get(cve["id"]),
                in_kev=cve["id"] in kev_set,
            ))
        written.append(fname)

    return written


def _cli() -> None:
    parser = argparse.ArgumentParser(
        description="Fetch CVEs from NVD into data/writeups/ for RAG ingestion."
    )
    parser.add_argument("keyword", help="Product/vendor keyword to search, e.g. 'wordpress'")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--api-key", default=os.getenv("NVD_API_KEY"))
    args = parser.parse_args()

    written = fetch_cves(args.keyword, limit=args.limit, api_key=args.api_key)
    print(f"Wrote {len(written)} new CVE writeup(s) for '{args.keyword}':")
    for fname in written:
        print(f"  data/writeups/{fname}")
    if written:
        print("\nRun writeup-mcp's reindex_all (or fetch_cves via MCP, which auto-embeds) to make these searchable.")
    else:
        print("(nothing new -- already ingested, or no matches)")


if __name__ == "__main__":
    _cli()
