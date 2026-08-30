"""Credentialed OSINT API aggregator -- Shodan/VirusTotal/Censys/
SecurityTrails. Confirmed gap: osint-and-secret-hunting already TEACHES
the favicon-hash-Shodan-pivot technique (and passive-DNS/internet-scan
lookups generally) as recon methodology, with no tool behind any of it --
every one of these is a manual "go paste this into the web UI" step today.

Deliberately NOT Tier-2/scope-gated: every lookup here queries a
THIRD-PARTY database ABOUT a target (Shodan/Censys's own internet-wide
scan cache, VirusTotal's/SecurityTrails's own passive-DNS and reputation
data) -- no request ever reaches the target's own infrastructure, the
same reasoning that already keeps bounty_scope.py/disclosed_reports.py
ungated. This is the OSINT-recon equivalent of a WHOIS lookup, not an
active probe.

Each service needs its own API key/credential, read from an env var
(never a config file, never committed) -- same "just works with whatever
key you already have" philosophy as model_gateway.py, and the same
graceful-not-crashing shape hackerone-mcp already established:
MissingApiKeyError is caught by the calling @app.tool() function and
turned into a plain "Error: ..." string, not an unhandled exception, so a
user who hasn't set up a given service's key yet gets a clear one-line
explanation instead of a stack trace.

All four are free-tier-usable APIs (Shodan/Censys/SecurityTrails all
offer a free tier with a real API key; VirusTotal's public API is free
with rate limits) -- this isn't gated behind a paid-only integration.
"""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request

SHODAN_BASE = "https://api.shodan.io"
VIRUSTOTAL_BASE = "https://www.virustotal.com/api/v3"
CENSYS_BASE = "https://search.censys.io/api/v2"
SECURITYTRAILS_BASE = "https://api.securitytrails.com/v1"

DEFAULT_TIMEOUT_S = 20


class MissingApiKeyError(Exception):
    pass


def _require_env(*names: str, how_to_get: str) -> list[str]:
    values = [os.getenv(n) for n in names]
    missing = [n for n, v in zip(names, values) if not v]
    if missing:
        raise MissingApiKeyError(
            f"{' and '.join(missing)} must be set. {how_to_get}"
        )
    return values


def _get_json(url: str, headers: dict, timeout: int = DEFAULT_TIMEOUT_S) -> dict:
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        raise RuntimeError(f"HTTP {e.code}: {body[:500]}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"unreachable: {e.reason}") from e


# ---------------------------------------------------------------------------
# Shodan
# ---------------------------------------------------------------------------

def shodan_host(ip: str) -> dict:
    """Raw host record for one IP: open ports, per-port service banners,
    org/ISP, hostnames, and any vulns Shodan itself has already tagged."""
    (api_key,) = _require_env(
        "SHODAN_API_KEY",
        how_to_get="Get a free-tier key at https://account.shodan.io/register.",
    )
    url = f"{SHODAN_BASE}/shodan/host/{urllib.parse.quote(ip)}?key={api_key}"
    return _get_json(url, headers={})


def shodan_favicon_search(favicon_hash: str, limit: int = 10) -> dict:
    """The exact favicon-hash pivot osint-and-secret-hunting already
    documents as a technique with no tool behind it: search Shodan's
    internet-wide scan cache for every host serving a favicon with this
    murmur3 hash -- if a target's own favicon hash is unique enough, this
    surfaces every other IP/subdomain serving the same app, including ones
    recon never otherwise found (a forgotten staging host, a load-balancer
    origin IP behind a CDN)."""
    (api_key,) = _require_env(
        "SHODAN_API_KEY",
        how_to_get="Get a free-tier key at https://account.shodan.io/register.",
    )
    query = urllib.parse.urlencode({"key": api_key, "query": f"http.favicon.hash:{favicon_hash}"})
    url = f"{SHODAN_BASE}/shodan/host/search?{query}"
    data = _get_json(url, headers={})
    if limit:
        data = {**data, "matches": data.get("matches", [])[:limit]}
    return data


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------

def virustotal_domain(domain: str) -> dict:
    """Domain reputation object: categorization, last_analysis_stats
    (how many of VT's partner engines flag this domain malicious/
    suspicious), and registration/whois summary -- a quick "is this
    domain itself known-bad, or does it belong to infra I should be
    suspicious of" check before spending time testing it."""
    (api_key,) = _require_env(
        "VIRUSTOTAL_API_KEY",
        how_to_get="Get a free public-API key from your VirusTotal account settings.",
    )
    url = f"{VIRUSTOTAL_BASE}/domains/{urllib.parse.quote(domain)}"
    return _get_json(url, headers={"x-apikey": api_key})


# ---------------------------------------------------------------------------
# Censys
# ---------------------------------------------------------------------------

def censys_host_search(query: str, per_page: int = 10) -> dict:
    """Internet-wide host search (Censys's own query syntax, e.g.
    `services.tls.certificates.leaf_data.subject.organization: "Example
    Corp"` to find every host presenting a cert for an org, independent of
    DNS -- catches infrastructure that never got a subdomain enumerated at
    all)."""
    api_id, api_secret = _require_env(
        "CENSYS_API_ID", "CENSYS_API_SECRET",
        how_to_get="Get a free-tier API ID/secret from your Censys account settings.",
    )
    creds = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
    q = urllib.parse.urlencode({"q": query, "per_page": per_page})
    url = f"{CENSYS_BASE}/hosts/search?{q}"
    return _get_json(url, headers={"Authorization": f"Basic {creds}"})


# ---------------------------------------------------------------------------
# SecurityTrails
# ---------------------------------------------------------------------------

def securitytrails_subdomains(domain: str) -> dict:
    """Passive-DNS-derived subdomain list -- a second, independent data
    source alongside subfinder-mcp's own sources; a subdomain SecurityTrails
    has historically seen resolve but subfinder's sources never indexed is
    a real, not-hypothetical gap two independent passive sources close
    better than either alone."""
    (api_key,) = _require_env(
        "SECURITYTRAILS_API_KEY",
        how_to_get="Get a free-tier key at https://securitytrails.com/app/signup.",
    )
    url = f"{SECURITYTRAILS_BASE}/domain/{urllib.parse.quote(domain)}/subdomains"
    return _get_json(url, headers={"APIKEY": api_key})
