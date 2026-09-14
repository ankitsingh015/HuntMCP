"""Credentialed OSINT API aggregator MCP server -- see osint_apis.py's
module docstring for the full design rationale (why not scope-gated, why
each service degrades to a plain error string instead of a crash when its
API key isn't configured).
"""

import sys

sys.path.insert(0, __file__.rsplit("/", 2)[0])

import osint_apis
from mcp.server.fastmcp import FastMCP

app = FastMCP("osint-mcp")


@app.tool()
def shodan_host_lookup(ip: str) -> str:
    """Look up one IP in Shodan's internet-wide scan cache: open ports,
    per-port service/version banners, org/ISP, known hostnames, and any
    CVEs Shodan itself has already tagged for services on this host.
    Passive -- reads Shodan's own prior scan data, never touches the IP
    directly. Requires SHODAN_API_KEY (free tier available)."""
    try:
        data = osint_apis.shodan_host(ip)
    except (osint_apis.MissingApiKeyError, RuntimeError) as e:
        return f"Error: {e}"

    ports = data.get("ports", [])
    hostnames = data.get("hostnames", [])
    vulns = list(data.get("vulns", []))
    lines = [
        f"Shodan host record for {ip}",
        f"  Org: {data.get('org', '(unknown)')} / ISP: {data.get('isp', '(unknown)')}",
        f"  Hostnames: {', '.join(hostnames) or '(none)'}",
        f"  Open ports: {', '.join(str(p) for p in sorted(ports)) or '(none recorded)'}",
        f"  Last update: {data.get('last_update', '(unknown)')}",
    ]
    if vulns:
        lines.append(f"  ⚠️ Shodan-tagged vulns: {', '.join(sorted(vulns))}")
    for svc in data.get("data", [])[:10]:
        banner = f"{svc.get('port')}/{svc.get('transport', 'tcp')} {svc.get('product', '')} {svc.get('version', '')}".strip()
        lines.append(f"  - {banner}")
    return "\n".join(lines)


@app.tool()
def shodan_favicon_search(favicon_hash: str, limit: int = 10) -> str:
    """Search Shodan for every host serving a favicon with this hash --
    the favicon-hash pivot osint-and-secret-hunting documents as a
    technique, now with an actual tool behind it. Pass the murmur3 hash of
    a target's own favicon (computed separately, e.g. via mmh3 over the
    base64-encoded favicon bytes) to find every other IP/subdomain serving
    the same app, including hosts recon never otherwise found (a forgotten
    staging box, a load-balancer's real origin IP behind a CDN). Requires
    SHODAN_API_KEY."""
    try:
        data = osint_apis.shodan_favicon_search(favicon_hash, limit=limit)
    except (osint_apis.MissingApiKeyError, RuntimeError) as e:
        return f"Error: {e}"

    total = data.get("total", 0)
    matches = data.get("matches", [])
    if not matches:
        return f"No hosts found serving favicon hash {favicon_hash!r} ({total} total reported by Shodan)."
    lines = [f"{total} host(s) match favicon hash {favicon_hash!r} (showing {len(matches)}):"]
    for m in matches:
        lines.append(f"  {m.get('ip_str')}:{m.get('port')} -- {m.get('org', '(unknown org)')}")
    return "\n".join(lines)


@app.tool()
def virustotal_domain_report(domain: str) -> str:
    """VirusTotal's reputation object for a domain: categorization, how
    many of VT's partner engines flag it malicious/suspicious/harmless,
    and registration summary -- a quick "is this domain itself known-bad"
    check. Requires VIRUSTOTAL_API_KEY (free public API)."""
    try:
        data = osint_apis.virustotal_domain(domain)
    except (osint_apis.MissingApiKeyError, RuntimeError) as e:
        return f"Error: {e}"

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    categories = attrs.get("categories", {})
    lines = [
        f"VirusTotal report for {domain}",
        f"  Reputation score: {attrs.get('reputation', '(unknown)')}",
        f"  Engine verdicts: {stats.get('malicious', 0)} malicious, "
        f"{stats.get('suspicious', 0)} suspicious, {stats.get('harmless', 0)} harmless, "
        f"{stats.get('undetected', 0)} undetected",
        f"  Categories: {', '.join(sorted(set(categories.values()))) or '(none)'}",
        f"  Creation date: {attrs.get('creation_date', '(unknown)')}",
    ]
    return "\n".join(lines)


@app.tool()
def censys_host_search(query: str, per_page: int = 10) -> str:
    """Internet-wide host search via Censys's own query syntax (e.g.
    `services.tls.certificates.leaf_data.subject.organization: "Example
    Corp"` to find every host presenting a matching cert, independent of
    DNS -- catches infrastructure that never got a subdomain enumerated at
    all). Requires CENSYS_API_ID and CENSYS_API_SECRET."""
    try:
        data = osint_apis.censys_host_search(query, per_page=per_page)
    except (osint_apis.MissingApiKeyError, RuntimeError) as e:
        return f"Error: {e}"

    result = data.get("result", {})
    total = result.get("total", 0)
    hits = result.get("hits", [])
    if not hits:
        return f"No hosts matched query {query!r} ({total} total reported by Censys)."
    lines = [f"{total} host(s) match {query!r} (showing {len(hits)}):"]
    for h in hits:
        services = ", ".join(str(s.get("port")) for s in h.get("services", []))
        lines.append(f"  {h.get('ip')} -- ports: {services or '(none)'}")
    return "\n".join(lines)


@app.tool()
def securitytrails_subdomains(domain: str) -> str:
    """Passive-DNS-derived subdomain list from SecurityTrails -- a second,
    independent data source alongside subfinder-mcp's own sources; a
    subdomain SecurityTrails has historically seen resolve but subfinder's
    sources never indexed is a real gap two independent sources close
    better than either alone. Requires SECURITYTRAILS_API_KEY."""
    try:
        data = osint_apis.securitytrails_subdomains(domain)
    except (osint_apis.MissingApiKeyError, RuntimeError) as e:
        return f"Error: {e}"

    subdomains = data.get("subdomains", [])
    if not subdomains:
        return f"No subdomains found for {domain} via SecurityTrails."
    full = sorted(f"{s}.{domain}" for s in subdomains)
    lines = [f"{len(full)} subdomain(s) for {domain} (SecurityTrails passive DNS):"]
    lines.extend(f"  {s}" for s in full)
    return "\n".join(lines)


if __name__ == "__main__":
    print("osint-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
