"""WAF bypass tooling (Phase 2.8) -- the actual escalation path when
tool_resolver.classify_block() returns "waf". Systematically tries the
Tier 1-4 techniques from knowledge/master-pentest-prompt.md's Phase 0.6
403/WAF bypass guide (header spoofing, path manipulation, method
switching, HTTP version tricks) against a blocked URL and reports which
variant(s), if any, got a materially different response than the
original block.

Tier 5 (CDN/origin-IP bypass) needs external OSINT (Shodan/Censys/CT-log
lookups to find the origin IP) rather than a simple retry loop, so it
stays a manual step per the master prompt -- not automated here.

Unlike oob-mcp, this sends real requests straight at the live target, so
it IS scope-gated exactly like the other Tier-2 MCP servers (its `url`
argument is covered by scope_gate_hook.py's HOST_ARG_KEYS, and
waf-bypass-mcp is listed in its TIER2_MCP_SERVERS set).
"""

import os
import subprocess
import sys
import time
from urllib.parse import urlsplit, urlunsplit

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from budget_guard import enforce as _enforce_budget  # noqa: E402

from mcp.server.fastmcp import FastMCP

app = FastMCP("waf-bypass-mcp")

REALISTIC_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


def _curl_status(url: str, extra_args: list[str], timeout: int = 15) -> tuple[int | None, str | None]:
    args = [
        "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
        "--max-time", str(timeout), "-A", REALISTIC_UA, *extra_args, url,
    ]
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout + 5)
    except subprocess.TimeoutExpired:
        return None, "timeout"
    except FileNotFoundError:
        return None, "curl not found"
    out = result.stdout.strip()
    if out.isdigit():
        return int(out), None
    return None, (result.stderr.strip() or f"curl exit {result.returncode}")


def _tier1_variants(url: str) -> list[tuple[str, list[str], str]]:
    """Header manipulation -- fake client IP / host / user-agent."""
    ip_headers = [
        "X-Forwarded-For: 127.0.0.1",
        "X-Real-IP: 127.0.0.1",
        "X-Originating-IP: 127.0.0.1",
        "X-Client-IP: 127.0.0.1",
        "True-Client-IP: 127.0.0.1",
        "Forwarded: for=127.0.0.1;host=localhost",
    ]
    variants = [(f"header {h}", ["-H", h], url) for h in ip_headers]
    variants.append(("fake Host: localhost", ["-H", "Host: localhost"], url))
    variants.append((
        "UA: Googlebot",
        ["-A", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"],
        url,
    ))
    variants.append(("UA: empty", ["-A", ""], url))
    return variants


def _tier2_variants(url: str) -> list[tuple[str, list[str], str]]:
    """Path manipulation -- encoding, case, trailing chars, extensions."""
    parts = urlsplit(url)
    path = parts.path or "/"
    variants: list[tuple[str, list[str], str]] = []

    for i, c in enumerate(path):
        if c.isalpha():
            encoded_path = path[:i] + f"%{ord(c):02x}" + path[i + 1:]
            new_url = urlunsplit((parts.scheme, parts.netloc, encoded_path, parts.query, parts.fragment))
            variants.append((f"path %-encode '{c}'", [], new_url))
            break

    for suffix, label in [("/", "trailing /"), ("/.", "trailing /."), ("//", "double //")]:
        new_path = path.rstrip("/") + suffix
        new_url = urlunsplit((parts.scheme, parts.netloc, new_path, parts.query, parts.fragment))
        variants.append((f"path {label}", [], new_url))

    upper_path = path.upper()
    if upper_path != path:
        new_url = urlunsplit((parts.scheme, parts.netloc, upper_path, parts.query, parts.fragment))
        variants.append(("path UPPERCASE", [], new_url))

    for ext in [".json", ";.css", "#"]:
        new_path = path.rstrip("/") + ext
        new_url = urlunsplit((parts.scheme, parts.netloc, new_path, parts.query, parts.fragment))
        variants.append((f"path append {ext!r}", [], new_url))

    return variants


def _tier3_variants(url: str) -> list[tuple[str, list[str], str]]:
    """Method switching -- WAF rules are frequently method-specific."""
    variants = [(f"method {m}", ["-X", m], url) for m in ("HEAD", "OPTIONS", "POST", "PATCH", "TRACE")]
    variants.append((
        "X-HTTP-Method-Override: GET",
        ["-X", "POST", "-H", "X-HTTP-Method-Override: GET"],
        url,
    ))
    return variants


def _tier4_variants(url: str) -> list[tuple[str, list[str], str]]:
    """HTTP version tricks -- some WAF rule engines only inspect one version."""
    return [
        ("HTTP/1.0", ["--http1.0"], url),
        ("HTTP/1.1", ["--http1.1"], url),
        ("HTTP/2", ["--http2"], url),
    ]


_TIER_BUILDERS = {"1": _tier1_variants, "2": _tier2_variants, "3": _tier3_variants, "4": _tier4_variants}


@app.tool()
def attempt_bypass(url: str, baseline_status: int = 403, tiers: str = "1,2,3,4", delay: float = 0.5) -> str:
    """Try the Tier 1-4 WAF-bypass techniques from
    knowledge/master-pentest-prompt.md's Phase 0.6 guide against a URL
    that tool_resolver.classify_block() flagged as WAF-blocked. Reports
    every variant whose response status differs from baseline_status
    (the originally observed block code, default 403).

    Tier 5 (CDN/origin-IP bypass) needs external OSINT (Shodan/Censys/CT
    logs to find the origin IP) rather than a retry, so it isn't automated
    here -- see the master prompt's Phase 0.6 for that step. `delay`
    (seconds between requests, default 0.5) keeps this from hammering an
    already-suspicious endpoint with a rapid burst."""
    try:
        _enforce_budget("curl-waf-bypass")
    except Exception as e:
        return f"Error: {e}"

    requested_tiers = [t.strip() for t in tiers.split(",") if t.strip()]
    variants: list[tuple[str, str, list[str], str]] = []
    for t in requested_tiers:
        builder = _TIER_BUILDERS.get(t)
        if builder:
            variants.extend((t, label, args, vurl) for label, args, vurl in builder(url))

    if not variants:
        return f"No valid tiers requested (got {tiers!r}, expected a subset of 1,2,3,4)."

    results = []
    successes = []
    for tier, label, extra_args, variant_url in variants:
        status, err = _curl_status(variant_url, extra_args)
        time.sleep(delay)
        if err:
            results.append(f"  [tier {tier}] {label}: ERROR ({err})")
            continue
        marker = ""
        if status is not None and status != baseline_status:
            marker = "  <-- DIFFERENT FROM BASELINE"
            successes.append((tier, label, status, variant_url))
        results.append(f"  [tier {tier}] {label}: HTTP {status}{marker}")

    header = f"Tried {len(variants)} bypass variant(s) against {url} (baseline {baseline_status}):"
    if successes:
        footer = "\n\nPossible bypasses found:\n" + "\n".join(
            f"  tier {t} / {label} -> HTTP {status} ({vurl})" for t, label, status, vurl in successes
        )
    else:
        footer = (
            "\n\nNo variant changed the response status. Still WAF-protected "
            "after tiers 1-4 -- consider Tier 5 (find the origin IP via "
            "SecurityTrails/Shodan/Censys/CT logs and connect directly) or "
            "document as WAF-protected and move on, per the master prompt's "
            "Phase 0.6 decision logic."
        )

    return header + "\n" + "\n".join(results) + footer


if __name__ == "__main__":
    print("waf-bypass-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
