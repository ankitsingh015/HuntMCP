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
import re
import subprocess
import sys
import time
from urllib.parse import urlsplit, urlunsplit

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from budget_guard import BudgetExceeded  # noqa: E402
from tool_resolver import run_tool  # noqa: E402

from mcp.server.fastmcp import FastMCP

app = FastMCP("waf-bypass-mcp")

REALISTIC_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# Keywords/markers used by mutate_payload() to auto-detect context and to
# target the case-mixing / comment-splitting mutations. Mirrors
# .claude/skills/waf-evasion-encoding-playbook/SKILL.md.
_SQL_KEYWORDS = [
    "UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "WHERE",
    "FROM", "AND", "OR", "EXEC", "EXECUTE", "ORDER BY", "GROUP BY",
]
_XSS_MARKERS = [
    "<script", "</script>", "onerror", "onload", "onclick", "javascript:",
    "<img", "<svg", "alert(",
]


def _curl_status(url: str, extra_args: list[str], timeout: int = 15) -> tuple[int | None, str | None]:
    # Routed through tool_resolver.run_tool() rather than a bare
    # subprocess.run() -- attempt_bypass() can send ~30-40 real requests at
    # the live target in one call (one per Tier 1-4 variant), and run_tool()
    # is the single chokepoint that enforces the per-engagement budget and
    # writes the audit log for every one of them, same as every other Tier-2
    # MCP server.
    args = [
        "-s", "-o", "/dev/null", "-w", "%{http_code}",
        "--max-time", str(timeout), "-A", REALISTIC_UA, *extra_args, url,
    ]
    try:
        result = run_tool("curl", args, retry_on_rate_limit=False, timeout=timeout + 5)
    except subprocess.TimeoutExpired:
        return None, "timeout"
    except FileNotFoundError:
        return None, "curl not found"
    out = result.stdout.strip()
    if out.isdigit():
        return int(out), None
    return None, (result.stderr.strip() or f"curl exit {result.returncode}")


# ---------------------------------------------------------------------------
# Payload-content mutation (mutate_payload()) -- distinct from the tiers
# above. Tiers 1-4 handle a WHOLE request getting blocked regardless of
# payload; these handle a payload getting blocked/stripped because a WAF's
# signature matched its literal content, even though the request itself
# reaches the backend. Every transform here is a deterministic string
# rewrite (percent/HTML/case/whitespace), not a live request or a model
# call -- see .claude/skills/waf-evasion-encoding-playbook/SKILL.md for the
# manual technique list this operationalizes.
# ---------------------------------------------------------------------------

def _percent_encode_all(s: str) -> str:
    return "".join(f"%{b:02X}" for b in s.encode("utf-8"))


def _double_percent_encode(s: str) -> str:
    return _percent_encode_all(s).replace("%", "%25")


def _html_entity_encode(s: str, hex_form: bool) -> str:
    if hex_form:
        return "".join(f"&#x{ord(c):x};" for c in s)
    return "".join(f"&#{ord(c)};" for c in s)


def _overlong_utf8(s: str) -> str:
    # Only characters with a well-documented overlong 2-byte UTF-8 encoding
    # that real WAF bypasses have relied on (Apache/Tomcat path-traversal
    # class) -- deliberately not generalized to arbitrary characters, since
    # getting the byte math wrong here would produce garbage instead of a
    # valid (if non-canonical) encoding.
    overlong = {"/": "%c0%af", ".": "%c0%ae", "<": "%c0%bc", ">": "%c0%be"}
    out = s
    for ch, enc in overlong.items():
        out = out.replace(ch, enc)
    return out


def _whitespace_variants(s: str) -> dict[str, str]:
    if " " not in s:
        return {}
    subs = {
        "whitespace -> %09 (tab)": "%09",
        "whitespace -> %0A (newline)": "%0A",
        "whitespace -> %0B (vertical tab)": "%0B",
        "whitespace -> %0C (form feed)": "%0C",
        "whitespace -> %A0 (NBSP)": "%A0",
        "whitespace -> /**/ (SQL comment)": "/**/",
    }
    return {name: s.replace(" ", sub) for name, sub in subs.items()}


def _mixed_case_keywords(s: str) -> str:
    def mix(word: str) -> str:
        return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(word))

    out = s
    for kw in _SQL_KEYWORDS:
        # \b word boundaries -- without them "OR" matches inside "FORMULA"
        # and "AND" inside "SANDBOX", corrupting unrelated text instead of
        # only mutating the actual keyword.
        out = re.sub(rf"\b{re.escape(kw)}\b", lambda m: mix(m.group(0)), out, flags=re.IGNORECASE)
    return out


def _sql_comment_split(s: str) -> str:
    def splitter(m: re.Match) -> str:
        w = m.group(0)
        mid = max(1, len(w) // 2)
        return w[:mid] + "/**/" + w[mid:]

    out = s
    for kw in _SQL_KEYWORDS:
        out = re.sub(rf"\b{re.escape(kw)}\b", splitter, out, flags=re.IGNORECASE)
    return out


def _js_hex_escape(s: str) -> str:
    out = []
    for c in s:
        cp = ord(c)
        if cp < 256:
            out.append(f"\\x{cp:02x}")
        elif cp <= 0xFFFF:
            out.append(f"\\u{cp:04x}")
        else:
            # \uXXXX is only valid for the BMP (exactly 4 hex digits) -- a
            # codepoint above 0xFFFF (e.g. an emoji) needs JS's \u{...}
            # codepoint escape form instead, or \uXXXX just emits invalid
            # syntax with 5+ digits.
            out.append(f"\\u{{{cp:x}}}")
    return "".join(out)


def _has_xss_marker(payload: str) -> bool:
    lower = payload.lower()
    for marker in _XSS_MARKERS:
        m = marker.lower()
        # A word boundary only makes sense on a side where the marker
        # itself starts/ends with a word character -- markers anchored by
        # punctuation ("<script", "alert(", "javascript:") are already
        # distinctive without one. Plain-word markers like "onload"/
        # "onclick" need it, or they match as a substring of an unrelated
        # word ("onload" inside "salonload", "onclick" inside "econclick").
        prefix = r"\b" if m[0].isalnum() else ""
        suffix = r"\b" if m[-1].isalnum() else ""
        if re.search(prefix + re.escape(m) + suffix, lower):
            return True
    return False


def _detect_context(payload: str) -> str:
    has_sql = any(re.search(rf"\b{re.escape(kw)}\b", payload, re.IGNORECASE) for kw in _SQL_KEYWORDS)
    has_xss = _has_xss_marker(payload)
    if has_sql and has_xss:
        return "both"
    if has_sql:
        return "sql"
    if has_xss:
        return "xss"
    return "generic"


def _tier1_variants(url: str) -> list[tuple[str, list[str], str]]:
    """Header manipulation -- fake client IP / host / user-agent."""
    ip_headers = [
        "X-Forwarded-For: 127.0.0.1",
        "X-Real-IP: 127.0.0.1",
        "X-Originating-IP: 127.0.0.1",
        "X-Remote-IP: 127.0.0.1",
        "X-Client-IP: 127.0.0.1",
        "X-Custom-IP-Authorization: 127.0.0.1",
        "X-ProxyUser-Ip: 127.0.0.1",
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

    for suffix, label in [
        ("/", "trailing /"), ("/.", "trailing /."), ("//", "double //"),
        ("%20", "trailing %20 (space)"), ("%00", "trailing %00 (null)"), ("/../", "trailing /../"),
    ]:
        new_path = path.rstrip("/") + suffix
        new_url = urlunsplit((parts.scheme, parts.netloc, new_path, parts.query, parts.fragment))
        variants.append((f"path {label}", [], new_url))

    if "/" in path.strip("/"):
        slash_encoded = path.replace("/", "%2f", 1) if path.count("/") > 1 else path
        if slash_encoded != path:
            new_url = urlunsplit((parts.scheme, parts.netloc, slash_encoded, parts.query, parts.fragment))
            variants.append(("path %2f-encode a '/'", [], new_url))

    upper_path = path.upper()
    if upper_path != path:
        new_url = urlunsplit((parts.scheme, parts.netloc, upper_path, parts.query, parts.fragment))
        variants.append(("path UPPERCASE", [], new_url))

    for ext in [".json", ".html", ".php", ";.css", ";.js", "#"]:
        new_path = path.rstrip("/") + ext
        new_url = urlunsplit((parts.scheme, parts.netloc, new_path, parts.query, parts.fragment))
        variants.append((f"path append {ext!r}", [], new_url))

    return variants


def _tier3_variants(url: str) -> list[tuple[str, list[str], str]]:
    """Method switching -- WAF rules are frequently method-specific."""
    variants = [(f"method {m}", ["-X", m], url) for m in ("HEAD", "OPTIONS", "POST", "PUT", "PATCH", "TRACE", "CONNECT")]
    variants.append((
        "X-HTTP-Method-Override: GET",
        ["-X", "POST", "-H", "X-HTTP-Method-Override: GET"],
        url,
    ))
    variants.append((
        "X-Method-Override: GET",
        ["-X", "POST", "-H", "X-Method-Override: GET"],
        url,
    ))
    sep = "&" if "?" in url else "?"
    variants.append((
        "_method=GET query param",
        ["-X", "POST"],
        f"{url}{sep}_method=GET",
    ))
    return variants


def _tier4_variants(url: str) -> list[tuple[str, list[str], str]]:
    """HTTP version tricks -- some WAF rule engines only inspect one version."""
    return [
        ("HTTP/1.0", ["--http1.0"], url),
        ("HTTP/1.1", ["--http1.1"], url),
        ("HTTP/2", ["--http2"], url),
        ("HTTP/2 prior-knowledge", ["--http2-prior-knowledge"], url),
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
    budget_exhausted = False
    for tier, label, extra_args, variant_url in variants:
        try:
            status, err = _curl_status(variant_url, extra_args)
        except BudgetExceeded as e:
            results.append(f"  [tier {tier}] {label}: SKIPPED (budget exhausted: {e})")
            budget_exhausted = True
            break
        time.sleep(delay)
        if err:
            results.append(f"  [tier {tier}] {label}: ERROR ({err})")
            continue
        marker = ""
        if status is not None and status != baseline_status:
            marker = "  <-- DIFFERENT FROM BASELINE"
            successes.append((tier, label, status, variant_url))
        results.append(f"  [tier {tier}] {label}: HTTP {status}{marker}")

    tried = len(results) if budget_exhausted else len(variants)
    header = f"Tried {tried} of {len(variants)} bypass variant(s) against {url} (baseline {baseline_status}):"
    if successes:
        footer = "\n\nPossible bypasses found:\n" + "\n".join(
            f"  tier {t} / {label} -> HTTP {status} ({vurl})" for t, label, status, vurl in successes
        )
    else:
        footer = (
            "\n\nNo variant changed the response status. Still WAF-protected "
            "after tiers 1-4. If this looks JS-challenge-shaped specifically "
            "(a Cloudflare/Akamai/Imperva/DataDome/PerimeterX interstitial or "
            "bot-check page rather than a plain rule-based block), try "
            "playwright-mcp's solve_js_challenge(url) once -- a real headless "
            "browser can clear a JS challenge that these curl-based tiers "
            "cannot. Otherwise consider Tier 5 (find the origin IP via "
            "SecurityTrails/Shodan/Censys/CT logs and connect directly) or "
            "document as WAF-protected and move on, per the master prompt's "
            "Phase 0.6 decision logic."
        )

    return header + "\n" + "\n".join(results) + footer


@app.tool()
def mutate_payload(payload: str, context: str = "auto") -> str:
    """Generate WAF/filter-evasion encodings of an injection payload using
    the deterministic techniques from
    .claude/skills/waf-evasion-encoding-playbook/SKILL.md -- for when a
    payload is logically correct but a WAF strips or blocks it based on
    its literal content. Distinct from attempt_bypass(): that handles the
    whole REQUEST being blocked regardless of payload; this handles the
    PAYLOAD itself being pattern-matched once the request already reaches
    the backend.

    Pure string transformation -- no live request is sent, so this isn't
    scope-gated or budget-counted. Feed the variant that looks most
    promising into sqlmap/dalfox/ffuf/curl yourself and diff the response
    against the baseline blocked one (status + body hash) -- a
    byte-identical block page means that variant didn't change anything.

    `context`: "sql" (keyword case-mixing/comment-splitting), "xss" (JS
    hex-escapes), or "auto" (detect from payload content -- runs both
    sets if it looks like both). Generic encodings (percent, double
    percent, HTML entity, overlong UTF-8, whitespace substitution) always
    run regardless of context."""
    if not payload:
        return "Error: payload is empty."

    ctx = context.lower().strip()
    if ctx == "auto":
        ctx = _detect_context(payload)
    elif ctx not in ("sql", "xss", "both", "generic"):
        return f"Error: unknown context {context!r}, expected one of: auto, sql, xss, both, generic."

    variants: dict[str, str] = {
        "percent-encode all": _percent_encode_all(payload),
        "double percent-encode": _double_percent_encode(payload),
        "HTML entity (hex)": _html_entity_encode(payload, hex_form=True),
        "HTML entity (decimal)": _html_entity_encode(payload, hex_form=False),
        "overlong UTF-8 (/ . < >)": _overlong_utf8(payload),
    }
    variants.update(_whitespace_variants(payload))

    if ctx in ("sql", "both"):
        variants["SQL mixed-case keywords"] = _mixed_case_keywords(payload)
        variants["SQL inline-comment split"] = _sql_comment_split(payload)
    if ctx in ("xss", "both"):
        variants["JS hex-escape"] = _js_hex_escape(payload)

    lines = [f"Encoded variants of {payload!r} (context: {ctx}):", ""]
    shown = 0
    for name, mutated in variants.items():
        if mutated == payload:
            continue
        shown += 1
        lines.append(f"  [{name}]")
        lines.append(f"    {mutated}")
    if shown == 0:
        lines.append("  (no transform changed the payload -- nothing to encode/mutate in it)")
    lines.append("")
    lines.append(
        "Send the promising ones yourself via sqlmap/dalfox/ffuf/curl and "
        "diff against the baseline blocked response -- a byte-identical "
        "block page means that variant didn't change anything."
    )
    return "\n".join(lines)


if __name__ == "__main__":
    print("waf-bypass-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
