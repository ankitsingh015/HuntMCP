"""Secrets/credential scanning (Phase 2.8 backlog).

Wraps gitleaks over a local directory -- katana-crawled JS, a downloaded
.git/.env, any files already pulled to disk by recon/scan -- to find
exposed API keys, tokens, and credentials. Operates on local files only,
no live network requests of its own, so it isn't a Tier-2 (target-
touching) action itself -- whatever crawled the files into that directory
already went through the scope gate.

Also exposes extract_endpoints() (added 2026-08-29, js_endpoints.py) --
the same local-directory scan, but for API route candidates instead of
credentials. Complementary, not overlapping: run both against the same
downloaded-JS directory, one for what the app talks to, one for what
secrets it's leaking while doing it.
"""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from tool_resolver import run_tool  # noqa: E402

import js_endpoints
from mcp.server.fastmcp import FastMCP

app = FastMCP("secrets-mcp")


@app.tool()
def scan_directory(path: str, redact: bool = True) -> str:
    """Scan a local directory (e.g. katana-mcp's crawl output, a saved
    .git/.env dump) for exposed secrets with gitleaks. Not a live-target
    action -- operates on files already on disk."""
    if not os.path.isdir(path):
        return f"Error: {path!r} is not a directory."

    # mkstemp() (not the deprecated, TOCTOU-prone mktemp()) reserves a
    # unique path atomically; immediately remove the empty file it creates
    # so gitleaks writes the real report there fresh, preserving the
    # "no report" check below.
    fd, report_path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    os.unlink(report_path)

    args = [
        "detect", "--no-git", "--source", path,
        "--report-format", "json", "--report-path", report_path,
        "--exit-code", "0",
    ]
    if redact:
        args.append("--redact")

    try:
        result = run_tool("gitleaks", args, retry_on_rate_limit=False, timeout=120)
    except FileNotFoundError:
        return "Error: gitleaks not found. Install with: go install github.com/zricethezav/gitleaks/v8@latest"
    except Exception as e:
        return f"Error: {e}"

    if result.returncode != 0:
        return f"gitleaks failed (exit {result.returncode}): {result.stderr.strip()[:500]}"

    try:
        if not os.path.isfile(report_path):
            return "No findings (gitleaks produced no report)."
        with open(report_path) as f:
            findings = json.load(f)
    finally:
        if os.path.isfile(report_path):
            os.unlink(report_path)

    if not findings:
        return f"No secrets found in {path!r}."

    lines = [f"{len(findings)} potential secret(s) found in {path!r}:"]
    for f in findings:
        lines.append(
            f"  [{f.get('RuleID', '?')}] {f.get('File', '?')}:{f.get('StartLine', '?')} "
            f"-- {f.get('Match', f.get('Secret', '(redacted)'))[:80]}"
        )
    return "\n".join(lines)


@app.tool()
def extract_endpoints(path: str, max_results: int = 500) -> str:
    """Scan a local directory (e.g. recon-agent's own downloaded-JS
    directory, data/engagements/<slug>/downloads/) for API-route
    candidates -- every "/api/...", "/v1/...", "/graphql", etc.-shaped
    string literal found across all .js/.ts/.jsx/.tsx files, deduped,
    with route-parameter names extracted (":id"/"{id}"/"[id]" style) and
    the source file(s) each one was found in. Regex-based candidate
    extraction, not verified ground truth -- treat results the same way
    subfinder/httpx/katana's own output is treated, as a list worth
    checking, not a guarantee every entry is a real, reachable endpoint.
    Not a live-target action -- operates on files already on disk, same
    as scan_directory()."""
    if not os.path.isdir(path):
        return f"Error: {path!r} is not a directory."

    inventory = js_endpoints.scan_directory_for_endpoints(path, max_results=max_results)
    if not inventory:
        return f"No API-route-shaped string literals found in {path!r}."

    lines = [f"{len(inventory)} candidate endpoint(s) found in {path!r}:"]
    for endpoint in sorted(inventory):
        params = js_endpoints.extract_params(endpoint)
        sources = inventory[endpoint]
        param_note = f" (params: {', '.join(params)})" if params else ""
        source_note = sources[0] if len(sources) == 1 else f"{sources[0]} +{len(sources) - 1} more"
        lines.append(f"  {endpoint}{param_note} -- {source_note}")
    return "\n".join(lines)


if __name__ == "__main__":
    print("secrets-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
