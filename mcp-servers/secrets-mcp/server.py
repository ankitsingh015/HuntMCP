"""Secrets/credential scanning (Phase 2.8 backlog).

Wraps gitleaks over a local directory -- katana-crawled JS, a downloaded
.git/.env, any files already pulled to disk by recon/scan -- to find
exposed API keys, tokens, and credentials. Operates on local files only,
no live network requests of its own, so it isn't a Tier-2 (target-
touching) action itself -- whatever crawled the files into that directory
already went through the scope gate.
"""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from tool_resolver import run_tool  # noqa: E402

from mcp.server.fastmcp import FastMCP

app = FastMCP("secrets-mcp")


@app.tool()
def scan_directory(path: str, redact: bool = True) -> str:
    """Scan a local directory (e.g. katana-mcp's crawl output, a saved
    .git/.env dump) for exposed secrets with gitleaks. Not a live-target
    action -- operates on files already on disk."""
    if not os.path.isdir(path):
        return f"Error: {path!r} is not a directory."

    report_path = tempfile.mktemp(suffix=".json")
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

    if not os.path.isfile(report_path):
        return "No findings (gitleaks produced no report)."

    with open(report_path) as f:
        findings = json.load(f)
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


if __name__ == "__main__":
    print("secrets-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
