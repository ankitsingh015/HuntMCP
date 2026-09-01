"""GitHub repo/org security-posture MCP server -- see github_security.py's
module docstring for the full design rationale.
"""

import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
sys.path.insert(0, __file__.rsplit("/", 2)[0])

import github_security
from dotenv_loader import load_dotenv_if_present
from mcp.server.fastmcp import FastMCP

load_dotenv_if_present()

app = FastMCP("github-security-mcp")


@app.tool()
def check_branch_protection(owner: str, repo: str, branch: str = "main") -> str:
    """Check whether `branch` (default "main") on owner/repo has branch
    protection configured -- required reviews, required status checks,
    enforce-admins, and whether force-pushes are allowed. A repo with NO
    protection on its default branch means anyone with write access can
    push directly, force-push over history, or merge without review or a
    passing CI run -- a real, common, checkable misconfiguration for any
    in-scope GitHub org. Requires GITHUB_TOKEN/GH_TOKEN or an
    already-authenticated gh CLI."""
    try:
        result = github_security.branch_protection(owner, repo, branch)
    except (github_security.MissingTokenError, RuntimeError) as e:
        return f"Error: {e}"

    if not result["protected"]:
        marker = "⚠️" if result["protected"] is False else "❌"
        return f"{marker} {owner}/{repo}@{branch}: {result['reason']}"
    lines = [
        f"✅ {owner}/{repo}@{branch} has branch protection:",
        f"  Required approving reviews: {result['required_reviews']}",
        f"  Required status checks: {result['required_status_checks']}",
        f"  Enforced for admins: {result['enforce_admins']}",
    ]
    if result["allows_force_pushes"]:
        lines.append("  ⚠️ Force pushes are ALLOWED despite protection -- history can still be rewritten")
    return "\n".join(lines)


@app.tool()
def check_dependabot_alerts(owner: str, repo: str) -> str:
    """List open Dependabot vulnerability alerts on owner/repo, grouped by
    severity. A 403 means the token doesn't have the security_events
    scope needed to see alerts -- reported explicitly, not silently
    treated as "zero alerts." Requires GITHUB_TOKEN/GH_TOKEN or an
    already-authenticated gh CLI."""
    try:
        result = github_security.dependabot_alerts(owner, repo)
    except (github_security.MissingTokenError, RuntimeError) as e:
        return f"Error: {e}"

    if not result["accessible"]:
        return f"Can't check Dependabot alerts for {owner}/{repo}: {result['reason']}"
    if result["open_count"] == 0:
        return f"{owner}/{repo}: no open Dependabot alerts."
    breakdown = ", ".join(f"{v} {k}" for k, v in sorted(result["by_severity"].items()))
    return f"{owner}/{repo}: {result['open_count']} open Dependabot alert(s) -- {breakdown}"


@app.tool()
def check_repo_security_posture(owner: str, repo: str) -> str:
    """Repo-level security configuration: private/public, default branch,
    and whether secret scanning / secret-scanning push protection /
    Dependabot security updates are enabled -- all from a single API call.
    Requires GITHUB_TOKEN/GH_TOKEN or an already-authenticated gh CLI."""
    try:
        result = github_security.repo_security_posture(owner, repo)
    except (github_security.MissingTokenError, RuntimeError) as e:
        return f"Error: {e}"

    if not result["accessible"]:
        return f"Can't check {owner}/{repo}: {result['reason']}"
    visibility = "private" if result["private"] else "PUBLIC"
    lines = [
        f"{owner}/{repo} ({visibility}, default branch: {result['default_branch']})",
        f"  Vulnerability alerts enabled: {result['has_vulnerability_alerts']}",
        f"  Secret scanning: {result['secret_scanning']}",
        f"  Secret scanning push protection: {result['secret_scanning_push_protection']}",
        f"  Dependabot security updates: {result['dependabot_security_updates']}",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    print("github-security-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
