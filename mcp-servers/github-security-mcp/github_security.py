"""GitHub repo/org security-posture checks via the GitHub REST API.
Confirmed gap: secrets-mcp (gitleaks) covers local-file secret scanning
and cicd-and-supply-chain already teaches CI/CD attack techniques, but
nothing here actually calls the GitHub API to check a real in-scope repo's
own security configuration.

Deliberately scoped to 3 checks that are genuinely achievable with a
handful of REST calls and no heavy dependency:
  - branch protection on one branch (missing/weak protection is a real,
    common, checkable misconfiguration)
  - Dependabot alerts (open vulnerable-dependency count by severity --
    requires the token to have the right scope; a 403 here is reported as
    "can't check" not silently swallowed)
  - repo-level security posture (private/public, security_and_analysis
    block -- secret scanning / push protection / Dependabot security
    updates enabled or not -- all from a single GET /repos/{owner}/{repo}
    call)

Explicitly NOT built here, and not pretended to be: scanning Actions
workflow run LOGS for leaked secrets. That needs pulling and unzipping
potentially large log archives per run, a meaningfully bigger scope than
the three checks above -- flagged as a real follow-up, not silently
skipped.

Deliberately NOT Tier-2/scope-gated, same reasoning as osint-mcp: every
call here queries GitHub's OWN API about a repo's configuration, never
the repo's actual deployed/running infrastructure -- reading a repo's
settings is closer to reading its README than to touching a live target.

Auth: GITHUB_TOKEN or GH_TOKEN env var, same names `gh` CLI itself
checks, so a user who already has an org token set up for other tooling
doesn't need a fourth copy of it. Falls back to `gh auth token` (the
already-authenticated `gh` CLI's own stored credential) if neither env
var is set, since this repo's own workflow already depends on `gh` being
authenticated for the PR/branch flow -- reusing that instead of forcing a
separate setup step is the same "just works with whatever you already
have" philosophy model_gateway.py applies to model provider keys.
"""

from __future__ import annotations

import json
import os
import subprocess
import urllib.error
import urllib.request

API_BASE = "https://api.github.com"
DEFAULT_TIMEOUT_S = 20


class MissingTokenError(Exception):
    pass


def _token_from_gh_cli() -> str | None:
    try:
        result = subprocess.run(
            ["gh", "auth", "token"], capture_output=True, text=True, timeout=5, check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 and result.stdout.strip() else None


def _get_token() -> str:
    token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN") or _token_from_gh_cli()
    if not token:
        raise MissingTokenError(
            "No GitHub token found. Set GITHUB_TOKEN or GH_TOKEN, or authenticate "
            "the gh CLI (gh auth login) -- its stored token is reused automatically."
        )
    return token


def _get(path: str) -> tuple[int, dict | list]:
    """Returns (status_code, parsed_body). A non-2xx status is returned,
    not raised -- several checks here (missing branch protection, no
    Dependabot access) are meaningful 403/404 responses to report, not
    failures to crash on."""
    token = _get_token()
    req = urllib.request.Request(
        f"{API_BASE}{path}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT_S) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            parsed = {"message": body[:500]}
        return e.code, parsed
    except urllib.error.URLError as e:
        raise RuntimeError(f"GitHub API unreachable: {e.reason}") from e


def branch_protection(owner: str, repo: str, branch: str = "main") -> dict:
    status, body = _get(f"/repos/{owner}/{repo}/branches/{branch}/protection")
    if status == 404:
        return {"protected": False, "reason": "no branch protection configured"}
    if status != 200:
        return {"protected": None, "reason": f"HTTP {status}: {body.get('message', body)}"}
    reviews = body.get("required_pull_request_reviews") or {}
    return {
        "protected": True,
        "required_reviews": reviews.get("required_approving_review_count", 0),
        "required_status_checks": bool(body.get("required_status_checks")),
        "enforce_admins": bool((body.get("enforce_admins") or {}).get("enabled")),
        "allows_force_pushes": bool((body.get("allow_force_pushes") or {}).get("enabled")),
    }


def dependabot_alerts(owner: str, repo: str) -> dict:
    status, body = _get(f"/repos/{owner}/{repo}/dependabot/alerts?state=open&per_page=100")
    if status == 403:
        return {"accessible": False, "reason": "token lacks Dependabot alerts access (needs security_events scope)"}
    if status == 404:
        return {"accessible": False, "reason": "Dependabot alerts not enabled for this repo"}
    if status != 200:
        return {"accessible": False, "reason": f"HTTP {status}: {body.get('message', body)}"}

    by_severity: dict[str, int] = {}
    for alert in body:
        sev = (alert.get("security_advisory") or {}).get("severity", "unknown")
        by_severity[sev] = by_severity.get(sev, 0) + 1
    return {"accessible": True, "open_count": len(body), "by_severity": by_severity}


def repo_security_posture(owner: str, repo: str) -> dict:
    status, body = _get(f"/repos/{owner}/{repo}")
    if status != 200:
        return {"accessible": False, "reason": f"HTTP {status}: {body.get('message', body)}"}

    analysis = body.get("security_and_analysis") or {}

    def _enabled(key: str) -> str:
        return (analysis.get(key) or {}).get("status", "not_available")

    return {
        "accessible": True,
        "private": body.get("private"),
        "default_branch": body.get("default_branch"),
        "has_vulnerability_alerts": body.get("has_vulnerability_alerts"),
        "secret_scanning": _enabled("secret_scanning"),
        "secret_scanning_push_protection": _enabled("secret_scanning_push_protection"),
        "dependabot_security_updates": _enabled("dependabot_security_updates"),
    }
