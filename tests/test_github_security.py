import importlib.util
import io
import json
import os
import urllib.error

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location(
    "github_security", os.path.join(ROOT, "mcp-servers", "github-security-mcp", "github_security.py"),
)
github_security = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(github_security)


def _fake_urlopen_ok(status: int, payload):
    class _Resp:
        def __init__(self):
            self.status = status
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def read(self):
            return json.dumps(payload).encode()
    def _open(req, timeout=None):
        return _Resp()
    return _open


def _fake_urlopen_http_error(code: int, payload: dict):
    def _open(req, timeout=None):
        raise urllib.error.HTTPError(
            req.full_url, code, "error", hdrs=None, fp=io.BytesIO(json.dumps(payload).encode()),
        )
    return _open


# ---------------------------------------------------------------------------
# _get() itself -- the low-level urlopen wrapper, including its
# HTTPError-to-(status, parsed_body) conversion
# ---------------------------------------------------------------------------

def test_get_returns_status_and_parsed_body_on_success(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "x")
    monkeypatch.setattr(github_security.urllib.request, "urlopen", _fake_urlopen_ok(200, {"ok": True}))
    status, body = github_security._get("/repos/acme/widgets")
    assert status == 200
    assert body == {"ok": True}


def test_get_converts_http_error_to_status_and_parsed_body(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "x")
    monkeypatch.setattr(
        github_security.urllib.request, "urlopen",
        _fake_urlopen_http_error(404, {"message": "Not Found"}),
    )
    status, body = github_security._get("/repos/acme/nonexistent")
    assert status == 404
    assert body == {"message": "Not Found"}


# ---------------------------------------------------------------------------
# Token resolution
# ---------------------------------------------------------------------------

def test_get_token_prefers_github_token_env(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "from-github-token")
    monkeypatch.setenv("GH_TOKEN", "from-gh-token")
    assert github_security._get_token() == "from-github-token"


def test_get_token_falls_back_to_gh_token_env(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setenv("GH_TOKEN", "from-gh-token")
    assert github_security._get_token() == "from-gh-token"


def test_get_token_falls_back_to_gh_cli(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.setattr(github_security, "_token_from_gh_cli", lambda: "from-gh-cli")
    assert github_security._get_token() == "from-gh-cli"


def test_get_token_raises_when_nothing_available(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.setattr(github_security, "_token_from_gh_cli", lambda: None)
    with pytest.raises(github_security.MissingTokenError):
        github_security._get_token()


# ---------------------------------------------------------------------------
# branch_protection
# ---------------------------------------------------------------------------

def test_branch_protection_reports_unprotected_on_404(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "x")
    monkeypatch.setattr(github_security, "_get", lambda path: (404, {"message": "Branch not protected"}))
    result = github_security.branch_protection("acme", "widgets")
    assert result["protected"] is False


def test_branch_protection_parses_enabled_protection(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "x")
    payload = {
        "required_pull_request_reviews": {"required_approving_review_count": 2},
        "required_status_checks": {"strict": True, "contexts": ["ci"]},
        "enforce_admins": {"enabled": True},
        "allow_force_pushes": {"enabled": False},
    }
    monkeypatch.setattr(github_security, "_get", lambda path: (200, payload))
    result = github_security.branch_protection("acme", "widgets", "main")
    assert result["protected"] is True
    assert result["required_reviews"] == 2
    assert result["required_status_checks"] is True
    assert result["enforce_admins"] is True
    assert result["allows_force_pushes"] is False


def test_branch_protection_flags_force_pushes_allowed(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "x")
    payload = {
        "required_pull_request_reviews": {},
        "required_status_checks": None,
        "enforce_admins": {"enabled": False},
        "allow_force_pushes": {"enabled": True},
    }
    monkeypatch.setattr(github_security, "_get", lambda path: (200, payload))
    result = github_security.branch_protection("acme", "widgets")
    assert result["allows_force_pushes"] is True


def test_branch_protection_reports_other_errors(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "x")
    monkeypatch.setattr(github_security, "_get", lambda path: (401, {"message": "Bad credentials"}))
    result = github_security.branch_protection("acme", "widgets")
    assert result["protected"] is None
    assert "401" in result["reason"]


# ---------------------------------------------------------------------------
# dependabot_alerts
# ---------------------------------------------------------------------------

def test_dependabot_alerts_reports_forbidden(monkeypatch):
    monkeypatch.setattr(github_security, "_get", lambda path: (403, {"message": "Forbidden"}))
    result = github_security.dependabot_alerts("acme", "widgets")
    assert result["accessible"] is False
    assert "scope" in result["reason"]


def test_dependabot_alerts_reports_not_enabled(monkeypatch):
    monkeypatch.setattr(github_security, "_get", lambda path: (404, {}))
    result = github_security.dependabot_alerts("acme", "widgets")
    assert result["accessible"] is False


def test_dependabot_alerts_groups_by_severity(monkeypatch):
    payload = [
        {"security_advisory": {"severity": "high"}},
        {"security_advisory": {"severity": "high"}},
        {"security_advisory": {"severity": "critical"}},
    ]
    monkeypatch.setattr(github_security, "_get", lambda path: (200, payload))
    result = github_security.dependabot_alerts("acme", "widgets")
    assert result["accessible"] is True
    assert result["open_count"] == 3
    assert result["by_severity"] == {"high": 2, "critical": 1}


def test_dependabot_alerts_empty_list(monkeypatch):
    monkeypatch.setattr(github_security, "_get", lambda path: (200, []))
    result = github_security.dependabot_alerts("acme", "widgets")
    assert result["open_count"] == 0


# ---------------------------------------------------------------------------
# repo_security_posture
# ---------------------------------------------------------------------------

def test_repo_security_posture_parses_full_response(monkeypatch):
    payload = {
        "private": False,
        "default_branch": "main",
        "has_vulnerability_alerts": True,
        "security_and_analysis": {
            "secret_scanning": {"status": "enabled"},
            "secret_scanning_push_protection": {"status": "disabled"},
            "dependabot_security_updates": {"status": "enabled"},
        },
    }
    monkeypatch.setattr(github_security, "_get", lambda path: (200, payload))
    result = github_security.repo_security_posture("acme", "widgets")
    assert result["accessible"] is True
    assert result["private"] is False
    assert result["secret_scanning"] == "enabled"
    assert result["secret_scanning_push_protection"] == "disabled"


def test_repo_security_posture_missing_analysis_block_defaults_gracefully(monkeypatch):
    payload = {"private": True, "default_branch": "main", "has_vulnerability_alerts": False}
    monkeypatch.setattr(github_security, "_get", lambda path: (200, payload))
    result = github_security.repo_security_posture("acme", "widgets")
    assert result["secret_scanning"] == "not_available"


def test_repo_security_posture_reports_error_status(monkeypatch):
    monkeypatch.setattr(github_security, "_get", lambda path: (404, {"message": "Not Found"}))
    result = github_security.repo_security_posture("acme", "nonexistent")
    assert result["accessible"] is False
