"""S3 acceptance evidence: 'live: tool sees only its key'
(IMPLEMENTATION-TASK-TRACKER.md's Acceptance-Evidence Matrix).

test_dotenv_loader.py proves the underlying get_secret() primitive never
leaks an unrelated key into os.environ. This file proves the same thing
one level up, through a real consuming function (osint_apis.shodan_host,
github_security._get_token) reading from a single .env file that holds
MULTIPLE services' credentials at once -- the exact shape the real
repo-root .env has (every documented key in one file) -- confirming the
whole call path, not just the primitive, keeps credentials scoped to the
one service that actually asked for its own key.
"""

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "osint-mcp"))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "github-security-mcp"))

import dotenv_loader  # noqa: E402
import github_security  # noqa: E402
import osint_apis  # noqa: E402

MULTI_SERVICE_ENV = """\
SHODAN_API_KEY=shodan-secret
GITHUB_TOKEN=github-secret
HACKERONE_API_TOKEN=hackerone-secret
ANTHROPIC_API_KEY=anthropic-secret
"""


def _write_multi_service_env(tmp_path) -> str:
    path = tmp_path / ".env"
    path.write_text(MULTI_SERVICE_ENV)
    return str(path)


def _fake_urlopen(payload: dict):
    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return json.dumps(payload).encode()

    def _open(req, timeout=None):
        return _Resp()

    return _open


def test_osint_shodan_call_uses_only_its_own_key_from_a_shared_env_file(monkeypatch, tmp_path):
    for key in ("SHODAN_API_KEY", "GITHUB_TOKEN", "HACKERONE_API_TOKEN", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    env_path = _write_multi_service_env(tmp_path)

    payload = {"ip_str": "1.2.3.4", "ports": [80], "org": "Example"}
    monkeypatch.setattr(osint_apis.urllib.request, "urlopen", _fake_urlopen(payload))

    # osint_apis.py's own _require_env() calls get_secret(name) with the
    # module-default path, not env_path -- point dotenv_loader's default
    # at our multi-service file for this one call so the real call path
    # (not a hand-picked path=) is what's under test here.
    monkeypatch.setattr(dotenv_loader, "_ENV_PATH", env_path)
    dotenv_loader._cache.clear()

    result = osint_apis.shodan_host("1.2.3.4")

    assert result == payload
    # The service actually got its own key (the call succeeded, proving
    # SHODAN_API_KEY was read) -- but nothing else in the same file ever
    # touched this process's shared environment.
    assert "GITHUB_TOKEN" not in os.environ
    assert "HACKERONE_API_TOKEN" not in os.environ
    assert "ANTHROPIC_API_KEY" not in os.environ
    assert "SHODAN_API_KEY" not in os.environ  # not even its own -- get_secret() never writes back


def test_github_security_token_lookup_uses_only_its_own_key_from_a_shared_env_file(monkeypatch, tmp_path):
    for key in ("SHODAN_API_KEY", "GITHUB_TOKEN", "HACKERONE_API_TOKEN", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    env_path = _write_multi_service_env(tmp_path)

    monkeypatch.setattr(dotenv_loader, "_ENV_PATH", env_path)
    dotenv_loader._cache.clear()
    monkeypatch.setattr(github_security, "_token_from_gh_cli", lambda: None)

    token = github_security._get_token()

    assert token == "github-secret"
    assert "SHODAN_API_KEY" not in os.environ
    assert "HACKERONE_API_TOKEN" not in os.environ
    assert "ANTHROPIC_API_KEY" not in os.environ
    assert "GITHUB_TOKEN" not in os.environ
