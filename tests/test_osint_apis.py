import importlib.util
import json
import os
import urllib.error

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location(
    "osint_apis", os.path.join(ROOT, "mcp-servers", "osint-mcp", "osint_apis.py"),
)
osint_apis = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(osint_apis)


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


def _fake_urlopen_http_error(code: int, body: str = "not found"):
    def _open(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, code, body, hdrs=None, fp=None)
    return _open


# ---------------------------------------------------------------------------
# Missing API key handling -- must raise MissingApiKeyError, never crash
# with a bare KeyError/TypeError, and must never attempt a network call.
# ---------------------------------------------------------------------------

def test_shodan_host_raises_when_key_missing(monkeypatch):
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    with pytest.raises(osint_apis.MissingApiKeyError, match="SHODAN_API_KEY"):
        osint_apis.shodan_host("1.2.3.4")


def test_shodan_favicon_search_raises_when_key_missing(monkeypatch):
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    with pytest.raises(osint_apis.MissingApiKeyError, match="SHODAN_API_KEY"):
        osint_apis.shodan_favicon_search("abc123")


def test_virustotal_domain_raises_when_key_missing(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    with pytest.raises(osint_apis.MissingApiKeyError, match="VIRUSTOTAL_API_KEY"):
        osint_apis.virustotal_domain("example.com")


def test_censys_host_search_raises_when_either_credential_missing(monkeypatch):
    monkeypatch.delenv("CENSYS_API_ID", raising=False)
    monkeypatch.delenv("CENSYS_API_SECRET", raising=False)
    with pytest.raises(osint_apis.MissingApiKeyError, match="CENSYS_API_ID"):
        osint_apis.censys_host_search("services.port: 443")


def test_censys_host_search_raises_when_only_secret_missing(monkeypatch):
    monkeypatch.setenv("CENSYS_API_ID", "some-id")
    monkeypatch.delenv("CENSYS_API_SECRET", raising=False)
    with pytest.raises(osint_apis.MissingApiKeyError, match="CENSYS_API_SECRET"):
        osint_apis.censys_host_search("services.port: 443")


def test_securitytrails_subdomains_raises_when_key_missing(monkeypatch):
    monkeypatch.delenv("SECURITYTRAILS_API_KEY", raising=False)
    with pytest.raises(osint_apis.MissingApiKeyError, match="SECURITYTRAILS_API_KEY"):
        osint_apis.securitytrails_subdomains("example.com")


# ---------------------------------------------------------------------------
# Successful lookups -- correct parsing/shape once a key IS configured
# ---------------------------------------------------------------------------

def test_shodan_host_returns_parsed_json(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "fakekey")
    payload = {"ip_str": "1.2.3.4", "ports": [80, 443], "org": "Example Corp"}
    monkeypatch.setattr(osint_apis.urllib.request, "urlopen", _fake_urlopen(payload))
    result = osint_apis.shodan_host("1.2.3.4")
    assert result == payload


def test_shodan_favicon_search_respects_limit(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "fakekey")
    payload = {"total": 5, "matches": [{"ip_str": f"1.2.3.{i}"} for i in range(5)]}
    monkeypatch.setattr(osint_apis.urllib.request, "urlopen", _fake_urlopen(payload))
    result = osint_apis.shodan_favicon_search("abc123", limit=2)
    assert len(result["matches"]) == 2
    assert result["total"] == 5  # total count itself is not truncated, only the list


def test_shodan_favicon_search_limit_zero_means_no_truncation(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "fakekey")
    payload = {"total": 3, "matches": [{"ip_str": f"1.2.3.{i}"} for i in range(3)]}
    monkeypatch.setattr(osint_apis.urllib.request, "urlopen", _fake_urlopen(payload))
    result = osint_apis.shodan_favicon_search("abc123", limit=0)
    assert len(result["matches"]) == 3


def test_virustotal_domain_returns_parsed_json(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fakekey")
    payload = {"data": {"attributes": {"reputation": -5}}}
    monkeypatch.setattr(osint_apis.urllib.request, "urlopen", _fake_urlopen(payload))
    result = osint_apis.virustotal_domain("example.com")
    assert result == payload


def test_censys_host_search_returns_parsed_json(monkeypatch):
    monkeypatch.setenv("CENSYS_API_ID", "id")
    monkeypatch.setenv("CENSYS_API_SECRET", "secret")
    payload = {"result": {"total": 1, "hits": [{"ip": "1.2.3.4"}]}}
    monkeypatch.setattr(osint_apis.urllib.request, "urlopen", _fake_urlopen(payload))
    result = osint_apis.censys_host_search("services.port: 443")
    assert result == payload


def test_securitytrails_subdomains_returns_parsed_json(monkeypatch):
    monkeypatch.setenv("SECURITYTRAILS_API_KEY", "fakekey")
    payload = {"subdomains": ["www", "api", "staging"]}
    monkeypatch.setattr(osint_apis.urllib.request, "urlopen", _fake_urlopen(payload))
    result = osint_apis.securitytrails_subdomains("example.com")
    assert result == payload


# ---------------------------------------------------------------------------
# HTTP error handling -- a 4xx/5xx from the API must become a RuntimeError
# with the status code visible, not an unhandled HTTPError.
# ---------------------------------------------------------------------------

def test_shodan_host_wraps_http_error(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "fakekey")
    monkeypatch.setattr(osint_apis.urllib.request, "urlopen", _fake_urlopen_http_error(404, "no information"))
    with pytest.raises(RuntimeError, match="404"):
        osint_apis.shodan_host("1.2.3.4")


def test_virustotal_domain_wraps_http_error(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "badkey")
    monkeypatch.setattr(osint_apis.urllib.request, "urlopen", _fake_urlopen_http_error(401, "invalid key"))
    with pytest.raises(RuntimeError, match="401"):
        osint_apis.virustotal_domain("example.com")
