"""Spec 2 (SSO surface), Task 1: pure SSO logic -- no browser.

Role classification, secret-param redaction, authorize/logout flags (never a
state/nonce/code value), strength classes, flow keys, repeat comparison and
discovery-document parsing.
"""

import base64
import json
import os
import secrets
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "browser-mcp"))

import ui_walk_sso_logic as S


def test_classify_roles():
    cases = {
        "https://login.microsoftonline.com/t/oauth2/v2.0/authorize?client_id=a&response_type=code": "authorize",
        "https://acme.okta.com/oauth2/default/v1/authorize?client_id=a": "authorize",
        "https://kc.acme.com/realms/acme/protocol/openid-connect/auth?client_id=a&response_type=code": "authorize",
        "https://acme.auth0.com/authorize?x=1": "authorize",
        "https://accounts.example.com/o/oauth2/auth?client_id=a": "authorize",
        "https://acme.auth.us-east-1.amazoncognito.com/oauth2/authorize?client_id=a": "authorize",
        "https://idp.acme.com/.well-known/openid-configuration": "discovery",
        "https://idp.acme.com/.well-known/oauth-authorization-server": "discovery",
        "https://app.acme.com/sso/callback?code=x&state=y": "callback",
        "https://idp.acme.com/sso?SAMLRequest=x": "saml-request",
        "https://kc.acme.com/realms/acme/protocol/openid-connect/logout": "logout",
        "https://idp.acme.com/oauth2/token": "token",
        "https://idp.acme.com/userinfo": "userinfo",
        "https://idp.acme.com/oauth2/revoke": "revocation",
        "https://idp.acme.com/oauth2/introspect": "introspection",
        "https://idp.acme.com/connect/register": "registration",
        "https://idp.acme.com/oauth2/device_authorization": "device_authorization",
    }
    for url, role in cases.items():
        assert S.classify_url(url) == role, url
    assert S.classify_url("https://app.acme.com/saml/acs", "POST", ["SAMLResponse", "RelayState"]) == "saml-response"


def test_classify_negatives():
    for url in ("https://a.com/author", "https://a.com/blog/authorize-payments",
                "https://a.com/tokens/list", "https://a.com/logout-tips/article",
                "https://a.com/?state=x", "https://a.com/register-interest"):
        assert S.classify_url(url) is None, url


def test_redact_query_and_fragment_case_insensitive():
    out = S.redact_sso_params("https://a.com/cb?STATE=s1secret&x=1#id_token=t1secret&Nonce=n1secret")
    assert "STATE=REDACTED" in out and "x=1" in out
    assert "id_token=REDACTED" in out and "Nonce=REDACTED" in out
    for v in ("s1secret", "t1secret", "n1secret"):
        assert v not in out


def test_redact_keeps_non_secret_and_non_url():
    assert S.redact_sso_params("https://a.com/p?q=hello") == "https://a.com/p?q=hello"
    assert S.redact_sso_params("not a url") == "not a url"


def test_redact_urls_deep_nested():
    obj = {"a": [{"b": ("https://x.com/cb?code=SECRETC1&z=2",)}], "c": "plain code=1", "n": 3}
    out = S.redact_urls_deep(obj)
    assert "SECRETC1" not in json.dumps(out)
    assert out["c"] == "plain code=1" and out["n"] == 3
    assert "z=2" in json.dumps(out)
    assert "SECRETC1" in json.dumps(obj)   # input not mutated


def test_authorize_flags_never_hold_secret_values():
    url = ("https://idp.acme.com/authorize?response_type=code&client_id=app1&scope=openid%20profile"
           "&state=SECRETSTATE123456&nonce=SECRETNONCE&code_challenge=CCVALUE&code_challenge_method=S256"
           "&login_hint=a@b.c&redirect_uri=https%3A%2F%2Fapp%2Fcb%3Fx%3D1")
    flags = S.authorize_flags(url)
    dump = json.dumps(flags)
    for v in ("SECRETSTATE123456", "SECRETNONCE", "CCVALUE", "a@b.c", "x=1"):
        assert v not in dump
    assert flags["redirect_uri"] == "https://app/cb"
    assert flags["pkce"] is True
    assert flags["code_challenge_method"] == "S256"
    assert flags["client_id"] == "app1" and flags["response_type"] == "code"
    assert flags["state"] == {"present": True, "strength": "ok", "length_bucket": "16-31"}
    assert flags["nonce"]["present"] is True
    assert "login_hint" in flags["param_names"]


def test_strength_classes():
    assert S.secret_strength(None) == "absent"
    assert S.secret_strength("") == "absent"
    assert S.secret_strength("abc") == "short"
    assert S.secret_strength("1234567890123456") == "low-charset"
    assert S.secret_strength("eyJhbGciOiJub25lIn0.eyJhIjoxfQ.sig") == "structured"
    b64 = base64.b64encode(b'{"r":"/x","pad":"aaaa"}').decode()
    assert S.secret_strength(b64) == "structured"
    assert S.secret_strength(secrets.token_urlsafe(24)) == "ok"
    assert S.length_bucket(None) is None
    assert [S.length_bucket("a" * n) for n in (3, 8, 16, 32)] == ["<8", "8-15", "16-31", "32+"]


def test_logout_flags():
    f = S.logout_flags("https://idp/logout?post_logout_redirect_uri=https://evil/x&id_token_hint=TOKHINT&returnTo=/y")
    assert f["redirect_params"] == ["post_logout_redirect_uri", "returnto"]
    assert f["post_logout_redirect_uri"] == "https://evil/x"
    assert "TOKHINT" not in json.dumps(f)


def test_flow_key_ignores_state():
    a = "https://idp/authorize?client_id=c1&redirect_uri=https://app/cb&state=AAAA1111&nonce=x"
    b = "https://idp/authorize?client_id=c1&redirect_uri=https://app/cb&state=BBBB2222&nonce=y"
    c = "https://idp/authorize?client_id=c2&redirect_uri=https://app/cb&state=AAAA1111"
    assert S.flow_key(a) == S.flow_key(b)
    assert S.flow_key(a) != S.flow_key(c)
    # two IdPs on one host name, different ports, are different flows
    assert S.flow_key("http://localhost:1/authorize?client_id=c1") != S.flow_key("http://localhost:2/authorize?client_id=c1")
    # implicit vs code against the same client is a different flow (different checks)
    assert S.flow_key(a + "&response_type=code") != S.flow_key(a + "&response_type=id_token%20token")


def test_secrets_of_and_compare():
    first = S.secrets_of("https://idp/authorize?state=s1&nonce=n1")
    assert first == {"state": "s1", "nonce": "n1"}
    assert S.compare_secrets(first, {"state": "s1", "nonce": "n2"}) == {
        "state_changes_per_request": False, "nonce_changes_per_request": True}
    assert S.compare_secrets(first, None) == {
        "state_changes_per_request": "unknown", "nonce_changes_per_request": "unknown"}
    assert S.compare_secrets({}, {})["nonce_changes_per_request"] == "unknown"


def test_discovery_urls_root_and_issuer_prefix():
    kc = S.discovery_urls("https://kc.acme.com/realms/acme/protocol/openid-connect/auth?client_id=a")
    # the issuer-specific URL first: a server may answer any root path with a bogus document
    assert kc == ["https://kc.acme.com/realms/acme/.well-known/openid-configuration",
                  "https://kc.acme.com/.well-known/openid-configuration"]
    assert S.discovery_urls("https://idp.acme.com/authorize?x=1") == [
        "https://idp.acme.com/.well-known/openid-configuration"]


def test_parse_discovery():
    doc = {"issuer": "https://idp.acme.com", "authorization_endpoint": "https://idp.acme.com/authorize",
           "token_endpoint": "https://other.com/token", "end_session_endpoint": "https://idp.acme.com/logout?x=1",
           "registration_endpoint": "https://idp.acme.com/register", "jwks_uri": "javascript:alert(1)",
           "response_types_supported": ["code", "id_token token"], "claims_supported": "notalist"}
    out = S.parse_discovery(json.dumps(doc).encode(), scope=lambda u: "idp.acme.com" in u)
    roles = {e["role"]: e for e in out["endpoints"]}
    assert set(roles) == {"authorize", "token", "logout", "registration"}
    assert roles["token"]["in_scope"] is False and roles["authorize"]["in_scope"] is True
    assert roles["logout"]["url"] == "https://idp.acme.com/logout"
    assert out["supported"] == {"response_types_supported": ["code", "id_token token"]}
    assert out["issuer"] == "https://idp.acme.com"
    assert S.parse_discovery(b"not json", scope=lambda u: True) is None
    assert S.parse_discovery(b"x" * 262145, scope=lambda u: True) is None
    assert S.parse_discovery(b"[1,2]", scope=lambda u: True) is None


def test_sso_page_role():
    assert S.sso_page_role([{"type": "password", "name": "pw"}], []) == "login"
    assert S.sso_page_role([{"type": "text", "name": "otp"}], []) == "mfa"
    assert S.sso_page_role([], [{"text": "Allow", "aria_label": ""}]) == "consent"
    assert S.sso_page_role([{"type": "search", "name": "q"}], [{"text": "Next", "aria_label": ""}]) == "idp-page"
    # an IdP login step without a password field (username-first, or a mock IdP)
    assert S.sso_page_role([{"type": "text", "name": "username"}], []) == "login"
    assert S.sso_page_role([{"type": "email", "name": "loginfmt"}], []) == "login"


def test_is_callback_url():
    assert S.is_callback_url("https://app/cb#access_token=x") is True
    assert S.is_callback_url("https://app/acs?SAMLResponse=x") is True
    assert S.is_callback_url("https://app/cb?state=x") is False
    assert S.is_callback_url("https://app/cb?CODE=x") is True


def test_endpoint_method():
    assert S.ENDPOINT_METHOD["token"] == "POST"
    assert S.ENDPOINT_METHOD.get("authorize", "GET") == "GET"


def test_redact_urls_inside_free_text():
    # review F2: error strings embed URLs (Playwright "... at <url>", "logged-out view at <url>")
    obj = {"error": "Error: net::ERR_ABORTED at https://idp/authorize?state=SECRETINTEXT1&x=1 (frame)",
           "nav": ["logged-out view at http://idp/login?nonce=SECRETINTEXT2"]}
    dump = json.dumps(S.redact_urls_deep(obj))
    assert "SECRETINTEXT1" not in dump and "SECRETINTEXT2" not in dump
    assert "x=1" in dump and "ERR_ABORTED" in dump


def test_more_secret_param_names():
    out = S.redact_sso_params("https://a/cb?SAMLart=A1A1A1&oauth_verifier=V1V1&oauth_token=T1T1&session_code=C1C1")
    for v in ("A1A1A1", "V1V1", "T1T1", "C1C1"):
        assert v not in out
    assert S.is_callback_url("https://a/acs?SAMLart=x") is True
