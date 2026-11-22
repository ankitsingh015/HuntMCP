"""Spec 2 (in-scope SSO / auth flows as surface): pure logic, no browser.

Recognises OAuth/OIDC/SAML endpoints from URLs the UI-walk already sees,
derives non-secret flags from them, redacts secret parameter values, parses
discovery documents and (Task 6) derives `sso-*` candidates.

Values policy (spec "Values policy", extends ruling R4): the values of
SECRET_PARAMS are never returned by anything here except `secrets_of` and
`all_params`, which exist only for in-memory comparison by the walker and
must never be stored. Only KEPT_PARAMS values (public identifiers / protocol
choices) and redirect URIs reduced to scheme://host/path are kept.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Callable
from urllib.parse import parse_qsl, quote, unquote_plus, urlsplit

SECRET_PARAMS = frozenset({
    "state", "nonce", "code", "code_verifier", "code_challenge", "id_token", "id_token_hint",
    "access_token", "refresh_token", "samlrequest", "samlresponse", "relaystate", "login_hint",
    "session_state", "client_secret", "client_assertion", "assertion",
    "samlart", "oauth_verifier", "oauth_token", "session_code",
})
KEPT_PARAMS = ("response_type", "response_mode", "scope", "prompt", "code_challenge_method", "client_id")
LOGOUT_REDIRECT_PARAMS = frozenset({
    "post_logout_redirect_uri", "redirect_uri", "returnto", "return_to", "returnurl", "redirect",
    "redirect_url", "next", "continue", "relaystate", "wreply", "target", "service", "url",
})
ROLES = ("authorize", "callback", "saml-request", "saml-response", "logout", "token", "discovery",
         "userinfo", "jwks", "revocation", "introspection", "registration", "device_authorization")
PAGE_ROLES = ("login", "consent", "mfa", "idp-page")
ENDPOINT_METHOD: dict[str, str] = {r: "GET" for r in ROLES}
ENDPOINT_METHOD.update({r: "POST" for r in ("token", "revocation", "introspection", "registration",
                                            "device_authorization", "saml-response")})

REDACTED = "REDACTED"
_CALLBACK_PARAMS = frozenset({"code", "id_token", "access_token", "samlresponse", "samlart"})
_EMBEDDED_URL_RE = re.compile(r"https?://[^\s\"'<>()]+", re.IGNORECASE)
_KEPT_MAX = 200
_URL_MAX = 500
_DISCOVERY_MAX_BYTES = 262144
_SUPPORTED_MAX_ITEMS = 30
_SUPPORTED_ITEM_MAX = 100

# Authorize path suffixes, longest first (discovery_urls derives the issuer prefix from them).
_AUTHORIZE_SUFFIXES = sorted((
    "/authorize", "/oauth2/authorize", "/oauth2/v2.0/authorize", "/protocol/openid-connect/auth",
    "/connect/authorize", "/o/oauth2/auth",
), key=len, reverse=True)
_LOGOUT_SUFFIXES = ("/logout", "/end_session", "/endsession", "/oauth2/logout", "/oauth2/v2.0/logout",
                    "/protocol/openid-connect/logout", "/v2/logout", "/connect/endsession")
_DISCOVERY_SUFFIXES = ("/.well-known/openid-configuration", "/.well-known/oauth-authorization-server")
# A path segment that marks the URL as part of an OAuth/OIDC server, so a
# generic last segment ("token", "register", "keys") is not misread on an app.
_OAUTH_SEGMENTS = frozenset({"oauth", "oauth2", "connect", "openid-connect", "oidc"})
_BY_LAST_SEGMENT = {
    "token": "token",
    "userinfo": "userinfo",
    "jwks": "jwks", "jwks.json": "jwks", "certs": "jwks", "keys": "jwks",
    "revoke": "revocation", "revocation": "revocation",
    "introspect": "introspection", "introspection": "introspection",
    "register": "registration", "registration": "registration",
    "device_authorization": "device_authorization", "devicecode": "device_authorization",
}
_ALWAYS_BY_LAST_SEGMENT = frozenset({"userinfo", "jwks", "jwks.json", "device_authorization"})

_MFA_RE = re.compile(r"otp|totp|mfa|2fa|one.?time|verification.?code", re.IGNORECASE)
_LOGIN_NAME_RE = re.compile(r"^(user(name)?|login(fmt|_?name)?|email|identifier|j_username)$", re.IGNORECASE)
_CONSENT_RE = re.compile(r"^(allow|accept|authori[sz]e|grant|consent)\b", re.IGNORECASE)


# ------------------------------------------------------------------ helpers

def _clean_url(u) -> str:
    """scheme://host/path only (same rule as ui_walk_events._clean_url)."""
    try:
        p = urlsplit(u if isinstance(u, str) else "")
    except ValueError:
        return ""
    if p.scheme in ("http", "https") and p.netloc:
        return f"{p.scheme}://{p.netloc}{p.path}"
    return f"{p.scheme}:" if p.scheme else ""


def all_params(url: str) -> list[tuple[str, str]]:
    """Query + fragment pairs (the fragment parsed as a query string). The
    values may be secrets: in-memory use only, never stored."""
    try:
        p = urlsplit(url or "")
    except ValueError:
        return []
    out = parse_qsl(p.query, keep_blank_values=True)
    if "=" in p.fragment:
        out += parse_qsl(p.fragment, keep_blank_values=True)
    return out


def _names(url: str) -> set[str]:
    return {k.lower() for k, _ in all_params(url)}


def _first(url: str, name: str) -> str | None:
    for k, v in all_params(url):
        if k.lower() == name:
            return v
    return None


def _redact_qs(qs: str) -> str:
    parts = []
    for part in qs.split("&"):
        name, sep, _val = part.partition("=")
        if sep and unquote_plus(name).lower() in SECRET_PARAMS:
            parts.append(f"{name}={REDACTED}")
        else:
            parts.append(part)
    return "&".join(parts)


def redact_sso_params(url: str) -> str:
    """The URL with every SECRET_PARAMS value (query and fragment, names
    case-insensitive) replaced by REDACTED; everything else kept as is."""
    if not isinstance(url, str):
        return url
    if "?" not in url and "#" not in url:
        return url
    try:
        p = urlsplit(url)
    except ValueError:
        return _clean_url(url)
    if p.scheme not in ("http", "https"):
        return _clean_url(url)
    base = f"{p.scheme}://{p.netloc}{p.path}"
    if p.query or url.split("#", 1)[0].endswith("?"):
        base += "?" + _redact_qs(p.query)
    if "#" in url:
        base += "#" + (_redact_qs(p.fragment) if "=" in p.fragment else p.fragment)
    return base


def redact_urls_deep(obj):
    """A copy of obj (dicts/lists/tuples recursed) with every http(s) URL
    string passed through redact_sso_params."""
    if isinstance(obj, str):
        if obj[:8].lower().startswith(("http://", "https://")) and not any(c.isspace() for c in obj):
            return redact_sso_params(obj)
        # a URL inside free text (error messages: "... at https://idp/authorize?state=...")
        return _EMBEDDED_URL_RE.sub(lambda m: redact_sso_params(m.group(0)), obj) if "://" in obj else obj
    if isinstance(obj, dict):
        return {k: redact_urls_deep(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_urls_deep(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(redact_urls_deep(v) for v in obj)
    return obj


def is_callback_url(url: str) -> bool:
    """Carries an authorization result (code / tokens / SAML response):
    re-requesting it would replay a one-time value."""
    return bool(_names(url) & _CALLBACK_PARAMS)


def _path(url: str) -> str:
    try:
        return (urlsplit(url or "").path or "/").lower()
    except ValueError:
        return "/"


def _ends_with(path: str, suffixes) -> str | None:
    p = path.rstrip("/") or "/"
    for s in suffixes:
        if p == s or p.endswith(s):
            return s
    return None


# ------------------------------------------------------------ classification

def is_logout_endpoint(url: str) -> bool:
    """An end-session / logout path (whatever params it carries, e.g. a SAML
    SingleLogout with SAMLRequest). Requesting it ends a session."""
    path = _path(url)
    return bool(_ends_with(path, _LOGOUT_SUFFIXES)) or "singlelogout" in path


def classify_url(url: str, method: str = "GET", body_fields: list[str] | None = None) -> str | None:
    """The SSO role of one request, or None."""
    names = _names(url)
    body = {str(f).lower() for f in body_fields or []}
    path = _path(url)
    if _ends_with(path, _DISCOVERY_SUFFIXES):
        return "discovery"
    if "samlresponse" in names or "samlresponse" in body:
        return "saml-response"
    if "samlrequest" in names or "samlrequest" in body:
        return "saml-request"
    if names & _CALLBACK_PARAMS or ("error" in names and "state" in names):
        return "callback"
    if ("response_type" in names and "client_id" in names) or _ends_with(path, _AUTHORIZE_SUFFIXES):
        return "authorize"
    if _ends_with(path, _LOGOUT_SUFFIXES) or "singlelogout" in path:
        return "logout"
    segs = [s for s in path.split("/") if s]
    if not segs:
        return None
    last = segs[-1]
    role = _BY_LAST_SEGMENT.get(last)
    if role is None:
        return None
    if last in _ALWAYS_BY_LAST_SEGMENT or path.rstrip("/") == "/token":
        return role
    if _OAUTH_SEGMENTS & set(segs[:-1]) or "discovery" in segs[:-1]:
        return role
    return None


# ------------------------------------------------------------------- flags

def secret_strength(value: str | None) -> str:
    """absent | structured | short | low-charset | ok (computed in memory)."""
    if not value:
        return "absent"
    if _structured(value):
        return "structured"
    if len(value) < 16:
        return "short"
    if value.isdigit() or (value.isalpha() and (value.islower() or value.isupper())):
        return "low-charset"
    return "ok"


def _b64_text(s: str) -> str | None:
    s = s.strip()
    try:
        raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (binascii.Error, ValueError):
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _structured(value: str) -> bool:
    parts = value.split(".")
    if len(parts) == 3 and all(parts[:2]):
        head = _b64_text(parts[0])
        if head and head.lstrip().startswith("{"):
            return True
    txt = _b64_text(value.replace("+", "-").replace("/", "_"))
    return bool(txt and txt.lstrip().startswith("{"))


def length_bucket(value: str | None) -> str | None:
    if not value:
        return None
    n = len(value)
    return "<8" if n < 8 else "8-15" if n < 16 else "16-31" if n < 32 else "32+"


def _secret_flags(value: str | None) -> dict:
    return {"present": bool(value), "strength": secret_strength(value), "length_bucket": length_bucket(value)}


def _uri(value: str | None) -> str | None:
    if not value:
        return None
    return _clean_url(value)[:_URL_MAX] or None


def authorize_flags(url: str) -> dict:
    """Non-secret facts about one authorize request."""
    kept = {k: (v[:_KEPT_MAX] if (v := _first(url, k)) is not None else None) for k in KEPT_PARAMS}
    method = kept["code_challenge_method"]
    return {
        "param_names": sorted(_names(url)),
        **kept,
        "redirect_uri": _uri(_first(url, "redirect_uri")),
        "pkce": bool(_first(url, "code_challenge")),
        "code_challenge_method": method,
        "state": _secret_flags(_first(url, "state")),
        "nonce": _secret_flags(_first(url, "nonce")),
    }


def logout_flags(url: str) -> dict:
    names = _names(url)
    return {
        "param_names": sorted(names),
        "redirect_params": sorted(names & LOGOUT_REDIRECT_PARAMS),
        "post_logout_redirect_uri": _uri(_first(url, "post_logout_redirect_uri")),
    }


def flow_key(url: str) -> str:
    try:
        p = urlsplit(url or "")
        host, path = (p.netloc or "").lower(), p.path   # host:port -- two IdPs may share a host name
    except ValueError:
        host, path = "", ""
    rtype = " ".join(sorted((_first(url, "response_type") or "").split()))
    return json.dumps([host, path, _first(url, "client_id"), _uri(_first(url, "redirect_uri")), rtype])


def secrets_of(url: str) -> dict[str, str]:
    """{"state": ..., "nonce": ...} for the present ones. IN MEMORY ONLY:
    callers compare and drop these; they are never stored."""
    out = {}
    for name in ("state", "nonce"):
        v = _first(url, name)
        if v:
            out[name] = v
    return out


def compare_secrets(first: dict, second: dict | None) -> dict:
    out = {}
    for name in ("state", "nonce"):
        key = f"{name}_changes_per_request"
        if second is None or not first.get(name) or not second.get(name):
            out[key] = "unknown"
        else:
            out[key] = first[name] != second[name]
    return out


# --------------------------------------------------------------- discovery

def discovery_urls(authorize_url: str) -> list[str]:
    try:
        p = urlsplit(authorize_url or "")
    except ValueError:
        return []
    if p.scheme not in ("http", "https") or not p.netloc:
        return []
    origin = f"{p.scheme}://{p.netloc}"
    root = origin + "/.well-known/openid-configuration"
    out = []
    path = p.path.rstrip("/")
    suffix = _ends_with(path.lower(), _AUTHORIZE_SUFFIXES)
    if suffix:
        prefix = path[: len(path) - len(suffix)].rstrip("/")
        if prefix:
            out.append(f"{origin}{quote(prefix, safe='/%')}/.well-known/openid-configuration")
    # issuer-specific URL first: some servers answer any root path with a bogus document
    if root not in out:
        out.append(root)
    return out[:2]


_DISCOVERY_KEYS = {
    "authorization_endpoint": "authorize", "token_endpoint": "token", "end_session_endpoint": "logout",
    "revocation_endpoint": "revocation", "introspection_endpoint": "introspection",
    "userinfo_endpoint": "userinfo", "jwks_uri": "jwks", "registration_endpoint": "registration",
    "device_authorization_endpoint": "device_authorization",
}


def parse_discovery(body: bytes, *, scope: Callable[[str], bool]) -> dict | None:
    """Endpoints + *_supported lists of an OIDC / OAuth AS metadata document.
    Target data: only http(s) endpoint URLs (stripped) and string lists kept."""
    if body is None or len(body) > _DISCOVERY_MAX_BYTES:
        return None
    try:
        doc = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(doc, dict):
        return None
    endpoints = []
    for key, role in _DISCOVERY_KEYS.items():
        v = doc.get(key)
        if not isinstance(v, str):
            continue
        clean = _clean_url(v)
        if not clean.startswith(("http://", "https://")):
            continue
        try:
            in_scope = bool(scope(clean))
        except Exception:  # noqa: BLE001 -- a scope error is "not in scope"
            in_scope = False
        endpoints.append({"role": role, "url": clean[:_URL_MAX], "in_scope": in_scope})
    supported = {}
    for k, v in doc.items():
        if isinstance(k, str) and k.endswith("_supported") and isinstance(v, list) \
                and all(isinstance(i, str) for i in v):
            supported[k[:_SUPPORTED_ITEM_MAX]] = [i[:_SUPPORTED_ITEM_MAX] for i in v[:_SUPPORTED_MAX_ITEMS]]
    issuer = doc.get("issuer")
    return {"issuer": _clean_url(issuer)[:_URL_MAX] if isinstance(issuer, str) else None,
            "endpoints": endpoints, "supported": supported}


# ------------------------------------------------------------------- pages

def sso_page_role(inputs: list[dict], controls: list[dict]) -> str:
    for i in inputs or []:
        if (i.get("type") or "").lower() == "password":
            return "login"
    for i in inputs or []:
        if any(_LOGIN_NAME_RE.match(str(i.get(k) or "")) for k in ("name", "id")):
            return "login"
    for i in inputs or []:
        hay = " ".join(str(i.get(k) or "") for k in ("name", "id", "label", "placeholder", "autocomplete"))
        if _MFA_RE.search(hay):
            return "mfa"
    for c in controls or []:
        if _CONSENT_RE.match((c.get("text") or c.get("aria_label") or "").strip()):
            return "consent"
    return "idp-page"


# -------------------------------------------------------------- candidates

def _rtypes(flags: dict) -> set[str]:
    return set((flags.get("response_type") or "").split())


def derive_sso_candidates(sso: dict) -> list[dict]:
    """Leads for exploit-agent (auth-and-session skill), never confirmed
    findings. IdP-targeted leads only when the IdP is in scope; state/nonce
    leads are about the app and carry idp_in_scope so the tester knows to test
    only against the app's callback when it is False."""
    out: list[dict] = []

    def add(type_, page, sig, detail):
        out.append({"type": type_, "page": page, "control_signature": sig, "detail": detail})

    for f in (sso or {}).get("flows") or []:
        a = f.get("authorize") or {}
        page, sig, idp_in = f.get("page"), f.get("control_signature"), bool(f.get("idp_in_scope"))
        rt = _rtypes(a)
        if idp_in and a.get("redirect_uri"):
            add("sso-redirect-uri-candidate", page, sig, {
                "client_id": a.get("client_id"), "redirect_uri": a.get("redirect_uri"),
                "response_type": a.get("response_type"), "idp_host": f.get("idp_host")})
        st = a.get("state") or {}
        reasons = []
        if not st.get("present"):
            reasons.append("missing")
        elif st.get("strength") != "ok":
            reasons.append(f"weak:{st.get('strength')}")
        if f.get("state_changes_per_request") is False:
            reasons.append("static")
        if f.get("state_echoed_on_callback") is False:
            reasons.append("not-echoed")
        if reasons:
            add("sso-state-candidate", page, sig, {"reasons": reasons, "idp_in_scope": idp_in})
        nonce = a.get("nonce") or {}
        n_reasons = []
        if "id_token" in rt and not nonce.get("present"):
            n_reasons.append("missing-with-id_token")
        if f.get("nonce_changes_per_request") is False:
            n_reasons.append("static")
        if n_reasons:
            add("sso-nonce-candidate", page, sig, {"reasons": n_reasons, "idp_in_scope": idp_in})
        if idp_in and "code" in rt and (not a.get("pkce") or (a.get("code_challenge_method") or "").lower() == "plain"):
            add("sso-pkce-candidate", page, sig, {
                "client_id": a.get("client_id"), "pkce": bool(a.get("pkce")),
                "code_challenge_method": a.get("code_challenge_method")})
        if "token" in rt:
            add("sso-implicit-flow-candidate", page, sig, {
                "client_id": a.get("client_id"), "response_type": a.get("response_type"), "idp_in_scope": idp_in})
    for e in (sso or {}).get("endpoints") or []:
        if not e.get("in_scope"):
            continue
        if e.get("role") == "logout" and e.get("redirect_params"):
            add("sso-logout-redirect-candidate", e.get("page"), e.get("control_signature"), {
                "url": e.get("url"), "redirect_params": list(e["redirect_params"])})
        elif e.get("role") == "registration":
            add("sso-registration-candidate", e.get("page"), e.get("control_signature"), {"url": e.get("url")})
    return out
