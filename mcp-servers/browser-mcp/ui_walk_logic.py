"""#164 UI-walk: pure decision logic (no browser, no network).

Everything the walker DECIDES lives here so it is unit-testable in isolation:
what kind of control an element is, which controls are the same control
repeated (dedup), which GET URLs look state-changing, which hosts are payment
providers, canary tokens/values, the walker-ownership rule for destructive
clicks, auth-lost detection, and the default in-code scope predicate.

Design: docs/superpowers/specs/2026-11-19-page-comprehension-ui-walk-design.md

HONEST LIMIT: the classifier works on visible text/attributes in English-ish
vocabulary. A control labelled "Löschen" or an icon-only button classifies as
"other". That is acceptable because Pass 1's guarantee ("nothing
state-changing is sent") is enforced by NETWORK interception in ui_walk.py,
not by this classifier; the classifier only decides what is never clicked at
all (logout/account-delete/payment) and what counts as destructive in Pass 2,
where the ownership rule is the second, independent safety net.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import sys
from urllib.parse import parse_qsl, urlsplit

sys.path.insert(0, __file__.rsplit("/", 2)[0])

import scope_guard
import ui_walk_sso_logic

CLASSIFICATIONS = ("navigational", "expand", "submit", "destructive", "logout",
                   "account-delete", "payment", "other")

NEVER_CLICK = frozenset({"logout", "account-delete", "payment"})

_ACCOUNT_DELETE_RE = re.compile(
    r"\b(delete|close|deactivate|remove|terminate)\s+(my\s+|your\s+)?account\b", re.IGNORECASE)
_PAYMENT_RE = re.compile(
    r"\b(pay|pay now|checkout|check out|place order|buy|purchase|subscribe|upgrade|"
    r"complete order|confirm payment|add payment)\b", re.IGNORECASE)
_LOGOUT_RE = re.compile(r"\b(log ?out|sign ?out|log off|sign off)\b", re.IGNORECASE)
_LOGOUT_HREF_RE = re.compile(r"/(logout|log-out|signout|sign-out|logoff)\b", re.IGNORECASE)
_DESTRUCTIVE_RE = re.compile(
    r"\b(delete|remove|revoke|cancel|unshare|destroy|discard|archive|"
    r"disable|deactivate|leave|unlink|disconnect|reset|purge|clear)\b", re.IGNORECASE)
_SUBMIT_RE = re.compile(
    r"\b(save|submit|send|create|add|update|post|apply|confirm|invite|upload|"
    r"generate|register|sign up|publish|share)\b", re.IGNORECASE)
_EXPAND_ROLES = {"tab", "menuitem", "treeitem", "switch"}
_EXPAND_RE = re.compile(r"\b(more|show|expand|details|open|menu|options|view all|advanced|filter)\b", re.IGNORECASE)


def _text_of(ctrl: dict) -> str:
    return " ".join(str(ctrl.get(k) or "") for k in ("text", "aria_label")).strip()


def classify_control(ctrl: dict) -> str:
    """Classify one control. Precedence: account-delete > payment > logout >
    destructive > submit > expand > navigational > other."""
    text = _text_of(ctrl)
    href = str(ctrl.get("href") or "")
    tag = str(ctrl.get("tag") or "").lower()
    role = str(ctrl.get("role") or "").lower()
    ctype = str(ctrl.get("type") or "").lower()
    if _ACCOUNT_DELETE_RE.search(text):
        return "account-delete"
    if _PAYMENT_RE.search(text):
        return "payment"
    if _LOGOUT_RE.search(text) or _LOGOUT_HREF_RE.search(href):
        return "logout"
    if _DESTRUCTIVE_RE.search(text):
        return "destructive"
    if ctype == "submit" or _SUBMIT_RE.search(text):
        return "submit"
    if role in _EXPAND_ROLES or ctrl.get("aria_expanded") is not None or _EXPAND_RE.search(text):
        return "expand"
    if tag == "a" and href:
        return "navigational"
    return "other"


_INDEX_RE = re.compile(r":nth-(of-type|child)\(\d+\)|\[\d+\]")


def _norm_text(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip().lower()


def control_signature(ctrl: dict, page_template: str) -> str:
    """Stable id for 'the same control', so a per-row button repeated across
    many rows is clicked once. Row indices are stripped from the DOM path."""
    parts = [
        page_template or "",
        str(ctrl.get("role") or ctrl.get("tag") or ""),
        _norm_text(_text_of(ctrl)),
        str(ctrl.get("form_action") or ""),
        _INDEX_RE.sub("", str(ctrl.get("dom_path") or "")),
    ]
    return hashlib.sha1("|".join(parts).encode()).hexdigest()[:16]


MUTATING_URL_WORDS = ("logout", "signout", "sign-out", "log-out", "delete", "remove",
                      "revoke", "cancel", "unsubscribe", "deactivate", "destroy")


def is_mutating_get_url(url: str) -> bool:
    """True if a path segment, or a query key/value, IS one of the mutating
    words (exact token, so /cancellation-policy does not match)."""
    parts = urlsplit(url)
    words = set(MUTATING_URL_WORDS)
    tokens = [seg.lower() for seg in parts.path.split("/") if seg]
    for k, v in parse_qsl(parts.query, keep_blank_values=True):
        tokens.append(k.lower())
        tokens.append(v.lower())
    if any(t in words for t in tokens):
        return True
    # spec 2: an OAuth/OIDC/SAML end-session endpoint (/endsession, /end_session,
    # SingleLogout ...) ends the IdP session just like a /logout link
    return ui_walk_sso_logic.is_logout_endpoint(url)


PAYMENT_HOST_SUFFIXES = ("stripe.com", "paypal.com", "braintreegateway.com", "adyen.com",
                         "checkout.com", "razorpay.com", "squareup.com", "klarna.com",
                         "paddle.com")


def is_payment_host(host: str) -> bool:
    h = (host or "").lower().strip(".")
    return any(h == s or h.endswith("." + s) for s in PAYMENT_HOST_SUFFIXES)


def make_canary(length: int = 10) -> str:
    """'hm' + random hex, `length` chars total (min 4) -- shorter tokens exist
    so a maxlength-limited field still carries a token that is REGISTERED
    exactly as typed (a truncated token could never be matched to a sink)."""
    length = max(4, length)
    return "hm" + secrets.token_hex((length - 1) // 2)[: length - 2]


_TEXTLIKE = {"", "text", "textarea", "search", "contenteditable"}


def canary_value(token: str, input_type: str | None, maxlength: int | None) -> str:
    """Value to type into an input for Pass 2. Text-like fields get an XSS
    canary whose marker is the token; typed fields get a type-valid value
    embedding the token; fields with no sensible text value get "" (caller
    leaves the field's default)."""
    t = (input_type or "").lower()
    if t == "email":
        value = f"{token}@example.com"
    elif t == "url":
        value = f"https://example.com/{token}"
    elif t in _TEXTLIKE:
        value = f"{token}\"'><img src=x onerror=alert('{token}')>"
    else:
        return ""
    if maxlength and maxlength > 0 and len(value) > maxlength:
        return token[:maxlength] if len(token) > maxlength else token
    return value


def _values_in(obj) -> list[str]:
    if isinstance(obj, dict):
        out = []
        for v in obj.values():
            out.extend(_values_in(v))
        return out
    if isinstance(obj, list):
        out = []
        for v in obj:
            out.extend(_values_in(v))
        return out
    return [str(obj)]


def is_walker_owned(control_request: dict | None, created_ids: set[str],
                    container_text: str, tokens: set[str]) -> bool:
    """Hard ownership rule for destructive clicks (spec decision 1): an id the
    walker's own create returned appears (exactly) in the control's request
    path/query/JSON body, OR a walker canary token appears in the control's
    container text. Anything else is not ours."""
    if control_request and created_ids:
        parts = urlsplit(str(control_request.get("url") or ""))
        values = [seg for seg in parts.path.split("/") if seg]
        values += [v for _, v in parse_qsl(parts.query, keep_blank_values=True)]
        body = control_request.get("body")
        if body:
            try:
                values += _values_in(json.loads(body))
            except (ValueError, TypeError):
                values += [v for _, v in parse_qsl(str(body), keep_blank_values=True)]
        if any(v in created_ids for v in values):
            return True
    text = container_text or ""
    return any(tok and tok in text for tok in tokens)


_LOGIN_PATH_RE = re.compile(r"/(login|signin|sign-in|auth)\b", re.IGNORECASE)
_LOGIN_TEXT_RE = re.compile(r"^(log ?in|sign ?in)$", re.IGNORECASE)


def looks_logged_out(final_url: str, controls: list[dict], had_session: bool) -> bool:
    if not had_session:
        return False
    if _LOGIN_PATH_RE.search(urlsplit(final_url or "").path):
        return True
    return any(_LOGIN_TEXT_RE.match(_text_of(c)) for c in controls or [])


def _default_scope_check(url: str) -> bool:
    host = scope_guard._host_of(url)
    if scope_guard.is_safe_test_host(host):
        return True
    try:
        eng = scope_guard.load_engagement()
    except scope_guard.NoEngagementFile:
        return False
    return scope_guard.is_in_scope(host, eng)


SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_MUTATING_GET_TYPES = frozenset({"document", "xhr", "fetch"})


def route_decision(method: str, url: str, resource_type: str, is_main_nav: bool, *,
                   scope_ok: bool, send_allowed: bool) -> tuple[str, str | None]:
    """What the walker's network interceptor does with one request:
    ("continue", None) or ("abort", reason). Order matters:
    payment host (any method, every mode) > safe-method rules > non-GET rules.
    reason in {"payment-host", "out-of-scope", "mutating-get", "pass1-non-get"}."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return ("continue", None)
    if is_payment_host(parts.hostname or ""):
        return ("abort", "payment-host")
    m = (method or "").upper()
    if m in SAFE_METHODS:
        if is_main_nav and not scope_ok:
            return ("abort", "out-of-scope")
        if resource_type in _MUTATING_GET_TYPES and is_mutating_get_url(url):
            return ("abort", "mutating-get")
        return ("continue", None)
    if not scope_ok:
        return ("abort", "out-of-scope")
    if send_allowed:
        return ("continue", None)
    return ("abort", "pass1-non-get")


def url_has_segment(url: str, value: str) -> bool:
    """value is an exact path segment or query value of url (so id "1" does
    not match /items/10 or /items/1abc)."""
    parts = urlsplit(url)
    segs = [seg for seg in parts.path.split("/") if seg]
    vals = [v for _, v in parse_qsl(parts.query, keep_blank_values=True)]
    return value in segs or value in vals


def form_unsafe_reason(submit_controls: list[dict], action: str, *, sso_page: bool = False) -> str | None:
    """Why a form must NOT be really submitted in Pass 2 (None = safe): its
    submit control is logout / account-delete / payment / destructive (those
    are never submitted -- destructive ones only via the ownership-checked
    destroy phase), or its action URL looks state-changing."""
    for c in submit_controls or []:
        cls = classify_control(c)
        if cls in NEVER_CLICK or cls == "destructive":
            return cls
    if action and is_mutating_get_url(action):
        return "mutating-action"
    # spec 2: a canary is never typed into an IdP login / consent / MFA form
    # (a failed-login storm can lock accounts and break programme rules)
    if sso_page or (action and ui_walk_sso_logic.classify_url(action, "POST") is not None):
        return "sso-form"
    return None
