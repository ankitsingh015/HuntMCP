"""Secret/PII redaction for anything that gets written to a persistent,
reviewable log -- currently wired into audit_log.log_call() (see its own
import), so every Tier-2 tool call's logged args get this for free with
zero per-caller changes, matching the "one shared chokepoint" pattern
budget_guard.py/tool_resolver.py already use.

Rule, deliberately narrow and shape/name-based, NOT entropy-based: redact
a value when its KEY NAME looks like a secret (token=, api_key=, a
Cookie:/Authorization: header line) or its VALUE SHAPE unambiguously is
one (a JWT, a card number) -- never because a value merely "looks random."
High-entropy-looking strings (UUIDs, hashids, ObjectIds, session/order/
user ids) are exactly the identifiers idor-mcp/browser-mcp's own callers
need to see in a logged url/arg to make sense of what was tested -- an
entropy-based redactor would silently blind every IDOR/BOLA tool that
depends on capturing real object ids. This mirrors a design point
confirmed by reading a competitor project's actual source during a
broader research pass (see gitignored RESEARCH-TODO.md) rather than
guessed: their own traffic-redaction pass explicitly avoids entropy-based
redaction for the identical reason.

A redacted value is replaced with `[REDACTED:<reason> sha256:<hash12>]` --
the truncated hash of the ORIGINAL value is kept in the replacement text
itself (not the value) so a human/agent scanning the log can still tell
whether two redacted entries were the same secret, without ever needing
to store or re-derive the real value.
"""

from __future__ import annotations

import hashlib
import re

# Key names (as they'd appear before `=` in a query string, or before `:` in
# an HTTP header line) that mark a value as a secret regardless of its shape.
# Substring match, case-insensitive -- "access_token"/"refresh-token" etc.
# all contain "token", "x-api-key" contains "api-key", and so on.
DENY_KEY_TOKENS = (
    "password", "passwd", "pwd", "secret", "token", "otp", "cvv", "cvc",
    "ssn", "pin", "auth", "cookie", "api-key", "api_key", "apikey",
    "credential", "session", "bearer",
)

# `key=value` inside a URL query string or form-encoded body -- redact the
# VALUE only, keep the key name so the log still shows what parameter it was.
_KEY_VALUE_RE = re.compile(
    r"(?P<key>" + "|".join(re.escape(k) for k in DENY_KEY_TOKENS) + r")"
    r"(?P<sep>=)(?P<value>[^&\s\"'<>]+)",
    re.IGNORECASE,
)

# Header names treated as unconditionally secret-by-name, regardless of value
# shape. Public (not `_`-prefixed) so a caller that already knows a value came
# from one of these header KEYS -- e.g. cem_engine._redact_recursive walking a
# {"Authorization": "Bearer ..."} dict, where the key and value are already
# split apart and can never be recombined into one "name: value" text line for
# _HEADER_LINE_RE to match -- can redact that value via `redacted()` below
# without redact_text() ever needing to accept a structured dict itself (this
# module's own documented boundary, see the module docstring).
KNOWN_SECRET_HEADER_NAMES = ("authorization", "cookie", "set-cookie", "x-api-key")

# Well-known secret-carrying HTTP header lines, redact the value after the
# colon, keep the header name. Matches within a larger text blob (e.g. a
# raw request/response dump), one line at a time.
_HEADER_LINE_RE = re.compile(
    r"(?im)^(?P<name>" + "|".join(re.escape(n) for n in KNOWN_SECRET_HEADER_NAMES) + r")"
    r"(?P<sep>:\s*)(?P<value>.+)$"
)

# JWTs always start with "eyJ" (base64 of `{"`) for their header segment in
# virtually every real-world token -- a cheap, accurate shape check without
# needing to base64-decode and validate structure.
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b")

# Candidate card numbers: 13-19 digits, optionally grouped with spaces/dashes.
# Luhn-validated below to cut down on false positives against ordinary long
# numeric ids that happen to be the right length but aren't real card numbers.
_CARD_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")


def _luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def hash_value(value: str) -> str:
    """Truncated sha256 of the ORIGINAL value -- stable across calls, so two
    redacted log lines carrying the same secret can be recognized as the
    same secret without either one ever revealing what it was."""
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def redacted(value: str, reason: str) -> str:
    """Build the `[REDACTED:<reason> sha256:<hash12>]` replacement text for a
    value already known to be a secret -- the single place this format is
    built, reused internally by redact_text()'s own regex substitutions below
    AND externally by any caller (e.g. cem_engine._redact_recursive) that
    already knows a value is secret by some other means (its dict KEY, not
    redact_text()'s own text-shape matching) and just needs the same
    replacement-text convention applied to it."""
    return f"[REDACTED:{reason} sha256:{hash_value(value)}]"


def redact_text(text: str) -> str:
    """Best-effort redaction over an arbitrary text blob (a URL, a logged
    arg, a raw header dump) -- never a structured dict, since audit_log's
    callers pass plain strings. Order matters: header lines and key=value
    pairs first (name-based, most precise), then shape-based JWT/card
    checks over whatever's left, so a JWT sitting inside an already-redacted
    header line's replacement text is never double-matched."""
    if not text:
        return text

    def _header_sub(m: re.Match) -> str:
        return f"{m.group('name')}{m.group('sep')}{redacted(m.group('value'), 'header-value')}"

    def _kv_sub(m: re.Match) -> str:
        return f"{m.group('key')}{m.group('sep')}{redacted(m.group('value'), m.group('key').lower())}"

    def _jwt_sub(m: re.Match) -> str:
        return redacted(m.group(0), "jwt")

    def _card_sub(m: re.Match) -> str:
        digits = re.sub(r"[ -]", "", m.group(0))
        if len(digits) < 13 or len(digits) > 19 or not _luhn_valid(digits):
            return m.group(0)
        return redacted(m.group(0), "card-number")

    text = _HEADER_LINE_RE.sub(_header_sub, text)
    text = _KEY_VALUE_RE.sub(_kv_sub, text)
    text = _JWT_RE.sub(_jwt_sub, text)
    text = _CARD_CANDIDATE_RE.sub(_card_sub, text)
    return text
