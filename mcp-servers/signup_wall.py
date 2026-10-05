"""Signup-wall / disposable-email-rejection detector.

Why this exists: hours were spent live, in a real engagement, on failed
automated signup attempts (disposable-address rejection on an OTP path; a
third-party passwordless provider gated behind a bot challenge requiring a
human) before recognizing the wall was a hard, policy-level disable rather
than a transient test gap -- the application-layer "unable to create user"
signal was the definitive marker, but nothing surfaced it early. This
detects the common phrasing a signup flow uses to reject a disposable/
temp-mail address and returns an explicit recommendation to stop iterating
on more temp-mail endpoints and prompt for a human/real account instead --
the moment the FIRST rejection is seen, not after N more retries.

Same "generic phrase classifier over response text" shape as
tool_resolver.classify_block() (rate-limit/WAF detection) -- these are
common, generic English phrases services use for this exact rejection
class, not fabricated per-target claims, so a reasonable starter pattern
list is safe to ship (unlike version_fingerprint.py's empty starter
database, where a wrong per-package version claim would be actively
harmful).

Uses only the standard library -- no new dependency.
"""

from __future__ import annotations

import re

_DISPOSABLE_EMAIL_REJECTION_PATTERNS = [
    re.compile(r"disposable\s*(email|e-?mail)?\s*(address|domain)?", re.I),
    re.compile(r"temp(?:orary)?\s*e?-?mail", re.I),
    re.compile(r"throwaway\s*(email|e-?mail|address)", re.I),
    re.compile(r"blacklisted\s*(email|e-?mail)?\s*domain", re.I),
    re.compile(r"(email|e-?mail)\s*(domain\s*)?(is\s*)?(not\s*allowed|not\s*permitted|is\s*blocked|is\s*banned)", re.I),
    re.compile(r"please\s*use\s*a\s*(valid|real|permanent)\s*(email|e-?mail)", re.I),
]

RECOMMENDATION = (
    "This looks like a policy-level disable, not a transient test gap -- stop "
    "iterating on more temp-mail endpoints. Surface to the operator: a human "
    "using their own real inbox in a real browser is needed to continue "
    "account-dependent testing."
)


def classify_signup_response(status: int | None, body: str | None) -> dict:
    """Returns {"blocked_reason": "disposable_email_rejected",
    "recommendation": RECOMMENDATION} if `body` matches a known
    disposable-email-rejection phrase, else {"blocked_reason": None,
    "recommendation": None}. `status` is accepted for the caller's own
    convenience/future use but not currently part of the classification --
    the phrasing in the body is the actual signal; a 422/400/403 alone is
    also returned by countless ordinary validation errors."""
    if not body:
        return {"blocked_reason": None, "recommendation": None}
    for pattern in _DISPOSABLE_EMAIL_REJECTION_PATTERNS:
        if pattern.search(body):
            return {"blocked_reason": "disposable_email_rejected", "recommendation": RECOMMENDATION}
    return {"blocked_reason": None, "recommendation": None}
