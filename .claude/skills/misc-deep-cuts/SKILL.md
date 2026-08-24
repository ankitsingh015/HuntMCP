---
name: misc-deep-cuts
description: Final gap-fill checklist of miscellaneous techniques that don't fit a single vuln-class skill -- OTP exposure patterns, feature-flag/beta-access toggles, multi-step flow step-skipping, "remember me" cookie forgery, image-proxy LFI, CSV/formula injection, PDF-generator SSRF, header-based admin spoofing, filename-based attacks, and referral/coupon abuse. Converted from master-pentest-prompt.md Phase 28. Use as a final pass after the mainstream vuln-class skills, catching real-world bugs that don't slot neatly into one category.
---

# Misc deep cuts -- final gap fill

## When to use

A final pass after the mainstream vuln-class skills -- these are real,
recurring bug patterns that just don't map cleanly onto a single
category, so they're easy to skip if testing is purely checklist-driven
by vuln class.

## Checklist

- **OTP exposure**: the OTP returned directly in the response body, an
  OTP embedded in a URL, or an OTP predictable from a timestamp
  (including backup codes shown in a response where they shouldn't be).
- **Feature flag / beta access**: toggling `X-Feature-Flags`,
  `X-Enable-Beta`, `?beta=1`, `?internal=1` -- these can reveal hidden
  admin routes that were only ever "hidden," never actually
  access-controlled.
- **Step-skip logic**: in a multi-step flow (signup -> verify ->
  payment), POST directly to a later step, reorder the steps, replay a
  step, or skip whatever CSRF protection only the last step has.
- **"Remember me" persistent cookie**: if the token is a base64/JSON
  blob rather than an opaque session ID, decrypting or just decoding it
  can lead straight to session takeover, especially with weak entropy.
- **Avatar/image URL endpoints**: an image proxy that reads a
  user-supplied URL/path can become an LFI vector, not just SSRF (see the
  `ssrf` skill for the URL-fetching side of this).
- **CSV/Excel export injection**: formula injection (`=`, `+`, `-`, `@`
  prefixes triggering DDE/command execution) in exported spreadsheet
  data an admin later opens.
- **Print/PDF generators**: SSRF via externally-loaded images in the
  rendered document, HTML injection into a server-side-rendered PDF,
  RCE through the rendering engine/font-handling layer itself.
- **Header-based admin detection**: `X-Admin`, `X-User`, `X-Role`
  headers that the backend trusts if simply forged by the client.
- **Filename-based attacks**: CRLF or `../` inside a filename parameter
  -- can produce stored XSS on download or path traversal via the
  filename itself, not just the file content.
- **Large file / decompression bombs**: zip bombs, PDF bombs -- see the
  `dos-and-resilience` skill for the broader DoS technique list.
- **GraphQL loose ends**: field suggestion left enabled, `__typename`
  leaking schema info, unbounded mutation complexity, WebSocket
  subscriptions with no auth check (see `deep-cut-surfaces` for the
  broader GraphQL/WebSocket list).
- **Email verification bypass**: changing the verification target to an
  attacker-owned email mid-flow, using a verification link with the
  attacker's own email against a victim's account, or an IDOR in the
  email-template's own ID parameter.
- **Referral/program abuse**: self-referrals, coupon stacking, invite-
  bonus farming through repeated fake signups.
- **API documentation exposure**: `/swagger-ui`, `/redoc`, `/api-docs`,
  a live `/graphql` playground, `/v3/api-docs` -- these map the entire
  API surface for free once found.
