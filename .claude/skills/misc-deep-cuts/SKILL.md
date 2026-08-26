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
- **Post-removal session/token persistence**: removing a user from an
  org/tenant often flips an `active=false` flag or deletes a membership
  row without revoking their live session or issued tokens. Capture a
  session/PAT before removal, have an admin remove that user through the
  normal flow, then replay the same API calls with the old
  credential -- cached permission checks frequently keep passing for
  days after removal, especially across a company/org boundary rather
  than a single-resource one.
- **Token scope checked at issuance, not at use**: an OAuth/PAT scope
  is validated when the token is created, but individual endpoint
  handlers don't re-check it. Create a token with a minimal scope (e.g.
  `read:user` only), then call a write/privileged endpoint directly --
  middleware that only checks "is authenticated" (not "is this scope
  sufficient for this handler") lets a read-only token act as
  write-equivalent. Check collection-level vs. individual sub-resource
  endpoints and legacy API versions separately -- scope enforcement
  gaps cluster there.
- **Blocklist responses mistaken for existence oracles**: when many
  different paths return the identical response shape/text, that's
  often a server-side extension/path blocklist, not a real
  file-or-user-existence oracle. Don't infer "this resource exists"
  from "this request got blocked" -- confirm with an independent
  signal (OOB callback, timing differential at scale, or a genuinely
  distinct response for a request known not to exist) before trusting
  the pattern. A blanket filter that rejects `.config`/`.ashx`/`.svc`
  extensions regardless of whether the underlying file exists will
  otherwise produce a list of "discovered" endpoints that were never
  real.
- **Integration config fields as a token-exfil vector**: URL fields in
  admin/integration settings (error-tracking DSN, webhook URL, outbound
  proxy URL) are often assumed to be set only by trusted admins, but a
  lower-privileged role (maintainer, not owner) can frequently edit
  them too. Repointing one of these at an attacker-controlled listener
  doesn't just prove SSRF -- the service's own auth token for that
  integration is often included in the outbound request, so the
  attacker-controlled endpoint captures a live credential, not just a
  callback.
