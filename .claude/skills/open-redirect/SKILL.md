---
name: open-redirect
description: Open-redirect parameter names, common vulnerable locations (login, OAuth callback, password reset), bypass encodings, and the real-impact chain (open redirect -> OAuth token exfiltration -> account takeover). Converted from master-pentest-prompt.md Phase 18. Use on any redirect/callback parameter, especially near an OAuth or SSO flow.
---

# Open redirect -- every param, every flow

## When to use

Any parameter that controls where the app sends the browser next --
especially valuable near an OAuth/SSO callback, since that's where an
open redirect stops being informational.

## Parameter names to check

`next`, `redirect`, `return_to`, `continue`, `callback`,
`post_login_url`, `url`, `dest`, `target`, `return`, `back`, `file`,
`path`, `RelayState` (SAML-specific).

## Locations

Login, logout, OAuth callback, signup onboarding, error pages, password
reset, download handlers, currency/locale switchers, deep links -- any of
these can carry a redirect param even when it's not obvious from the UI.

## Finding it in JS

Grep for `window.location`, `location.href`, `location.replace`,
`location.assign` (see the `reconnaissance` skill's JS-mining checklist
for the full approach) -- client-side redirect logic is easy to miss by
only testing server responses.

## Bypass encodings

`//evil`, `/\/evil`, `%5c`, `\evil`, `@` in the URL (browsers treat
everything before `@` as userinfo), `#` prefix confusion,
`target.com.evil.com`, `evil.com.target.com` (domain confusion both
directions), `javascript:`, `data:`, `vbscript:` schemes, `http:evil`
(scheme confusion), double-encoding, unicode lookalikes.

## The real finding is the chain

An open redirect alone is often low severity. The actual impact:

- **Open redirect -> OAuth code/token exfiltration -> account takeover.**
- **Fragment reattachment**: `#access_token` gets re-attached to the
  attacker's `Location` during the redirect chain.
- **Path confusion in `redirect_uri`**: a meaningful fraction of real
  identity providers (roughly a third in published research) are
  vulnerable to path-confusion tricks in their redirect_uri validation.
- **OAuth parameter pollution**: sending two `redirect_uri` params, where
  the validator checks one and the app uses the other.
- **Referer leak to third parties** through the redirect chain.
- **`javascript:` in a SAML `form_post` action**.

Always chase the chain to an OAuth/SSO flow before writing up a plain
open redirect as low severity -- the same bug is critical if it reaches
that context.
