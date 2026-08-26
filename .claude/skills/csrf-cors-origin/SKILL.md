---
name: csrf-cors-origin
description: CSRF token-bypass techniques, CORS misconfiguration patterns, postMessage origin issues, clickjacking, and WebSocket cross-origin hijacking. Converted from master-pentest-prompt.md Phase 10. Use on any state-changing request, any endpoint with CORS headers, and any page that could be framed.
---

# CSRF / CORS / origin

## When to use

Any state-changing request (form submit, API call with side effects),
any response carrying `Access-Control-Allow-Origin`, and any page worth
framing for clickjacking.

## CSRF

Token bypass techniques: duplicate token submission, null token, a
session-tied check that can be satisfied without the real token, regex
prefix matching that a crafted value slips past. Also: integer/boolean
maze parameters, JSON content-type tricks (legacy old-browser CSRF via
form-encoded JSON), multipart/form-data bypass, GET-to-POST method
switching, Referer regex bypass.

## CORS

Null origin, arbitrary origin reflected with `credentials: true`,
subdomain-origin trust, regex bypass (e.g. a check that matches
`evil.com` when it meant to match `not-evil.com`), preflight request
smuggling.

**Hard rule before claiming anything**: `Access-Control-Allow-Origin: *`
cannot legally be combined with credentials -- if the server sends `ACAO: *`,
the browser refuses to expose the response body to a `credentials: include`
request, full stop. That's Informational/Low, not a finding, regardless of
what `curl` shows (curl doesn't enforce CORS -- it happily displays a
reflected header a real browser would block). A High needs: attacker origin
reflected in `ACAO` + `ACAC: true` + a browser-proven readable body via
`mcp__browser-mcp` (fetch with `credentials:"include"` from the test page,
confirm the body actually renders, not just that the header looks
promising).

**Subdomain-regex bypass -- match the payload to the actual flaw**, don't
throw one generic bypass at every target:

| Intended regex | Flaw | Bypass that matches |
|---|---|---|
| `^https?://.*\.target\.com$` | none (escaped dot + end-anchor) | no simple bypass -- look at subdomain-takeover instead |
| `^https?://.*target\.com$` | missing dot separator | `https://eviltarget.com` |
| `^https?://.*\.target\.com` | missing end-anchor `$` | `https://x.target.com.evil.com` |
| `^https?://target\.com` | prefix-only, no `$` | `https://target.com.evil.com` |
| `.*.target.com$` (unescaped dot) | `.` matches any char | any origin one char off from `target.com` |

`evil.target.com` reflecting back is not automatically a bug -- it's an
in-scope subdomain by design unless you actually control it (see
`subdomain-takeover`).

## postMessage

Null origin checks, unvalidated `message` event handling, `window.name`
abuse, popup-opener relationship abuse (see the `reconnaissance` skill's
JS-mining checklist item 3 for finding the actual `addEventListener`
handlers first).

## Clickjacking

Test everywhere, including sandboxed-iframe bypass techniques (a
`sandbox` attribute doesn't always prevent the framed page from still
being interactable in an exploitable way).

## WebSocket CORS

Cross-origin WebSocket hijack, missing `Origin` header validation on the
WS upgrade request.
