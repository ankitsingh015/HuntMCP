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

**Duende BFF (ASP.NET Core) non-user-bound header**: Duende BFF's
antiforgery primitive is not a per-session/per-user token -- it's a
static, identical-for-everyone header `X-CSRF: 1` whose only job is to
force a CORS preflight on cross-origin calls. It doesn't bind to
identity, so on a BFF serving multiple privilege partitions (e.g.
`/admin/*` and `/user/*` behind one session cookie), any same-origin
script that can attach `X-CSRF: 1` plus the ambient session cookie
reaches admin endpoints if that session happens to hold the admin role --
stock ASP.NET Core antiforgery rejects on identity mismatch; Duende BFF's
does not.

**SignalR antiforgery carve-out**: browser WebSockets can't send custom
headers, so `X-CSRF: 1` can't be enforced on the upgrade -- developers
routinely work around this by excluding SignalR hub paths from BFF
antiforgery entirely (`.DisableAntiforgery()` or registering the hub as a
non-BFF endpoint). Once excluded, any same-site origin -- a taken-over
sibling subdomain, a stored-XSS page -- can open the WS with the ambient
session cookie and invoke hub methods with no CSRF check at all.

**Cookie-domain-wildcard CSRF chain**: a session cookie scoped with
`Domain=.example.com` (rather than host-only or `__Host-`-prefixed) is
readable by every subdomain, which turns any subdomain takeover or
stored-XSS-on-a-subdomain into CSRF against the whole parent domain --
host a CSRF PoC on the compromised `*.example.com` subdomain and it
forges requests (and, if the takeover can set cookies, can fixate a
session) against the main app. Check the `Domain=` attribute on
`Set-Cookie` for exactly this before ruling a subdomain-scoped issue
low-impact.

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

**socket.io/Engine.IO namespace-authorization bypass**: namespace
selection is a protocol-level frame, not a URL param -- a `?nsp=/admin`
query string is silently ignored and just connects to the root namespace
`/`, giving a false sense of having tested `/admin`. The actual bypass:
open the raw Engine.IO WebSocket
(`wss://target/socket.io/?EIO=4&transport=websocket`), then send the
socket.io CONNECT packet `40/admin,` directly -- `4` = Engine.IO MESSAGE,
`0` = socket.io CONNECT, `/admin,` = target namespace. A
`40/admin,{"sid":...}` success reply as a low/no-priv user means the app
never checked namespace authorization at the protocol layer. Only counts
as a finding once a subsequent `42` EVENT frame in that namespace
actually carries another tenant's data -- a bare `40` ack on an
otherwise-empty namespace is not proof.

**Handshake-layer Upgrade smuggling**: distinct from CSWSH -- once a
socket is open, bytes sent through it are wrapped in WS frames and never
re-parsed as HTTP by the proxy. The real technique lives at the handshake
itself: send an Upgrade request the front proxy and origin disagree on
(e.g. an unsupported `Sec-WebSocket-Version` that makes the origin reply
`426`/`400` while the proxy has already committed to treating the
connection as upgraded and stops parsing HTTP on it). The proxy then
tunnels subsequent bytes straight to the origin as an opaque stream --
smuggling arbitrary HTTP requests past front-end WAF/authz. Confirm with
a timing/differential probe plus real impact (reach an internal path,
poison a cache, capture another user's request), same bar as the
`request-smuggling` skill.
