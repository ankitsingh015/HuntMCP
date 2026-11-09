---
name: crlf-injection
description: CRLF injection into redirect params/Location/Set-Cookie/request URI, response-splitting to inject a rendered body, 302-splitting and hop-by-hop header abuse, and CRLF-driven request smuggling. Converted from master-pentest-prompt.md Phase 19. Use on any parameter that ends up in a response header, especially Location/redirect handling.
---

# CRLF injection -> XSS / smuggling (2026-era)

## When to use

Any parameter that flows into a response header -- redirect handlers are
the highest-yield target since `Location` is attacker-influenced there
more often than anywhere else.

## Injection points

`%0d%0a` / `%0a` / raw CRLF into: redirect params, the `Location` header
itself, `Set-Cookie`, the request URI, or (on nginx specifically) `$uri`.

## Response splitting

Injecting a full second response into the body so the browser renders
attacker-controlled content:

```
%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23%0d%0a<svg onload=alert(document.domain)>%0d%0a0%0d%0a/..
```

## 302 / redirect-specific tricks

- **Split 302 before the `Location` header** so the response becomes a
  200 that renders an injected `<script>` instead of redirecting.
- **Hop-by-hop header abuse**: injecting `Connection: Location, close`
  strips the `Location` header at the proxy hop, killing the redirect and
  causing the body to render instead.
- **301 Location corruption**: breaks the redirect and renders
  attacker-controlled HTML in its place.

## Hop-by-hop header abuse (general technique, beyond killing `Location`)

The HTTP/1.1 hop-by-hop headers (`Connection`, `Keep-Alive`,
`Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailers`,
`Transfer-Encoding`, `Upgrade`) are stripped by a compliant proxy before
forwarding, and `Connection` itself can name *additional* headers to
treat as hop-by-hop for that request -- e.g. `Connection: close, Cookie`
asks every intermediate proxy to also drop `Cookie` before the request
reaches the origin. Not every proxy implementation strips correctly
(some forward the whole `Connection` header untouched, or copy the named
list into their own outbound `Connection` header instead of consuming
it), so the technique is to name a security-relevant header -- `Cookie`,
`Authorization`, `X-Forwarded-For` -- in `Connection` and see whether the
origin ends up processing the request as if that header were never
sent. If an endpoint that should require a valid session cookie still
responds successfully once `Cookie` is named this way, that's an
auth-bypass via hop-by-hop stripping, not just a redirect-killer.

Beyond auth bypass, the same mechanism has been used for: fingerprinting
backend services (differential behavior when a header is stripped vs.
not), masking the true source IP (stripping `X-Forwarded-For` injected
by a trusted proxy), Cache Poisoned Denial of Service (CPDoS) by getting
a cache to store an error response generated after a required header was
dropped, SSRF (stripping a header an internal proxy relies on to route
correctly), and WAF bypass (stripping the header the WAF itself keys its
rules on before the request reaches the real origin).

## Escalation

CRLF in a request (not just influencing the response) can enable request
smuggling -- see the `request-smuggling` skill for the full 2025-26
desync technique list; this is the injection vector that feeds it.

## Log poisoning via CRLF

Injecting CRLF sequences into values that end up written to server logs
can forge fake log entries or break a log parser's line-based structure
-- useful both to cover tracks and, where a log viewer renders entries
as HTML, to chain into stored XSS against whoever reads the logs.

## CRLF-driven cache poisoning

The same header-injection primitive can be used to add arbitrary
response headers that a caching layer keys on, poisoning what gets
served to subsequent users from cache -- treat any CRLF injection point
on a cacheable response as a candidate for the `infrastructure-and-protocol`
skill's cache-poisoning techniques, not just an isolated header-splitting
bug.

## Mixed encodings to try if the plain form is filtered

`%250a` (double-encoded), `\r` only, `\t`.
