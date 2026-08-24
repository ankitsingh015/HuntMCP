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

## Escalation

CRLF in a request (not just influencing the response) can enable request
smuggling -- see the `request-smuggling` skill for the full 2025-26
desync technique list; this is the injection vector that feeds it.

## Mixed encodings to try if the plain form is filtered

`%250a` (double-encoded), `\r` only, `\t`.
