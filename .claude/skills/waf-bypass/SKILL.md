---
name: waf-bypass
description: Systematic, tiered 403/WAF bypass decision guide plus common curl error diagnosis. Converted from master-pentest-prompt.md Phase 0.6. Use whenever a request comes back 403/blocked, or tool_resolver.classify_block() flags a WAF signature.
---

# 403 / WAF bypass master guide

## When to use

A 403 appears, or `mcp-servers/tool_resolver.py`'s `classify_block()`
returns `"waf"` on a tool's output. Work the tiers in order before giving
up on a blocked endpoint you actually need to test.

Tiers 1-4 below are automated by `mcp-servers/waf-bypass-mcp`'s
`attempt_bypass(url, baseline_status, tiers)` -- call that first rather
than hand-crafting each variant; it runs all of them in one call and
reports which (if any) changed the response. This skill documents what
it's actually doing, plus Tier 5, which isn't automated (it needs
external OSINT, not a retry loop).

## Tier 1 -- Header manipulation

- Fake client IP: `X-Forwarded-For` / `X-Real-IP` / `X-Originating-IP` /
  `X-Remote-IP` / `X-Client-IP` / `X-Custom-IP-Authorization` /
  `X-ProxyUser-Ip` / `True-Client-IP` / `Forwarded: for=127.0.0.1;host=localhost`
  -- set to `127.0.0.1`/`localhost` on the blocked endpoint.
- Fake `Host`: `localhost`, `127.0.0.1`, `internal.<domain>`.
- UA spoofing: Googlebot, Bingbot, empty UA.

## Tier 2 -- Path manipulation

URL-encode letters (`%61dmin`), `%2f` for `/`, trailing space/tab/null,
`--path-as-is` with `./`, `/.`, `//`, `/../`, `%2e`; case variations
(`Admin`, `ADMIN`); extension append (`.json`/`.html`/`.php`/`;.js`/`#`).

## Tier 3 -- Method switching

`POST`/`PUT`/`PATCH`/`OPTIONS`/`TRACE`/`HEAD`/`CONNECT` plus method
override headers (`X-HTTP-Method-Override`, `X-Method-Override`,
`_method=`).

## Tier 4 -- HTTP version tricks

`--http1.0`/`--http1.1`, `--http2`, `--http2-prior-knowledge`.

## Tier 5 -- CDN/Cloudflare origin bypass (not automated)

Find the origin IP (SecurityTrails/Shodan/Censys/CT logs), then
`--resolve <domain>:443:<IP>` or `-H "Host: <domain>"` straight to the
IP; spoof `CF-Connecting-IP`/`CF-IPCountry`; reuse `cf_clearance` if
known. This needs real OSINT lookups per target, not a retry loop, which
is why `waf-bypass-mcp` doesn't automate it.

## Decision logic

Still 403 after all tiers -> document the host as WAF-protected and move
on. If the target is heavily WAF-protected, research current WAF-bypass
techniques for that specific vendor online, apply them; if bypass still
fails, move on rather than looping.

## Diagnosing curl errors

| curl error | Meaning | Fix |
|---|---|---|
| (6) DNS | Couldn't resolve host | `--dns-servers 8.8.8.8` |
| (7) port closed | Connection refused | try 80/8080/8443 |
| (35) SSL | SSL handshake failed | `-k` / `--tlsv1.2` |
| (52) empty reply | Server closed connection | `--http1.1` |
| (56) recv failure | Receive error | retry with delay + a legit UA |
