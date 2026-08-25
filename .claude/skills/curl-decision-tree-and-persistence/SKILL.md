---
name: curl-decision-tree-and-persistence
description: A diagnostic decision tree for common curl/HTTP errors (connection failures, TLS, 400/401/403/429/500), a URL-parameter-to-test-priority lookup table, and persistence rules for how long to keep pushing on a target before moving on. Converted from master-pentest-prompt.md Phase 21.5. Use whenever a request fails or errors, or when triaging a new URL to decide what to test first.
---

# Curl self-healing, URL->test decision tree, persistence

## When to use

Any time a request errors instead of returning a clean response, or when
looking at a fresh URL and deciding what to test first.

## Diagnostic decision tree (diagnose, fix, retry)

| Symptom | Fix |
|---|---|
| curl (6) resolve fail | `--dns-servers 8.8.8.8` / `--resolve` / try plain `http://` |
| curl (7) connect fail | try ports 80, 8080, 8443; `-v` to inspect the TLS handshake |
| curl (35) SSL | `-k`, `--tlsv1.2`/`--tlsv1.3`, `--ssl-no-revoke` |
| curl (52) empty reply | `--http1.1`/`--http1.0`, `Connection: keep-alive` |
| curl (56) recv fail | a legit browser UA, `--limit-rate` (slow down), a proxy, `--http2` |
| 400 | malformed request -- clean up headers, URL-encode special chars, fix `Content-Type` |
| 401 | needs a session cookie / Bearer token / Basic auth (`-u user:pass` or `-u :`) |
| 403 | see the `waf-bypass` skill's tiered bypass guide |
| 429 | `tool_resolver.run_tool()` already does a 5s delay + exactly one automatic retry of the identical request for any Tier-2 tool call -- if that single retry still 429s, escalate manually: rotate `X-Forwarded-For`, start a fresh session, before trying again |
| 500 | **potential vuln** -- simplify the payload to isolate the trigger, try variants of the triggering input |
| Payload not reflected | URL-encode, double-encode, HTML entities, hex, unicode, case variation, JSON-unicode-escape, or an alternative vector entirely |
| Genuinely stuck | `curl --help all` / `--help <category>` / `--manual` |

## URL pattern -> test priority (quick triage)

| Pattern | Test first |
|---|---|
| `?id=`, `?user_id=`, `?order=` | SQLi (`'`), IDOR (swap the numeric ID) |
| `?q=`, `?search=`, `?input=` | XSS canary + reflection check, SQLi `'` |
| `?redirect=`, `?next=`, `?url=` | Open redirect, SSRF (`169.254.169.254`) |
| `?file=`, `?path=`, `?include=` | LFI/traversal (`../../etc/passwd`) |
| `?name=`, `?template=`, `?msg=` | SSTI (`{{7*7}}` -> `49`) |
| `?cmd=`, `?exec=`, `?host=`, `?ping=` | Command injection (`;id`) |
| `?callback=` | JSONP hijacking |
| XML/SOAP body | XXE |
| `/graphql` | Introspection, batching, aliases |
| Login form | SQLi auth bypass, brute force, logic flaws |
| Password reset | Host header poisoning, token checks |
| Any `Set-Cookie` | Cookie flags audit |
| Any headers/about page | Security header + version audit |
| File upload | The upload bypass matrix (`file-upload-and-traversal` skill) |
| No params at all | Recon: headers, `/.env`, `/.git/config`, `/swagger.json`, `/api/` enumeration |

## Persistence & evolution rules

- Never give up after one failure: try at least 3 alternative
  payloads/bypasses per failed test before moving on.
- Follow new endpoints discovered mid-test up to 4 levels deep (same
  domain); adapt from errors, timing, and response differences as you go.
- Reuse successful patterns across endpoints; don't repeat an identical
  test unless a genuine payload mutation is being applied.
- Attempt to exploit every discovered vulnerability, not just note it --
  try bypasses on the current vuln before moving to the next one.
- Always test for security misconfiguration regardless of the specific
  params/URL/domain in front of you.
- If a request or scan hangs for an extended time, move on rather than
  blocking the rest of the engagement on it.
- Stop only when no new attack surface appears after two full passes, or
  the Tier-2 tool-call budget is exhausted (`budget_guard.py`'s
  `HUNTMCP_MAX_TOOL_CALLS`, default 500 -- this is now an enforced
  circuit-breaker, not just a guideline).
- Write back every confirmed bug and every triager-closed false positive
  to the Lessons Registry immediately (see the `knowledge-loading` skill)
  -- don't batch this for later.
- Re-check the Lessons Registry before each new phase to apply the
  latest confirmed techniques to that phase's surface.
