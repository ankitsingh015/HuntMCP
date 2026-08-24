---
name: tool-usage-and-curl
description: Tool-separation doctrine (what's allowed to touch the live target vs. research-only) and a curl flag cheat sheet for manual PoC/verification work. Converted from master-pentest-prompt.md Phase 0.7. Use whenever an agent needs to hand-craft a curl request instead of going through an MCP tool wrapper.
---

# Tool usage doctrine and curl master flags

## When to use

Any time a technique needs a hand-crafted HTTP request that none of the
existing MCP tool wrappers cover directly -- proof-capsule reproduction
in exploit-agent, a WAF-bypass variant, or any manual verification step.

## Tool separation (never mix the two)

- **Target testing** (live requests against the target): the MCP tool
  servers (`subfinder-mcp`, `httpx-mcp`, `nuclei-mcp`, etc.), direct
  HTTPS via curl, and Burp/Caido if configured (see `AGENTS.md`'s runtime
  dependencies). Only these touch the target.
- **Research / learning** (never sent to the target): reading CVEs,
  writeups, skill files, WAF-bypass ideas, framework weaknesses. Research
  first, then return to the target and apply the technique with curl or
  an MCP tool. Never test the target through a research/fetch tool.
- Every curl request must carry a realistic browser User-Agent
  (`Mozilla/5.0 ... Chrome/Safari`) plus useful headers (`Accept`,
  `Accept-Language`, `Referer`) so WAF/CDN products don't fingerprint the
  client as a bot by default.

## Curl master flags (compact cheat sheet)

Extend with `curl --help all` for anything not listed here.

```
-v                verbose
-i                include response headers
-I                HEAD only
-s                silent
-o file           write body to file
-o /dev/null      discard body
-w "%{http_code}|%{time_total}|%{size_download}|%{remote_ip}"   stats line
-L                follow redirects
-k                skip SSL verification
-x 127.0.0.1:8080 proxy through Burp/Caido
--http1.0 / --http1.1 / --http2 / --http2-prior-knowledge
-H "Header: value"
-b cookie(s)/file
-c cookie-jar
-d data / -d @file / --data-raw / --data-binary
-X METHOD
--upload-file     (PUT)
-F "field=val" / -F "file=@x;type=image/jpeg"
--resolve host:port:ip
--connect-to
-e referer
-A "User-Agent"
--compressed
-u user:pass      (Basic auth)
--oauth2-bearer TOKEN
--max-time / --retry / --retry-delay
-D                dump headers
--path-as-is      (keep ../ literal, don't normalize)
--request-target  exact path override
--unix-socket
--cacert / --cert
--tlsv1.2 / --tlsv1.3
-r                byte range
--limit-rate
--tr-encoding
--anyauth / --ntlm / --negotiate
-p                proxytunnel
--socks5
```
