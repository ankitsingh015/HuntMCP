---
title: "HTTP/1.1 must die: the desync endgame"
url: "https://portswigger.net/research/http1-must-die"
vuln_class: "HTTP Request Smuggling"
tech: "HTTP/1.1, HTTP/2 downgrade, CDNs"
bounty: 350000
cve: "CVE-2025-32094"
source: "PortSwigger Research"
content_quality: "full"
date: 2025-08-06
---

## Abstract
Upstream HTTP/1.1 is inherently insecure: request boundaries are weak (concatenated on a shared
TCP/TLS socket, multiple length mechanisms). Novel HTTP desync classes enable mass credential
compromise. Case studies subverted Akamai, Cloudflare and Netlify. Toolkit + techniques yielded
**$200,000+** in two weeks.

## The fatal flaw
Four length interpretations: `CL` (Content-Length), `TE` (Transfer-Encoding), `0` (implicit-zero),
`H2` (HTTP/2 built-in). HTTP/2 is often **downgraded to HTTP/1.1 upstream**, adding a 4th
ambiguity. Classic CL.TE probes now fail due to WAF regex, missing gadgets, and server-side race.

## Hacking 20 million websites by accident
Wannes Verwimp found an H2.0 desync on a site behind Cloudflare, poisoned the cache of a JS file ->
persistent site takeover of **random third-party sites**. Root cause was a desync internal to
Cloudflare's infra -> **24,000,000 websites** exposed. Patched in hours; $7,000 bounty.

## Detection: V-H / H-V discrepancies
Send a partially-hidden header; a unique response means a parser discrepancy:
- **V-H** (Visible-Hidden): masked header visible to front-end, hidden from back-end
- **H-V** (Hidden-Visible): hidden from front-end, visible to back-end
Turn a V-H into a **CL.0** desync (hide Content-Length):
```
GET /style.css HTTP/1.1
Host: <redacted>
Foo: bar
Content-Length: 23
GET /404 HTTP/1.1
X: y
```
If the front-end rejects GET-with-body, switch to OPTIONS.

## H-V on IIS behind AWS ALB (unpatched)
ALB + IIS H-V: AWS won't patch (compatibility). Mitigation: set
`routing.http.drop_invalid_header_fields.enabled` and `routing.http.desync_mitigation_mode = strictest`.

## 0.CL desync attacks
0.CL usually deadlocks. Escape with an **early-response gadget** — on IIS, request `/con`
(a reserved Windows filename) makes it respond without waiting for the body:
```
GET /con HTTP/1.1
Host: <redacted>
Content-Length: 7
```
Convert 0.CL -> CL.0 with a **double-desync** (most servers append front-end headers at the END of
the header block, so a smuggled request that starts before them works reliably). Proven with the
HEAD technique serving malicious JS to random users. ~10 0.CL vulns; $21,645 (EXNESS $7,500).

## Expect-based desync (complexity bomb)
`Expect: 100-continue` splits a request in two; breaks proxies. Categories:
- **0.CL via vanilla Expect** — T-Mobile, $12,000.
- **0.CL via obfuscated Expect** (`Expect: y 100-continue`) — h1.sec.gitlab.net RQP, $7,000.
- **CL.0 via vanilla Expect** — Netlify CDN (stream of responses from every Netlify site).
- **CL.0 via obfuscated Expect** — Akamai, served content on auth.lastpass.com ($5,000);
  CVE-2025-32094; 74 bounties, $221,000.
- **Bypassing response header removal**: Expect makes a second header block -> front-end strips fail
  (Netlify `X-Bb-*`, `X-Nf-*` leaked).

## Exploit history
2004 HTTP Request Smuggling · 2016 Hiding Wookies · 2019 CL.TE/TE.CL · 2021 H2.CL/H2.TE ·
2022 CL.0/H2.0/CSD · 2024 TE.0 · 2025 TE.TE chunk extensions · now 0.CL.

## Defence
Turn on **upstream HTTP/2** (HAProxy, F5, GCP, Imperva, Apache exp., Cloudflare); nginx/Akamai/
CloudFront/Fastly pending. HTTP/2 downgrading gives minimal benefit. If stuck on HTTP/1.1: enable
normalisation/validation front and back. HTTP/1.1 must die.

## Tooling
Burp extension **HTTP Request Smuggler v3.0** (detects parser discrepancies).
