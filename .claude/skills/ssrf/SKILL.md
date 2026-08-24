---
name: ssrf
description: SSRF technique list covering IP-bypass encodings, cloud metadata endpoints (AWS/GCP/Azure/Alibaba/DigitalOcean), protocol smuggling, and common SSRF injection points (URL fetchers, image proxies, PDF generators, webhooks). Converted from master-pentest-prompt.md Phase 5. Use on any endpoint that accepts or derives a URL, including indirectly (webhook config, image-from-URL, PDF export).
---

# SSRF -- every variant

## When to use

Any parameter that accepts a URL, or any feature that fetches a
resource server-side based on user input even indirectly (a webhook
callback URL, an "import from URL" feature, a PDF/image generator that
renders a URL). Always confirm via an actual out-of-band callback before
calling anything SSRF-confirmed -- see exploit-agent's Phase 1.5
rationalizations-to-reject check ("the parameter accepts a URL" is
necessary, not sufficient).

## IP bypass encodings

`0.0.0.0`, `[::1]`, `127.1`, decimal/hex/octal IP encodings, short URLs,
DNS rebinding, the public-suffix trick, redirect chains.

## Cloud metadata endpoints

- AWS: `169.254.169.254` (IMDSv1, and IMDSv2 header-bypass techniques).
- GCP metadata, Azure, Alibaba, DigitalOcean equivalents.

## Protocol smuggling

`gopher://`, `dict://`, `file://`, `ftp://`.

## Escalation targets

SSRF into internal panels (Kibana, Jenkins, Redis for a webshell) -- see
the `injection-and-rce` skill's SSRF-to-RCE section for the full chain.

## Blind SSRF

URL-based out-of-band detection (`oob-mcp`'s `generate_payload_url()` /
`check_interactions()`) plus time-based SSRF detection when no OOB
channel is reachable.

## Where to look for it

URL fetchers, image proxies, PDF generators, webhooks, server-side
browser/headless rendering, email parsers, OCR pipelines -- any feature
that does something with a URL or file the server fetches on the user's
behalf.

## Tools

Burp Collaborator, interactsh (`oob-mcp`), axios/requests-style HTTP
tooling for building the actual test requests.
