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

### What is NOT confirmation (the traps that produce a false SSRF claim)

- The server **echoing your URL back in an error message** ("The Web
  application at http://evil.example.com could not be found") -- that's
  string formatting the input into an error, not an outbound fetch.
- A **different status code** for an external URL vs. `localhost` -- can
  come from a URL-scheme validator rejecting the input, not from a fetch
  attempt.
- **Response delay** when the URL is sent -- can be DNS resolution inside a
  parser/validator, not a completed HTTP fetch.

Confirmation is a DNS lookup or HTTP hit on your `oob-mcp` callback URL, with
the target's own source IP/User-Agent, not a browser's. Sub-tag the callback
per sink (`dlsrcurl.<id>`, `import.<id>`) when testing multiple URL-accepting
parameters at once so a hit tells you which one fired. If a plausible-looking
"SSRF" produces zero callbacks after trying every sub-tagged sink, retract
the claim -- an internal resolver (e.g. SharePoint's `SPFile`/
`SPWebApplication` path handler) can format an error around a URL string
without ever making a network request with it.

## Where to look for it

URL fetchers, image proxies, PDF generators, webhooks, server-side
browser/headless rendering, email parsers, OCR pipelines -- any feature
that does something with a URL or file the server fetches on the user's
behalf.

## Tools

Burp Collaborator, interactsh (`oob-mcp`), axios/requests-style HTTP
tooling for building the actual test requests.
