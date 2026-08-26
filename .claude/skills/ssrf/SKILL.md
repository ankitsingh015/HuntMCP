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

## Host-header-driven SSRF

A different mechanism from the URL-accepting injection points above: here
the app trusts the `Host` header itself for internal routing or URL
construction, not a URL-shaped parameter.

- **Password-reset / URL-construction poisoning** -- the server builds an
  absolute URL (reset link, invite link, webhook callback) from the
  request `Host` with no allowlist. Set `Host: evil.com` (or
  `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`) and confirm in the
  actual email/response body that the link points at the attacker host --
  a Host reflected in the HTTP response is not proof; some mailers
  rewrite links to a fixed `SITE_URL` regardless of Host.
- **Routing-based SSRF** -- the front-end/proxy uses the Host header
  itself (not the path) to pick the upstream. `Host: 169.254.169.254` or
  `Host: internal-admin.svc.cluster.local`, with the path kept on the
  request line as normal, routes the request to that internal target --
  cloud metadata, internal admin panels, Redis. This never composes with
  the path-override technique below; the two headers act at different
  layers.
- **Cache poisoning via unkeyed Host** -- if `X-Forwarded-Host` is
  reflected into an absolute URL in the response body (script `src`,
  `<base href>`, canonical link) and the response is cached on a key that
  doesn't include that header (check `Vary`), poisoning one request
  poisons the cached response for every later visitor.

Confirm with a Collaborator/OOB host as the injected value, not curl
status codes alone -- same false-positive discipline as Blind SSRF below.

## Path-override ACL bypass

A separate, adjacent technique: `X-Original-URL` / `X-Rewrite-URL`
(IIS/ASP.NET/Spring Cloud Gateway) let the app override the *routed path*
while the real `Host` and request line stay untouched -- this bypasses a
reverse-proxy's path-based access control, not an upstream selection.

```bash
curl -s "https://$TARGET/" -H "Host: $TARGET" -H "X-Original-URL: /admin"
curl -s "https://$TARGET/" -H "Host: $TARGET" -H "X-Rewrite-URL: /internal/metrics"
```

Diff against a direct `GET /admin` that the edge blocks -- a different
status/body proves the override took. Don't combine this with the
routing-based Host trick above (e.g. `Host: 169.254.169.254` +
`X-Original-URL: /latest/meta-data/`) -- that combination doesn't work;
the metadata service never sees `X-Original-URL`.

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
