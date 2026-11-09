---
name: infrastructure-and-protocol
description: HTTP/2/3 protocol attacks, TLS/security-header audits, WebSocket transport issues, cache poisoning/deception, exposed container/orchestration surfaces (K8s/Docker), serverless misconfig, and log-poisoning-to-RCE. Converted from master-pentest-prompt.md Phase 12. Use during infrastructure-level recon on any target, especially ones fronted by a proxy/CDN or running on Kubernetes/serverless.
---

# Infrastructure & protocol

## When to use

Infrastructure-level testing on any target -- protocol behavior, TLS
config, caching layer, and container/orchestration exposure are worth
checking regardless of the application layer above them.

## Protocol-level

- HTTP/2 current attacks: downgrade, rapid reset, HPACK-related issues.
- HTTP/3/QUIC behaviors and proxy bypass.
- TLS: weak ciphers, full SSL Labs-style checks, missing HSTS, mixed
  content, certificate issues, CN/SAN mismatches.
- Security headers audit: CSP, HSTS, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP/COEP.
- WebSocket over `ws://` (insecure transport), missing auth on the
  upgrade. Also check whether a `wss://` endpoint will quietly downgrade
  and still accept a plaintext `ws://` connection.
- WebSocket-specific follow-ups once a connection is intercepted
  (Burp's WS proxy, or a browser WS extension, to view/edit/replay
  frames): IDOR by swapping an id/uuid/sid-style field inside a frame
  to another user's value and checking for cross-account delivery;
  connection-flood DoS by opening many concurrent upgrades in a short
  window; reflected/blind XSS and injection (SQLi etc.) through
  unvalidated frame parameters, tested the same way as HTTP params;
  sensitive data leaking in frame payloads the way it would in JS/API
  responses.

## TLS bug triage

Offered != exploitable -- a successful handshake against a weak cipher
means the server negotiates it, not that anything is demonstrably
broken. Triage legacy-cipher/protocol CVE scanner flags before
reporting rather than passing them through at face value:

| Finding | Real precondition | Bounty reality |
|---|---|---|
| SWEET32 (CVE-2016-2183) | 3DES support alone is just a scanner flag; the birthday-attack decrypt needs ~hundreds of GB on one key over a long-lived session plus an on-path attacker | Report support only, expect Info/Low, frequently OOS |
| POODLE (CVE-2014-3566) | Needs SSLv3 actually negotiable -- modern OpenSSL 3.x dropped `-ssl3` entirely, so most "POODLE" scanner flags are stale | Confirm with `testssl.sh --poodle` (or `nmap --script ssl-poodle`); if SSLv3 won't negotiate, there is no finding |
| FREAK (CVE-2015-0204) / DROWN (CVE-2016-0800) | Requires export-grade RSA, or a live SSLv2 endpoint sharing the cert/key somewhere across the SAN list -- a precondition to prove, not assume | Scan the full SAN list (`testssl.sh --drown` / `nmap --script sslv2-drown`); absent that, Info only |
| Heartbleed (CVE-2014-0160) | Genuinely unpatched OpenSSL 1.0.1 leaking process memory | The one legacy TLS bug worth a full report -- verify with `testssl.sh --heartbleed` and capture leaked bytes as PoC, High/Critical |

DNS AXFR (zone transfer) misconfiguration check: enumerate nameservers
(`dig NS $TARGET +short`), then attempt `dig AXFR $TARGET @$NS` against
each one. A nameserver that answers hands over the full internal
hostname/IP map -- staging hosts, internal admin panels, CI/CD servers
-- concrete recon value, usually Medium on its own, higher paired with
what those internal hosts expose.

DMARC / email-spoofing proof bar: reading `p=none` (or a missing
`_dmarc` TXT record) from `dig` output is Info, not a finding --
receiving mail providers apply their own SPF/heuristics/ARC checks
independent of the sender's published policy. The only proof that
survives triage is a spoofed message actually delivered: send from
`ceo@target.com` (e.g. via `swaks`) to a tester inbox you own, and show
(1) it landed in Inbox, not Spam, (2) the raw `Authentication-Results`
header showing `dmarc=none`/`fail` alongside real delivery, not a
bounce, and (3) the visible `From:` header carries `@target.com`
rather than only the envelope-from. Medium at best even when proven,
and many programs list email-auth findings as out of scope -- confirm
before filing.

## Cache

Cache key manipulation, cache poisoning, web cache deception (path
rules, appending `.css`/other static extensions to a dynamic endpoint so
the cache treats it as static), `PURGE` verb abuse.

Unkeyed-header wordlist -- headers a cache may forward to the origin but
exclude from its cache key; vary each one at a time and check for
reflection in the response body (redirects, canonical links, CSP,
script `src`): `X-Forwarded-Host`, `X-Forwarded-Scheme`,
`X-Forwarded-Proto`, `X-Forwarded-Server`, `X-Original-URL`,
`X-Rewrite-URL`, `X-Host`, `X-HTTP-Host-Override`, `Forwarded`,
`True-Client-IP`. Burp's Param Miner "Guess headers" automates this
discovery.

Web-cache-deception poison-then-clean-fetch methodology -- the step
that turns "header is reflected" into an actual finding: (1) send the
poisoning request (malicious header, or a static-looking suffix on a
dynamic path) with a cache-busting query param so it lands on a fresh
key instead of clobbering the live shared one; (2) confirm storage on a
follow-up request (`X-Cache`/`Age` incrementing); (3) fetch the same
URL clean -- no malicious header, no cache-buster, ideally from a
different IP/session -- and confirm the poisoned or deceptively-cached
response comes back. If only your own request sees the effect, it's
self-reflection, not cache poisoning/deception.

Cache-Poisoned Denial of Service (CPDoS) -- distinct from poisoning a
response body: the goal is to get the intermediate cache to store an
*error* page as if it were the legitimate resource, denying it to
every later visitor until the cache entry expires or is purged.
Variants to try per cached endpoint: HTTP Header Oversize (send a
header larger than the origin's limit but within the cache's limit,
e.g. `X-Oversized-Header: <big value>`, so the origin 4xxs on it and
the cache stores that error); HTTP Meta Character (send a header
value containing raw `\r`/`\n`/other control characters the origin
rejects); HTTP Method Override (send `X-HTTP-Method-Override` /
`X-HTTP-Method` / `X-Method-Override: DELETE` or another verb the
origin doesn't support, so it errors and the cache stores the error
for subsequent GETs). Confirm with the same poison-then-clean-fetch
check used for other cache poisoning above -- a second, unauthenticated
client must see the stored error page for it to count as a finding,
not just a self-inflicted error.

Web cache deception via path confusion: when the backend's URL-routing
regex normalizes a path like `/myprofile/x.css` down to the same
handler as `/myprofile`, a shared cache sitting in front may still key
on the full path and treat the `.css`/`.jpg`/other static-looking
suffix as cacheable static content -- caching a logged-in user's
sensitive page under that URL. Confirm by requesting
`/<sensitive-authenticated-path>/<random>.<static-ext>` while
authenticated, then re-requesting the exact same URL unauthenticated
(or as a different user) and checking whether the victim's private
content comes back.

Disclosed precedents: Shopify paid for `X-Forwarded-Host` poisoning
that propagated a fake host into cached redirect/script-src output (H1
#977851); Cloudflare's Cache Deception Armor extension allowlist missed
`.avif`, letting authenticated account HTML get cached as a "static
image" (H1 #1391635); Akamai's multi-tier edge proxies disagreed on
hop-by-hop header handling, letting a smuggled request's response get
stored server-side at the edge for other visitors (Tediosi & Mariani,
>$50K combined across PayPal/Airbnb/Goldman Sachs).

## Container / orchestration exposure

- K8s/Docker: exposed `2375`/`6443`, privileged containers, exposed
  Docker socket, service-account token readable inside a pod, exposed
  dashboard, exposed `etcd` on `2379`.
- Serverless: Lambda environment variables, IAM role reuse, the
  Denonia-class of serverless-specific malware/misconfig patterns.
- Docker Registry API (usually port `5000`, HTTP-based so it can sit
  behind a proxy nmap won't fingerprint): neither v1 nor v2 of the
  registry API requires auth by default. Fingerprint with `GET /v2/`
  (expect `{}`) then `GET /v2/_catalog` (expect a `repositories` list,
  or a 401 w/ `WWW-Authenticate` challenge if it's actually locked
  down -- the challenge itself is the "properly configured" signal to
  check for). Pull `GET /v2/<name>/manifests/<tag>` for the
  `fsLayers`/`blobSum` SHA256 list, then `GET
  /v2/<name>/blobs/sha256:<digest>` to download each layer tarball and
  grep the extracted contents for secrets. `GET /v2/<name>/tags/list`
  plus brute-forcing `<name>` enumerates further repos/images beyond
  what `_catalog` discloses.

## Exposed infrastructure/OT services

- Rsync (`873/tcp`, config in `rsyncd.conf`): anonymous or
  weakly-authenticated modules let you list and pull/push files
  without credentials -- `rsync <ip>::` lists top-level modules,
  `rsync <ip>::<module>` lists its contents, `rsync -r
  <ip>::<module>/<path>` recurses, and a module writable by an
  anonymous connection allows file upload. Impact depends on which
  user the daemon runs as (root-owned daemon + anonymous write = direct
  path to a shell-equivalent file drop); check `rsyncd.conf` itself if
  it's ever reachable, since it defines the module's filesystem path,
  access mode, and run-as user.
- FTP (`21/tcp`, plaintext, uses `\r\n`): test anonymous login
  (`anonymous`/`anonymous`, `anonymous`/blank, `ftp`/`ftp`) before
  anything else, and check whether anonymous sessions got write access
  in addition to read. Banner-grab for version-specific known CVEs.
  The `PORT` command, if the server honors it, lets an authenticated
  session instruct the FTP server to open a connection to an
  attacker-chosen host:port and report back whether it connected --
  an FTP-bounce port scan against internal hosts the tester can't
  otherwise reach.
- BACnet (building-automation/ICS protocol, UDP `47808`): unencrypted
  and unauthenticated by design, so any client on the segment can
  spoof device messages, submit a corrupted/faulty routing table entry
  to disable a device's network connectivity, write object properties
  to change real building-control values (HVAC/lighting/access/fire
  systems), or flood the segment for DoS. Enumerate with `nmap
  --script bacnet-info --script-args full=yes -sU -p 47808 <ip>` or
  the Python `BAC0` library to pull vendor/instance info before
  deciding impact -- this is OT/ICS scope, so confirm engagement rules
  explicitly cover it before anything beyond passive enumeration.

## Log poisoning

Log poisoning escalating to LFI, cron-based RCE, or exposure of
debug/admin consoles reachable through poisoned log content.
