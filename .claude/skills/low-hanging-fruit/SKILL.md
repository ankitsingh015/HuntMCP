---
name: low-hanging-fruit
description: The never-skip checklist of cheap, high-yield checks -- default credentials, installer leftovers, HTTP verb tampering, TRACE/XST, MIME-sniffing XSS, integer/type-confusion bypasses, unicode normalization tricks, cache deception/poisoning, and rate-limit gaps -- plus PortSwigger's 2025-26 top web hacking techniques (XS-Leaks, internal cache poisoning, parser differentials). Converted from master-pentest-prompt.md Phases 20/20.5, explicitly flagged in the source as responsible for 21% of confirmed findings across real engagements. Use on every engagement, early -- these are cheap to check and disproportionately rewarded.
---

# Low-hanging fruit (never skip -- 21% of engagements)

## When to use

Every engagement. The source material's own framing: these are checks
that take seconds each but account for a disproportionate share of real
confirmed findings -- skipping them to chase something more "interesting"
is a real cost, not a shortcut.

## Default credentials first

`admin:admin`, `admin:password`, `root:root`, `admin:` (blank password),
Tomcat `tomcat:s3cret`, Jenkins `admin:`, phpMyAdmin `root:`, GLPI
`glpi:glpi`, Nagios defaults, Cisco `cisco:cisco`, and company-name
patterns (`admin:<company>123`).

## Installer leftovers

`/setup/`, `/install/`, `/wp-admin/`, `/administrator/`, `/dbadmin`,
`/mysqladmin`, `/manager/html`.

## Verb tampering

`OPTIONS /` to get the `Allow:` header's method list, then replay every
privileged action as GET/HEAD/PATCH/PUT/DELETE/an arbitrary method.
HEAD requests sometimes still set admin cookies; PATCH can flip a role
field a POST validation would have blocked. Method-override headers
(`X-HTTP-Method`, `X-HTTP-Method-Override`, `_method`) are a real bypass
vector -- Google's ESPv2 (CVE-2023-30845) let an override to a spec'd
method skip JWT validation entirely.

## TRACE/TRACK -> XST

If TRACE/TRACK is enabled, the echoed request body can leak an
`HttpOnly` cookie that JS can't read directly.

## MIME sniffing

Upload a `<script>`-containing file as `image/jpeg` and check whether
it's served inline without `X-Content-Type-Options: nosniff` -- a
browser MIME-sniffing the actual content can trigger stored XSS from an
"image." Also check JSON endpoints for the same missing header (JSON
hijacking) and for dual `Content-Type` headers (CVE-2023-38199 class).

## Integer overflow / type confusion in IDs

`9223372036854775807` (int64 max), `-1`, `0x`-prefixed hex, `true`,
`id[]=` array syntax, leading zeros -- any of these can resolve to the
wrong record or skip a filter the application assumed would always see a
clean positive integer.

## Unicode normalization

Fullwidth `%uff07` normalizing to `'` (a quote-stripping filter bypass
for SQLi), Turkish `İ`/`i` case-folding oddities, zero-width characters
slipping past an allowlist regex that wasn't unicode-aware.

## More method/content-type confusion

- **Method-based auth bypass**: the exact same URL behaving differently
  for POST vs. GET.
- **Content-Type switching**: a JSON-only endpoint that also silently
  parses form-encoded bodies -- opens mass-assignment or CSRF bypass
  paths the JSON-only assumption was relying on (CVE-2023-38199 class
  again).
- **Regex bypass**: duplicate parameters (does validation check the first
  occurrence or the last?), duplicate JSON keys, array-vs-scalar type
  confusion (`indexOf("..")` assuming a string, getting an array),
  max-length truncation cutting a payload's malicious suffix off cleanly.

## Second-order attacks

Input stored with its dangerous characters escaped, then re-inserted
somewhere that isn't escaped the same way -> second-order SQLi. Stored
XSS that only renders in an admin view, an email, or a generated PDF --
easy to miss if you only check the direct response. A stored filename
later joined into a `path.resolve()`-style call downstream.

## Session cookie audit

`Secure`/`HttpOnly`/`SameSite` flags present and correct, `Domain`
scoped no wider than necessary, `Path=/` not unnecessarily broad,
`__Host-` prefix used correctly where claimed, and no subdomain-fixation
gap (a cookie set on a takeover-able or attacker-influenced subdomain
being trusted by the parent).

## Sensitive data in URLs/logs

Tokens, session IDs, reset tokens, `access_token` sitting in a query
string -- these leak via the `Referer` header to any third party the page
loads resources from.

## Cache deception

Appending a static-looking suffix to a dynamic, authenticated URL
(`/profile.css`, `/me/index.html`, `/dashboard/foo.js`) can get the
*authenticated* response cached and then served to unauthenticated
users. Also check path delimiters (`;`, `#`, `?`) against how the cache
layer normalizes paths, and the `X-Original-URL` header for override
behavior.

## Cache poisoning

Unkeyed headers reflected into the response but not part of the cache
key (`X-Forwarded-Host`, `X-Forwarded-Scheme`, a cookie value,
`X-HTTP-Method-Override`) can be injected once and then served to every
subsequent visitor from cache. Detect caching behavior via
`X-Cache`/`CF-Cache-Status`/`Age`/`Via` response headers.

## Rate limiting

Explicitly check: OTP/2FA verification (a 6-digit code is only 10^6
values -- at 100 requests/second that's a ~83-minute account takeover if
truly unlimited), login, password-reset token verification,
registration, SMS/email sending, and API key generation.

## PortSwigger's 2025-26 top web hacking techniques

- **XS-Leak via Chrome connection-pool prioritization**: a timing
  side-channel that can leak a cross-origin redirect's target -- apply
  this to OAuth `redirect_uri`, password-reset links, and magic links.
- **Cross-Site ETag Length Leak**: another XS-Leak class, using the
  `ETag`/strong-validator header as an oracle for cross-origin response
  size.
- **Internal cache poisoning** (the "stale elixir" / Next.js-class bug):
  poisoning a framework's *internal* render cache so unauthenticated
  users receive an attacker-controlled cached page -- enumerate cache-key
  behavior per route rather than assuming one global cache policy.
- **Malformed chunk desync**: novel chunk-encoding parser differentials
  using malformed or oversized chunk sizes -- extends the
  `request-smuggling` skill's checks.
- **Browser-redirect stalling**: slowing a redirect deliberately to alter
  `SameSite`/credential-inclusion behavior and leak state across origins
  -- combines with the XS-Leak techniques above.
- **New SAML exploitation classes**: auth bypass via profile/document
  tampering, issuer confusion, and attribute-confusion flows beyond
  classic XML signature wrapping -- revisit the `auth-and-session`
  skill's SAML bullet with these in mind.
- **Parser differentials**: proxy-vs-application differences (how the
  backend treats an escaped backslash, header folding) and HTTP/2
  front-end differentials, both usable for routing/auth bypass.
- **ORM leak methodology**: search/filter endpoints that leak
  non-matching records through boolean, ordering, or filter-confusion
  edge cases.
- **Successful-errors**: attacker-controlled error text flowing into a
  template engine -- test on custom 500/400 error pages specifically for
  SSTI/code-injection.
- **HTTP/2 CONNECT tunnelling**: using an HTTP/2 CONNECT-enabled endpoint
  for port scanning or SSRF.
- **SOAPwn (.NET)**: WSDL/HTTP client proxy endpoints exploitable for
  SSRF/XXE -- probe `/?WSDL` and WS-Discovery endpoints specifically.
- **Unicode normalization exploitation** ("Lost in Translation"):
  punycode/NFKC-equivalent identifiers used for cross-origin confusion or
  username squatting.
