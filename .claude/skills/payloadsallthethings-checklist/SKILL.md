---
name: payloadsallthethings-checklist
description: The full PayloadsAllTheThings category checklist (60+ vuln classes) as a final coverage sweep. Converted from master-pentest-prompt.md Phase 22. Use as a closing checklist near the end of an engagement to catch any category that wasn't explicitly covered by another skill.
---

# PayloadsAllTheThings full directory list (check every box)

## When to use

Late in an engagement, as a coverage sweep against the
[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
category list -- cross-check this against what's actually been tested and
chase down anything that fell through the gaps between the other skills.

## The checklist

API Key Leaks · Account Takeover · Brute Force Rate Limit · Business
Logic Errors · CORS Misconfiguration · CRLF Injection · CSS Injection ·
CSV Injection · CVE Exploits · Clickjacking · Client Side Path Traversal
· Command Injection · CSRF · DNS Rebinding · DOM Clobbering · Denial of
Service · Dependency Confusion · Directory Traversal · Encoding
Transformations · External Variable Modification · File Inclusion ·
Google Web Toolkit · GraphQL Injection · HTTP Parameter Pollution ·
Headless Browser · Hidden Parameters · Insecure Deserialization · IDOR ·
Insecure Management Interface · Insecure Randomness · Insecure Source
Code Management · JWT · Java RMI · LDAP Injection · LaTeX Injection ·
Mass Assignment · NoSQL Injection · OAuth Misconfiguration · ORM Leak ·
Open Redirect · Prompt Injection · Prototype Pollution · Race Condition ·
Regular Expression (ReDoS) · Request Smuggling · Reverse Proxy
Misconfigurations · SAML Injection · SQL Injection · SSI (Server Side
Include) Injection · SSRF · SSTI · Tabnabbing · Type Juggling · Upload
Insecure Files · Virtual Hosts · Web Cache Deception · Web Sockets ·
XPATH Injection · XS-Leak (cross-site leaks) · XSLT Injection · XSS ·
XXE · Zip Slip

Most of these are already covered in depth by a dedicated skill
(`injection-and-rce`, `xss`, `ssrf`, `xxe`, `access-control-and-idor`,
`request-smuggling`, `open-redirect`, `csrf-cors-origin`, and others) --
treat this list as the final "did I actually hit every category" check,
not a first-pass technique reference.

## Triage-time sanity check: always-rejected findings

Before writing up anything from the sweep above, run it past this list.
These are the finding types bug bounty triagers consistently close as
informational / N/A regardless of how the checklist item was technically
"hit" -- submitting them without the extra PoC impact noted burns your
validity ratio for no payout:

- Missing security headers (CSP, HSTS, X-Frame-Options) with no PoC that
  actually exploits their absence
- Self-XSS (only reachable in the reporter's own account, no CSRF/clickjack
  path to trigger it on a victim)
- Clickjacking on a page with no sensitive state-changing action framed
- Verbose error messages / stack traces / banner-version disclosure with
  no secret, credential, or working exploit in them
- Missing SPF/DKIM/DMARC records alone (no actual spoofed-mail delivery
  demonstrated)
- GraphQL introspection enabled with no auth-bypass mutation or IDOR found
  through it
- Open redirect alone, with no OAuth `redirect_uri` token-theft or ATO
  chain behind it
- CORS wildcard (`*`) with no credentialed-request PoC exfiltrating actual
  user data
- Logout CSRF, or CSRF on a non-sensitive action
- Rate-limit absence on non-critical forms (search, contact, a
  Cloudflare-fronted login already rate-limited upstream)
- Missing `HttpOnly`/`Secure` cookie flags alone, with no session-theft PoC
- Autocomplete enabled on password fields
- Mixed content / weak TLS cipher suites with no demonstrated downgrade

If a checklist category above only produces one of these on a given
target, treat it as covered-but-not-reportable and keep looking for the
chain that turns it into real impact, rather than filing it as-is.
