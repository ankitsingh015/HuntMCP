---
name: subdomain-takeover
description: Full subdomain-takeover matrix -- provider fingerprinting (GitHub Pages, S3, Heroku, Azure, Netlify, Shopify, and more), claimable-string signatures, the four takeover mechanisms (CNAME->NXDOMAIN, expired apex, recycled cloud IP, abandoned NS delegation), and impact multipliers. Converted from master-pentest-prompt.md Phase 17. Use on every subdomain found during recon, every engagement.
---

# Subdomain takeover -- full matrix

## When to use

Every engagement, on every enumerated subdomain -- this is cheap to check
and frequently rewarded, so it should never be skipped even when it
doesn't feel like the main focus.

## Procedure

1. Enumerate all subdomains (`subfinder-mcp`, crt.sh), then
   `dig +short CNAME` each one.
2. Flag CNAMEs pointing at a takeover-prone provider: GitHub Pages, S3,
   Heroku, Azure, Netlify, Shopify, Zendesk, Fastly, Vercel, ReadMe,
   Pantheon, GitLab Pages, Ghost, Tumblr, Surge, Azure Traffic Manager.
3. Fingerprint claimable-string signatures in the response: "There isn't
   a GitHub Pages site here", "NoSuchBucket", "No such app", "404 Web
   Site not found", "This shop is currently unavailable" -- and check
   against a `can-i-take-over-xyz`-style fingerprint database for
   anything not covered above.

## The four takeover mechanisms

- **CNAME -> NXDOMAIN** (the cleanest signal -- the CNAME target doesn't
  resolve at all).
- **CNAME -> expired apex domain**.
- **A record -> recycled cloud IP** (the IP was reassigned to another
  cloud customer).
- **NS delegation -> abandoned zone** (full DNS control if claimable --
  this is the highest-impact variant).
- **MX -> dead host**.

## Impact multipliers

A takeover is worth more when the subdomain also carries: cookies scoped
to `Domain=<parent>` (session-cookie theft from the parent domain), a CSP
`script-src` allowlist entry (bypasses CSP on the main app), an OAuth
`redirect_uri` allowlist entry (token theft via the OAuth flow -- see the
`open-redirect` skill), a SAML `entityID`, or an SPF/DKIM `include:`
reference (email spoofing capability, see the `email-security` skill).
Note any of these explicitly in the writeup -- they're what turns a
takeover from informational into critical.
