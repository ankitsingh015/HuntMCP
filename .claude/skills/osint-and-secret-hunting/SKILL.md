---
name: osint-and-secret-hunting
description: OSINT and secret-hunting tactics -- Google/GitHub/paste dorking, favicon-hash Shodan pivots, source-code disclosure paths (.git/HEAD, .env, .DS_Store, backup files), Wayback URL mining, steganography in uploaded images, metadata leaks, and WHOIS-derived username conventions. Converted from master-pentest-prompt.md Phase 32. Use early in an engagement, alongside recon, and again whenever a new asset (domain, image upload, employee name) surfaces.
---

# OSINT, stego & secret hunting -- real engagement tactics

## When to use

Alongside recon at the start of an engagement, and again any time a new
asset surfaces mid-engagement -- a newly discovered subdomain, an image
upload feature, an employee name from a bio page.

## Dorking

Google/GitHub/Bing operators: `site:` `filetype:` `inurl:` `intitle:`
`intext:`, `inurl:q=` for reflected-param discovery, Pastebin/Gist search
for company keywords, npm/pip package search by company name (dependency
confusion candidates), leaked creds on S3 (bucket-leak style search
tools).

## Paste-site and code-search dorks

Beyond generic `site:`/`intext:` operators, run these directly: paste-site
sweeps (`site:pastebin.com "<domain>"`, plus the same query against
`ghostbin.com`, `rentry.co`, `hastebin.com`, `gist.github.com`) catch
copy-pasted configs and stack traces that never touch the target's own web
root. On GitHub code search, run `filename:.env "<domain>"`,
`AWS_ACCESS_KEY_ID "<domain>"`, `authorization: Bearer "<domain>"`,
`filename:id_rsa "<domain>"`, and `filename:.git-credentials "<domain>"`
for credential leaks tied to the org, plus `"@<domain>" password` to
surface employee emails appearing alongside plaintext passwords in
committed code or scripts. Internal-hostname leakage rarely announces
itself as `internal.<domain>` in a dork -- instead search for the
internal tool it's fronting: `site:<domain> intitle:"Jenkins"`,
`intitle:"Grafana"`, `intitle:"Kibana"`, `intitle:"Splunk"`, or
`intitle:"Argo CD"` surfaces the hostname via the page title even when
the tool itself blocks anonymous auth.

## High-precision secret dorks

A curated, lowest-noise subset worth running directly against
`site:<target>`: `"-----BEGIN RSA PRIVATE KEY-----"` for exposed private
keys, `"firebase" "apiKey"` and `"supabase" "anon" "key"` for BaaS
credentials, `"client_secret" "redirect_uris" extension:json` for OAuth
app configs, `"private_key" "client_email" extension:json` for GCP
service-account JSON, `"AKIA" filetype:env NOT example NOT test` for live
AWS keys (the `NOT example NOT test` pair cuts most tutorial-repo noise),
`"mongodb+srv://" "password"` for connection strings with embedded
credentials, and `"JWT_SECRET" OR "jwt_secret" filetype:env` for signing
secrets. Each pairs a specific-enough string with a file-type or
extension constraint, which is what keeps the false-positive rate low
compared to a bare keyword search.

## Source code / config disclosure

`.git/HEAD` returning 200 (then dump the whole repo), `.DS_Store`
parsing (a dedicated ds-store tool), `.env`, `.swp`/`.swo` editor
leftovers, `*~` backup files, `.bak`/`.old` backups, stray IDE project
files -- all are routine, high-yield checks on every target.

## GitLab org secret mining

Distinct from the CVE and general-recon angle already covered under
`cms-and-framework-specific` -- this is treating a public/registration-
open GitLab instance purely as a secret source, org-wide rather than
one repo at a time. Page through
`/api/v4/projects?visibility=public&per_page=100` to inventory the full
public-project list, then pull each project's
`/repository/commits` for author names/emails -- commit authors reveal
the org's real `firstname.lastname` / `flastname` email convention far
faster than WHOIS or LinkedIn guessing, and feed straight into the
WHOIS/org-intel section below. Don't stop at known filenames: pull the
full recursive tree (`/repository/tree?recursive=true`) and grep every
file's raw content, not just its name, against the standard secret regex
catalog -- a credential can be embedded mid-file in something that
doesn't look like a config file by name. Always try
`/api/v4/projects/:id/variables` directly even though it's nominally
admin-gated -- misconfigured permissions occasionally leave CI/CD
variables (including runner-registration tokens) readable to any caller,
and `/users/sign_up` returning 200 (open registration) is itself a free
path to becoming that authenticated caller.

## Historical / passive intel

- Wayback Machine URLs with `?q=`/`?api=`/`?token=` params still baked
  into old crawled links -- see the `autonomous-research-loops` skill's
  Loop E for the deeper passive-asset-intelligence sweep.
- Public paste/breach dumps: HIBP, dehashed subsets, IntelX.
- `favicon.ico` hash -> Shodan search (`http.favicon.hash`) to pivot
  from one known asset to other infrastructure sharing the same
  favicon -- `osint-mcp`'s `shodan_favicon_search(favicon_hash)` runs
  this directly (needs `SHODAN_API_KEY`; compute the hash yourself, e.g.
  via `mmh3` over the base64-encoded favicon bytes). Same server also has
  `shodan_host_lookup(ip)` (open ports/banners/CVEs Shodan already
  tagged), `virustotal_domain_report(domain)` (reputation/categorization),
  `censys_host_search(query)` (internet-wide host search independent of
  DNS), and `securitytrails_subdomains(domain)` (a second passive-DNS
  source alongside subfinder). None of these are scope-gated -- they
  query a third-party database ABOUT the target, never the target itself
  -- so they're safe to run before or without an active engagement.

## Steganography

Both a CTF technique and something that shows up in real engagements
when employees embed creds in uploaded images: `exif`, `strings`,
`binwalk`, `zsteg`, `steghide`, `stegsolve` against any uploaded or
publicly hosted image.

## Metadata leaks

EXIF GPS coordinates, author/editor names embedded in office documents
or images -- feeds directly into social-engineering pretexting even
when it isn't itself a technical finding.

## Standard discovery files

`robots.txt`, `sitemap.xml`, `humans.txt`, `security.txt`, `ads.txt` --
hidden directories referenced in these routinely reveal admin panels,
staging environments, or an old parallel app.

## Certificate transparency

CT logs surface internal hostnames via the issuer/SAN fields even when
those hosts were never meant to be public.

## WHOIS / org intel

Registration data reveals org naming conventions, which in turn predicts
targeted usernames (`firstname.lastname`, `flastname`) for credential
stuffing or password-spray planning.
