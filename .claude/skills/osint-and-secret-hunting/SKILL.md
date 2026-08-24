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

## Source code / config disclosure

`.git/HEAD` returning 200 (then dump the whole repo), `.DS_Store`
parsing (a dedicated ds-store tool), `.env`, `.swp`/`.swo` editor
leftovers, `*~` backup files, `.bak`/`.old` backups, stray IDE project
files -- all are routine, high-yield checks on every target.

## Historical / passive intel

- Wayback Machine URLs with `?q=`/`?api=`/`?token=` params still baked
  into old crawled links -- see the `autonomous-research-loops` skill's
  Loop E for the deeper passive-asset-intelligence sweep.
- Public paste/breach dumps: HIBP, dehashed subsets, IntelX.
- `favicon.ico` hash -> Shodan search (`http.favicon.hash`) to pivot
  from one known asset to other infrastructure sharing the same
  favicon.

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
