---
name: reconnaissance
description: Full-spectrum recon technique list (subdomains, JS mining, history, dorks, cloud storage, internet-exposure scanners, DNS) and the 8-category JavaScript intelligence-mining checklist. Converted from master-pentest-prompt.md Phases 1/1.5. Use during recon-agent's Phase 1-2, and again any time a new JS bundle is discovered later in the engagement.
---

# Reconnaissance

## When to use

recon-agent's primary phase, and again whenever a later phase turns up a
new JS bundle worth mining (the JS-mining checklist applies any time, not
just at the start).

## Recon technique list

- Subdomains: crt.sh, Amass, Subfinder, SecurityTrails, Certificate
  Transparency (recon-agent's `subfinder-mcp`).
- JS files: analyze all bundled JS -- see the JavaScript intelligence
  mining checklist below.
- History: Wayback CDX, web.archive.org, Play Store policy files.
- Search dorks: `site:`, `inurl:admin`, `filetype:pdf/sql/env/log`,
  `intitle:index.of`.
- GitHub/GitLab/Yandex code search for leaked credentials.
- Cloud: S3 buckets, Azure Blob, GCP GCS (test `--no-sign-request`),
  CloudBrute + GrayhatWarfare-style enumeration.
- Internet exposure: Shodan, Censys, FOFA (ports, banners, SSL cert
  names).
- Full port scan (65535) + service version detection + vuln lookup
  (`nmap-mcp`).
- DNS: zone transfer, wildcard, DKIM/SPF/DMARC, subdomain takeover
  (dangling CNAME).
- Tech stack fingerprinting -> framework-specific exploit path (see
  `engagement-setup` skill's header-to-stack table).
- Error output, `phpinfo.php`, `server-status`, build files,
  `terraform.tfstate` leaks.

**Attack-surface map** (running deliverable): maintain
`chat-logs/<target>-<date>/attack-surface-map.md` as recon grows --
hosts/subdomains, ports, tech stack, endpoints (auth'd/unauth'd), roles,
auth model, state transitions, integrations, hidden params, response
differences. Update it after every phase; it's the miss-nothing checklist
and the roadmap for where to hunt next.

## JavaScript intelligence mining (read every .js fully)

Download every JS bundle. Read and analyze the full content, not just
grep hits -- a minified bundle is intelligence waiting to be read; the
goal is understanding developer INTENT and finding what wasn't meant to
be exposed. Scan mentally for all 8 categories:

1. **Hardcoded secrets**: `sk-`, `pk_`, `AKIA`, `AIza`, `SG.`, `ghp_`,
   `xox`, JWT/bearer tokens, passwords, private keys, base64 that decodes
   to creds, AWS/GCP/Azure key patterns, Stripe/Twilio/SendGrid/Mailgun/
   Firebase keys, vars named `apiKey`/`secretKey`/`accessToken`/
   `clientSecret`/`privateKey`.
2. **Undocumented endpoints**: `/api/`, `/v1/`, `/v2/`, `/internal/`,
   `/admin/`, `/graphql/` strings; `fetch()`/axios/XHR hardcoded URLs;
   `baseUrl`/`apiUrl`/`endpoint`/`host` vars pointing at
   dev/staging/internal/beta/test subdomains; `ws://`/`wss://` sockets.
   Test every endpoint found immediately.
3. **postMessage origin validation**: every `addEventListener('message')`.
   No `event.origin` check = exploitable. Weak checks
   (`.includes`/`.endsWith`) = bypassable with `evil-target.com`/
   `eviltarget.com`. Document the handler, what it processes, and the
   action it triggers.
4. **DOM XSS sources -> sinks**: sources = `location.*`,
   `document.referrer`/`URL`/`baseURI`, `window.name`,
   `URLSearchParams`, `decodeURIComponent`; sinks = `innerHTML`/
   `outerHTML`, `document.write`, `eval`, `setTimeout(string)`,
   `insertAdjacentHTML`, `$.html()`, `.src`/`.href` assignment. Flag any
   source -> sink flow, including partial/stored flows.
5. **Hidden params & fields**: `FormData()`, fetch/axios bodies, fields
   the UI hides: `user_id`, `account_id`, `org_id`, `tenant_id`, `role`,
   `is_admin`, `plan`, `scope`, `internal_flag`, `feature_flag`, `debug`,
   `admin`, `verified` -- plus any field built from
   `localStorage`/`sessionStorage`. Test manipulation of each
   server-side.
6. **Client-side access control**: routes gated only by JS
   (`user.role === 'admin'`), UI-hidden features backed by real
   endpoints, client-side feature flags. Test those endpoints directly
   with a non-admin session.
7. **Sensitive data in client storage**: `localStorage`/`sessionStorage`
   tokens, user IDs, roles, PII; `document.cookie` without `HttpOnly` =
   XSS-exposed.
8. **Source map exposure**: `//# sourceMappingURL=*.map` -> fetch the
   `.map` -> full unminified source (field names, comments, dev logic,
   internal routes, sometimes credentials).

After each file: 1) list findings from all 8 categories, 2) test every
new endpoint, 3) include every new param in injection tests (see
`injection-and-rce` skill), 4) attempt to use every secret found
(`secrets-mcp` finds candidates; using them against the target's APIs is
still a manual step), 5) build a PoC for every DOM XSS chain, 6) document
each postMessage handler and its reachable action.
