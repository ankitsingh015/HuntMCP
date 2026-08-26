---
name: xss
description: XSS technique list covering reflected/stored/DOM/blind/mutation XSS, injection contexts, CSP bypass classes, postMessage leakage, and storage-based XSS via uploaded file formats. Converted from master-pentest-prompt.md Phase 9. Use when a parameter reflects user input in an HTML/JS/CSS/attribute context, or a file upload gets rendered back to users.
---

# XSS -- universe

## When to use

Any parameter that reflects into the response, any stored user content
that gets rendered later, and any file-upload feature whose output might
be rendered inline (SVG, PDF preview, Office doc preview).

## Core classes

- Reflected / stored / DOM / blind (XSS Hunter, `oob-mcp` for the
  callback).
- mXSS (mutation XSS), SVG/MathML vectors, CSS injection
  (`@import`/`@import url(evil)`), attribute injection (`style`/
  `onerror`), the full HTML5 vector list.

## Injection contexts

JS string/comment, JSON parse, template literal, URL context, HTML
attribute, CSS, `noscript` bypass -- the same payload rarely works across
all of these; identify which context the input lands in before choosing
one.

## Presence != exploitation -- check the sink before claiming it

Reflection alone is not XSS; modern frameworks escape text by default.
Before calling anything confirmed: (1) payload reflected/stored, (2) payload
lands in a *renderable* sink, (3) payload actually executes (verify with
`mcp__browser-mcp` `check_js_execution(url, marker)`, not by eyeballing the
raw response). Framework default behavior and what actually opens a sink:

| Framework | Escapes by default | Sink requires |
|---|---|---|
| React/JSX | yes | `dangerouslySetInnerHTML`, raw `innerHTML` on a ref |
| Vue | yes (`{{ }}`) | `v-html` |
| Angular | yes (`{{ }}`) | `[innerHTML]` binding |
| Svelte | yes (`{ }`) | `{@html}` |
| Next.js RSC | yes (JSX text) | `dangerouslySetInnerHTML` in a component |
| Plain HTML/JS | no | `innerHTML`, `document.write()`, `eval()` |

Grep the JS bundle for these sink names near the reflected field before
spending time on payload crafting -- if none appear, it's stored HTML
without an exploitable sink, not XSS.

**Canary discipline**: use a unique random marker (8+ chars, no English
words -- `cpmark987abc`, not `test`/`marker`/`payload`), and check the
*baseline* (no-marker) response for it first. A marker that already appears
naturally in the page (e.g. the literal word "javascript" in every help-link
href) is a false-positive trap, not a real reflection.

## Encoding & browser bypass

Entities, unicode escapes, WAF-evasion encodings (see the `waf-bypass`
skill for the general WAF-tier approach; this is the XSS-specific
subset).

## CSP bypass (every class)

`unsafe-inline` gadgets, JSONP endpoints, script gadgets, CDN allowlist
bypass, worker/blob URLs, dangling markup, DOM clobbering (`name`
attribute colliding with `innerHTML`, id-based anchor collision).

## Blind/stored XSS -- OOB confirmation gate

Same discipline as SSRF: a blind or stored claim needs a real callback, not
an inference. Plant an `oob-mcp` `generate_payload_url()` callback (sub-tag
per field so the hit tells you which sink fired) in error messages,
auth-flow source params (`?Source=`, `?ReturnUrl=`), the username field
(admin log viewers), User-Agent/Referer (some SOC dashboards render these as
HTML), and file-upload filenames -- then `check_interactions()`. For stored
XSS specifically, keep the listener open; the callback can fire hours later
when an admin actually views the affected resource, not immediately. Zero
callbacks across every planted sink means the claim gets retracted, even if
the payload superficially "looks like it landed" -- a request-validator
rejection or an error-string echo is not the same as browser execution.

## Other vectors

- **postMessage leakage**: parent-origin leakage, message-listener XSS
  (see the `reconnaissance` skill's JS-mining checklist for finding the
  listeners in the first place).
- **Dangling markup injection**.
- **Storage XSS** via markdown, PDF, SVG, DOCX, uploaded images, CSV/Excel
  formula injection.
- **Service worker registration, blob URL** vectors.
- **Chained**: delimiter-based cache poisoning combined with XSS for
  wider blast radius.

## Standalone XSS pays Low-Medium -- chains pay 5-20x

Before writing up plain `alert(1)`, ask what the JS execution actually
unlocks:

- **XSS + cache poisoning -> stored-at-CDN-scale**: an unkeyed input
  (`X-Forwarded-Host`, a cookie stripped from the cache key but reflected in
  the body) turns one reflected payload into persistent stored XSS for every
  CDN-edge visitor until the cache TTL expires -- see `waf-bypass` skill's
  cache-key-confusion notes.
- **Self-XSS + CSRF -> effective stored XSS -> ATO**: a profile field only
  fires for the logged-in owner, but a CSRF-vulnerable endpoint that writes
  that same field turns it into a real stored payload against the victim's
  own session -- chase the CSRF angle before writing off a self-XSS as
  unexploitable (see `csrf-cors-origin`).
- **DOM XSS on an OAuth callback -> fragment token capture**: `#access_token=`
  never reaches the server, only the browser -- a DOM sink reading
  `location.hash` on `/oauth/callback` can exfiltrate it directly.
- **SVG upload -> CSP bypass**: CSP frequently gates HTML responses but not
  `image/svg+xml` -- an SVG served same-origin executes with full
  session-cookie access despite a strict CSP on the rest of the app.
