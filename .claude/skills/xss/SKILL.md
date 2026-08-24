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

## Encoding & browser bypass

Entities, unicode escapes, WAF-evasion encodings (see the `waf-bypass`
skill for the general WAF-tier approach; this is the XSS-specific
subset).

## CSP bypass (every class)

`unsafe-inline` gadgets, JSONP endpoints, script gadgets, CDN allowlist
bypass, worker/blob URLs, dangling markup, DOM clobbering (`name`
attribute colliding with `innerHTML`, id-based anchor collision).

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
