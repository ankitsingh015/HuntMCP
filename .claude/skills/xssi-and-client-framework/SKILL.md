---
name: xssi-and-client-framework
description: XSSI (cross-site script inclusion) and client-side framework attack techniques -- JSONP hijacking, AngularJS sandbox escapes, Vue/React unsafe-HTML sinks, client-side prototype pollution gadgets, service-worker hijacking, Sass/SCSS server-side injection, and full DOM clobbering. Converted from master-pentest-prompt.md Phase 25. Use on any endpoint returning JS/JSONP containing authenticated data, and on any modern JS-framework-heavy frontend.
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
