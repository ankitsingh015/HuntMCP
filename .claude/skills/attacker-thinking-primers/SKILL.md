---
name: attacker-thinking-primers
description: Conceptual mindset primers for reasoning about each major vuln class during live testing (SQLi, auth, info disclosure, access control, API testing, cache deception, request smuggling, Host header, JWT, SSTI, GraphQL, LLM) -- the "why" behind the payload, not another payload list. Converted from master-pentest-prompt.md Phase 21.6. Use alongside the technique-specific skills as a reasoning framework, especially when a class's standard payloads aren't landing.
---

# Attacker-thinking primers (conceptual knowledge base)

## When to use

The payloads live in the technique-specific skills (`injection-and-rce`,
`auth-and-session`, etc.) -- this is the reasoning layer underneath them,
most useful when the standard payload list for a class isn't landing and
a different angle is needed.

## Primers

- **SQLi**: any input placed into a query is a candidate. Break structure
  first (`'`), then control logic (`AND 1=1` vs. `AND 1=2`), then shape
  output (`UNION`, comment-out the rest of the `WHERE` clause), then go
  blind (`SLEEP`/`pg_sleep`/behavioral diff), then substring-extract.
  Watch for second-order: a payload stored safely that executes later.
- **Authentication**: find what the app actually uses to prove identity,
  then ask whether *you* can control it -- a cookie, a parameter, a
  token, or the order of steps. Test for no lockout on brute force, 2FA
  step skipping, a reset token not actually tied to the user it was
  issued for, and remember-me cookie forgery.
- **Info disclosure**: you don't attack this class, you *notice* it.
  Verbose errors, stack traces, `/robots.txt` pointing at
  `/backup/config.php.bak`, hidden debug endpoints, `.git` diffs
  containing old credentials, `X-Backend-Server` headers. Each leak
  reduces unknowns -- one leaked header (`X-Admin-Auth: true`) can bypass
  auth entirely on its own.
- **Access control**: after login, what is actually *stopping* you from
  doing X as another user, or as no user at all? Swap IDs, hit `/admin`
  directly, change `Cookie: role=user` to `role=admin`, method-swap the
  privileged action, exploit UI-hidden-but-live endpoints. This class is
  simple to exploit because the underlying mistake is simple: the backend
  assumed instead of enforced.
- **API testing**: the same web hacking, minus the UI's restraint. APIs
  routinely expose more than the frontend does, trust client-sent
  structure over server-side context (`role: "admin"` in the body), leak
  their own docs (`/swagger`, `/api-docs`), accept methods the frontend
  never uses, skip rate limiting, and return verbose JSON errors. Ask
  "what else will this endpoint accept that the UI never actually sends?"
- **Web cache deception**: make the cache believe a dynamic,
  authenticated page is a static one. `/my-account/wcd.js`,
  `/profile/..%2faccount.css`, `/settings;file.css` -- the backend
  normalizes the path and serves the real page, the cache stores it under
  the static-looking key. The victim visits while authenticated; you
  fetch the same cached response unauthenticated.
- **Request smuggling**: desync the front-end and back-end on where one
  request ends and the next begins (CL.TE/TE.CL/TE.TE/H2 -- see the
  `request-smuggling` skill). Smuggle a request past the front-end for an
  access-control bypass, or attach your payload to the next victim's
  request for session theft or XSS delivered to everyone behind that
  connection. Detect via unexplained timeouts or hangs.
- **Host header**: changing `Host`/`X-Forwarded-Host` changes how the
  server perceives itself. Password-reset link poisoning (the token
  points at your server), `Host: localhost` sometimes grants admin
  access, cache poisoning, SSRF via host-based routing.
- **JWT**: the data is signed, not encrypted -- read it, modify it,
  replay it. The core question is always: is the server actually
  verifying the signature, or just trusting whatever the client sends?
  Test `alg: none`, a weak/guessable secret, RS-to-HS confusion,
  `kid`/`jku`/`jwk` injection, claim tampering (`role: admin`), and the
  classic server-side RS256->HS256 downgrade.
- **SSTI**: the input is being rendered as a template, not treated as
  data. `{{7*7}}` -> `49` proves server-side evaluation is happening.
  From there, climb from a simple expression to engine objects to
  `system()` for RCE, or at minimum read files/dump config via a
  debug-mode template directive.
- **GraphQL**: the client decides exactly what it queries.
  Introspection gives a full map of queries, mutations, and hidden
  fields (including ones like a `password` field that shouldn't be
  queryable). Ask for fields the UI never shows, try IDOR via ID swap in
  variables, use batching/aliases to bypass rate limits, and check for
  injection inside arguments. The governing question: "what else will it
  return if I just ask?"
- **LLM**: abuse what the model can see and what it can do -- see the
  `emerging-surfaces` skill's practical probing loop for the concrete
  step-by-step version of this primer.

## The rule

Never read a class primer without applying it. For each one above,
actually execute it against the target's matching endpoints before
moving on to the next -- this is a reasoning checklist to act on, not
background reading.
