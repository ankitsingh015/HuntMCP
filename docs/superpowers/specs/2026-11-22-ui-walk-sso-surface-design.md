# UI-walk: in-scope SSO / auth flows as surface — Design (spec 2 of 3)

Date: 2026-11-22
Status: Approved (2026-11-22)
Size: Project
Builds on: #164 UI-walk (`2026-11-19-page-comprehension-ui-walk-design.md`) and
spec 1, the event recorder (`2026-11-20-ui-walk-event-recorder-design.md`,
inventory schema_version 2, redirect events with hops, ruling R4).
Followed by: spec 3 (Burp-style parameter + request mutation).

## Intent and the why

The user wants the walker to "capture every corner of a page, every small
browser event, every parameter". Login is the biggest gap left. When an app
signs users in through an identity provider (IdP), the walker sees the
redirect bounce today, but:

- in a walk with a session, a page on the IdP looks "logged-out", so it is
  marked `login-required` and never mapped, and `emit_nodes` skips it (only
  `auth_state == "ok"` pages become nodes);
- event URLs keep only query parameter **names** (ruling R4), so nothing
  records whether `state`/`nonce` exist, how strong they are, or whether they
  change per request;
- the token and logout endpoints are never recorded. In the normal code flow
  the app's server calls `/token` itself, so the browser never sees it.

The goal: when the IdP host is **in scope**, the SSO flow (authorize, login,
consent, callback, token, logout, discovery) becomes surface-map nodes that
queue `auth-and-session` checks: `redirect_uri` parser differentials,
`state`/`nonce` handling, PKCE, and logout `post_logout_redirect_uri` open
redirect. Exploit-agent then works through them with the `auth-and-session`
skill.

Success: after a map walk of an app with an in-scope IdP, the surface map
holds a node for every SSO endpoint the walk saw or the IdP's discovery
document lists (in scope only). Each node carries the coverage classes that
must be tested, and the inventory carries `sso-*` candidates with the flags
that make each one a lead. None of this stores a single `state`, `nonce`,
`code` or token value.

## Goals

1. **Recognise SSO hops** (pure logic, new `ui_walk_sso_logic.py`) from URLs
   the walker already sees: redirect-chain hops, main-frame navigations,
   UI→API edges (sent or aborted), control `href`s and form actions. Roles:
   - `authorize`: OAuth/OIDC authorization request (`response_type` +
     `client_id` in the query, or a known authorize path such as
     `/authorize`, `/oauth2/authorize`, `/oauth2/v2.0/authorize`,
     `/protocol/openid-connect/auth`, `/connect/authorize`, `/o/oauth2/auth`).
   - `callback`: request to the app carrying `code`, `id_token`, `error` or a
     `state` that came back from an authorize hop (query or fragment, read in
     memory).
   - `saml-request` / `saml-response`: `SAMLRequest` / `SAMLResponse` in a
     query or in a form's field names (the auto-posting ACS form is a POST,
     aborted in Pass 1 as today).
   - `logout`: end-session / logout paths (`/logout`, `/end_session`,
     `/oauth2/logout`, `/protocol/openid-connect/logout`, `/v2/logout`,
     SAML `SingleLogout`), or the discovery document's `end_session_endpoint`.
     Logout is never visited or clicked (unchanged #164 rule); it is recorded
     from attributes, aborted mutating-GET edges and discovery.
   - `token`, `revocation`, `userinfo`, `jwks`, `registration`,
     `device_authorization`, `introspection`: from the discovery document,
     or from an observed browser request (an SPA/PKCE `POST /token` is a
     non-GET, so it is aborted in Pass 1 and recorded with its body field
     names, as today).
   - `discovery`: the discovery document itself.
   - `login` / `consent` / `mfa` pages: IdP pages the browser lands on
     (password input present → `login`; "allow/accept/authorize" controls plus
     a scope list → `consent`; OTP-style input → `mfa`).
2. **Map in-scope IdP pages** even when they look logged-out: inputs,
   controls and the Pass 1 click rules as on any page (nothing is filled;
   the login/consent submit is a non-GET, so it is aborted and recorded as a
   UI→API edge). They get `auth_state: "sso"` plus `sso_role`, and they do
   become nodes. The `_session_still_valid` check still runs, so a dead
   session still stops the walk.
3. **Per-flow flags, values never stored** (see Values policy): per
   authorize hop, whether `state`/`nonce`/PKCE are present, a strength class,
   `response_type`, whether the `state` is echoed on the callback, and, from
   the repeat (Goal 4), whether `state`/`nonce` change per request.
4. **The repeat (user decision B: one extra GET).** For each distinct
   authorize flow (key: authorize host+path, `client_id`, `redirect_uri`
   host+path), the walker triggers the flow **once more** and compares the
   new `state`/`nonce` with the first ones in memory. Budget-charged, at most
   5 per walk. How the flow is re-triggered (in this order):
   a. the chain's first in-scope hop that is not the authorize request (the
      app's "start login" URL) is re-requested **without following
      redirects**, through `context.request` (shares the walk's cookie jar),
      and the fresh `Location` is read in memory;
   b. if the authorize URL came from a control's `href` (state baked into the
      page), the page is reloaded once and the same control's `href` is read
      again;
   c. if it came from a click whose JS built the authorize URL, that control
      is clicked once more.
   None of these applies, or the second value can't be read → the flag is
   `unknown`, never a guess.
5. **Discovery.** For each in-scope IdP host seen in an authorize hop, GET
   `/.well-known/openid-configuration`, at the host root and at the issuer
   path prefix when the authorize path has one (e.g. Keycloak
   `/realms/<r>/`). Fall back to `/.well-known/oauth-authorization-server`
   on 404. At most 3 GETs per host and 3 hosts per walk, budget-charged,
   via `context.request` with no redirects followed and at most 256 KB read.
   Endpoint URLs and the `*_supported` lists are kept (not secrets). Only
   endpoints whose host is in scope become nodes; others are recorded.
6. **Surface-map nodes** (`ui_walk_store.emit_nodes`), in scope only:
   - IdP `login`/`consent`/`mfa` pages → `page` nodes, `meta.sso_role` set.
   - every other in-scope SSO endpoint role (see decision 6) → `action` nodes,
     signature `action:<METHOD> <route-template>`, `meta.sso_role`, the
     param names and flags, parent = the page where it was seen (or the IdP
     login page node for discovery-only endpoints).
7. **Coverage battery for SSO nodes** (`coverage_manifest.required_classes`,
   meta-conditional, like `destructive` → `business-logic`):
   - any node with `meta.sso_role` → `auth`;
   - `authorize`, `callback`, `logout` → also `open-redirect`;
   - `authorize`, `login`, `consent` → also `csrf` (login CSRF / state).
   For SSO `action` nodes this **replaces** the generic action battery
   (`idor`, `business-logic` and `access-control` mean nothing on an authorize
   URL and would only force `mark_na` noise). SSO `page` nodes keep the
   page battery and add the above. *(Author's call.)*
8. **Candidates** (leads for exploit-agent, never auto-confirmed):
   - `sso-redirect-uri-candidate`: an in-scope authorize hop with
     `redirect_uri` → test parser differentials (detail: `client_id`,
     `redirect_uri` host+path, `response_type`).
   - `sso-state-candidate`: `state` missing, weak, static across the repeat,
     or not echoed on the callback.
   - `sso-nonce-candidate`: `response_type` contains `id_token` and `nonce`
     is missing, or `nonce` is static across the repeat.
   - `sso-pkce-candidate`: code flow without `code_challenge`, or
     `code_challenge_method=plain`.
   - `sso-implicit-flow-candidate`: `response_type` contains `token`.
   - `sso-logout-redirect-candidate`: a logout endpoint that takes a redirect
     parameter (`post_logout_redirect_uri`, `returnTo`, `redirect`,
     `RelayState`, `wreply`, `next`, …) → test open redirect.
   - `sso-registration-candidate`: an in-scope `registration_endpoint`
     (dynamic client registration).
   Candidates whose test target is the IdP (`redirect-uri`, `logout-redirect`,
   `registration`, `pkce` enforcement) are only made when the IdP is in
   scope. `state`/`nonce` candidates are about the app (in scope) and are made
   either way, with `idp_in_scope` in the detail so the tester knows to test
   only against the app's callback.
   The existing spec 1 `redirect-param-candidate` (`redirect_param_names`) is
   reused unchanged. It already fires on SSO hops whose `Location` echoes a
   parameter, so no SSO copy of that rule is made.
9. **Pass 2 never submits SSO forms.** `form_unsafe_reason` refuses any form
   on an SSO page (login/consent/mfa) or whose action is an SSO endpoint, so
   a canary is never typed into a login form. A failed-login storm could lock
   accounts and break programme rules (Bentley bans brute force).
10. **Output:** `check_ui_walk` prints an SSO section (flows, endpoints by
    role, flags, candidates), quarantined, provenance line still last.
    Inventory `schema_version` 2 → 3, additive only: `inv.sso`
    (`flows`, `endpoints`, `discovery`, `repeats`,
    `out_of_scope_idp_redirects`), `pages[].sso_role`.
11. **Agent prompts:** recon-agent: the walk covers SSO when the IdP is in
    scope (no extra step). exploit-agent: `sso-*` candidates are worked with
    the `auth-and-session` skill; out-of-scope IdPs are never tested.

## Out-of-scope IdP (user decision, 2026-11-22)

Following the browser's HTTP redirect to an out-of-scope IdP (e.g.
`login.microsoftonline.com`) is what any user's browser does. It is
**allowed and not blocked**; blocking it would break SSO bounces such as
app → IdP → app with an existing IdP session. What stays forbidden is
**interacting** with that host: no mapping, clicking, filling, discovery GET,
repeat that lands there, or candidate that tests it. The walker leaves the
page (`about:blank`, as today) unless the IdP bounced straight back in
scope, in which case the walk simply continues.

Each followed out-of-scope GET is recorded honestly in
`inv.sso.out_of_scope_idp_redirects` (`host`, page, `control_signature`;
URL stripped per R4), and an honest-limits line says that following a
redirect sends one GET there.

The repeat path (a) never follows redirects, so it adds no GET to an
out-of-scope IdP. Paths (b)/(c) re-trigger a browser navigation; for an
out-of-scope IdP they are **not used** (flag `unknown`), so the repeat never
causes an extra out-of-scope GET.

Unchanged #164 rule (not reopened here): a **JavaScript** navigation
(`location.href = …`) to an out-of-scope host is still aborted by the
interceptor. Only HTTP redirects are followed. The aborted URL is still
analysed in memory for SSO flags.

## Values policy (extends ruling R4)

Every URL is analysed **in memory** where the walker first sees it (the
interceptor, the recorder's redirect chain, the repeat), and only derived
data is kept.

- **Never stored, logged, hashed or printed:** `state`, `nonce`, `code`,
  `code_verifier`, `code_challenge`, `id_token`, `id_token_hint`,
  `access_token`, `refresh_token`, `SAMLRequest`, `SAMLResponse`,
  `RelayState` value, `login_hint` (an email, i.e. PII), and every value of a
  parameter not on the allow-list below. No hashes either: comparison
  happens in memory within one walk, so a hash is never needed. A hash of a
  short value could also be brute-forced.
- **Kept (non-secret allow-list):** `response_type`, `response_mode`,
  `scope`, `prompt`, `code_challenge_method`, `client_id` (a public
  identifier the tester needs), and `redirect_uri` /
  `post_logout_redirect_uri` reduced to scheme://host/path (no query or
  fragment). Discovery-document endpoint URLs and `*_supported` lists.
- **Derived flags:** `present` (bool); `strength`: `absent`, `short` (< 16
  chars), `low-charset` (digits only, or a single repeated char class),
  `structured` (JWT- or base64-JSON-looking, i.e. state carries data),
  `ok`; `length_bucket` (`<8`, `8-15`, `16-31`, `32+`);
  `changes_per_request` (`true`/`false`/`unknown`); `echoed_on_callback`
  (`true`/`false`/`unknown`).
- The in-memory first values for the repeat live on the walker object only
  until that flow's comparison is done, then are dropped. They are never
  part of the inventory, never in an exception message and never in an audit
  log.

## Non-goals

- Sending `redirect_uri`, `state`, `nonce` or logout-redirect variants.
  That is spec 3 / exploit-agent work; this spec only queues them.
- Logging in to the IdP. Passwords and CAPTCHAs stay human; the walker never
  types into a login form (Pass 1 or Pass 2). An already captured
  `session_file` (incl. an IdP session cookie) is used as today.
- Calling the token endpoint or exchanging a code.
- Fetching or decoding SAML metadata / `SAMLRequest` contents (role and
  presence only). Possible later.
- Changing the #164 JS-navigation abort rule for out-of-scope hosts.
- `run_teardown`'s logout step: unchanged. It does not use the recorder.
- Any attempt to get around an IdP's bot protection or CAPTCHA. A challenge
  page is mapped as a page and nothing more.
- New MCP server, new dependency.

## Anti-goals (failure even if it "works")

- Any `state`/`nonce`/`code`/token/SAML value (or a hash of one) in the
  inventory, tool output, audit log, surface map or exception text.
- Any interaction with an out-of-scope IdP beyond the followed redirect GET,
  or an extra GET to it caused by the repeat or discovery.
- A canary or any text typed into an IdP login/consent/MFA form.
- Pass 1 sending a non-GET (login/consent submits stay aborted).
- A logout endpoint visited or clicked.
- The repeat/discovery GETs escaping the budget guard or their caps.
- A #164 / spec 1 contract changing silently (tool params, v2 inventory
  fields, quarantine, provenance line last).

## Approaches considered

| | Approach | Trade-off | Verdict |
|---|---|---|---|
| A | Let the browser follow HTTP redirects to an out-of-scope IdP; never interact there; record the GET honestly | No change to how pages load; SSO bounces keep working; one passive GET per bounce | **User-picked** (blocking it is wrong: it breaks normal SSO) |
| B | `route.fetch(max_redirects=0)` for every main-frame load, abort out-of-scope `Location` | Blocks the GET, but every page load changes network stack (TLS fingerprint, Burp path, cookies) | Rejected |
| C | CDP `Fetch` response-stage pause for documents, fail out-of-scope redirects | Blocks the GET with Chrome's own stack; untested next to Playwright's own interception; breaks SSO bounces | Rejected |

For `state`/`nonce` depth the user picked **B: one extra GET** (the repeat)
over watch-only. Values are never stored in either case.

The rest (recognition in a pure-logic module, nodes as `page`/`action`
with `meta.sso_role`, discovery) has one sensible shape: it reuses the spec 1
recorder and the #164 node kinds, as both specs planned.

## Design

### Where the code goes

- New `ui_walk_sso_logic.py` (pure, unit-tested, no browser): role
  classification of a URL / form, allow-list param extraction, flag
  derivation, strength classifier, flow key, repeat comparison, discovery
  JSON parsing (endpoints + `*_supported`, size-capped), SSO candidate rules,
  SSO page-role heuristic.
- `ui_walk_events.py` (recorder): in `_record_redirect`, before the hop URLs
  are stripped, hand the full chain to an SSO observer callback (set by the
  walker). Spec 1 redirect events themselves are unchanged.
- `ui_walk.py`: the walker owns an `SsoTracker` (flows, first values for the
  repeat, endpoints). It feeds it from `_on_route` (main-frame navigations
  and API edges, full URL in memory), the recorder callback, control hrefs
  and form actions. `_visit_page` maps in-scope IdP pages (`auth_state:
  "sso"`) instead of returning early as logged-out. After the click loop of
  a page it runs pending repeats (bounded); after the BFS it runs discovery
  (bounded). `SCHEMA_VERSION = 3`.
- `ui_walk_logic.py`: `form_unsafe_reason` gains the SSO refusal.
- `ui_walk_store.emit_nodes`: SSO pages and endpoints as nodes.
- `coverage_manifest.py`: the SSO battery rule.
- `server.py` `_format_walk`: SSO section.
- `.claude/agents/recon-agent.md`, `exploit-agent.md`: short additions.

### Safety & constraints (unchanged from #164 / spec 1 unless stated)

- Pass 1 sends nothing state-changing. The repeat and discovery are GETs,
  in scope only, budget-charged per request, and capped.
- Scope checked on every navigation and request (unchanged interceptor);
  repeat/discovery requests are scope-checked in code before sending, and
  never follow redirects. Payment hosts blocked.
- Target text quarantined; provenance line last. Discovery JSON is target
  data: only endpoint URLs (which must parse as http(s) URLs) and the known
  `*_supported` string lists are kept, each truncated.
- No secret values (Values policy). The recorder's existing redaction and
  R4 stripping are unchanged.
- No bot-protection evasion; passwords/CAPTCHAs stay human.

## Verification

- **Unit (pure logic):** role classifier (each role, common IdP paths for
  Entra ID/Okta/Auth0/Keycloak/Google/Cognito, negatives such as `/author`
  and `/blog/authorize-payments`); allow-list extraction never returns a
  forbidden value; strength classes; flow key; repeat comparison;
  discovery parsing (bad JSON, huge doc, non-URL endpoints, out-of-scope
  endpoints); each candidate rule positive and negative; SSO battery rule;
  `form_unsafe_reason` SSO refusal.
- **Black-box on the local fixture** (`tests/fixtures/ui_walk_target/
  ui_walk_app.py` gains a fake IdP at `/idp/*` and an RP flow at `/sso/*`;
  `alt_base_url` (localhost) serves the IdP and the test's `scope_check`
  makes it in or out of scope; the fixture logs the Host header per request).
  Vulnerable vs patched:
  - static `state` (same every request) vs random per request;
  - `response_type=id_token token` without `nonce` vs code flow with `nonce`;
  - no PKCE vs `S256`;
  - logout accepting any `post_logout_redirect_uri` (the candidate is about
    the param, so both variants make it, and the patched one has an
    allow-list for spec 3 to find) — asserted only that the logout endpoint
    is never requested;
  - `registration_endpoint` in discovery (vulnerable) vs absent (patched);
  - callback echoing `state` (with a fixture IdP session cookie the IdP
    auto-bounces to the callback).
  Assertions: nodes and candidates as expected per variant; the login form
  is mapped, never filled, its POST aborted; Pass 1 sends zero non-GETs;
  logout never requested; with the IdP out of scope: exactly the followed
  GET(s) reach the alt host, no discovery/repeat/click there, no IdP nodes,
  `out_of_scope_idp_redirects` recorded; the fixture's `state`/`nonce`/`code`
  values (known to the test) appear nowhere in the inventory file, the tool
  output or the audit log.
- **Pass 2:** a canary walk never submits the IdP login form.
- **Prove it runs:** real `mcp__browser-mcp__start_ui_walk` /
  `check_ui_walk` against the fixture on the throwaway engagement
  `ui-walk-proof-localhost` (switch with
  `scripts/switch-engagement.sh set ui-walk-proof.localhost --force`,
  switch back to `bentley.com` afterwards, asking the user first). Never
  against `bentley-com`.

## Decisions settled after builder check (author's calls)

1. **Secret params are redacted in every stored URL, not only in new SSO
   fields.** Today `pages[].url`, `controls[].href`, `api_edges[].url`,
   `get_log`, surface-map `meta.endpoint` and node labels keep full query
   strings, so a callback `?code=…` or an `href` with `state` baked in would
   be stored. A single `redact_sso_params(url)` helper replaces the
   **value** of every deny-listed parameter (the "never stored" list in the
   Values policy, in query and fragment, case-insensitive names) with
   `REDACTED`, keeping the name. Applied to every URL the walker writes to
   the inventory or the surface map, whatever its role. The real URL lives
   only in memory (queue, navigation). Field names and meaning stay the
   same, only those values change. This is the user's standing rule ("no
   secret values stored"), so it is not treated as a silent contract change.
2. **Callback and SAML-ACS URLs are never re-requested.** A URL that
   carries `code`, `id_token`, `access_token` or `SAMLResponse` (query or
   fragment) is never enqueued, never the target of the click loop's
   back-navigation, and never a repeat source. Replaying a used code is a
   state-changing GET (RFC 6749: reuse may revoke tokens, which can kill the
   session). A callback is recorded as an `action` node, never as a `page`.
   If the page being mapped was reached through a callback, back-navigation
   uses the URL the callback finally landed on (the app page), never the
   callback itself.
3. **What counts as an IdP page (Goal 2):** an in-scope page reached
   through a navigation chain that contained an `authorize` or
   `saml-request` hop, or any in-scope page on a host recorded as an IdP host
   in this walk (an authorize/saml hop or discovery issuer was seen there).
   The app's own local password login, with no such hop, stays as today
   (`login-required`, not mapped). An IdP on the same host as the app is
   told apart by the chain, not the host.
4. **`same_origin_only` and IdP hosts:** an in-scope IdP host recorded in
   this walk is allowed past `same_origin_only` for links found **on IdP
   pages** (forgot-password, sign-up, other login options), at most 10 pages
   per IdP host. Those are GETs, mapped under the normal Pass 1 rules.
   App-page links to that host are enqueued the same way, not recorded as
   `out-of-scope` skips. Social-login buttons to out-of-scope providers stay
   recorded-only.
5. **Repeat path (a) never touches the walk's cookies.** It uses a separate
   `request` context seeded with a copy of the walk's cookies; any
   `Set-Cookie` it receives is discarded with the context. The walk's
   session and any half-done bounce are unaffected.
6. **Every in-scope SSO endpoint becomes a node**, including `userinfo`,
   `jwks`, `introspection` and `discovery`. The method in a
   discovery-only signature is the protocol's: `POST` for `token`,
   `revocation`, `introspection`, `registration`, `device_authorization`;
   `GET` for the rest. It equals what an observed edge would get, so
   `add_node` dedups them. `jwks`, `userinfo` and `discovery` get `auth`
   only (no `open-redirect`/`csrf`).
7. **Repeat and discovery run in map walks only.** A canary (Pass 2) walk
   still recognises SSO hops and records flags passively, but does not
   repeat or fetch discovery, so its budget and tests stay as they are.

## Left to the builder

- Exact path/keyword lists for roles and SSO page roles, the strength
  thresholds' fine print, caps beyond those stated, field names inside
  `inv.sso`, how `_format_walk` lays out the SSO section.
- How the `SsoTracker` is split between `ui_walk.py` and the logic module.
- Fixture internals.
