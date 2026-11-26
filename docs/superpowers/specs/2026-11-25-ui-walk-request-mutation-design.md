# UI-walk: Burp-style parameter + request mutation — Design (spec 3 of 3)

Date: 2026-11-25
Status: Approved (2026-11-25)
Size: Project, shipped in three parts — **3a → 3b → 3c** — each with its own
plan, review-and-audit, runtime proof and PR.
Builds on: #164 UI-walk (`2026-11-19-page-comprehension-ui-walk-design.md`),
spec 1 event recorder (`2026-11-20-ui-walk-event-recorder-design.md`),
spec 2 SSO surface (`2026-11-22-ui-walk-sso-surface-design.md`).

## Intent and the why

Authorized bug-bounty tooling. Today the walk records every UI→API request but
only by its shape (method, URL, body field names, per spec 1/2). Nothing
tampers with the recorded requests. The access-control, API and request-level
bug classes the repo skills already describe (access-control-and-idor,
api-security-top10, low-hanging-fruit, infrastructure-and-protocol,
request-smuggling) all live at the request level and are never exercised by
the walker.

The user wants the walker to look at each recorded request, understand it, and
apply careful request-level checks — parameter add/remove/duplicate/retype
plus whole-request variants (routing headers, method/content-type switch, path
and cache-key tricks, GraphQL batching, races, and a safe smuggling detector).
Explicitly: the variant set must be **chosen per request**, not a fixed list.

Success: for every in-scope request the walk recorded, HuntMCP builds a
variant plan that fits that request, the agent may add its own variants, the
tool sends them under the existing safety rules, compares each against a
baseline, restores the test account's own state afterwards, and hands
exploit-agent evidence-backed **candidates**. Nothing is auto-confirmed.

## Scope split

- **3a — parameter-level.** Per-parameter add / remove / duplicate / retype,
  numeric edges, nested JSON, and the deferred `?query` DOM-XSS source.
- **3b — request-level.** Routing/authz headers, method override,
  content-type switch, path + cache-key tricks, GraphQL alias/batch, and races.
- **3c — request smuggling.** Timing-only desync detection over HTTP/1.1, raw
  socket, grant-gated. No cross-user exploitation; that stays manual.

Each part is its own branch, review-and-audit, runtime proof and PR. 3c's
sender and risk profile differ from 3a/3b (raw socket vs browser request
context), so it is reviewed on its own.

## Approaches considered (how the variants are chosen)

| | Approach | Trade-off | Verdict |
|---|---|---|---|
| A | Pure code rules only | Cheap, deterministic, testable; blind to any pattern not pre-written | Half of chosen |
| B | An LLM inside the tool builds variants | Most flexible; costly, non-deterministic, sends target text to a model (injection risk), safety would depend on the model | Rejected |
| **C** | **Code builds a ranked, request-specific plan; the agent (exploit-agent) may add/drop variants; the tool enforces every safety rule on each variant** | Rules guarantee the basics never get skipped; the agent adds judgement per request; safety stays in code, never in the model; target text stays quarantined | **User-picked (2026-11-25)** |

So the "per-request brain" is: the tool profiles each request and emits a
ranked plan with a reason per variant; the agent reads the plan and may extend
it in a fixed, validated vocabulary; the tool runs what passes the gates.

## User decisions (binding)

1. 3a / 3b / 3c split, one PR each, in order. (2026-11-25)
2. Approach C. (2026-11-25)
3. Mutated **GET** variants may be sent **without** the Pass-2 grant — still
   under scope, budget, the payment-host block and the mutating-keyword GET
   block. (spec 1 ruling, carried here.)
4. Non-GET variants (and races) are sent **only** under the existing
   human-written Pass-2 grant file, within its caps, and **only** against
   walker-owned objects. In Pass 1 they are generated and recorded, never sent.
5. **Ownership is widened for grant mode:** the test identity's **own**
   account surface (profile / settings / "me") counts as walker-owned, so
   mass-assignment on the real high-value target can be tested. (2026-11-25)
6. **Restore is mandatory:** after any accepted state-changing variant on an
   owned object (including the own-account surface), the tool replays the
   original recorded request to put the field back, and records whether the
   restore succeeded. (2026-11-25)
7. Smuggling is included but as **timing detection only**, raw-socket,
   grant-gated, no new dependency; HTTP/2 smuggling is out until the user
   approves an `h2` dependency. (2026-11-25)
8. `?query` DOM-XSS source (planting a canary in the query string) is done
   here, reusing spec 1's sink hooks in `ui_walk_events.py`. (carried from
   spec 1.)
9. Secret values are never stored. Mutation needs the real recorded values to
   replay; they live only where decided below, never in output or inventory.

## Goals

1. **Replay store (3a).** While walking, the walker keeps the real request of
   every in-scope UI→API edge (sent GETs, Pass-1-aborted non-GETs, Pass-2 real
   submits) and writes it to a 0600 file next to the inventory. See Values
   policy for what is withheld. Inventory `api_edges[]` gain a `replay_id`.
2. **Request profile + ranked plan (3a, extended in 3b/3c).** A pure-logic
   profiler reads each stored request and the walk's other data (responses of
   related GETs, other requests' fields, events, SSO roles) and decides which
   variant families fit *this* request and why. It emits a ranked plan, one
   line per variant with a reason ("`role` is in GET /api/me's response but
   never sent by the UI"; "`otp` looks like a verification field"; "response
   has `Age`/`X-Cache` headers, so cache-key checks apply").
3. **Agent extension (approach C).** The agent may add, drop or re-rank
   variants using a fixed op vocabulary (below). Every variant, built-in or
   agent-added, passes the same code gates before it is sent.
4. **Send + compare.** Each request first gets a **baseline**, sent twice so
   volatile fields (timestamps, nonces, request ids) can be masked, reusing
   `authz_diff`'s JSON-leaf and volatile-mask logic. Then every variant is sent
   and compared: status class, length delta beyond noise, JSON key set,
   reflection of the injected value, error signatures, and for state-changing
   variants a **read-back** (re-GET the object's read endpoint) to see whether
   the change persisted.
5. **Restore (decision 6).** A state-changing variant that persisted (or whose
   read-back is unknown) is followed by the restore request, then a read-back.
   Restore failure stops the run for that object with a loud
   `RESTORE FAILED` status naming the endpoint and field (never the value).
6. **Candidates** (leads, never confirmed), each with redacted evidence
   (variant spec, baseline vs variant status/length/key diff, short redacted
   response excerpts, read-back result). Types listed per part below.
7. **Agent prompts**: exploit-agent (and huntbrain's flow) run
   `plan_mutations` → review/extend → `run_mutations` → work the candidates with
   the matching skills.

## The variant catalogue (what the profiler can choose from)

The profiler picks from these families **only when the request's profile makes
them meaningful**; the reason is recorded. Per-request and per-run caps apply
(see Safety). Built-in lists below are seeds, not a fixed run list.

### 3a — parameter level (query, form, JSON incl. nested, multipart field names)

- **add** (mass assignment). Names ranked: (1) fields seen in a response of the
  same resource or a related GET (`/api/me`, the listing) but never sent by the
  UI; (2) field names other requests send for the same resource; (3) a short
  curated privilege list (`role`, `roles`, `admin`, `is_admin`, `isAdmin`,
  `permissions`, `user_id`/`userId`/`owner_id`/`account_id`, `email_verified`,
  `verified`, `status`, `plan`, `tier`, `price`, `amount`, `discount`,
  `credits`, `balance`). Values typed to look plausible (bool `true`,
  `"admin"`, numbers). Foreign ids: see Ownership.
- **remove** (missing-check bypass). Fields that look like checks — `otp`,
  `code`, `mfa`, `totp`, `captcha`, `csrf`/`_token`/`xsrf`, `old_password`/
  `current_password`, `signature`/`sig`/`hmac`, `nonce` — removed one at a time;
  also "empty value" and "key present, value null" forms.
- **duplicate** (HPP). Query/form `a=1&a=2` in both orders, `a[]=`, JSON
  duplicate keys (raw body string), mixed query+body copies of the same name.
- **retype** (type juggling). string → number / array / object / null / bool;
  `"0e1"`-style strings; `password[]=` form; number → string.
- **numeric edges** for numeric-looking fields: `-1`, `0`, `0.0001`, `1e9`,
  `2147483648`, `9007199254740993`, `-0`, `"1 "`.
- **`?query` DOM-XSS source.** For every mapped page whose URL has query
  params, navigate (browser, not request context) with a canary in each param
  value, one at a time; spec 1's sink hooks record `dom_sink`; execution of the
  payload form → `dom-xss-candidate`, sink only → `dom-sink-candidate`
  (existing types, `source: "query"`). This is a GET to the server, so no grant
  is needed.

3a candidates: `mass-assignment-candidate` (with `persisted: true/false/
unknown`), `param-removal-bypass-candidate`, `hpp-candidate`,
`type-juggling-candidate`, `numeric-edge-candidate`, plus the DOM types.

### 3b — request level

- **Routing / authz headers**, one at a time: `X-Forwarded-For`, `X-Real-IP`,
  `X-Client-IP`, `True-Client-IP`, `Forwarded` (all `127.0.0.1`),
  `X-Original-URL` / `X-Rewrite-URL` (path of a 401/403/404 route seen in the
  walk), `X-Forwarded-Host`, `X-Forwarded-Proto`/`-Scheme`, `X-Host`.
  Reuses waf-bypass-mcp's tier-1 header list as data (import of the pure
  builder only; its tier-3 method list is NOT reused because it sends
  non-GETs). Chosen when a baseline is 401/403, a page is admin-ish, or the
  response shows a proxy/CDN.
- **Method override**: `X-HTTP-Method-Override` / `X-HTTP-Method` /
  `X-Method-Override` / `_method=`; GET↔POST/HEAD swap. The **effective**
  method (see Safety) decides grant need.
- **Content-type switch**: JSON ↔ form ↔ `text/plain` ↔ XML for the same
  fields; chosen for JSON endpoints (CSRF / mass-assignment parser paths).
- **JSON parser differentials**: duplicate keys with differing values, unicode
  escaped key names (`"role"`), comments/trailing commas, big numbers.
- **Path / encoding**: trailing `/`, `/.`, `;.css`, `%2f`, case change,
  double-encoding, overlong-dot segments — reusing waf-bypass tier-2 builders.
- **Cache-key confusion**: only when the response shows caching
  (`Age`, `X-Cache`, `CF-Cache-Status`, `Cache-Control: public`, `Via`). Every
  cache variant carries a unique cache-buster query param (`hmcb=<token>`), so a
  poisoned entry can only ever live at a URL no real user requests. Detection:
  send the header variant on the buster URL, then fetch the same buster URL
  without the header; injected value served back → candidate. Also web cache
  deception (`/<authed-page>/x.css`) with a buster.
- **GraphQL alias / batch** when a request is GraphQL: aliased duplicate of the
  recorded query (`a1: q … a2: q …`, bounded to 5), array batch of 2–5. Queries
  only without grant; mutations only under grant on owned objects.
- **Race** (grant + owned only): N parallel copies (default 5, max 10) of an
  owned non-GET via the request context; compare end state by read-back.
  Honest limit: no single-packet sync (needs HTTP/2 or raw sockets); 3c may add
  HTTP/1.1 last-byte sync later.

3b candidates: `header-authz-bypass-candidate`, `method-override-candidate`,
`content-type-confusion-candidate`, `json-parser-differential-candidate`,
`path-normalization-candidate`, `cache-poisoning-candidate`,
`cache-deception-candidate`, `graphql-batching-candidate`, `race-candidate`.

### 3c — request smuggling (timing detection only)

- Gate: the existing Pass-2 grant for the host (decision 8 below).
- Hosts: in-scope hosts of recorded requests only, at most 3 per run.
- Sender: stdlib `socket`/`ssl`, HTTP/1.1, one connection at a time, its own
  connection per probe (never reused), short fixed timeouts.
- Probes, in PortSwigger's safe order: **CL.TE timing** first; **TE.CL timing
  only if CL.TE is negative** (a TE.CL probe against a CL.TE stack can poison
  the next request); a few TE-obfuscation variants (`Transfer-Encoding : chunked`,
  `xchunked`, tab, duplicate TE). Each positive repeated once to confirm;
  timing compared against a normal-request baseline.
- Result: `smuggling-candidate` with the probe type and timings. Anything
  beyond detection (capturing another user's request, response queue
  poisoning) is manual and never done by the tool.
- Not built: HTTP/2 (H2.CL/H2.TE) — needs the `h2` dependency the user has not
  approved.

## Tools (browser-mcp, no new server)

- `plan_mutations(walk_id, request_filter="", max_requests=50)` — no traffic.
  Reads the inventory + replay store, returns `plan_id` and the ranked plan per
  request (variant id, family, the change described by field name / header
  name, reason, whether it needs the grant, and whether it would be sent or
  only recorded). Target text quarantined, provenance line last.
- `run_mutations(plan_id, session_file="", identity_label="", variants="auto",
  extra_variants=None, drop_variants=None, upstream_proxy="")` — background job
  (`job_runtime.start_thread_job`); `variants="auto"` = the plan's top variants
  within caps; `extra_variants` = the agent's additions (op vocabulary below).
- `check_mutations(job_id)` / `list_mutation_runs()` — same shape as
  `check_ui_walk`.

**Agent op vocabulary** (each item: `request_id` + op): `add_param`,
`remove_param`, `duplicate_param`, `retype_param`, `set_param` (name, value),
`set_header` / `remove_header`, `method` (incl. override form),
`content_type`, `path` (transform name from a fixed list, or a literal path on
the same host), `graphql_batch`. Validation in code: value length ≤ 2 KB; no
CR/LF/NUL anywhere in header names/values or paths; host can never change;
`Host`, `Cookie`, `Authorization`, `Proxy-*`, `Content-Length`,
`Transfer-Encoding` cannot be set (credentials come only from `session_file`;
framing headers only in 3c's own code); every variant then passes the
send-gates below exactly like a built-in one.

## Sending

- One Playwright browser context per run, opened from `session_file` (same
  helpers as the walker, incl. keep-alive-compatible session handling). Request
  variants go through `context.request` (shares the cookie jar; raw string
  bodies allow duplicate JSON keys). The `?query` DOM source uses a real page.
- Burp mirror: same resolution as the walk (`upstream_proxy`, env, auto-detect),
  loopback only, applied to the context and its request object.
- 3c uses its own stdlib socket sender and never the browser.

## Safety & constraints (all #164 properties kept)

- **Scope** checked in code on every variant URL (and every 3c host) before
  sending; the host is fixed to the recorded request's host.
- **Payment hosts** never sent to, any method. Requests recorded on payment
  pages / checkout flows are planned but only GET variants are sent.
- **Effective method** = the method after any override header / `_method` /
  content-type trick. A GET carrying `_method=DELETE` or `X-HTTP-Method-
  Override: PUT` is treated as that non-GET. A GET whose final URL matches the
  mutating-keyword list is never sent (same `is_mutating_get_url`).
- **Non-GET variants** (and GraphQL mutations and races): only when
  `ui_walk_grant.grant_allows(host)` and the target is **owned** (below);
  counted against the grant's `real_submit_cap_per_walk` (restore requests use
  a reserved share so a restore is never starved by the cap). No grant → the
  variant is in the plan with `would_send: false, reason: "needs grant"`.
- **Never mutated:** logout / account-delete / payment-classified requests, SSO
  endpoint roles (spec 2 hands those to exploit-agent), and the teardown's own
  requests.
- **Budget**: `budget_guard.enforce` per sent request (baseline, variant,
  read-back, restore, 3c probe). Per-run caps: 400 sent requests, 40 variants
  per request, 10 per family per request (defaults; lower via args). Engagement
  rate delay between sends.
- **Block signals**: a 429, or `tool_resolver.classify_block` = waf / rate
  limit on a variant → stop all variants for that host, status `blocked`.
  Nothing tries to get past bot protection, CAPTCHAs or TLS fingerprinting.
- **Quarantine / provenance**: all target text in tool output quarantined;
  provenance line last.
- **Pass 1 unchanged**: the walk itself still sends nothing state-changing;
  the replay store only records.

## Ownership (for non-GET variants)

A non-GET variant targets an owned object only if one holds:
1. **Walker-created** (existing #164 rule): an id from a walker create
   response appears in the request path/query/body, or the object's container
   carries a walker canary.
2. **Own account (decision 5)**: the request path is an own-account route with
   no foreign id (`/me`, `/profile`, `/account`, `/settings`, `/user/settings`,
   `/preferences`, …, matched as path segments), **or** it carries the
   identity's own user id learned in memory from a `/me`-like GET response
   during the walk (stored in the replay store as `self_ids`).
Anything else → planned, recorded `not-owned`, never sent.

**Foreign ids in variants:** a GET variant may carry another object id seen in
the walk (read-only IDOR-style lead). A non-GET variant may only carry the id
of the **second test identity** from the roster (both are the hunter's own
accounts); never an id the walk saw on a non-owned object.

## Restore (decision 6)

- Before the first state-changing variant on an object, a **snapshot read**:
  the GET that returns the object (own-account: the `/me`-like GET; created
  object: its detail GET). Kept in memory for the run only.
- After a variant: read-back. Changed (or unknown) → **restore** = the
  original recorded request with the snapshot's values for the touched
  field(s), then read-back again. Recorded per variant: `restore: ok / failed /
  not-needed / unknown`.
- `failed` → no more state-changing variants on that object, run status
  `restore_failed` printed first in `check_mutations`, naming endpoint + field.
- A role/permission change that persisted is restored **before** any further
  variant runs (so later results are not measured as a different user).

## Values policy (replay store)

- File: `data/engagements/<slug>/ui-walk/<walk-id>.replay.json`, 0600, atomic
  write, via `engagement_paths`. Never printed by any tool; inventory and tool
  output carry only `replay_id`s and field names.
- **Never stored:** `Cookie`, `Authorization`, `Proxy-Authorization` headers
  (credentials come from `session_file` at run time); values of fields/headers
  whose name looks like a password, OTP/MFA code, card/CVV, or secret/API key
  (same heuristic family as `redact.py` / spec 1's auth-ish names) — replaced by
  a placeholder and listed in `withheld_fields`. Variants that would need a
  withheld value are skipped (the `remove` variant still runs, since it needs
  no value).
- **Stored:** method, full URL, other headers (incl. CSRF header/field values,
  which replay needs and which expire), raw body capped at 64 KB, source
  (`pass1-aborted` / `pass2-sent` / `get-sent`), `self_ids`.
- Results file (`<walk-id>.mutations-<run-id>.json`) holds variant specs
  (injected values are ours), field names, diffs and **redacted, truncated**
  response excerpts; never original recorded values.
- `run_teardown`'s cleanup step deletes the walk's replay stores.
- Honest limit: the replay store sits on disk like `session_file`; anything
  with the user's file access can read it.

## Fixture + tests (TDD)

`tests/fixtures/ui_walk_target/ui_walk_app.py` gains, each with a vulnerable
and a patched mode:
- 3a: mass-assignable `PUT /api/profile` (vulnerable persists `role`, visible
  in `GET /api/me`; patched ignores unknown fields); HPP-confused
  `GET /api/transfer-preview?to=..&to=..` (validates first, acts on last vs
  rejects duplicates); removable-OTP `POST /api/change-email` (missing `otp`
  skips the check vs required); a type-juggling login-ish compare; a page that
  writes a query param into `innerHTML` (vs `textContent`).
- 3b: `X-Original-URL` admin route; `_method` override; a JSON endpoint that
  also parses form; a cached page reflecting `X-Forwarded-Host`; a GraphQL
  endpoint without alias limits; a race-able redeem on a walker-owned coupon.
- 3c: a tiny stdlib CL.TE-desynced front proxy in front of the fixture vs a
  normalising one.
Assertions: candidates only on vulnerable modes; zero non-GET without grant;
non-GET only on owned objects; restore leaves the profile as it was; no
withheld/recorded value in any output, inventory, results file or audit log
(grep for fixture secrets); cache variants always carry the buster; caps and
block stop honoured.

## Non-goals

- Exploiting smuggling, poisoning a real cache key, or anything that can affect
  another user.
- HTTP/2 smuggling (needs `h2`).
- Bypassing bot protection, CAPTCHA, TLS fingerprinting.
- An LLM inside the tool.
- Fuzzing values with big payload lists (sqli/xss lists stay with
  sqlmap/dalfox); this is structure tampering, not payload spraying.
- Mutating SSO endpoints (spec 2 queues them; exploit-agent does them).

## Anti-goals

- Any non-GET variant sent without the grant, or to a non-owned object.
- A test-account change left un-restored without a loud status.
- A recorded secret value in output, inventory, results, logs or surface map.
- A cache variant without the buster.
- A smuggling probe that reuses a connection or runs TE.CL before CL.TE.
- A #164 / spec 1 / spec 2 contract changing silently.

## Decisions settled after builder check (author's calls)

1. **Objects created by mutation runs.** Every id returned by a non-GET sent
   in a run (baseline, variant, race) is registered walker-owned
   (`ui_walk_store.register_created_id`), listed in the results file, and
   deleted by `run_teardown`'s cleanup step like any canary object. Races on
   a create endpoint are capped at 3 copies. Nothing is left behind silently.
2. **Non-GET baseline = a real submit.** It needs the grant and ownership like
   any variant, is sent **once**, and counts against the cap. The noise mask
   for non-GETs comes from the snapshot GET sent twice (GET baselines are sent
   twice as stated).
3. **Cap is cumulative per walk.** `real_submit_cap_per_walk` covers the walk's
   own Pass-2 submits **plus every `run_mutations` on that `walk_id`**, kept in
   a persisted counter (`<walk-id>.sendcount.json`, file-locked). Calling
   `run_mutations` again does not reset it. 10% of the cap (at least 5) is
   reserved for restores and is only usable by restore requests.
4. **Own account is narrow.** A route counts as own-account only if (a) it
   matches the own-account path list, (b) it has **no** object/container id
   segment and no `org`/`team`/`workspace`/`tenant`/`project`/`group`/
   `company` segment, **and** (c) its snapshot GET's response contains one of
   the walking identity's `self_ids`. Anything else is `not-owned`.
5. **No foreign ids in non-GET variants at all.** Foreign object ids only
   appear in GET variants (read-only leads). Cross-account checks stay with
   `idor-mcp` and two identities. (Replaces the earlier "second identity id"
   idea, so no second session and no second restore path is needed.)
6. **No restore path → no send.** If no snapshot GET is found for an object,
   its state-changing variants are planned but not sent
   (`would_send: false, reason: "no restore path"`). Restore is a hard
   precondition, not best-effort.
7. **Same identity only.** The replay store records the walking identity
   (roster label + a session fingerprint that is not a secret, e.g. the
   `self_ids` set). `run_mutations` refuses a different identity; GET-only
   runs as another identity are also refused, to keep evidence unambiguous.

8. **3c gate (USER DECISION, 2026-11-25): the same grant.** Smuggling probes
   run only when the existing `canary_submit: true` grant allows the host
   (`grant_allows`, incl. its optional `hosts` subset). No new grant field, so
   the protected `ui_walk_grant.py` and the grant file format stay unchanged.
   Each 3c probe also counts against the cumulative per-walk cap (decision 3).

## Left to the builder

- Exact ranking weights, cap numbers within the stated maxima, noise threshold
  for length deltas, op-vocabulary JSON field names, results-file layout,
  own-account path list details, fixture internals.
