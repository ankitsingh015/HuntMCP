# Page Comprehension — UI-walk, canary submit, teardown — Design

Date: 2026-11-19
Status: Approved (2026-11-19)
Size: Project
Issue: #164 (builds on #159 coverage manifest + #161 surface-map; feeds #163 flow harness)

## Intent and the why

Agents test at the URL/link/param level (katana links → curl/httpx → param
fuzz) and never comprehend the rendered **page**: which forms, inputs, buttons,
modals and lazy-loaded embeds it really has, which API call each UI action
fires, and where user-controlled values render back (stored-XSS surface).
Observed live on bentley-com: e.g. `www.bentley.com/en/contact/` is a
lazy-loaded third-party Marketo form, invisible to link crawling.

The **unit of testing becomes the page + its inputs + its actions**, not the
URL. Success = the agent cannot declare a surface exhausted while a rendered
page's inputs/actions are untested, and the high-yield UI-only bug classes
(stored XSS in rendered values, broken delete, cancel-without-revoke, delete
IDOR, logout/account-deletion session survival) are exercised with evidence.

User's stated priority: best performance and highest real-bug yield, without
losing test data/session mid-engagement or breaking programme rules.

## Goals

1. **Pass 1 — Map (always on, safe).** Render each in-scope page, expand every
   tab/menu/accordion/modal, click every control; any non-GET request a click
   would send is **intercepted and not sent**, but recorded (method, URL, body
   shape). Output: per-page inventory + UI→API map + surface-map nodes per
   page/input/action.
2. **Pass 2 — Canary submit (human grants once per engagement).** Fill every
   text input with a unique tagged canary, really submit as the test account,
   then re-walk and detect where each canary renders and whether it executes.
3. **Create → destroy → verify** for every delete/remove/revoke/cancel control,
   only on objects the walker itself created (canary-tagged).
4. **Teardown phase (last step, human-gated).** Cleanup of all walker-created
   objects + logout-invalidation test + account-deletion test.
5. **Viewable screenshots** (file the agent can `Read` as an image).
6. **Authenticated SPAs actually render** (sessionStorage persisted/restored;
   auth-lost detected loudly).
7. **Page-first methodology** in agent prompts + coverage gate counts the new
   node kinds.

## Non-goals

- Autonomous real payments — ever. Payment flows are map-only (see Safety).
- Auto-running teardown when agents finish.
- A bentley-specific token refresher in-repo (the existing
  `~/.config/huntmcp/refresh_bentley_tokens.py` stays out-of-repo; the repo
  gains only the generic seeding/persistence it needs).
- Generic vision/LLM interpretation of screenshots inside the tool — the
  agent itself looks at the saved image.
- New Python dependencies (no Pillow; Playwright already does JPEG + clip).

## Anti-goals (failure even if it "works")

- Walker deletes/modifies data it did not create, or sends a canary/non-GET to
  an out-of-scope host.
- Walker silently maps the logged-out shell and reports it as the
  authenticated surface.
- Walker floods the target (bypasses budget_guard / rate limits) or runs
  unbounded.
- A capability that exists today (render_dom, extract_page_content,
  fill_and_submit, screenshot, session_file semantics, provenance lines,
  quarantine) is dropped or changes contract silently.

## Approaches considered

| | Approach | Trade-off | Verdict |
|---|---|---|---|
| A | Look-only: render + enumerate, click nothing | Zero risk; misses everything behind a click | Rejected — misses the gap #164 is about |
| B | Safe clicks only, non-GET intercepted | Full UI→API map, zero state change; never finds stored XSS / delete bugs | Becomes **Pass 1** |
| C | Click-and-send everything | Max coverage; destroys test data/session, sends mail, breaks programme rules, low yield (random data rarely finds bugs) | Rejected as-is (user initially picked C) |
| **Chosen** | **Pass 1 (B) + Pass 2 canary submit with create→destroy→verify + human-gated Teardown** | Keeps C's coverage, adds deliberate high-yield payloads, defers irreversible tests (logout/account-delete) to the end instead of skipping them | **User-approved** |

User decisions recorded in conversation: two-pass; delete flows must be
tested (not skipped) via create→destroy→verify; logout/account-deletion moved
to a final, doable teardown phase that also cleans up (stops mail); payment
stays map-only.

## Design

### Components (all inside existing servers; no new MCP server)

1. `mcp-servers/browser-mcp/ui_walk.py` — the walker.
   - **Pure logic** (unit-testable, no browser): control classification
     (`navigational` / `expand` / `submit` / `destructive` / `logout` /
     `account-delete` / `payment`) from role, text, aria-label, href, form
     action, keyword lists; control dedup signature (role + normalized text +
     form action + DOM-path-without-indices, so the same "Edit" across 50 rows
     is clicked once); canary generation; canary-registry I/O.
   - **Driver** (Playwright): reuses `browser_confirm._new_page`,
     `_launch_kwargs`, `_save_session`, `_enforce_budget`, `_log_call`.
2. `browser-mcp/server.py` new tools:
   - `start_ui_walk(url, mode="map"|"canary", session_file="", max_pages=50,
     max_clicks_per_page=40, same_origin_only=True)` → job id (uses
     `job_runtime.start_thread_job`; walks exceed MCP per-call timeouts).
   - `check_ui_walk(job_id)` / `list_ui_walks()` (same shape as other
     `check_scan`/`list_scans` tools).
   - `run_teardown(session_file, identity_label, base_url)` — gated (below).
   - `screenshot(...)` gains file output (below); existing params unchanged.
3. `surface_map.py` / `coverage_manifest.py`: new node kinds `page`, `input`,
   `action` + their battery.
4. Agent prompts: recon-agent, scan-agent, exploit-agent, huntbrain.
5. `scripts/confirm-teardown.sh` — human confirmation, reusing
   `capture_confirm.write_confirmation/verify_confirmation`.

### Pass 1 — Map

Per page (BFS from `url`, in-scope + `same_origin_only` navigations, up to
`max_pages`):

1. Navigate; wait for network-idle (bounded); detect **auth-lost** (redirect
   to a login URL, or a visible login/sign-in control when the walk was
   started with a session) → stop the walk with `AUTH LOST` status, never
   continue mapping the logged-out shell.
2. Enumerate inputs/forms/controls across the main frame, **same-origin and
   third-party iframes** (Marketo case) and open shadow roots. Record per input:
   name/id/type/label/placeholder/required/form-action/method/frame-origin.
3. Expand: click `expand`/`navigational`-in-page controls (tabs, menus,
   accordions, modal openers), re-enumerate after each — new inputs revealed
   by a click are attributed to that click.
4. Click every remaining control (deduped). `page.route("**/*")` intercepts:
   - non-GET/HEAD/OPTIONS → **abort**, record `{method, url, headers-shape,
     body (redacted, truncated)}` as a UI→API edge "control X → POST /y".
   - top-level navigation to an out-of-scope host → abort, record.
   - subresource GETs (scripts/css/img) to third parties → allowed (normal
     page rendering), host recorded.
   - Controls classified `logout`/`account-delete`/`payment` are **never
     clicked** in Pass 1 or 2 (also covers GET-based `/logout`); their target
     is recorded from attributes only.
5. Record XHR/fetch GETs fired by load/clicks (UI→API GET edges).
6. One viewport screenshot per page saved (file path in inventory).

Output: inventory JSON at `data/engagements/<slug>/ui-walk/<walk-id>.json`
(via `engagement_paths.resolve_dir`) + a compact text summary returned by
`check_ui_walk` (pages, inputs, actions, intercepted non-GET edges, auth
status). Target text in the summary is quarantined (`injection_boundary`).

Surface-map nodes (via `surface_map.add_node`, dedup on signature):
- `page` — signature `page:<normalized-route-template>` (reuse
  `endpoint_template.py` for `/items/123` → `/items/{id}`).
- `input` — child of page, signature `input:<form-action>:<field-name>`.
- `action` — child of page, one per state-changing control, signature
  `action:<METHOD> <api-route-template>`; meta records classification
  (`destructive` etc.) and the triggering control.

### Pass 2 — Canary submit (human-granted once per engagement)

Switch: the human-owned, hook-protected
`data/engagements/<slug>/ui-walk-authorized.yaml` (see decision 3 below);
`mode="canary"` refused when absent/false. Programmes that forbid real
submits simply never get that file.

1. Canary per input: `hm<8 hex>` token; text fields get
   `hm7f3a"'><img src=x onerror=alert('hm7f3a')>`-style payload (token is the
   `check_js_execution` marker); length-limited/typed fields (email, number,
   url) get a type-valid value embedding the token where possible. Registry
   `ui-walk/canaries.json`: token → {page, input, submitted request, time}.
2. Submit forms / click `submit` controls for real — **only** non-GETs to
   in-scope hosts and never to payment providers; still subject to budget +
   engagement rate limit.
3. Re-walk (Pass-1 style) all mapped pages + any page the submit landed on;
   every occurrence of any registered token on any page → **render sink**
   record {token origin page/input → sink page, raw vs rendered, executed?}.
   Execution confirmed via existing `check_js_execution` logic (dialog/title);
   cross-page sinks (submitted on A, renders on B) are explicitly reported.
   Findings are **candidates** for exploit-agent, not auto-confirmed bugs.

### Create → destroy → verify

For each `destructive` control (delete/remove/revoke/cancel/unshare/…):

1. **Ownership rule (hard):** a destructive click is permitted only when the
   control's nearest repeating container / detail view contains a walker
   canary token — i.e. the object was created by this walker. Otherwise the
   control stays map-only.
2. If no owned instance exists, the walker creates one via the mapped create
   flow (Pass 2 submit) first.
3. Before deleting: snapshot the object's reach-paths seen during the walk —
   GETs whose URL or response contains the object id/token (detail API, file/
   CDN URL, share/invite link, listing/search/export entries).
4. Delete through the real UI control.
5. Re-request every reach-path with the same session → **broken-delete
   candidate** if still 200 with the canary content; listing/search still
   showing it → **leftover candidate**.
6. Emit for exploit-agent (not run by the walker): the recorded delete request
   as a **delete-IDOR candidate** for `idor-mcp replay_authz_matrix` with
   account B against a fresh A object; revoke/cancel controls as
   **cancel-without-revoke candidates** (replay the revoked link/key/invite).

### Teardown (final step, human-gated)

`run_teardown` refuses unless a fresh confirmation exists from
`scripts/confirm-teardown.sh <slug> <identity>` (human runs it in their own
terminal, TTL as `capture_confirm`). Huntbrain never runs the script and never
calls teardown on its own; report-agent prompts the human that teardown is
available once reports are drafted (human ideally waits until after triage, so
findings stay reproducible).

Order:
1. **Cleanup** — destroy every canary-owned object still present (each runs the
   create→destroy→verify checks), remove walker-created invites/members.
2. **Logout test** — snapshot cookies/storage/bearer, click real logout,
   replay a mapped authenticated GET with the old credentials → candidate if
   still authorized.
3. **Account-deletion test** — only for an identity whose roster entry is
   marked `disposable: true`; snapshot session/API keys/share links, delete
   account via UI, replay all → candidates; check re-registration of the same
   email reaches old data.
Payment: never in teardown either.

### Screenshots

`screenshot` keeps its params; adds `as_base64: bool = False`. Default now
saves a JPEG (quality ~70, viewport 1280 wide, full-page clipped to a max
height, e.g. 4000px) to `data/engagements/<slug>/screenshots/<ts>-<host>.jpg`
and returns the path + dimensions + provenance line; the agent views it with
`Read`. `as_base64=True` returns the old `data:image/png;base64,...` exactly
(report-agent / any existing consumer keeps working). Agent prompts updated to
"Read the saved file to look at the page".

### Authenticated SPA sessions

- `_save_session` also captures `sessionStorage` for every visited origin
  (`page.evaluate`) into a sidecar key in the session file
  (`"huntmcp_session_storage": {origin: {k: v}}`; Playwright ignores unknown
  keys). `_new_page` restores it via an origin-guarded `add_init_script`.
- New optional seed param `session_storage: dict` on browser tools, mirroring
  `local_storage`, so a freshly refreshed token (e.g. from the out-of-repo
  refresher's `live_tokens.json`) can be injected before the SPA boots.
- Session file remains 0600 and is never echoed (same handling as today).
- Hypothesis to confirm during implementation (not assumed): the bentley
  logged-out shell is caused by OIDC user state living in sessionStorage,
  which storage_state drops. Verified on the local fixture; noted if live
  confirmation is not possible.

### Coverage gate additions (`coverage_manifest.BATTERY_BY_KIND`)

- `page`: {xss, access-control, csrf}
- `input`: {xss, sqli}
- `action`: {csrf, idor, access-control, business-logic}
Precedent continues to add classes on top (existing union). Destructive
actions additionally require `business-logic` covered (broken-delete is
recorded under business-logic). `mark_na` remains the escape valve. huntbrain's
step-14.5 gate therefore cannot pass while page/input/action cells are open.

### Page-first methodology (prompts)

- recon-agent: for every in-scope app/host with UI, run `start_ui_walk`
  (map) before declaring recon done; `extract_page_content` stays for single
  pages.
- scan-agent / exploit-agent: test inputs/actions from the walk inventory
  first; URL/param reasoning is secondary. exploit-agent consumes canary sink,
  broken-delete, delete-IDOR and cancel-without-revoke candidates.
- huntbrain: Pass 2 after Pass 1 per app when the switch is on; teardown only
  ever human-triggered.

## Safety & constraints

- Tier-2: `start_ui_walk`/`run_teardown` URL args are scope-gated by the hook
  **and** in code (`scope_guard.is_in_scope` on start URL and every
  navigation/non-GET; same pattern as `session_capture`).
- `budget_guard.enforce` per page load and per real submit; engagement rate
  limit honoured between actions; hard caps `max_pages`,
  `max_clicks_per_page`, wall-clock limit per walk (e.g. 20 min), per-walk
  real-submit cap.
- Payment: controls classified `payment` never clicked; non-GETs to known
  payment-provider hosts (stripe, paypal, braintree, adyen, checkout.com,
  razorpay, …) always aborted in every pass. Map records checkout request
  shapes so exploit-agent can test price/quantity/coupon tampering up to the
  gateway. A programme sandbox/test-card mode is a future per-engagement flag,
  not built here.
- Evidence: every candidate stores the real request/response (redacted via
  `redact.py`) for case-mcp `add_evidence`; provenance line stays the last
  line of tool output.
- Target text is untrusted: quarantined in returned text; never interpreted as
  instructions.

## Verification

- Unit (pure logic): classifier, dedup signature, canary generation/registry,
  ownership rule, route-template node signatures, battery/gate additions,
  sessionStorage sidecar round-trip, teardown confirmation gate.
- Black-box integration on a **local fixture app** under `tests/fixtures/`
  (stdlib `http.server`, localhost only) exhibiting: a lazy-loaded iframe form,
  a modal-revealed input, a stored-XSS sink on a different page, a soft-delete
  (object still reachable after delete), a non-invalidating logout, an
  sessionStorage-token SPA, a fake payment button, an out-of-scope link.
  Assertions: Pass 1 sends zero non-GETs; Pass 2 finds the cross-page sink and
  the broken delete; payment never clicked; out-of-scope never navigated;
  auth-lost detected when the session is removed; SPA renders logged-in after
  save/restore. Also the patched variant (hard delete, invalidating logout,
  escaped render) yields no candidates.
- Prove it runs: after session restart, call the real
  `mcp__browser-mcp__start_ui_walk` / `check_ui_walk` / `screenshot` /
  `run_teardown` against the local fixture; `Read` the saved screenshot.

## Decisions settled after builder check (author's calls unless marked)

1. **Ownership proof (hard rule).** A destructive control is "walker-owned"
   when EITHER (a, preferred) an id returned by a walker create request (Pass 2
   UI→API edge) appears in that control's intercepted request URL/body, OR (b)
   its nearest repeating container / detail view contains a walker canary
   token. Neither → map-only, recorded as `ownership-unproven`. Never guess.
2. **Object handle.** Prefer the id from the create response; fallback = diff
   the mapped listing before/after the create; if still no handle, no destroy
   and the destructive control stays map-only (noted in inventory).
3. **Pass 2 / create→destroy→verify authorization (USER DECISION: B —
   one-time per-engagement file setting, no terminal keystroke).** The human
   grants canary mode once per engagement; after that every canary walk runs
   with no prompt. (Considered and rejected by the user: a TTY confirmation per
   walk, and per host per 24h — too much manual friction for automation.)
   - **Where the grant lives (author's call, closes a self-authorization
     hole):** NOT in `engagement.yaml`, because huntbrain itself writes that
     file at engagement start, so an agent (or prompt-injected target text)
     could grant itself canary mode. Instead a separate human-owned file
     `data/engagements/<slug>/ui-walk-authorized.yaml`
     (`canary_submit: true`, optional `hosts: [...]` subset of scope,
     optional `real_submit_cap_per_walk`, default 200). It is added to the
     scope-gate hook's protected paths (resolved per active engagement, like
     the confirm-token paths), so agent Write/Edit/Bash to it is blocked; the
     human creates it once by hand. Absent/false → canary mode refused, Pass 1
     still allowed. (So the "default ON" of the earlier draft becomes "ON once
     the human drops that file in"; no file → map-only.)
   - Caps still apply per walk (`real_submit_cap_per_walk`), plus budget
     guard, scope, ownership rule, payment block. Every real submit is
     audit-logged with the walk id. Honest limit: an agent that bypasses the
     hook entirely (its own pty etc.) is out of this module's reach — same
     stated limit as `state_change_confirm`.
4. **Disposable identity.** Add optional `disposable: bool` (default false) to
   the test-identity roster schema (`session_capture.load_roster`) and expose
   it in `list_test_identities`. Non-disposable → account-deletion test skipped
   with a note "provide a disposable identity to run this".
5. **Teardown confirmation** reuses `state_change_confirm`'s human-TTY
   mechanism (single-use, host-bound, time-limited), fingerprint = sha256 of
   {slug, identity, base_url, sorted cleanup object list, steps}; so a token
   cannot be replayed against a different object set or identity.
   `scripts/confirm-teardown.sh` prints that summary for the human to confirm.
6. **Pass 1 "nothing state-changing sent" covers:** HTTP non-GET via
   `page.route` (form-submit navigations and `sendBeacon` are POSTs, so caught);
   WebSocket client→server frames via `context.route_web_socket` (Playwright
   1.62 in venv) — recorded, not forwarded; service workers blocked
   (`service_workers="block"`); document/XHR/fetch GETs whose URL matches
   mutating keywords (logout, signout, delete, remove, revoke, cancel,
   unsubscribe, deactivate) aborted+recorded; script/style/image/font GETs
   allowed. Honest limit (stated in output): a GET with a non-obvious URL that
   mutates server-side cannot be detected a priori.
7. **Session across a long walk.** One browser context per walk. On auth-lost
   the walker re-reads `session_file` once (picks up an external refresher's
   update, incl. the new sessionStorage sidecar) and retries the page; still
   lost → stop with `AUTH LOST`. `budget_guard.enforce` is called per page load
   and per real submit (each counts), not once per job.
8. **Execution detection** is inline during the re-walk: the walk page's own
   dialog handler + `document.title` check match the token (same logic as
   `check_js_execution`), no second render per sink.
9. **Node kinds** are free strings in `surface_map` (no allowlist) — no schema
   change. The destructive-action extra class lives in
   `coverage_manifest.required_classes` (meta-conditional on
   `meta.classification == "destructive"`). Inventory JSON carries
   `"schema_version": 1` so #163's flow harness can rely on it.
10. **Screenshot format.** No test pins the base64 output; `as_base64=True`
    still returns the old PNG data URI for compatibility; exploit-agent's
    evidence step updated to use the file path.

## Left to the builder

- Exact keyword lists for classification, max-height/quality numbers, the
  re-walk scheduling, fixture app internals, inventory JSON field names.
- Whether `run_teardown` is also a background job (likely yes).
