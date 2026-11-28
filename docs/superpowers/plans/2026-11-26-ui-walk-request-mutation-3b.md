# UI-walk request mutation — Part 3b (request level) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Request-level Burp-style mutation over the requests a UI-walk recorded: routing/authz headers, method override, content-type switch, JSON parser differentials, path/encoding tricks, cache-key confusion (always with an `hmcb=` buster), GraphQL alias/batch, and owned-object races — emitting evidence-backed *candidates* (leads) for exploit-agent.

**Architecture:** 3b adds one new pure module, `mutation_xform.py` (request transforms, the request-level plan builder, GraphQL helpers, the agent's new ops, the 3b candidate rules), and extends the 3a pieces in place: `Variant` gains `xforms`; `mutation_logic.gate()` / `effective_method()` get the request-level hardening; the replay store records response *metadata* (status + header NAMES only); `mutation_runner.py` sends the new variant kinds, runs the cache and race two-step flows, and dispatches candidates. Every variant — rule-built or agent-added — still passes `gate()`, budget, scope, cap and read-back/restore exactly like a 3a variant. No new dependency, no new MCP server.

**Tech Stack:** Python 3.12, Playwright (existing), FastMCP, pytest, stdlib only.

**Spec:** `docs/superpowers/specs/2026-11-25-ui-walk-request-mutation-design.md` (Approved 2026-11-25) — section "3b — request level" plus "Safety & constraints", "Ownership", "Restore", "Values policy" and "Decisions settled after builder check". Builds on merged 3a (PR #186). 3c (smuggling) is NOT in this plan.

## Global Constraints

- No new dependency; all code in `mcp-servers/browser-mcp/`; waf-bypass-mcp is used **as data only** (load `mcp-servers/waf-bypass-mcp/server.py` by path with `importlib`, call only `_tier1_variants` and `_tier2_variants`; **never** `_tier3_variants` — it contains non-GET methods; never tier 4 / UA tricks; no bot-protection or TLS-fingerprint evasion).
- Mutated **GET-class** variants (effective method GET/HEAD): sent without the grant, but scope, `budget_guard`, the payment-host block and the mutating-URL block apply to the **final** URL (path, query, and any routing-header path value).
- Non-GET variants (effective method), GraphQL **mutations**, and races: only under `ui_walk_grant.grant_allows(grant, host)` AND an owned object AND a restore path; counted against `real_submit_cap_per_walk` (cumulative, restore reserve `max(5, cap // 10)`).
- Races: grant + owned only, N default 5, max 10; create-style endpoints N ≤ 3.
- Every cache variant (poison and deception) carries a unique `hmcb=<token>` query param; no cache variant is ever sent without one.
- Agent op validation (new ops `set_header`, `remove_header`, `method`, `content_type`, `path`, `graphql_batch`): value ≤ 2048 chars; no CR/LF/NUL in header names/values/paths; cannot set `Host`, `Cookie`, `Authorization`, `Proxy-*`, `Content-Length`, `Transfer-Encoding`; the host (netloc) never changes.
- Never mutated: logout / account-delete / payment-classified edges, SSO endpoint roles, teardown requests. Payment hosts never sent to.
- Block signals (429, or WAF/bot signature via `is_block_signal`) stop the host; nothing tries to get past them.
- No secret values stored: `response_meta` holds header NAMES and the status only; results/plan files hold variant specs and redacted excerpts only.
- Tool output: target text quarantined, provenance line last.
- Commits only on the user's in-the-moment OK; explicit `git add` paths; no AI attribution lines; never stage `data/writeups/hexbrain-*` or `oom`. No worktrees; branch `feat/ui-walk-request-mutation-3b`.

## Plan-level decisions (builder calls inside the spec's "Left to the builder"; please sanity-check)

1. **Races run only on walker-created objects** (ownership kind `created`), not on the own-account surface. A race on `/me`-like state has no clean restore; created objects are destroyed by `run_teardown` (spec decision 1), so their restore status is `teardown`. This is narrower than the spec ("grant + owned"), never wider. A race also needs the sequential-repeat check below to pass (the endpoint must be one-shot, not idempotent).
2. **GraphQL read-only POST** (single object body, operation is a query, no mutation/subscription token anywhere) is treated GET-class by `gate()` via a `graphql_readonly` flag, because the spec says "queries only, without grant". Anything else GraphQL is non-GET.
3. **Replay store gains `response_meta`** per entry (additive; old stores without it still load): `{"status": int, "content_type": str, "cache_signals": [header names], "proxy_signals": [header names]}`. Needed so the plan (no traffic) can say "response has `Age`/`X-Cache`, so cache checks apply" and "baseline was 403".
4. **`effective_method()` is hardened:** if *any* override source (header, `_method` in query/form/JSON) names a non-GET/HEAD verb, the effective method is non-GET, and any header whose name contains `method` is treated as an override header. `gate()` also re-checks the mutating-URL rule on `X-Original-URL`/`X-Rewrite-URL` values and on the twice-percent-decoded final URL.

## File structure

| File | Change | Responsibility |
|---|---|---|
| `mcp-servers/browser-mcp/mutation_xform.py` | create | `Xform`, `apply_xforms`, `with_buster`, waf data loaders, `build_request_plan`, `merge_plans`, GraphQL helpers, `validate_request_ops`, `request_candidates`, race helpers — all pure |
| `mcp-servers/browser-mcp/mutation_logic.py` | modify | `Variant.xforms`, `_vid(…, xforms)`, `Context.denied_paths`, `effective_method` hardening, `gate()` hardening + `graphql_readonly` |
| `mcp-servers/browser-mcp/ui_walk_replay.py` | modify | `ReplayBuffer.note_response_meta`, `response_meta` in entries |
| `mcp-servers/browser-mcp/ui_walk.py` | modify | `_on_response` records meta for every status/resource type (names only) |
| `mcp-servers/browser-mcp/mutation_runner.py` | modify | merge request-level plan, `apply_variant`, anon context, cache two-step, race executor, candidate dispatch, header-strip defense in `_send`, honest limits |
| `mcp-servers/browser-mcp/server.py` | modify | docstrings (3b families, extra_variants vocabulary), plan/result formatting for xforms |
| `tests/fixtures/ui_walk_target/ui_walk_app.py` | modify | `/v4*` fixture endpoints, vulnerable + patched |
| `.claude/agents/exploit-agent.md`, `huntbrain.md`, `CLAUDE.md` | modify | 3b candidate types / op vocabulary |
| tests | create/extend | `test_mutation_fixture_3b.py`, `test_mutation_xform.py`, `test_mutation_xform_plan.py`, `test_mutation_xform_ops.py`, `test_mutation_graphql.py`, `test_mutation_request_candidates.py`, `test_mutation_runner_3b_get.py`, `test_mutation_runner_3b_nonget.py`, extend `test_ui_walk_replay.py`, `test_mutation_tools.py`, `test_ui_walk_agent_wiring.py` |

## Review Focus

1. A GET carrying `X-HTTP-Method-Override: HEAD, DELETE`, two disagreeing override headers, or an unknown `X-…-Method` header — expected: treated as non-GET, never sent without grant+owned. → Task 2 `test_effective_method_any_nonget_source_wins`, `test_gate_get_with_conflicting_overrides_needs_grant`.
2. `X-Original-URL` / `X-Rewrite-URL` pointing at a mutating or never-mutated path, or a path trick that percent-decodes into a mutating word — expected: not sent. → Task 2 `test_gate_routing_header_to_mutating_path_blocked`, `test_gate_double_encoded_mutating_path_blocked`.
3. A cache-hinted GET whose response is public and keyed without the header — expected: only the buster URL is ever touched (no variant or follow-up on the plain URL). → Task 8 `test_cache_variants_always_carry_buster`.
4. GraphQL body that is a batch array, has `mutation` inside a string/fragment, or is not parseable — expected: not read-only; non-GET gating applies or no variant. → Task 6 `test_graphql_readonly_conservative`.
5. A race against an idempotent endpoint (second sequential send also 2xx) or a cap too small for N — expected: no race, no candidate, status says why. → Task 9 `test_race_idempotent_endpoint_skipped`, `test_race_respects_cap_and_n_max`.

---

### Task 1: Fixture endpoints (vulnerable + patched)

**Files:**
- Modify: `tests/fixtures/ui_walk_target/ui_walk_app.py`
- Test: `tests/test_mutation_fixture_3b.py`

**Interfaces:**
- Produces (fixture, plain HTTP; all `/api/v4/*` need the `sid` cookie except where noted; existing routes unchanged). New state on `FixtureApp`: `v4_requests` (list of `(method, path+query, headers dict)` for v4 only), `v4_cache: dict`, `v4_coupons: dict`, `v4_prefs: dict`, `non_get_v4()` helper.
  - `GET /v4` — page: links to `/v4/page?lang=en`, `/v4/account-page?tab=1`; on load `fetch`es `/api/v3/me`, `/api/v4/reports`, `/api/v4/admin`, `/api/v4/export`, `/api/v4/preferences`; a Save form → `PUT /api/v3/profile` (JSON); a Prefs form → `PUT /api/v4/preferences` (JSON `{"theme":"dark"}`); a GraphQL button → `POST /api/v4/graphql` JSON `{"query":"query Me { me { id display_name } }"}`; a Redeem button → `POST /api/v4/coupons/c-1/redeem`.
  - `GET /api/v4/admin` → 403 `{"error":"forbidden"}`; vulnerable: 200 `{"admin":true}` when `X-Forwarded-For: 127.0.0.1` (or `X-Original-URL: /api/v4/admin` honoured as an ACL-bypass: a request to `/api/v4/export` carrying it is routed to admin); patched: always 403.
  - `GET /api/v4/reports` → 403 (ACL on the exact string `/api/v4/reports`); vulnerable: path normalisation happens *after* the ACL, so `/api/v4/reports/`, `/API/V4/REPORTS`, `/api/v4/reports;.css` → 200 `{"reports":[...]}`; patched: 403 for all.
  - `GET|HEAD /api/v4/export` → GET 200 `{"rows":3}`. Vulnerable: honours `X-HTTP-Method-Override` / `?_method=` (value `HEAD` → HEAD semantics). Method ACL: `GET /api/v4/reports2`… (not needed). Method-swap lead: `GET /api/v4/export-acl` → 403, `HEAD /api/v4/export-acl` → 200 (vulnerable; patched 403 for both), and override `HEAD` on GET → 200 (vulnerable).
  - `PUT /api/v3/profile` (existing) — vulnerable additionally accepts `application/x-www-form-urlencoded` and `text/plain` JSON bodies; patched answers 415 for anything but `application/json`.
  - `GET|PUT /api/v4/preferences` → `{"id":"u-1001","theme":"dark"}`; the PUT validates the **first** `"theme"` key in the raw body (allowed `dark|light`, else 400) but stores the **last** (vulnerable); patched rejects duplicate keys with 400.
  - `GET /v4/page?lang=en` (public, no auth) → 200 HTML with `Cache-Control: public, max-age=60`, `Age: 0`, `X-Cache: MISS|HIT`; vulnerable: reflects `X-Forwarded-Host` into the body and caches by path+query only (second request for the same path+query gets the first body, `X-Cache: HIT`); patched: header ignored.
  - `GET /v4/account-page?tab=1` (authed) → personalised HTML containing the identity's id `u-1001`; vulnerable: `/v4/account-page/<anything>.css` serves the same personalised page with `Cache-Control: public` and caches it by path (served to **unauthenticated** requests on the second hit); patched: 404 for the `.css` form.
  - `POST /api/v4/graphql` → JSON `{"data":{"me":{"id":"u-1001","display_name":"Tester"}}}`; vulnerable: any number of aliases (`a1: me {…}`) and an array batch both answered; patched: >1 top-level field → `{"errors":[{"message":"alias limit"}]}` and arrays → 400. A `mutation` operation (`mutation { setName(name:"x") { id } }`) is answered 200 and changes `display_name` (used only by the no-send-without-grant assertions).
  - `POST /api/v4/coupons` → 201 `{"id":"c-<n>"}`; `GET /api/v4/coupons/<id>` → `{"id","redeemed":int}`; `POST /api/v4/coupons/<id>/redeem` → 200 `{"redeemed":n}` once. Vulnerable: check-then-act with a 50 ms sleep (N parallel redeems all return 200, `redeemed == N`); patched: lock, exactly one 200 and the rest 409. A pre-seeded `c-1` exists.

- [ ] **Step 1: Write failing tests** (plain `urllib`, no browser; each asserts both modes): `test_admin_xff_vulnerable_200_patched_403`, `test_reports_path_tricks_vulnerable_200_patched_403` (`/`, uppercase, `;.css`), `test_export_acl_head_swap_and_override`, `test_profile_content_types_vulnerable_accepts_form_and_text_patched_415`, `test_preferences_dup_key_vulnerable_stores_last_patched_400` (body `{"theme":"dark","theme":"evil"}` → vulnerable GET shows `evil`), `test_page_cache_poison_vulnerable_serves_injected_host_to_second_request_patched_clean`, `test_account_page_css_deception_vulnerable_served_unauth_second_time_patched_404`, `test_graphql_alias_and_array_vulnerable_ok_patched_rejected`, `test_coupon_race_vulnerable_all_succeed_patched_exactly_one` (5 threads).
- [ ] **Step 2: Run** `pytest tests/test_mutation_fixture_3b.py -v` → FAIL (404s).
- [ ] **Step 3: Implement** the handlers (`_get_v4`, `_get_api_v4`, `_mutate_v4`, a `_v4_cache_get` helper) in `ui_walk_app.py`; extend `_mutate_v3` profile branch for content types. Do not change any existing route's behaviour.
- [ ] **Step 4: Run** `pytest tests/test_mutation_fixture_3b.py tests/test_mutation_fixture.py tests/test_ui_walk_pass1.py -v` → PASS.

### Task 2: Request transforms + gate/effective-method hardening (pure)

**Files:**
- Create: `mcp-servers/browser-mcp/mutation_xform.py` (part 1)
- Modify: `mcp-servers/browser-mcp/mutation_logic.py` (`Variant`, `_vid`, `Context`, `effective_method`, `gate`)
- Test: `tests/test_mutation_xform.py`

**Interfaces:**
- Produces:
  - `mutation_logic.Variant` gains `xforms: list = field(default_factory=list)` (after `origin`); `_vid(replay_id, ops, xforms=())` — ids of variants without xforms unchanged from 3a.
  - `mutation_logic.Context` gains `denied_paths: set = field(default_factory=set)` (paths of GETs recorded with 401/403/404) and `meta: dict = field(default_factory=dict)` (replay_id → response_meta).
  - `@dataclass class Xform: kind: str  # "set_header"|"remove_header"|"method"|"override"|"content_type"|"path"|"graphql"|"race"|"cache_poison"|"cache_deception"; name: str = ""; value: object = None; n: int = 0`
  - `apply_xforms(req: Req, xforms: list[Xform]) -> Req` — a NEW Req, input untouched. `set_header` replaces case-insensitively; `method` swaps `req.method`; `override` with `name` `header:<H>` or `param:_method` sets an override header or adds `_method=` to query (GET) / body; `content_type` (`json|form|text|xml`) re-encodes the same top-level fields (nested values JSON-dumped into form; XML `<root><k>v</k></root>`) and sets the header; `path` replaces the URL path (value is the new path, host unchanged); `graphql` rewrites the body (see Task 6).
  - `with_buster(url: str, token: str) -> str` — adds `hmcb=<token>` (replacing an existing `hmcb`), other params untouched.
  - `routing_alt_urls(req: Req) -> list[str]` — absolute URLs implied by `X-Original-URL` / `X-Rewrite-URL` values (same scheme+host as the request).
  - Hardened `effective_method(req)`: returns a non-GET/HEAD verb when **any** source (override headers, any header whose name contains `method`, `_method` in query/form/JSON) names one; a value that is not a plain verb token (`HEAD, DELETE`) counts as non-GET.
  - Hardened `gate(...)` gains kwarg `graphql_readonly: bool = False`; GET-class path additionally blocks (`reason "routing-header-mutating"`) when any `routing_alt_urls` is a mutating URL or `never_mutated(alt)`, and (`"mutating-get"`) when `is_mutating_get_url` matches the final URL after two rounds of `urllib.parse.unquote`. `graphql_readonly` makes a POST with effective method POST and no override GET-class (all other checks apply).

- [ ] **Step 1: Write failing tests** `tests/test_mutation_xform.py`: `test_apply_set_header_replaces_case_insensitive`, `test_apply_does_not_mutate_input`, `test_apply_method_swap_and_override_header_and_param`, `test_apply_content_type_json_to_form_and_text_and_xml` (fields preserved; header set), `test_apply_path_keeps_host_and_query`, `test_with_buster_adds_and_replaces`, `test_variant_id_unchanged_without_xforms` (a 3a variant's id equals its pre-3b value), `test_effective_method_any_nonget_source_wins` (`HEAD, DELETE`; two disagreeing override headers; `X-Foo-Method: DELETE`; JSON `_method`), `test_gate_get_with_conflicting_overrides_needs_grant` (`Gate.needs_grant True, send False` with no grant), `test_gate_routing_header_to_mutating_path_blocked` (`X-Original-URL: /api/account/delete` → blocked, `routing-header-mutating`), `test_gate_double_encoded_mutating_path_blocked` (`/api/%2564elete`), `test_gate_graphql_readonly_post_sends_without_grant_but_not_to_payment_host_or_out_of_scope`.
- [ ] **Step 2: Run** `pytest tests/test_mutation_xform.py -v` → FAIL.
- [ ] **Step 3: Implement** `Xform`, `apply_xforms`, `with_buster`, `routing_alt_urls` in `mutation_xform.py`; edit `mutation_logic.py` as listed. Existing 3a tests must stay green.
- [ ] **Step 4: Run** `pytest tests/test_mutation_xform.py tests/test_mutation_logic_request.py tests/test_mutation_logic_gate.py -v` (and the other 3a `test_mutation_logic_*` files) → PASS.

### Task 3: Replay store `response_meta` + walker capture

**Files:**
- Modify: `mcp-servers/browser-mcp/ui_walk_replay.py`, `mcp-servers/browser-mcp/ui_walk.py` (`_on_response`)
- Test: extend `tests/test_ui_walk_replay.py`; `tests/test_ui_walk_pass1.py` stays green

**Interfaces:**
- Produces: `ReplayBuffer.note_response_meta(method: str, url: str, status: int, headers: dict) -> None` — stores on the matching entry `response_meta = {"status", "content_type" (main type only, e.g. "text/html"), "cache_signals" (subset of header names present among age, x-cache, x-cache-hits, cf-cache-status, x-served-by, via, plus "cache-control:public" when `Cache-Control` has `public` or `s-maxage`), "proxy_signals" (subset of via, x-forwarded-for, x-forwarded-host, cf-ray, x-amz-cf-id, x-varnish, x-akamai-*, x-served-by)}`. Header **values** are never stored. Entries without it read as `{}`.
- `_on_response` calls it for every status and for `document`/`xhr`/`fetch` GETs and non-GETs that were forwarded; the JSON-key capture for `<300` xhr/fetch is unchanged.

- [ ] **Step 1: Write failing tests:** `test_note_response_meta_stores_names_not_values` (feed `Age: 12`, `X-Cache: HIT`, `Set-Cookie: sid=SECRET` → entry meta has `age`, `x-cache`, no `SECRET` anywhere in `json.dumps(buffer.to_dict(...))`), `test_meta_records_403_status`, `test_old_store_without_meta_loads_in_plan` (entry lacking the key → profile treats as `{}`), and a walker black-box `test_walk_records_response_meta_for_fixture_page` (walk `/v4`, the `/api/v4/reports` entry has `status 403`; the `/v4/page?lang=en` entry has `cache_signals` containing `age`).
- [ ] **Step 2: Run** the replay test file → FAIL.
- [ ] **Step 3: Implement** both functions; keep recording failure-silent (never affects the walk).
- [ ] **Step 4: Run** `pytest tests/test_ui_walk_replay.py tests/test_ui_walk_pass1.py -v` → PASS.

### Task 4: Request-level plan builder (profiler + waf data)

**Files:**
- Modify: `mcp-servers/browser-mcp/mutation_xform.py` (part 2)
- Test: `tests/test_mutation_xform_plan.py`

**Interfaces:**
- Consumes: Tasks 2-3 (`Xform`, `Context.denied_paths/meta`, `response_meta`).
- Produces:
  - `waf_header_data() -> list[tuple[str, str]]` — `(name, value)` pairs from `waf-bypass-mcp`'s `_tier1_variants`, only entries whose curl args are a single `-H "Name: value"`, minus forbidden names (Host, Cookie, Authorization, Proxy-*, Content-Length, Transfer-Encoding) — i.e. the 9 IP headers; UA variants dropped. `waf_path_data(url: str) -> list[tuple[str, str]]` — `(label, new_path)` from `_tier2_variants` (same host/query; label from its description). Loaded via `importlib.util.spec_from_file_location`; neither function touches tier 3.
  - `PATH_TRANSFORMS: tuple[str, ...]` — the fixed transform names the agent may use (`trailing-slash`, `trailing-dot`, `semicolon-css`, `encode-slash`, `uppercase`, `double-encode`, `dot-segment`) and `path_transform(url, name) -> str | None`.
  - `build_request_plan(req: Req, ctx: Context, meta: dict, *, graphql: bool = False, is_create: bool = False) -> list[Variant]` — request-level variants, each with a `reason`, `score`, `family` ∈ `header | method | content-type | json-diff | path | cache | graphql | race`:
    - `header`: chosen when `meta.status in (401,403,404)`, or the path matches an admin-ish word (`admin|internal|manage|console|debug|staff|dashboard|config`), or `meta.proxy_signals`; tier-1 IP headers + `X-Forwarded-Host`/`X-Host`/`X-Forwarded-Proto`/`X-Forwarded-Scheme`; `X-Original-URL`/`X-Rewrite-URL` valued with a path from `ctx.denied_paths` (GET only). Score 80 (denied baseline) / 50 otherwise.
    - `method`: GET entries → `HEAD` swap, `X-HTTP-Method-Override: HEAD`, `?_method=HEAD` (GET-class) plus POST/PUT/DELETE override and swap variants (non-GET → gated); non-GET entries → `X-HTTP-Method-Override`/`X-HTTP-Method`/`X-Method-Override` with the original verb sent as POST, and `_method=`. Higher score when `meta.status in (401,403,405)`.
    - `content-type`: JSON-body entries → form, `text/plain`, XML (also form → JSON).
    - `json-diff` (JSON body, ≥1 top-level scalar): duplicate key with a second differing value (raw body), unicode-escaped key name, trailing comma, comment, big-number value.
    - `path`: `waf_path_data` variants (GET entries; at most 6), higher score when `meta.status in (401,403,404)`.
    - `cache`: only when `meta.cache_signals` is non-empty (GET only): `cache_poison` variants (`X-Forwarded-Host`, `X-Host`, `X-Forwarded-Proto`) and one `cache_deception` variant (path + `/hm.css`); reasons name the signal seen.
    - `graphql` (when `graphql`): `graphql` xforms alias ×3 / ×5 and array batch ×2 / ×5 (see Task 6).
    - `race` (non-GET, JSON/form, route/body names matching `redeem|claim|apply|use|withdraw|transfer|vote|like|invite|coupon|voucher|checkout|buy|order`, or `is_create`): one variant, `Xform("race", n=3 if is_create else 5)`.
  - `merge_plans(param_variants: list[Variant], request_variants: list[Variant], *, max_variants: int = 40, max_per_family: int = 10) -> list[Variant]` — union, de-duplicated by `variant_id`, sorted by `(-score, family order)` with an order list covering every 3a and 3b family, caps applied per family and in total.

- [ ] **Step 1: Write failing tests:** `test_waf_header_data_is_tier1_only_and_has_no_forbidden_names`, `test_waf_data_never_references_tier3` (the built data contains no non-GET verb tokens; a spy on the loaded module proves `_tier3_variants` is not called), `test_header_family_chosen_for_403_not_for_plain_200`, `test_header_family_includes_original_url_with_denied_path_only_for_get`, `test_method_family_get_vs_nonget_forms`, `test_content_type_family_only_for_body_requests`, `test_json_diff_only_for_json_with_scalar`, `test_path_family_cap_six_and_same_host`, `test_cache_family_requires_cache_signal_and_every_variant_marked_cache` (each cache variant's xforms include `cache_poison`/`cache_deception`), `test_race_family_only_for_racey_names_and_create_n_is_three`, `test_merge_caps_per_family_and_total_and_dedupes`, `test_every_variant_has_reason_and_stable_id`.
- [ ] **Step 2: Run** `pytest tests/test_mutation_xform_plan.py -v` → FAIL.
- [ ] **Step 3: Implement** the functions above in `mutation_xform.py` (profiler is rule-based; ranking weights are builder's call within the stated shape).
- [ ] **Step 4: Run** → PASS.

### Task 5: Agent op vocabulary (3b ops) with validation

**Files:**
- Modify: `mcp-servers/browser-mcp/mutation_xform.py` (part 3)
- Test: `tests/test_mutation_xform_ops.py`

**Interfaces:**
- Consumes: Task 2 `Xform`, Task 4 `PATH_TRANSFORMS`.
- Produces: `validate_request_ops(raw: list, known: dict[str, M.Req]) -> tuple[list[Variant], list[str]]` — items `{"replay_id", "op", ...}`:
  - `set_header` `{"name","value"}`; `remove_header` `{"name"}` (header-name token `^[A-Za-z0-9-]{1,64}$`; forbidden: `host`, `cookie`, `authorization`, `proxy-*`, `content-length`, `transfer-encoding`, plus names starting with `:`; value ≤ 2048, no CR/LF/NUL; `remove_header` may only remove a header present in the recorded request or one we add).
  - `method` `{"method": GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS, "via"?: "swap"|"header"|"param", "override"?: verb}` (TRACE/CONNECT rejected).
  - `content_type` `{"to": "json"|"form"|"text"|"xml"}`.
  - `path` `{"transform": <PATH_TRANSFORMS name>}` or `{"literal": "/x/y"}` (must start with `/`, not `//`, no `?#\`, no CR/LF/NUL, length ≤ 512; resulting netloc must equal the original).
  - `graphql_batch` `{"n": 2..5, "mode": "alias"|"array"}`.
  - Accepted items become `Variant(origin="agent", score=100, family=…)` with a `"agent: <reason>"` reason; rejected items return `"#i: …"` messages (never echo more than 40 chars of target-controlled text). Unknown ops return `op … is not available`.
- `mutation_runner._agent_extras` routes items by op: 3a kinds → `M.validate_agent_ops`, 3b kinds → `validate_request_ops`, anything else → an error line.

- [ ] **Step 1: Write failing tests:** `test_forbidden_headers_rejected` (parametrised over Host, Cookie, Authorization, Proxy-Foo, Content-Length, Transfer-Encoding, `:authority`), `test_crlf_nul_rejected_in_name_value_path` , `test_value_over_2kb_rejected`, `test_path_literal_cannot_change_host` (`//evil.example/x`, `http://evil.example/`, `/a?b`), `test_method_trace_connect_rejected`, `test_valid_ops_become_agent_variants` (one of each kind), `test_unknown_replay_id_rejected`, `test_agent_override_variant_still_gated_as_nonget` (gate on `method=GET, override DELETE` → needs grant), `test_agent_set_header_x_original_url_to_mutating_path_blocked_by_gate`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** `pytest tests/test_mutation_xform_ops.py tests/test_mutation_logic_agent.py -v` → PASS.

### Task 6: GraphQL helpers (pure)

**Files:**
- Modify: `mcp-servers/browser-mcp/mutation_xform.py` (part 4)
- Test: `tests/test_mutation_graphql.py`

**Interfaces:**
- Produces:
  - `graphql_kind(req: Req) -> str | None` — `"query"` only when the body is a single JSON object with a string `query`, no `mutation`/`subscription` token anywhere in the document (strings/comments ignored would be wrong: be conservative, so any occurrence counts), no override signals; `"mutation"` when it parses as GraphQL but is not a safe query; `None` when the request is not GraphQL (path has `graphql`, or keys ⊆ {query, variables, operationName, extensions} with a `{` in the query). Arrays → `"mutation"` (conservative).
  - `alias_query(query: str, n: int) -> str | None` — exactly one top-level field → n aliased copies (`hmA1: field …`); brace matcher skips string literals and comments; multi-field / fragment spread / unparsable → `None`.
  - `graphql_body(req: Req, mode: str, n: int) -> str | None` — alias mode rewrites `query`, array mode returns a JSON list of n copies of the original object; `None` when not applicable. `apply_xforms` uses it for `Xform("graphql", name=mode, n=n)`.
  - `graphql_candidate(mode: str, n: int, base: Resp, var: Resp) -> dict | None` — `graphql-batching-candidate` lead when the variant body shows n successful results (alias: n `hmA*` keys under `data` with no `errors`; array: a list of n objects with `data`), evidence = counts, no excerpts of values.

- [ ] **Step 1: Write failing tests:** `test_graphql_readonly_conservative` (batch array, `mutation` hidden in a comment/string/fragment name, unparsable text → not `"query"`), `test_graphql_kind_detects_non_graphql_json_as_none`, `test_alias_query_single_field_n_copies`, `test_alias_query_skips_multi_field_and_braces_in_strings`, `test_array_batch_body`, `test_graphql_candidate_only_when_all_n_succeed`, `test_graphql_candidate_none_on_alias_limit_error`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.

### Task 7: Request-level candidate rules (pure)

**Files:**
- Modify: `mcp-servers/browser-mcp/mutation_xform.py` (part 5)
- Test: `tests/test_mutation_request_candidates.py`

**Interfaces:**
- Consumes: `mutation_logic.Resp/Diff/diff/noise/_excerpt`, Task 4 families.
- Produces: `request_candidates(variant: Variant, base: Resp, var: Resp, d: Diff, *, readback: str = "n/a", single_value_resp: Resp | None = None, followup: Resp | None = None, anon_original: Resp | None = None, anon_variant: Resp | None = None, race: dict | None = None, recorded_values=None) -> list[dict]` — same candidate dict shape as 3a (`type, variant_id, replay_id, family, origin, reason, persisted, change, evidence`), `change` describing header **name** / transform name (never injected values other than ours):
  - `header` → `header-authz-bypass-candidate` when base ∈ {401,403,404} and var 2xx (for `X-Original-URL`/`-Rewrite-URL`: the response differs from base's masked body).
  - `method` → `method-override-candidate` when base ∈ {401,403,405} and var 2xx (GET-class), or (non-GET) base rejected and var accepted with `readback == "persisted"`.
  - `content-type` → `content-type-confusion-candidate` when base 2xx, var 2xx and (readback persisted, or the content type was form/text — the CSRF-relevant ones).
  - `json-diff` → `json-parser-differential-candidate` when `single_value_resp` rejected (4xx) and var 2xx, or readback persisted the *second* value.
  - `path` → `path-normalization-candidate` when base ∈ {401,403,404} and var 2xx.
  - `cache` poison → `cache-poisoning-candidate` when `followup` is 2xx and its body contains the injected header value that the variant sent (and the base did not); deception → `cache-deception-candidate` when `anon_variant` is 2xx with a body equal (volatile-masked) to the authed variant body and `anon_original` is not equal to the authed baseline.
  - `race` → `race-candidate` when `race = {"n", "ok", "statuses", "idempotent": False}` has `ok ≥ 2` and `persisted` readback; evidence = n, ok count, status histogram.
  - Evidence excerpts go through the 3a `_excerpt` redaction.

- [ ] **Step 1: Write failing tests** (positive and negative for each type): `test_header_candidate_403_to_200_only`, `test_header_no_candidate_when_403_stays`, `test_method_candidate_head_swap`, `test_content_type_candidate_form_accepted_persisted`, `test_content_type_no_candidate_when_415`, `test_json_diff_candidate_when_single_rejected_dup_accepted`, `test_path_candidate_403_to_200`, `test_cache_poison_requires_followup_reflection`, `test_cache_deception_requires_anon_equal_and_original_differs`, `test_race_candidate_needs_two_ok_and_not_idempotent`, `test_candidate_evidence_redacts_recorded_values`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.

### Task 8: Runner — GET-class 3b families (header, method, path, cache, GraphQL queries)

**Files:**
- Modify: `mcp-servers/browser-mcp/mutation_runner.py`, `mcp-servers/browser-mcp/ui_walk_replay.py` (nothing further)
- Test: `tests/test_mutation_runner_3b_get.py`

**Interfaces:**
- Consumes: Tasks 1-7.
- Produces (runner):
  - `make_plan`/`_variants_for` merge `MX.build_request_plan(...)` into every entry's plan via `MX.merge_plans`; plan view shows xform variants (`_xform_text`: `header X-Forwarded-For`, `method HEAD (swap)`, `path trailing-slash`, `cache-poison X-Forwarded-Host (buster)`, `graphql alias x3`, `race x5`), gated by `gate()` with `graphql_readonly`; `Context.denied_paths/meta` built from the replay entries.
  - `apply_variant(base: M.Req, v: M.Variant) -> M.Req` = `apply_ops` then `apply_xforms`; used by both the GET and non-GET loops.
  - `_send` defense in depth: drops `proxy-*`, `transfer-encoding`, `content-length`, `host`, `cookie`, `authorization` from any variant request's headers (agent or rule) before sending.
  - GET loop (`_run_get`): variants with `xforms` go through the same gate/budget/diff; cache-hinted entries get a buster on the **baseline pair and every variant** (`hmcb=<12 hex random>` per request, distinct per variant); cache variants run the two-step (variant on buster URL, then the same buster URL with no variant headers; deception also fetches the buster `.css` URL and the buster original through a cookie-less browser context `self.anon`); a cache variant is never sent when it cannot carry a buster (e.g. URL parse failure) and a follow-up is never sent to a non-buster URL.
  - Candidate dispatch: `variant.family` in the 3b families → `MX.request_candidates(...)`, else `M.candidates_for`.
  - `HONEST_LIMITS`: the "Duplicate HTTP headers … (3b/3c)" line becomes "Duplicate HTTP headers and HTTP/2-only behaviour are not exercised (3c)"; add "Race variants use parallel browser-context requests, not single-packet sync, so a miss is not proof of no race."

- [ ] **Step 1: Write failing tests** (`requires_browser`, fixture app + `Env` helper as in `test_mutation_runner.py`, walking `/v4`): `test_plan_has_request_families_with_reasons` (header family on `/api/v4/admin`, cache family on `/v4/page?lang=en`, no cache family on non-cache routes), `test_header_authz_vulnerable_candidate_patched_none` (XFF on `/api/v4/admin`), `test_path_trick_vulnerable_candidate_patched_none` (`/api/v4/reports`), `test_method_head_swap_and_override_vulnerable_candidate_patched_none` (`/api/v4/export-acl`), `test_cache_poison_vulnerable_candidate_patched_none`, `test_cache_deception_vulnerable_candidate_patched_none`, `test_cache_variants_always_carry_buster` (every fixture-logged v4 request for `/v4/page` and `/v4/account-page` from cache variants has `hmcb=`; no request with a cache-variant header lacks it), `test_graphql_query_alias_and_batch_sent_without_grant_vulnerable_candidate_patched_none` (POSTs to `/api/v4/graphql` sent with grant=None; zero other non-GET), `test_no_grant_run_sends_only_get_class` (fixture `non_get_v4()` shows only the graphql query POSTs), `test_override_delete_and_swap_post_are_held_without_grant`, `test_forbidden_headers_stripped_from_agent_variant_on_the_wire` (agent `set_header` rejected earlier; plus a hand-built variant with `Cookie` is stripped by `_send`), `test_block_signal_stops_host_for_3b_variants` (fixture `refuse_all`).
- [ ] **Step 2: Run** `pytest tests/test_mutation_runner_3b_get.py -v` → FAIL.
- [ ] **Step 3: Implement** the runner changes above.
- [ ] **Step 4: Run** `pytest tests/test_mutation_runner_3b_get.py tests/test_mutation_runner.py tests/test_mutation_tools.py -v` → PASS (3a runner tests unchanged).

### Task 9: Runner — non-GET 3b families (content-type, JSON differential, GraphQL mutation gating, races)

**Files:**
- Modify: `mcp-servers/browser-mcp/mutation_runner.py`
- Test: `tests/test_mutation_runner_3b_nonget.py`

**Interfaces:**
- Produces: the non-GET loop (`_run_non_get`) applies xform variants through `apply_variant`, with `single_value_resp` for `json-diff` (the second value alone, sent as a normal 3a `set_param`), read-back + restore via the existing `_state_change`; `race` variants handled by `_run_race(e, pe, base, v, ...)`:
  1. precondition: `owned.kind == "created"`, grant ok, snapshot GET present (read-back), grant cap has `n` + 1 sends available (`_take(n)`); otherwise `why_not` = `race needs walker-created object` / `cap-reached`;
  2. baseline single send (existing) then **one sequential repeat**; if the repeat is also 2xx → result `why_not="idempotent endpoint"`, no race;
  3. `n = min(v.n, 10)` (create-style → ≤ 3, clamped again here if the baseline response carried a created id); budget enforced per request *before* the gather; `asyncio.gather` of n identical sends; every created id registered (`_note_created`);
  4. read-back; restore status `teardown` for created objects (cleanup by `run_teardown`), recorded per result; candidate via `request_candidates(race=…)`.
- GraphQL mutation variants: kept in the plan, held with `why_not` from `gate()` (`needs grant` / `not-owned`); never sent to a non-owned object.

- [ ] **Step 1: Write failing tests** (`requires_browser`; the test registers the seeded coupon via `ui_walk_store.register_created_id("seed","c-1")` to model "walker-created"): `test_content_type_form_text_vulnerable_candidate_patched_none` (granted run on `PUT /api/v3/profile`; role not left changed — restore ok), `test_json_dup_key_vulnerable_candidate_patched_none` (`/api/v4/preferences`, restore ok, `app.v4_prefs["theme"]` back to `dark`), `test_graphql_mutation_never_sent_even_with_grant_when_not_owned` (fixture `display_name` unchanged), `test_race_vulnerable_candidate_patched_none` (coupon `c-1`; vulnerable ≥2 OK → candidate; patched exactly one 200), `test_race_requires_grant_and_created_object` (no grant → zero races; own-account object → held with reason), `test_race_idempotent_endpoint_skipped`, `test_race_respects_cap_and_n_max` (cap too small → `cap-reached`; agent cannot request n > 10 — `race` is not in the vocabulary), `test_create_race_n_at_most_three` (`POST /api/v4/coupons` → ≤ 3 sends), `test_created_ids_from_race_registered_for_teardown`, `test_restore_failed_stops_further_3b_variants_on_object` (sticky fixture mode).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** `pytest tests/test_mutation_runner_3b_nonget.py tests/test_mutation_runner_3b_get.py tests/test_mutation_runner.py -v` → PASS.

### Task 10: Tools, formatting, agent prompts, docs

**Files:**
- Modify: `mcp-servers/browser-mcp/server.py`, `.claude/agents/exploit-agent.md`, `.claude/agents/huntbrain.md`, `CLAUDE.md` (browser-mcp line)
- Test: extend `tests/test_mutation_tools.py`, `tests/test_ui_walk_agent_wiring.py`

**Interfaces:**
- `plan_mutations` / `run_mutations` docstrings list the 3b families and the full `extra_variants` vocabulary (3a + `set_header|remove_header|method|content_type|path|graphql_batch` with their fields); `_format_plan` prints xform variants (`_xform_text`); `_format_mutations` unchanged in layout (RESTORE FAILED first, quarantine, provenance last). Tool signatures unchanged.
- exploit-agent prompt: after `plan_mutations`, read reasons, add `extra_variants` (e.g. a `set_header` for a header the app is known to trust), work the 3b candidates with `access-control-and-idor`, `waf-bypass` (as technique reference only), `infrastructure-and-protocol` (cache), `api-security-top10` (GraphQL), `race-conditions`; never treat a candidate as confirmed; races/mutations only with the human grant.

- [ ] **Step 1: Write failing tests:** `test_plan_output_lists_xform_variants_and_quarantines`, `test_run_mutations_docstring_names_3b_ops`, `test_check_mutations_shows_3b_candidate_types`, `test_agent_prompts_mention_3b_candidates_and_ops`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** `pytest tests/test_mutation_tools.py tests/test_ui_walk_agent_wiring.py tests/test_ui_walk_tools.py -v` → PASS.

### Task 11: Full verification, review-and-audit, runtime proof

- [ ] **Step 1:** `pytest tests/ -k "mutation or ui_walk" -q` → all pass (skips only where browser/IdP image missing).
- [ ] **Step 2:** `pytest tests/ -q` → full suite green (record counts); `ruff check mcp-servers/ --ignore E402,F811 --target-version py312`; `python -m py_compile` on every changed `.py`; `bash -n scripts/*.sh`.
- [ ] **Step 3: Leak check:** a test (`test_3b_outputs_hold_no_secret`) greps every file in the walk dir except `.replay.json` plus the audit log for the fixture's secrets (sid cookie, OTP, injected `hmcb`-free recorded values) — added in Task 9's file, run here.
- [ ] **Step 4: Review and audit:** run `/code-review` AND `/security-review` on the branch; fix each finding test-first; re-run Steps 1-3.
- [ ] **Step 5: Prove it runs** (ask the user first, then: `scripts/switch-engagement.sh set ui-walk-proof.localhost --force`; the user restarts browser-mcp to load the code): serve the fixture (vulnerable), real `mcp__browser-mcp__start_ui_walk` (map) on `/v4` → `plan_mutations` → `run_mutations` without grant (GET-class only) → `check_mutations`; then with the human-written grant for the fixture host → content-type / JSON-diff / race candidates, restore ok, teardown cleans created ids; then the patched fixture shows none. Record `Runtime-verified: …` evidence; switch back to `bentley.com`; never touch the live bentley-com engagement.
- [ ] **Step 6:** Commit / PR only on the user's explicit OK (explicit `git add` of the changed files; no attribution lines).

---

## Self-review

- **Spec coverage:** routing/authz headers (T4, T7, T8) · method override + effective-method gating (T2, T4, T8) · content-type switch (T4, T7, T9) · JSON parser differentials (T4, T7, T9) · path/encoding via tier-2 data (T4, T7, T8) · cache-key confusion + buster (T4, T7, T8) · GraphQL alias/batch, queries without grant, mutations grant+owned (T2, T6, T8, T9) · races ≤10, create ≤3 (T4, T9) · agent op vocabulary + validation (T5) · nine candidate types (T7) · fixtures with vulnerable/patched (T1) · no secrets/withheld values (T3, T11 leak check). 3c is out of scope.
- **Type consistency:** `Xform` / `Variant.xforms` / `Context.denied_paths/meta` defined in T2 and used unchanged in T4-T9; `request_candidates` (T7) keyword names match T8/T9 calls; family names (`header|method|content-type|json-diff|path|cache|graphql|race`) are the same in T4, T7, T8, T9.
- **Proportion:** each task lists signatures, fixture contract and named tests; bodies are left to the implementer.
