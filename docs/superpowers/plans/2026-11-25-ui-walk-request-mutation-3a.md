# UI-walk request mutation — Part 3a (parameter level) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Burp-style parameter mutation (add / remove / duplicate / retype / numeric edges) over the requests a UI-walk recorded, plus the `?query` DOM-XSS source, emitting evidence-backed candidates for exploit-agent.

**Architecture:** The walker records each in-scope UI→API request into a 0600 replay store. A pure-logic module (`mutation_logic.py`) parses a stored request, profiles it, and builds a ranked, request-specific variant plan; the agent may extend it with validated ops. A runner (`mutation_runner.py`) opens a browser context from the same session, sends baselines and variants through `context.request` under every safety gate, reads back / restores owned state, compares, and writes candidates. Three new browser-mcp tools drive it.

**Tech Stack:** Python 3.12, Playwright 1.62 (already in venv), FastMCP, pytest; stdlib only (no new dependency).

**Spec:** `docs/superpowers/specs/2026-11-25-ui-walk-request-mutation-design.md` (Approved 2026-11-25). This plan covers **3a only**; 3b and 3c get their own plans.

## Global Constraints

- No new dependency; no new MCP server (all in `mcp-servers/browser-mcp/`).
- Mutated **GET** variants: sent without grant, but scope + `budget_guard` + payment-host block + `is_mutating_get_url` block apply to the **final** URL.
- **Effective method** decides the grant need (`_method=` query/body, `X-HTTP-Method-Override` / `X-HTTP-Method` / `X-Method-Override` header).
- Non-GET variants: only with `ui_walk_grant.grant_allows(grant, host)` **and** an owned target; never in a walk's Pass 1.
- Cap: `real_submit_cap_per_walk` is cumulative over the walk's Pass-2 submits + all runs on that `walk_id`; restore reserve = `max(5, cap // 10)`, usable only by restore requests.
- Own account = own-account path segment **and** no id/container segment **and** no `org|team|workspace|tenant|project|group|company` segment **and** snapshot GET response contains a `self_id`.
- No restore path (no snapshot GET) → state-changing variant not sent (`would_send: false, reason: "no restore path"`).
- `run_mutations` refuses an identity different from the walk's (session_file realpath equal, or live self-id matches a stored `self_id`).
- Never mutated: logout / account-delete / payment-classified edges, any SSO-role URL (`ui_walk_sso_logic.classify_url(url) is not None`), teardown requests.
- Never stored anywhere: `Cookie`, `Authorization`, `Proxy-Authorization` header values; values of fields/headers whose name matches the withheld heuristic (password, passwd, pwd, otp, totp, mfa, cvv, cvc, card, pin, secret, api_key/apikey/api-key, private_key). Replaced by `"<hm-withheld>"`, listed in `withheld_fields`.
- Replay store `data/engagements/<slug>/ui-walk/<walk-id>.replay.json`, mode 0600, atomic, body capped at 64 KB. Never printed by any tool.
- Per-run defaults: 400 sent requests max, 40 variants per request, 10 per family per request.
- 429 or `tool_resolver.classify_block` in (`waf`, `rate_limit`) → stop that host, status `blocked`; no evasion.
- Tool output: target text through `injection_boundary` quarantine; provenance line last.
- Agent op values ≤ 2048 chars; no CR/LF/NUL in names/values; cannot set `Host`, `Cookie`, `Authorization`, `Proxy-*`, `Content-Length`, `Transfer-Encoding`; host never changes.
- Commits: only on the user's in-the-moment OK; explicit `git add` paths; no AI attribution lines; never stage `data/writeups/hexbrain-*` or `oom`.

## Review Focus

1. A recorded request whose body is not JSON/form (binary, `text/plain`, huge) — expected: profiled as `unparsed`, no body variants, never a crash; query variants still built. → Task 2 test `test_parse_unparseable_body_keeps_query_variants`.
2. A GET variant whose added/changed value turns it into a mutating URL (e.g. `action=delete`, `_method=DELETE`) — expected: not sent without grant. → Task 4 test `test_get_with_method_param_needs_grant` and `test_variant_url_mutating_word_blocked`.
3. Session expires mid-run (baseline 401 after a 200 earlier) — expected: run stops with `auth_lost`, no candidates from 401-vs-200 diffs. → Task 8 test `test_auth_lost_mid_run_stops`.
4. A restore whose read-back still shows the injected value — expected: `restore_failed` status first in output, no more state-changing variants on that object. → Task 8 test `test_restore_failure_stops_object`.
5. A response echoing the injected value only because it reflects input (not persisted) — expected: `persisted: false` from read-back, candidate confidence lower, never `true`. → Task 5 test `test_reflection_without_readback_is_not_persisted`.

---

### Task 1: Fixture endpoints (vulnerable + patched)

**Files:**
- Modify: `tests/fixtures/ui_walk_target/ui_walk_app.py`
- Test: `tests/test_mutation_fixture.py`

**Interfaces:**
- Produces (fixture, HTTP, all under the existing `sid` cookie auth unless noted):
  - Page `GET /acct` (authed): on load `fetch('/api/v3/me')`, renders a form (`display_name` text, `Save` button) that `fetch('PUT', '/api/v3/profile', JSON {"display_name": ...})`; a second form (`new_email`, `otp`, `Change email`) that POSTs JSON `{"email":..., "otp":...}` to `/api/v3/change-email`; a link to `/api/v3/transfer-preview?to=<own id>` and `/api/v3/promo-check?code=WELCOME0`.
  - `GET /api/v3/me` → `{"id": "u-1001", "display_name": str, "role": "user", "email": str, "plan": "free"}`.
  - `PUT /api/v3/profile`: vulnerable = every JSON key persisted into the `me` record (incl. `role`, `plan`); patched = only `display_name`.
  - `POST /api/v3/change-email`: vulnerable = `otp` key absent → change accepted (200); wrong otp → 403; patched = absent or wrong → 403. Correct otp = `app.v3_otp` (test helper).
  - `GET /api/v3/transfer-preview?to=..` : own id `u-1001` allowed, any other → 403; vulnerable = checks the **first** `to`, previews the **last** (`{"preview_for": last}`); patched = duplicate `to` → 400.
  - `GET /api/v3/promo-check?code=..` : `code` == `app.v3_promo` → 200 `{"valid": true}`, else 403; vulnerable = `code[]` (array form) → 200 `{"valid": true}`; patched → 400.
  - Page `GET /qsink?msg=hello` (no auth): vulnerable writes `msg` into `innerHTML`, patched into `textContent`.
  - `app.v3_me` dict (the live `me` record) exposed for assertions.

- [ ] **Step 1: Write failing tests** in `tests/test_mutation_fixture.py` (plain `urllib`, no browser): `test_profile_mass_assign_vulnerable_persists_role` (PUT `{"display_name":"x","role":"admin"}` then GET me → `role == "admin"`), `test_profile_patched_ignores_role`, `test_change_email_without_otp_vulnerable_200_patched_403`, `test_transfer_preview_hpp_vulnerable_previews_last` (`?to=u-1001&to=u-2002` → `preview_for == "u-2002"`), `test_transfer_preview_patched_rejects_duplicate` (400), `test_promo_array_vulnerable_200_patched_400`, `test_qsink_vulnerable_uses_innerhtml` (body contains `innerHTML`; patched contains `textContent`).
- [ ] **Step 2: Run** `pytest tests/test_mutation_fixture.py -v` → FAIL (404s).
- [ ] **Step 3: Implement** the handlers in `ui_walk_app.py` (`_get_acct`, `_get_qsink`, v3 branches in `_get_api` and `_mutate`; PUT already routes to `_mutate`). Do not change any existing route's behaviour.
- [ ] **Step 4: Run** `pytest tests/test_mutation_fixture.py tests/test_ui_walk_pass1.py -v` → PASS (existing walk tests unchanged).

### Task 2: Request model — parse and apply (`mutation_logic.py`)

**Files:**
- Create: `mcp-servers/browser-mcp/mutation_logic.py`
- Test: `tests/test_mutation_logic_request.py`

**Interfaces:**
- Produces:
  - `@dataclass class Param: location: str  # "query"|"form"|"json"|"multipart"; path: tuple  # name, or JSON key path; value: object; withheld: bool`
  - `@dataclass class Req: replay_id: str; method: str; url: str; headers: dict[str, str]; body: str | None; body_kind: str  # "none"|"json"|"form"|"multipart"|"unparsed"; source: str`
  - `parse_params(req: Req) -> list[Param]` — query (order kept, repeats kept), form, JSON leaves to depth 5 (dict keys only; list items as index path elements), multipart text fields (file parts skipped).
  - `@dataclass class Op: kind: str  # "add_param"|"remove_param"|"duplicate_param"|"retype_param"|"set_param"; location: str; path: tuple; value: object = None; order: str = "orig_first"  # duplicate only: "orig_first"|"new_first"; style: str = "repeat"  # duplicate: "repeat"|"brackets"`
  - `apply_ops(req: Req, ops: list[Op]) -> Req` — returns a new Req; JSON duplicate keys produced by emitting the raw body string; content-type unchanged; multipart rebuilt with the original boundary.
  - `effective_method(req: Req) -> str` — upper-case; `_method` in query/form/JSON top level, or the three override headers, win over `req.method`.

- [ ] **Step 1: Write failing tests:** `test_parse_query_keeps_repeats_and_order`, `test_parse_json_nested_paths` (`{"a":{"b":1},"c":[{"d":2}]}` → paths `("a","b")`, `("c",0,"d")`), `test_parse_form_and_multipart_text_only`, `test_parse_unparseable_body_keeps_query_variants` (body `b"\x00\x01"`-like string, `body_kind == "unparsed"`, query params still parsed), `test_apply_add_json_top_level`, `test_apply_remove_nested`, `test_apply_duplicate_query_orders` (`a=1` + dup `2` → `a=1&a=2` and `a=2&a=1`), `test_apply_duplicate_json_raw_keys` (body text contains `"role"` twice), `test_apply_duplicate_brackets_form` (`a[]=1&a[]=2`), `test_apply_retype_each_type` (str→int/list/dict/None/bool in JSON; query `code` → `code[]=`), `test_apply_does_not_mutate_input`, `test_effective_method_override_header_and_param`.
- [ ] **Step 2: Run** `pytest tests/test_mutation_logic_request.py -v` → FAIL (module missing).
- [ ] **Step 3: Implement** the dataclasses and functions above (stdlib `json`, `urllib.parse`, `email`-free multipart split on the boundary from `Content-Type`).
- [ ] **Step 4: Run** → PASS.

### Task 3: Profiler + 3a plan builder

**Files:**
- Modify: `mcp-servers/browser-mcp/mutation_logic.py`
- Test: `tests/test_mutation_logic_plan.py`

**Interfaces:**
- Consumes: `Req`, `Param`, `Op`, `parse_params` (Task 2).
- Produces:
  - `@dataclass class Variant: variant_id: str; replay_id: str; family: str  # "add"|"remove"|"duplicate"|"retype"|"numeric-edge"; ops: list[Op]; reason: str; score: int; origin: str = "rule"  # "rule"|"agent"`
  - `@dataclass class Context: response_keys: dict[str, set[str]]  # route template -> JSON keys seen in GET responses of that template; sibling_fields: dict[str, set[str]]  # route template -> field names other recorded requests send; foreign_ids: set[str]  # object ids seen in the walk that are not self_ids/created ids`
  - `PRIV_FIELDS: tuple[str, ...]` = `role, roles, admin, is_admin, isAdmin, permissions, user_id, userId, owner_id, account_id, email_verified, verified, status, plan, tier, price, amount, discount, credits, balance`
  - `CHECK_FIELD_RE` matching `otp|code|mfa|totp|captcha|csrf|_token|xsrf|old_password|current_password|signature|sig|hmac|nonce` as whole name words.
  - `NUMERIC_EDGES = (-1, 0, 0.0001, 1e9, 2147483648, 9007199254740993, "-0", "1 ")`
  - `build_plan(req: Req, ctx: Context, *, max_variants: int = 40, max_per_family: int = 10) -> list[Variant]` — sorted by `score` desc, ties by family order add>remove>duplicate>retype>numeric-edge.
- Ranking (pins): add from `ctx.response_keys[template] - sent names` score 90 ("`X` is in a response of this resource but never sent by the UI"); add from `ctx.sibling_fields` score 70; add from `PRIV_FIELDS` score 50; remove of a `CHECK_FIELD_RE` field score 85 (also emits "empty value" and "null" forms, score 80); duplicate of an id-looking or check field score 75, others 40; retype of a check/id field 70, others 30; numeric edges only for numeric-looking values, score 45. GET requests only: an id-looking param also gets a `set_param` variant (family `add`, score 60) per foreign id (≤ 3) — never for non-GETs (spec decision 5). Withheld fields: only `remove` variants. Every variant's `reason` names the field and the rule.

- [ ] **Step 1: Write failing tests:** `test_plan_prefers_response_only_fields` (ctx says GET `/api/v3/me` has `role`, request lacks it → first variant is add `role`, reason mentions response), `test_plan_remove_check_fields_otp` (otp → remove, empty, null variants present), `test_plan_withheld_field_only_remove`, `test_plan_caps_per_family_and_total`, `test_plan_numeric_edges_only_for_numbers`, `test_plan_ids_are_stable` (same input → same `variant_id`s; id = sha1 of replay_id+ops, 12 hex), `test_plan_no_variants_for_unparsed_body_except_query`, `test_plan_foreign_ids_only_for_get`.
- [ ] **Step 2: Run** `pytest tests/test_mutation_logic_plan.py -v` → FAIL.
- [ ] **Step 3: Implement** `Context`, `Variant`, the constants and `build_plan` in `mutation_logic.py`. Route template via `endpoint_template.endpoint_template(url)`.
- [ ] **Step 4: Run** → PASS.

### Task 4: Send gates, ownership, agent-op validation

**Files:**
- Modify: `mcp-servers/browser-mcp/mutation_logic.py`
- Test: `tests/test_mutation_logic_gates.py`

**Interfaces:**
- Consumes: `Req`, `Op`, `Variant`, `apply_ops`, `effective_method`.
- Produces:
  - `OWN_ACCOUNT_SEGMENTS = ("me","self","profile","account","accounts","settings","preferences","user")`; `SHARED_SEGMENTS = ("org","orgs","organization","team","teams","workspace","workspaces","tenant","tenants","project","projects","group","groups","company","companies")`
  - `own_account_route(url: str) -> bool` — rule from Global Constraints (id-looking segment = digits, UUID, 8+ hex, or `endpoint_template` placeholder position).
  - `@dataclass class Ownership: owned: bool; kind: str  # "created"|"own-account"|"none"; reason: str`
  - `ownership(req: Req, created_ids: set[str], self_ids: set[str], snapshot_has_self_id: bool | None) -> Ownership`
  - `@dataclass class Gate: send: bool; needs_grant: bool; reason: str  # "ok"|"out-of-scope"|"payment-host"|"mutating-get"|"needs grant"|"host-not-granted"|"not-owned"|"no restore path"|"never-mutated"`
  - `gate(variant_req: Req, *, scope: Callable[[str], bool], grant, owned: Ownership, has_restore_path: bool, never_mutated: bool) -> Gate`
  - `validate_agent_ops(raw: list[dict], known_replay_ids: set[str]) -> tuple[list[Variant], list[str]]` — returns accepted variants (`origin="agent"`, `score=100`) and per-item rejection messages; ops limited to the 3a kinds plus `set_param` in this part (3b adds the rest).

- [ ] **Step 1: Write failing tests:** `test_get_variant_sent_without_grant`, `test_get_with_method_param_needs_grant` (`?_method=DELETE` → `needs_grant`, not sent without grant), `test_variant_url_mutating_word_blocked` (added `action=delete` → `mutating-get`), `test_payment_host_never`, `test_out_of_scope_never`, `test_non_get_needs_grant_and_owned`, `test_non_get_owned_without_restore_path_not_sent`, `test_own_account_route_rules` (`/api/v3/profile` true; `/api/v3/users/42/profile` false; `/org/settings` false; `/workspace/ab12cd34ef/settings` false), `test_own_account_requires_snapshot_self_id`, `test_created_id_ownership_exact_segment`, `test_never_mutated_sso_logout_payment`, `test_agent_ops_reject_forbidden_headers_crlf_long_values_unknown_replay`, `test_agent_ops_cannot_change_host`.
- [ ] **Step 2: Run** `pytest tests/test_mutation_logic_gates.py -v` → FAIL.
- [ ] **Step 3: Implement**, reusing `ui_walk_logic.is_payment_host`, `ui_walk_logic.is_mutating_get_url`, `ui_walk_logic.url_has_segment`, `ui_walk_grant.grant_allows`, `ui_walk_sso_logic.classify_url`.
- [ ] **Step 4: Run** → PASS.

### Task 5: Comparator + candidate rules

**Files:**
- Modify: `mcp-servers/browser-mcp/mutation_logic.py`
- Test: `tests/test_mutation_logic_compare.py`

**Interfaces:**
- Produces:
  - `@dataclass class Resp: status: int; length: int; body: str  # truncated to 256 KB in memory; json_keys: frozenset[str] | None`
  - `noise(b1: Resp, b2: Resp) -> dict` — `{"volatile": frozenset, "length_tol": int}`; volatile via `authz_diff._json_leaves` differences; `length_tol = max(32, abs(b1.length-b2.length)*2)`.
  - `@dataclass class Diff: status_changed: bool; class_change: str | None  # e.g. "4xx->2xx"; length_delta: int; significant_length: bool; keys_added: list[str]; keys_removed: list[str]; reflected: bool; error_signature: bool`
  - `diff(base: Resp, var: Resp, noise: dict, injected: list[str]) -> Diff` — `error_signature` = 5xx or body matches stack-trace/SQL/parse-error regex list.
  - `candidates_for(variant: Variant, base: Resp, var: Resp, d: Diff, *, readback: str  # "persisted"|"not-persisted"|"unknown"|"n/a"; single_value_resp: Resp | None = None) -> list[dict]` — returns 0..n dicts `{"type", "variant_id", "replay_id", "reason", "persisted", "evidence": {...}}`.
- Rules (pins):
  - `mass-assignment-candidate`: family add, variant 2xx, and (`readback == "persisted"` → `persisted: true`) or (`reflected` and readback `unknown` → `persisted: "unknown"`); readback `not-persisted` → no candidate.
  - `param-removal-bypass-candidate`: family remove, base (field present with our wrong/dummy value) 4xx/401/403, variant 2xx; or same status but readback persisted.
  - `hpp-candidate`: family duplicate; `single_value_resp` (only the new value) is 4xx and variant is 2xx, or variant body differs from both base and single beyond noise and reflects the second value.
  - `type-juggling-candidate`: family retype; base 4xx and variant 2xx, or variant 2xx with JSON keys equal to the success shape.
  - `numeric-edge-candidate`: family numeric-edge; variant 2xx with readback persisted, or `error_signature`.
- Evidence holds: status pair, length pair, keys diff, readback, and `redact.redact_text` of ≤ 400 chars around the first difference — never the recorded request values.

- [ ] **Step 1: Write failing tests:** one positive + one negative per rule; `test_reflection_without_readback_is_not_persisted` (reflected, readback "not-persisted" → no mass-assignment candidate; readback "unknown" → `persisted == "unknown"`, never `True`); `test_noise_masks_timestamp_fields`; `test_evidence_never_contains_recorded_values` (Req with value `FIXTURESECRET9` → not in any candidate JSON).
- [ ] **Step 2: Run** `pytest tests/test_mutation_logic_compare.py -v` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** → PASS.

### Task 6: Replay store, self-ids, cumulative send counter

**Files:**
- Create: `mcp-servers/browser-mcp/ui_walk_replay.py`
- Modify: `mcp-servers/browser-mcp/ui_walk.py` (`_Walker.__init__`, `_on_route`, `_edge`, `run` end-of-walk save; `SCHEMA_VERSION = 4`), `mcp-servers/browser-mcp/ui_walk_pass2.py` (`forward_sent` records the sent request; end of walk adds `self.sent` to the counter)
- Test: `tests/test_ui_walk_replay.py`

**Interfaces:**
- Produces:
  - `WITHHELD_RE` (names in Global Constraints, whole-word, case-insensitive); `CREDENTIAL_HEADERS = ("cookie","authorization","proxy-authorization")`.
  - `class ReplayBuffer: add(method: str, url: str, headers: dict, post: str | None, source: str, page: str | None, control_signature: str | None) -> str | None` (returns `replay_id` = `r` + 10 hex, None when out of scope / cap 2,000 reached / exact duplicate of an earlier entry → returns that entry's id); `note_self_id(value: str) -> None`; `to_dict(walk_id: str, session_file: str | None) -> dict`.
  - Stored entry: `{"replay_id","method","url","headers","body","body_truncated","withheld_fields","source","page","control_signature","response_keys"}` (`response_keys`: top-level JSON key names of an in-scope xhr/fetch GET response, ≤ 200, names only, captured in the same `page.on("response")` handler as self-ids); top level `{"schema":1,"walk_id","session_file_realpath","self_ids":[...],"entries":[...]}`.
  - `save_replay(data: dict) -> str` (0600 atomic, path `<walk_dir>/<walk-id>.replay.json`); `load_replay(walk_id: str) -> dict | None`; `delete_replays(walk_ids: list[str] | None = None) -> int`.
  - `class SendCounter(walk_id)`: `used() -> int`, `try_take(n: int, *, restore: bool, cap: int) -> bool` (file-locked via `file_lock.locked`; non-restore takes may use at most `cap - max(5, cap // 10)`), file `<walk-id>.sendcount.json`.
  - Inventory: every `api_edges[]` entry gains `"replay_id"` (or null); `inv["replay"] = {"entries": n, "withheld_fields": [...names...], "self_ids_learned": n}`.
- self_ids learning: in `_Walker`, `page.on("response")` for in-scope `xhr`/`fetch` GETs whose path has an `OWN_ACCOUNT_SEGMENTS` segment and no id segment → parse JSON top-level `id`/`user_id`/`userId`/`uuid` (string or int) → `note_self_id`. Body read async, failures ignored.

- [ ] **Step 1: Write failing tests:** `test_buffer_withholds_credentials_and_secret_fields` (Cookie/Authorization absent; `password`, `otp` → `"<hm-withheld>"`, listed), `test_buffer_keeps_csrf_value`, `test_buffer_scope_and_cap_and_dedupe`, `test_save_is_0600_and_atomic`, `test_load_rejects_bad_walk_id`, `test_send_counter_cumulative_and_reserve` (cap 20 → reserve 5; 15 normal takes ok, 16th refused, restore take still ok), `test_send_counter_survives_new_instance`, black-box (`requires_browser`): `test_map_walk_writes_replay_with_profile_put_and_self_id` — map walk of fixture `/acct` → replay has the aborted `PUT /api/v3/profile` with body, `self_ids == ["u-1001"]`, inventory edges carry `replay_id`, and `grep` of inventory JSON finds no replay body values; `test_replay_never_holds_sid_cookie` (fixture sid value absent from the replay file).
- [ ] **Step 2: Run** `pytest tests/test_ui_walk_replay.py -v` → FAIL.
- [ ] **Step 3: Implement** `ui_walk_replay.py`; wire `ReplayBuffer` into `_Walker._on_route` for `document`/`xhr`/`fetch` requests (record before the abort/continue decision, after the DOM-token abort), `_edge` gets the id; save at the end of `run()` next to `save_inventory` (the server path, `_run_walk`, calls both). Pass 2: `forward_sent` records with `source="pass2-sent"`; `SendCounter.try_take(self.sent, restore=False, cap=self.cap)` at walk end (best effort, recorded in `inv["replay"]`).
- [ ] **Step 4: Run** `pytest tests/test_ui_walk_replay.py tests/test_ui_walk_pass1.py tests/test_ui_walk_pass2.py tests/test_ui_walk_store.py -v` → PASS.

### Task 7: `?query` DOM-XSS source

**Files:**
- Modify: `mcp-servers/browser-mcp/ui_walk_events.py` (`Recorder.plant_sources`, new `server_token_allowed`), `mcp-servers/browser-mcp/ui_walk.py` (`_on_route` exemption)
- Test: `tests/test_ui_walk_dom.py` (extend)

**Interfaces:**
- Produces:
  - `Recorder.plant_sources(...)` result dict gains key `"query"`: `"skipped" | "no-params" | "planted" | "failed" | "left-scope"`; for each of the first 3 query params of the page URL, one budget-charged `page.goto(url with that param's value = dom_payload(tok))`, source name `"query:<param>"`, then return to the original URL is **not** needed (the next page load replaces it). Per-walk cap 30 query plants (`_MAX_QUERY_PLANTS`).
  - `Recorder.server_token_allowed(tok: str, url: str, is_main_nav: bool) -> bool` — True only for a `query:` token, a main-frame navigation, and `_defrag(url)` equal to the URL it planted.
  - `_on_route`: when `dom_token_in` finds a token and `server_token_allowed` is True → continue (still scope/payment/mutating-GET checked by `route_decision`); else unchanged abort.
  - Candidates: existing `dom-xss-candidate` / `dom-sink-candidate` with `source: "query:<param>"`.

- [ ] **Step 1: Write failing tests** (`requires_browser`): `test_query_source_vulnerable_qsink_dom_xss` (map walk of `/qsink?msg=hello` vulnerable → a `dom-xss-candidate` with source `query:msg`), `test_query_source_patched_no_candidate`, `test_query_token_only_reaches_server_on_planted_nav` (fixture request log: token appears only in the `/qsink` navigation, not in any subresource), `test_query_plants_budget_charged_and_capped`.
- [ ] **Step 2: Run** `pytest tests/test_ui_walk_dom.py -k query -v` → FAIL.
- [ ] **Step 3: Implement.** Plant order: query (if params) → window.name → hash, so the hash plant still runs on the original URL (re-goto the original URL, budget-charged, after query plants).
- [ ] **Step 4: Run** `pytest tests/test_ui_walk_dom.py tests/test_ui_walk_events.py -v` → PASS.

### Task 8: Runner (`mutation_runner.py`)

**Files:**
- Create: `mcp-servers/browser-mcp/mutation_runner.py`
- Test: `tests/test_mutation_runner.py`

**Interfaces:**
- Consumes: Tasks 2-6.
- Produces:
  - `make_plan(walk_id: str, *, request_filter: str = "", max_requests: int = 50) -> dict` — loads inventory + replay, builds `Context` from the replay entries (`response_keys`, sibling field names, `foreign_ids`), runs `build_plan` + `gate` (with `has_restore_path` computed from available snapshot GETs), writes `<walk-id>.plan-<plan_id>.json` (no recorded values: ops show field names and **our** injected values), returns `{"plan_id","walk_id","requests":[{"replay_id","method","route","variants":[{"variant_id","family","change","reason","needs_grant","would_send","why_not"}]}]}`.
  - `async run(plan_id: str, *, session_file: str, variants: str = "auto", extra_variants: list[dict] | None = None, drop_variants: list[str] | None = None, scope_check=None, grant=None, upstream_proxy: str = "", max_sent: int = 400, action_delay_s: float | None = None) -> dict` — the results dict (also saved as `<walk-id>.mutations-<run_id>.json`): `{"run_id","plan_id","walk_id","status"  # "complete"|"blocked"|"auth_lost"|"budget_exhausted"|"restore_failed"|"refused"; "sent": int, "results":[...per variant: variant_id, gate, base/var status+length, diff, readback, restore...], "candidates":[...], "created_ids":[...], "restore_failures":[{"route","field"}], "honest_limits":[...]}`.
  - Behaviour pins: identity check first (Global Constraints) → `refused`; one browser context via `browser_confirm._new_page` + mirror handling copied from the walker's `_request_context` rules; GET baseline ×2 → `noise`; non-GET baseline ×1 with withheld fields set to a dummy of ours (`"000000"` for otp-like, `"hm-wrong"` otherwise); snapshot GET ×2 before the first state-changing variant per object; after each state-changing variant: read-back GET → `persisted`/`not-persisted`; persisted or unknown → restore = the variant request with touched fields set to snapshot values (or the original recorded request when the field had no snapshot value) via `SendCounter.try_take(1, restore=True)`, then read-back; still differs → `restore_failed` for that object; ids in 2xx non-GET JSON responses (`ui_walk_pass2._created_id`) → `ui_walk_store.register_created_id(f"mut-{run_id}", id)` + `created_ids`; every send: `browser_confirm._enforce_budget("browser-mcp")` + `scope` + delay; 401 after a 2xx baseline → `auth_lost` stop; 429 / `classify_block` → host `blocked`; duplicate family also sends the single-new-value request (`single_value_resp`).
  - `browser_confirm._log_call("browser-mcp:mutations", [walk_id, plan_id, run_id], ...)` once per run.

- [ ] **Step 1: Write failing tests** (`requires_browser`, fixture app, `HUNTMCP_UI_WALK_DIR` tmp, budget patched like `test_ui_walk_sso_walk.py`): `test_plan_lists_variants_with_reasons_and_no_values`, `test_run_without_grant_sends_only_gets` (fixture `non_get_requests()` count unchanged by the run), `test_run_vulnerable_finds_mass_assignment_persisted_and_restores` (candidate `persisted: true`; after run `app.v3_me["role"] == "user"`), `test_run_patched_no_mass_assignment`, `test_run_vulnerable_otp_removal_candidate` / patched none, `test_run_vulnerable_hpp_candidate` / patched none, `test_run_vulnerable_promo_type_juggling` / patched none, `test_run_refuses_other_identity`, `test_auth_lost_mid_run_stops` (fixture invalidates sid after N requests), `test_restore_failure_stops_object` (fixture mode where PUT persists but ignores restores → status `restore_failed`, route+field named, no further PUT to that route), `test_cap_cumulative_across_runs`, `test_block_stops_host` (fixture `refuse_all` after baseline), `test_results_and_plan_files_hold_no_secret` (grep `FIXTURESECRET`, sid, otp value, password across every file in the walk dir except `.replay.json`).
- [ ] **Step 2: Run** `pytest tests/test_mutation_runner.py -v` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** → PASS.

### Task 9: MCP tools, teardown cleanup, agent prompts

**Files:**
- Modify: `mcp-servers/browser-mcp/server.py`, `mcp-servers/browser-mcp/ui_walk_teardown.py`, `.claude/agents/exploit-agent.md`, `.claude/agents/huntbrain.md`, `.claude/agents/recon-agent.md` (one line), `CLAUDE.md` (browser-mcp line in the MCP servers paragraph)
- Test: `tests/test_ui_walk_tools.py` (extend), `tests/test_ui_walk_teardown.py` (extend), `tests/test_ui_walk_agent_wiring.py` (extend)

**Interfaces:**
- Produces tools (Tier-2, URL-free args so the scope hook gates nothing new; scope is enforced in code on every send):
  - `plan_mutations(walk_id: str, request_filter: str = "", max_requests: int = 50) -> str`
  - `run_mutations(plan_id: str, session_file: str = "", variants: str = "auto", extra_variants: list[dict] | None = None, drop_variants: list[str] | None = None, upstream_proxy: str = "") -> str` → job id via `job_runtime.start_thread_job("ui-walk-mutations", ..., _UI_JOBS, ...)`
  - `check_mutations(job_id: str) -> str`, `list_mutation_runs() -> str`
  - Output layout: status line first (`RESTORE FAILED: <route> field <name>` lines before anything else when present), counts (planned / sent / not-sent-by-reason), candidates grouped by type (quarantined target text), results file path, honest limits, provenance line last.
  - Teardown `cleanup` step: also destroys `mut-*` registered created ids and calls `ui_walk_replay.delete_replays()` for the engagement; reported in the teardown output.
- Prompts: exploit-agent — after a walk: `plan_mutations` → read reasons, add `extra_variants` where the request suggests more → `run_mutations` → work `mass-assignment` / `param-removal-bypass` / `hpp` / `type-juggling` / `numeric-edge` candidates with `access-control-and-idor` / `api-security-top10` / `deep-cut-surfaces`; never treat a candidate as confirmed. huntbrain — the mutation step sits after Pass 1 (and Pass 2 when granted) per app.

- [ ] **Step 1: Write failing tests:** `test_tools_registered_and_docstrings`, `test_check_mutations_restore_failed_first_and_provenance_last`, `test_output_quarantines_target_text`, `test_run_mutations_requires_existing_plan`, `test_teardown_cleanup_deletes_replay_and_mutation_objects`, `test_agent_prompts_mention_plan_and_run_mutations`.
- [ ] **Step 2: Run** the three test files → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `pytest tests/test_ui_walk_tools.py tests/test_ui_walk_teardown.py tests/test_ui_walk_agent_wiring.py -v` → PASS.

### Task 10: Full verification

- [ ] **Step 1:** `pytest tests/ -k "ui_walk or mutation" -q` → all pass (skips only where the browser/IdP image is missing).
- [ ] **Step 2:** `pytest tests/ -q` → full suite green (record counts).
- [ ] **Step 3:** `ruff check mcp-servers/ --ignore E402,F811 --target-version py312` and `python -m py_compile` on every changed `.py` → clean.
- [ ] **Step 4:** Review and audit: `/code-review` and `/security-review` on the branch; fix findings TDD; re-run Steps 1-3.
- [ ] **Step 5:** Prove it runs (after asking the user to switch the engagement): `scripts/switch-engagement.sh set ui-walk-proof.localhost --force`; serve the fixture; real `mcp__browser-mcp__start_ui_walk` (map) → `plan_mutations` → `run_mutations` without grant (GET-only) → `check_mutations`; then with the human-written grant for the fixture host → mass-assignment `persisted: true` + restored; record `Runtime-verified:` evidence; switch back to `bentley.com`.
- [ ] **Step 6:** Commit / PR only on the user's explicit OK (explicit `git add` of the changed files, no attribution lines).
