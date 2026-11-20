# Page-Comprehension UI-Walk Implementation Plan (#164)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the rendered page + its inputs + its actions the unit of testing: a browser-mcp UI-walk (Pass 1 safe map, Pass 2 canary submit with create→destroy→verify), a human-gated teardown, viewable screenshots, sessionStorage-aware sessions, and surface-map/coverage-gate integration.

**Architecture:** All new code lives inside `browser-mcp` (pure-logic module + store module + grant module + Playwright driver) reusing `browser_confirm`'s context setup, budget, audit, and quarantine patterns. Long walks run as `job_runtime` thread jobs. Results become `page`/`input`/`action` surface-map nodes that `coverage_manifest` gates on. State-changing teardown reuses `state_change_confirm`'s human-TTY token; Pass 2 is enabled by a human-owned, hook-protected grant file.

**Tech Stack:** Python 3.12, Playwright 1.62 (async, already in venv), FastMCP, pytest, stdlib `http.server` for the fixture app. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-11-19-page-comprehension-ui-walk-design.md`

## Global Constraints

- No new Python dependencies (no Pillow). Playwright pin stays `>=1.40.0,<1.63.0`.
- Existing browser-mcp tool names, params and output contracts unchanged; new params are optional with old-behaviour defaults. `screenshot(as_base64=True)` returns exactly `data:image/png;base64,...` as today.
- Provenance line stays the LAST line of every browser-mcp tool output; target-controlled text in output goes through `injection_boundary.quarantine`.
- Every page load and every real (sent) non-GET calls `budget_guard.enforce("browser-mcp")`; every walk/teardown writes `audit_log.log_call`.
- In-code scope: start URL, every top-level navigation, every sent non-GET checked by a scope predicate (`_default_scope_check`, Task 1); out-of-scope → aborted + recorded.
- Pass 1 sends ZERO non-GET/HEAD/OPTIONS requests and zero client→server WebSocket frames; service workers blocked.
- Controls classified `logout` / `account-delete` / `payment` are never clicked by `walk()` in any mode; non-GETs to payment-provider hosts are aborted in every mode, teardown included.
- Pass 2 (`mode="canary"`) refused unless the grant file `data/engagements/<slug>/ui-walk-authorized.yaml` has `canary_submit: true` (and, if `hosts` given, the start host is listed). Default `real_submit_cap_per_walk` = 200.
- Destructive clicks only on walker-owned objects (ownership rule, Task 1). Unproven → map-only, `skipped_reason="ownership-unproven"`.
- Teardown requires a fresh `state_change_confirm` token for host + {POST,PUT,PATCH,DELETE} + fingerprint; account deletion only for roster identities with `disposable: true`.
- Defaults: `max_pages=50`, `max_clicks_per_page=40`, `wall_clock_s=1200`, `MAX_PER_TEMPLATE=3`, screenshot JPEG quality 70, viewport 1280×800, full-page clip max height 4000px.
- Inventory JSON carries `"schema_version": 1`.
- Commits: explicit `git add <path>` only; never `git add -A`; `data/writeups/hexbrain-*` and `oom` stay untracked; no Co-Authored-By/AI footer (repo CLAUDE.md).
- Real-browser tests skip cleanly when Playwright or a Chromium executable is unavailable (CI installs neither).

## Review Focus

1. **Non-English / icon-only destructive controls** ("Löschen", a trash-can icon with no text): the classifier cannot see them, but Pass 1 must still send zero non-GETs — network interception, not the classifier, is the guarantee. Test in Task 4.
2. **Unbounded URL spaces** (calendar `?d=` next-links, pagination): the walk must terminate — `MAX_PER_TEMPLATE` per route template plus `max_pages`. Test in Task 4.
3. **Controls that open a popup/new tab** (`target=_blank`, `window.open`) that then POSTs: interception must be context-level so the popup is covered too. Test in Task 4.
4. **`window.confirm("Are you sure?")` on delete**: Pass 1 must dismiss (and the request is aborted anyway); Pass 2 owned-object delete must accept, otherwise create→destroy→verify silently never deletes. Test in Task 7.
5. **Canary rendered escaped** (patched app): must be reported as a reflected render sink with `executed=false`, never as an executing sink. Test in Task 6.

---

### Task 1: Pure walker logic

**Files:**
- Create: `mcp-servers/browser-mcp/ui_walk_logic.py`
- Test: `tests/test_ui_walk_logic.py`

**Interfaces:**
- Produces:
  - `CLASSIFICATIONS = ("navigational","expand","submit","destructive","logout","account-delete","payment","other")`
  - `classify_control(ctrl: dict) -> str` — `ctrl` keys: `tag, role, text, aria_label, href, type, form_action, form_method`. Precedence: account-delete > payment > logout > destructive > submit > expand > navigational > other.
  - `NEVER_CLICK = frozenset({"logout","account-delete","payment"})`
  - `control_signature(ctrl: dict, page_template: str) -> str` — sha1-hex[:16] of `page_template | role | normalized text | form_action | dom_path_without_indices` (`ctrl["dom_path"]`, strip `:nth-of-type(n)`/`[n]`).
  - `is_mutating_get_url(url: str) -> bool` — path/query contains a keyword from `MUTATING_URL_WORDS = ("logout","signout","sign-out","log-out","delete","remove","revoke","cancel","unsubscribe","deactivate","destroy")` as a path segment or query key/value token.
  - `PAYMENT_HOST_SUFFIXES = ("stripe.com","paypal.com","braintreegateway.com","adyen.com","checkout.com","razorpay.com","squareup.com","klarna.com","paddle.com")`; `is_payment_host(host: str) -> bool`.
  - `make_canary() -> str` — `"hm" + secrets.token_hex(4)` (10 chars).
  - `canary_value(token: str, input_type: str, maxlength: int | None) -> str` — text/textarea/search/None: `f"{token}\"'><img src=x onerror=alert('{token}')>"`; email: `f"{token}@example.com"`; url: `f"https://example.com/{token}"`; number/range/date/etc.: `""` (caller leaves default); truncate to `maxlength` but always keep the token (fall back to bare token if payload doesn't fit).
  - `is_walker_owned(control_request: dict | None, created_ids: set[str], container_text: str, tokens: set[str]) -> bool` — True iff any created id appears as a path segment/query value/JSON body value in `control_request` (`{"url","body"}`), OR any token is a substring of `container_text`.
  - `looks_logged_out(final_url: str, controls: list[dict], had_session: bool) -> bool` — False if not `had_session`; True if final_url path matches `/(login|signin|sign-in|auth)\b` or any control with text matching `^(log ?in|sign ?in)$` (case-insensitive) is present.
  - `_default_scope_check(url: str) -> bool` — host via `scope_guard._host_of`; `scope_guard.is_safe_test_host(host)` → True; else `load_engagement()` + `is_in_scope`; `NoEngagementFile` → False.

- [ ] **Step 1: Write failing tests** — one test per function, including:
  - `classify_control({"tag":"button","text":"Delete item"}) == "destructive"`; `{"text":"Sign out"}` → `"logout"`; `{"text":"Delete account"}` → `"account-delete"`; `{"text":"Pay now"}` → `"payment"`; `{"role":"tab","text":"API keys"}` → `"expand"`; `{"tag":"button","type":"submit","text":"Save"}` → `"submit"`; `{"tag":"a","href":"/items"}` → `"navigational"`; `{"text":"Löschen"}` → `"other"` (documents the limit; Pass 1 interception covers it).
  - `control_signature` equal for two rows differing only in `:nth-of-type(3)` vs `(7)`, different for different text.
  - `is_mutating_get_url("https://x/a/logout")`, `("https://x/u?action=delete")` True; `("https://x/catalog?page=2")` False; `("https://x/cancellation-policy")` False (segment match, not substring).
  - `is_payment_host("api.stripe.com")` True, `("stripe.com.evil.io")` False.
  - `canary_value` keeps token under `maxlength=12`; email shape; number → `""`.
  - `is_walker_owned` true via id in `/api/items/42` with `created_ids={"42"}`; true via container text; false when neither; false for id `"4"` vs url `/api/items/42` (segment-exact).
  - `looks_logged_out` cases incl. `had_session=False` → False.
  - `_default_scope_check("http://127.0.0.1:8000/")` True with no engagement; external host with no engagement → False.
- [ ] **Step 2:** `.venv/bin/python -m pytest tests/test_ui_walk_logic.py -v` → FAIL (module missing).
- [ ] **Step 3:** Implement `ui_walk_logic.py` (stdlib only + `scope_guard`).
- [ ] **Step 4:** Re-run → PASS. `ruff check mcp-servers/browser-mcp/ --ignore E402,F811 --target-version py312` clean.
- [ ] **Step 5:** Commit `git add mcp-servers/browser-mcp/ui_walk_logic.py tests/test_ui_walk_logic.py` — `feat: ui-walk control classification, canary, ownership logic (#164)`.

### Task 2: Fixture app + sessionStorage-aware sessions

**Files:**
- Create: `tests/fixtures/__init__.py` (if absent), `tests/fixtures/ui_walk_app.py`
- Modify: `mcp-servers/browser-mcp/browser_confirm.py` (`_new_page`, `_save_session`, every public function's signature), `mcp-servers/browser-mcp/server.py` (every tool gains `session_storage: dict[str, str] | None = None`, passed through)
- Test: `tests/test_browser_session_storage.py`

**Interfaces:**
- Produces (fixture): `serve(vulnerable: bool = True) -> FixtureApp` with `.base_url` (`http://127.0.0.1:<port>`), `.alt_base_url` (`http://localhost:<port>`, used as the "out-of-scope" host via an injected scope predicate), `.requests: list[tuple[str, str]]` (method, path) appended server-side, `.items: dict[str, dict]`, `.close()`. Also `requires_browser` = `pytest.mark.skipif(...)` (playwright import fails OR neither `browser_launch.find_browser_executable()` nor Playwright's bundled chromium exists).
  Routes (vulnerable vs patched behaviour in brackets):
  - `/` index: links to `/items`, `/contact`, `/settings`, `/checkout`, `/activity`, `/app`, `/cal?d=1`, `/logout` (GET), `{alt_base_url}/elsewhere`, a `target=_blank` link to `/popup`, an icon-only `<button aria-label="" data-act="del-all">🗑</button>` that `fetch(..., {method:"POST"})` to `/api/purge`, and a `<button>Löschen</button>` POSTing to `/api/purge`.
  - `/contact`: after 300 ms JS inserts `<iframe src="/embed/form">`; the iframe form (`name`, `message`) POSTs `/api/contact`.
  - `/items`: JS `GET /api/items` renders rows [`innerHTML` | `textContent`]; "New item" opens a hidden modal with `name`, `description` → `POST /api/items` → `{"id": "<n>"}`; each row: "View" link `/items/<id>` (detail via `GET /api/items/<id>`), "Delete" button → `confirm("Are you sure?")` → `DELETE /api/items/<id>`.
  - `GET /api/items/<id>` after delete: [200 with item (soft delete) | 404].
  - `/activity`: renders latest item names [`innerHTML` | `textContent`] (cross-page sink).
  - `/settings`: tabs; "API keys" tab reveals input `key_label`; "Delete account" button → `POST /api/account/delete`.
  - `/checkout`: "Pay now" → `fetch("https://api.stripe.com/v1/charges",{method:"POST"})`.
  - `/popup`: on load `fetch("/api/popup-post",{method:"POST"})`.
  - `/cal?d=N`: link to `/cal?d=N+1` (unbounded).
  - `/app`: SPA; reads `sessionStorage["oidc.user"]`; absent → only a "Sign in" button; present → "Welcome, alice" + input `nickname`. `/app/login` sets `sessionStorage["oidc.user"]` via JS then redirects to `/app`.
  - Cookie auth: `/login` POST-free GET sets `sid=valid`; `/items`, `/settings`, `/activity` without valid `sid` → 302 `/login`. `/logout` [does not invalidate sid server-side | invalidates].
  - WebSocket: not needed in fixture; WS frame blocking is unit-checked by asserting `context.route_web_socket` is registered (Task 4).
- Produces (browser_confirm): `_new_page(..., session_storage: dict[str,str] | None = None)`; session file sidecar key `SESSION_STORAGE_KEY = "huntmcp_session_storage"` mapping `origin -> {k: v}`; `_save_session(context, session_file, page=None)` additionally evaluates `Object.entries(sessionStorage)` on each open page's origin and merges into the sidecar; `_new_page` restores via `add_init_script` guarded by `location.origin === <origin>`; explicit `session_storage` seed applied for the target URL's origin.

- [ ] **Step 1: Write failing tests** (`@requires_browser`, fixture `serve()`):
  - `test_session_storage_survives_save_and_restore`: `render_dom(app.base_url+"/app/login", session_file=f)` then `render_dom(app.base_url+"/app", session_file=f)` → html contains `Welcome, alice` (today: shows `Sign in` — this is the bentley hypothesis reproduced).
  - `test_session_storage_seed_param`: `render_dom(base+"/app", session_storage={"oidc.user": "{\"name\":\"alice\"}"})` → `Welcome, alice`.
  - `test_session_storage_is_origin_guarded`: sidecar for `base_url` origin not visible on `alt_base_url` (`render_dom(alt+"/app", session_file=f)` → `Sign in`).
  - `test_session_file_is_0600_after_save`.
  - `test_existing_session_file_without_sidecar_still_loads` (old-format file).
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Write the fixture; implement the browser_confirm/server changes (Playwright ignores the unknown top-level key when given the file path — if it does not, load JSON, strip the key, pass the dict as `storage_state`). `chmod 0o600` after `context.storage_state` write.
- [ ] **Step 4:** Run new tests + `tests/test_browser_mcp*.py` → PASS.
- [ ] **Step 5:** Commit fixture + browser_confirm + server + test — `feat: browser-mcp persists/restores sessionStorage, session_storage seed (#164)`.

### Task 3: Viewable screenshots

**Files:**
- Modify: `mcp-servers/browser-mcp/browser_confirm.py` (add `screenshot_to_file`), `mcp-servers/browser-mcp/server.py` (`screenshot` gains `as_base64: bool = False`)
- Test: `tests/test_browser_screenshot_file.py`

**Interfaces:**
- Produces: `async def screenshot_to_file(url, wait_ms=1000, timeout_ms=DEFAULT_TIMEOUT_MS, cookie_header=None, bearer_token=None, local_storage=None, session_storage=None, session_file=None, out_dir: str | None = None, page=None) -> dict` → `{"path","width","height","status","final_url","error"}`. Default `out_dir = engagement_paths.resolve_dir("screenshots")`. File name `<UTC yyyymmddTHHMMSS>-<host>-<6hex>.jpg`. Viewport 1280×800, `type="jpeg", quality=70`, `full_page=True` with `clip` height `min(scrollHeight, 4000)`. When `page` is passed (used by the walker) it screenshots that page without navigating or launching.
- `server.screenshot(..., as_base64=False)`: default returns `Screenshot saved: <path> (<w>x<h>). View it with Read.` + provenance line last; `as_base64=True` returns the exact old string.

- [ ] **Step 1: Failing tests:** file exists, is JPEG (starts `b"\xff\xd8"`), height ≤ 4000 on a fixture page made 10000px tall (add `/tall` route to fixture), size < 1 MB; `as_base64=True` output starts `data:image/png;base64,`; default output's last line starts `\nProvenance` shape (`splitlines()[-1].startswith("Provenance (for case-mcp add_evidence):")`).
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement. **Step 4:** Run → PASS.
- [ ] **Step 5:** Update `.claude/agents/exploit-agent.md` step referencing `screenshot(url)` to say "returns a saved JPEG path — `Read` it to look at the page; attach the path as screenshot evidence". Commit `browser_confirm.py server.py tests/test_browser_screenshot_file.py tests/fixtures/ui_walk_app.py .claude/agents/exploit-agent.md` — `feat: browser-mcp screenshot saves a viewable JPEG by default (#164)`.

### Task 4: Pass 1 map driver

**Files:**
- Create: `mcp-servers/browser-mcp/ui_walk.py`
- Test: `tests/test_ui_walk_pass1.py`

**Interfaces:**
- Consumes: Task 1 functions; `browser_confirm._new_page/_save_session/_launch_kwargs/_enforce_budget/_log_call`; `screenshot_to_file(page=...)`; `endpoint_template.endpoint_template`.
- Produces:
  - `MAX_PER_TEMPLATE = 3`
  - `async def walk(start_url: str, mode: str = "map", *, session_file: str | None = None, cookie_header: str | None = None, bearer_token: str | None = None, local_storage: dict | None = None, session_storage: dict | None = None, max_pages: int = 50, max_clicks_per_page: int = 40, same_origin_only: bool = True, wall_clock_s: int = 1200, scope_check: Callable[[str], bool] | None = None, grant: "Grant | None" = None, walk_id: str | None = None, action_delay_s: float | None = None, screenshot_dir: str | None = None) -> dict`
  - Inventory dict (schema_version 1): `{schema_version, walk_id, start_url, mode, status ∈ {"complete","auth_lost","budget_exhausted","time_limit","refused","error"}, error, honest_limits: [str], pages: [Page], real_submits: [], canaries: [], sinks: [], candidates: []}`; `Page = {url, template, title, screenshot, inputs: [{frame_origin, form_action, form_method, name, id, type, label, placeholder, required, maxlength, revealed_by}], controls: [{signature, text, role, classification, clicked, skipped_reason}], api_edges: [{control_signature, method, url, sent, blocked_reason, body_shape}], ws_frames_blocked: int, third_party_hosts: [str]}`.
  - `blocked_reason ∈ {"pass1-non-get","out-of-scope","payment-host","mutating-get","ws-frame","cap-reached"}`.
- Behaviour: one browser + one context per walk; `service_workers="block"`; `context.route("**/*", handler)` (context-level → popups covered); `context.route_web_socket("**/*", ...)` dropping client→server frames in map mode; `page.on("dialog", dismiss)` in map mode; BFS over in-scope same-origin links, skipping a URL whose template already has `MAX_PER_TEMPLATE` visits; per page: goto (`budget enforce`), wait `networkidle` (bounded 5 s), auth-lost check (on hit: re-read `session_file` once into a fresh context and retry; still lost → `status="auth_lost"`, stop), enumerate inputs in all frames (`page.frames`, includes cross-origin iframes) + open shadow roots, expand `expand` controls and re-enumerate (new inputs get `revealed_by`), click remaining deduped controls except `NEVER_CLICK` (record `skipped_reason="never-click"`), go back to the page URL after a click navigates, screenshot via `screenshot_to_file(page=...)`. `honest_limits` always includes the "GET with non-obvious mutating URL cannot be detected" sentence from the spec. Rate: `action_delay_s` defaults to `load_engagement().min_request_interval_s` (0 if none).

- [ ] **Step 1: Failing tests** (`@requires_browser`, `serve()`, `scope_check=lambda u: urlparse(u).hostname == "127.0.0.1"`, session cookie `sid=valid`):
  - `test_pass1_sends_zero_non_get`: after walk, `[m for m,_ in app.requests if m not in ("GET","HEAD","OPTIONS")] == []` (covers Löschen, icon-only button, popup POST, iframe form, modal submit, delete, settings delete-account).
  - `test_pass1_records_intercepted_edges`: edges include `POST /api/items`, `DELETE /api/items/<id>` with `sent=False, blocked_reason="pass1-non-get"`, and `POST https://api.stripe.com/v1/charges` with `blocked_reason="payment-host"`.
  - `test_pass1_finds_lazy_iframe_inputs`: `/contact` page inputs include `name`,`message` with `frame_origin` = base origin and `form_action` ending `/api/contact`.
  - `test_pass1_finds_modal_and_tab_revealed_inputs`: `/items` has `name`/`description` with non-empty `revealed_by`; `/settings` has `key_label`.
  - `test_pass1_never_clicks_logout_payment_account_delete`: controls `Sign out`/`/logout`, `Pay now`, `Delete account` have `clicked=False, skipped_reason="never-click"`; `("GET","/logout") not in app.requests`.
  - `test_pass1_out_of_scope_not_navigated`: no page with host `localhost`; edge/nav recorded `blocked_reason="out-of-scope"`.
  - `test_pass1_unbounded_template_terminates`: pages with template `/cal` count ≤ `MAX_PER_TEMPLATE`; `status=="complete"`.
  - `test_pass1_popup_post_aborted`: `("POST","/api/popup-post") not in app.requests` and edge recorded.
  - `test_pass1_dedups_row_controls`: with 20 items seeded, `View`/`Delete` row controls clicked once per signature.
  - `test_pass1_auth_lost_stops`: walk with `session_file` whose `sid` is invalid → `status=="auth_lost"`, pages == [] or only the login page; not "complete".
  - `test_pass1_screenshot_per_page`: every page has an existing `.jpg` path.
  - `test_pass1_respects_max_pages` (max_pages=2 → ≤2 pages).
  - `test_pass1_budget_enforced` (monkeypatch `_enforce_budget` to raise after 3 calls → `status=="budget_exhausted"`).
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement `walk()` map mode. **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `ui_walk.py tests/test_ui_walk_pass1.py` — `feat: ui-walk Pass 1 safe map driver (#164)`.

### Task 5: Inventory store, surface-map nodes, coverage battery

**Files:**
- Create: `mcp-servers/browser-mcp/ui_walk_store.py`
- Modify: `mcp-servers/coverage_manifest.py` (`BATTERY_BY_KIND`, `required_classes`)
- Test: `tests/test_ui_walk_store.py`, extend `tests/test_coverage_manifest.py`

**Interfaces:**
- Produces:
  - `walk_dir() -> str` = `engagement_paths.resolve_dir("ui-walk")`.
  - `save_inventory(inv: dict) -> str` (path `ui-walk/<walk_id>.json`, atomic); `load_inventory(walk_id: str) -> dict | None`.
  - `CANARY_REGISTRY = "canaries.json"`; `register_canary(token: str, record: dict) -> None` (file-locked append); `load_canaries() -> dict[str, dict]`.
  - `emit_nodes(inv: dict, map_path: str | None = None) -> dict[str, int]` → counts `{"page","input","action"}`; signatures exactly: page `page:<template>`; input `input:<form_action_template>:<name>` (parent = page node); action `action:<METHOD> <endpoint_template(url)>` (parent = page node) with node meta `{"classification": <control classification>, "control_text": ..., "walk_id": ...}`. Uses `surface_map.add_node(kind, label, signature, parent_id=..., meta=..., path=map_path)` (already takes `meta`; dedups on kind+signature+parent).
  - `coverage_manifest.BATTERY_BY_KIND` adds `"page": {"xss","access-control","csrf"}`, `"input": {"xss","sqli"}`, `"action": {"csrf","idor","access-control","business-logic"}`; `required_classes(node)` adds `"business-logic"` when `node.get("meta",{}).get("classification") == "destructive"` (already in action battery — the rule matters for a destructive control recorded under another kind; keep it kind-agnostic).
- [ ] **Step 1: Failing tests:** save/load round-trip + atomic temp cleanup; canary registry concurrent append (two processes or threads, both tokens present); `emit_nodes` on a hand-built inventory yields the exact signatures, parent links, meta, and is idempotent (second call → same ids, no duplicates); `compute_manifest` on an isolated map with one `page`, `input`, `action` node → open cells exactly the battery above; `is_exhausted` False until covered/`mark_na`.
- [ ] **Step 2–4:** FAIL → implement → PASS; also run `tests/test_surface_map*.py tests/test_coverage_manifest.py`.
- [ ] **Step 5:** Commit — `feat: ui-walk inventory store + page/input/action surface nodes in the coverage gate (#164)`.

### Task 6: Grant file + Pass 2 canary submit and sink detection

**Files:**
- Create: `mcp-servers/browser-mcp/ui_walk_auth.py`
- Modify: `mcp-servers/browser-mcp/ui_walk.py` (canary mode), `scripts/hooks/scope_gate_hook.py` (`_protected_paths` adds the grant path for the active engagement)
- Test: `tests/test_ui_walk_auth.py`, `tests/test_ui_walk_pass2.py`, extend `tests/test_hook_tamper_resistance.py`

**Interfaces:**
- Produces:
  - `GRANT_FILENAME = "ui-walk-authorized.yaml"`; `grant_path(slug: str | None = None) -> str` (under `engagement_paths.ENGAGEMENTS_ROOT/<slug>/`; active slug when None; raises `RuntimeError` if no active engagement).
  - `@dataclass Grant: canary_submit: bool; hosts: list[str]; real_submit_cap_per_walk: int = 200`.
  - `load_grant(slug: str | None = None) -> Grant | None` — absent/unparsable/`canary_submit` not literally `True` → None.
  - `grant_allows(grant: Grant | None, host: str) -> bool`.
  - `walk(mode="canary")`: `grant` param None → `load_grant()`; not allowed → `status="refused"`, `error="canary mode needs data/engagements/<slug>/ui-walk-authorized.yaml with canary_submit: true"`, no browser launched. Allowed → runs Pass 1 mapping, then for each form/submit control in scope: fill every text-like input with `canary_value(make_canary(), type, maxlength)` (register each token via `register_canary` with `{page, input, walk_id}`), click submit / dispatch the form for real (non-GET allowed only to in-scope, non-payment hosts, count ≤ `real_submit_cap_per_walk` else `blocked_reason="cap-reached"`; `budget enforce` per sent request); record each in `real_submits` (`{method,url,status,created_id}` — `created_id` from JSON response `id`/`uuid`/`_id` when present); dialogs accepted only during owned-object deletes (Task 7) else dismissed; then re-walk all mapped pages: every registered token found in rendered DOM text/HTML → `sinks.append({token, origin_page, origin_input, sink_page, rendered_raw: bool, executed: bool})`, `executed` via page dialog handler/`document.title` containing the token; each sink also appended to `candidates` as `{type:"stored-xss" if executed else "reflected-render", ...evidence}`.
  - Hook: `_protected_paths()` adds `Path(ui_walk_auth.grant_path()).resolve()` when an active engagement exists (wrapped so no active engagement → skip).
- [ ] **Step 1: Failing tests:**
  - `test_ui_walk_auth.py`: absent file → None; `canary_submit: "yes"` → None; `hosts` restriction honoured; malformed YAML → None.
  - `test_canary_mode_refused_without_grant` (no browser needed: assert `status=="refused"` and launcher never called — monkeypatch `async_playwright`).
  - `test_hook_blocks_agent_write_to_grant_file`: Write tool call to the grant path → hook blocks (mirror existing tamper tests' `_run_main` shape).
  - `@requires_browser` vulnerable fixture with `Grant(True, [], 200)`: `test_pass2_cross_page_executing_sink` — a sink with `origin_page` `/items`, `sink_page` `/activity`, `executed=True`; `test_pass2_never_posts_to_payment_or_out_of_scope`; `test_pass2_respects_submit_cap` (cap=1 → exactly one sent non-GET, rest `cap-reached`); `test_pass2_records_created_id`.
  - Patched fixture: `test_pass2_escaped_render_not_executing` — sinks exist with `executed=False`, candidates type `reflected-render`, none `stored-xss`.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement. The hook edit is a protected-path edit: **the human must run `scripts/confirm-hook-edit.sh` first** — stop and ask the user at this step.
- [ ] **Step 4:** Run new tests + `tests/test_hook_tamper_resistance.py tests/test_scope_gate_hook.py` → PASS.
- [ ] **Step 5:** Commit two concerns separately: (a) `ui_walk_auth.py scope_gate_hook.py tests/test_ui_walk_auth.py tests/test_hook_tamper_resistance.py` — `feat: human-owned ui-walk grant file, hook-protected (#164)`; (b) `ui_walk.py tests/test_ui_walk_pass2.py` — `feat: ui-walk Pass 2 canary submit + render-sink detection (#164)`.

### Task 7: Create → destroy → verify

**Files:**
- Modify: `mcp-servers/browser-mcp/ui_walk.py`
- Test: `tests/test_ui_walk_destroy.py`

**Interfaces:**
- Consumes: `is_walker_owned`, Pass 2 `real_submits[].created_id`, registered tokens.
- Produces (inside canary mode, after sinks): for each `destructive` control: build `container_text` (nearest ancestor matching `tr, li, [role=row], article, .card, [data-id]`, else page `main`), intercept its request first in a dry click (aborted, gives `control_request`), decide `is_walker_owned`; not owned → control `skipped_reason="ownership-unproven"`. Owned → reach-paths = every GET in the walk's network log whose URL contains the created id or whose response body contains the token (cap 20); accept the confirm dialog; real click (counts toward cap + budget); re-GET each reach-path through `context.request` with the same session; still 2xx and body contains token → candidate `{type:"broken-delete", reach_path, status, evidence}`; listing page still renders token → `{type:"delete-leftover"}`. Always append `{type:"delete-idor-candidate", request: <redacted delete request>}` and, for controls whose text matches revoke/cancel/unshare, `{type:"cancel-without-revoke-candidate", ...}` for exploit-agent. All request/response evidence passed through `redact.redact_text` / `redact_structured`.
- [ ] **Step 1: Failing tests** (`@requires_browser`, grant on):
  - vulnerable: `test_destroy_finds_broken_delete` — candidate `broken-delete` with reach_path `/api/items/<created_id>`; the deleted item was walker-created (`items[id]["name"]` contains a registered token).
  - `test_destroy_never_touches_preexisting_items` — seed item `"Alice's report"` before walk; after walk it is not deleted; its Delete control `skipped_reason=="ownership-unproven"`.
  - `test_destroy_accepts_confirm_dialog` — `("DELETE", f"/api/items/{created_id}") in app.requests`.
  - `test_destroy_emits_delete_idor_candidate`.
  - patched: `test_destroy_hard_delete_no_candidate` — no `broken-delete` candidate.
- [ ] **Step 2–4:** FAIL → implement → PASS (+ Task 4/6 tests still green).
- [ ] **Step 5:** Commit — `feat: ui-walk create-destroy-verify on walker-owned objects (#164)`.

### Task 8: Teardown + disposable identities

**Files:**
- Create: `mcp-servers/browser-mcp/ui_walk_teardown.py`
- Modify: `mcp-servers/session_capture.py` (`list_identities` adds `"disposable": bool`; new `is_disposable(label, path=None) -> bool`)
- Test: `tests/test_ui_walk_teardown.py`, extend `tests/test_session_capture_roster.py`

**Interfaces:**
- Produces:
  - `TEARDOWN_STEPS = ("cleanup","logout","account_delete")`; `TEARDOWN_METHODS = ["POST","PUT","PATCH","DELETE"]`.
  - `plan_teardown(base_url: str, identity_label: str, steps: list[str]) -> dict` → `{host, steps (account_delete dropped + note if not disposable), cleanup_tokens: sorted registered tokens, fingerprint}`; `teardown_fingerprint(slug, identity_label, base_url, cleanup_tokens, steps) -> str` = sha256 hex[:32] of canonical JSON.
  - `async def run_teardown(base_url: str, identity_label: str, session_file: str, steps: list[str] | None = None, scope_check=None) -> dict` → if `state_change_confirm.consume_approval(host, TEARDOWN_METHODS, fingerprint)` is None: `state_change_confirm.write_pending(host, TEARDOWN_METHODS, fingerprint, summary)` and return `{"status":"blocked","command": f"scripts/confirm-state-change.sh {host} POST,PUT,PATCH,DELETE {fingerprint}", "summary": ...}`. Else run steps in order: cleanup (walk every mapped page, run Task 7 destroy flow for every token-owned object), logout (snapshot cookies; click the `logout` control — the only place it is ever clicked; replay one mapped authenticated GET via `context.request` with old cookies → 2xx and not login → candidate `logout-session-survives`), account_delete (only if disposable; click `account-delete` control, accept dialog; replay old session → candidate `account-deleted-session-survives`; also always emit `{type:"reregistration-candidate", email_identity: identity_label}` for exploit-agent/human — re-signup needs a new account, so it is never automated). Payment controls/hosts still blocked. Returns `{status:"complete", steps_run, candidates, deleted}`.
  - Spec deviation (DRY, author's call): reuses the existing `scripts/confirm-state-change.sh` instead of a new `confirm-teardown.sh`.
- [ ] **Step 1: Failing tests:**
  - roster: `disposable: true` surfaced; absent → False; listing still omits profile_dir/mailbox.
  - `test_fingerprint_changes_with_object_set_and_identity`.
  - `test_teardown_blocked_without_token` — returns `status=="blocked"`, exact command string, pending file written; no browser launched.
  - `test_teardown_drops_account_delete_for_non_disposable`.
  - `@requires_browser` vulnerable, token pre-written via `rce_confirm`'s test helper path used in existing state_change tests: `test_teardown_logout_session_survives_candidate`; `test_teardown_cleans_up_walker_objects` (no item containing a token remains); patched: no `logout-session-survives` candidate; disposable identity: `POST /api/account/delete` sent and candidate evaluated.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit — `feat: human-gated ui-walk teardown (cleanup, logout, account-delete tests) (#164)`.

### Task 9: MCP tools

**Files:**
- Modify: `mcp-servers/browser-mcp/server.py`
- Test: `tests/test_ui_walk_tools.py`

**Interfaces:**
- Produces tools:
  - `start_ui_walk(url: str, mode: str = "map", session_file: str = "", cookie_header: str = "", bearer_token: str = "", local_storage: dict[str,str] | None = None, session_storage: dict[str,str] | None = None, max_pages: int = 50, max_clicks_per_page: int = 40, same_origin_only: bool = True) -> str` — validates `mode ∈ {"map","canary"}`, scope-checks `url` in code (refuse → message), starts `job_runtime.start_thread_job("ui-walk", _run, _JOBS, ...)` where `_run` = `asyncio.run(ui_walk.walk(...))` → `ui_walk_store.save_inventory` → `ui_walk_store.emit_nodes`; returns job id.
  - `check_ui_walk(job_id: str) -> str` — running → status line; done → summary: status, pages, inputs, actions, intercepted edges, real submits, sinks, candidates by type, inventory path, honest limits; target-derived text (titles, control text, URLs) inside one `quarantine(..., source_label="ui-walk inventory")` block; provenance line last (`url` = start URL).
  - `list_ui_walks() -> str`.
  - `run_teardown(url: str, identity_label: str, session_file: str, steps: list[str] | None = None) -> str` — param named `url` (not `base_url`) so the hook's existing `HOST_ARG_KEYS` (`url` is already in it) scope-gates it with no further hook edit; passes `url` as `base_url` to `ui_walk_teardown.run_teardown`. Blocked → the exact command and summary; else summary of candidates; provenance last.
  - All four documented in the module docstring. browser-mcp is already in the hook's `TIER2_MCP_SERVERS`.
- [ ] **Step 1: Failing tests:** tools exist on `server.app` with these params; `start_ui_walk(mode="bogus")` → error; out-of-scope url (no engagement, external host) → refused without starting a job; `check_ui_walk` on an injected finished job renders quarantined block and last line provenance; decoy `Provenance` line planted in a page title stays inside the quarantine (mirror `test_browser_mcp_provenance.py`); `run_teardown` blocked path returns the command.
- [ ] **Step 2–4:** FAIL → implement → PASS; `python -m py_compile mcp-servers/browser-mcp/server.py`; `tests/test_agent_mcp_registry_drift.py` green.
- [ ] **Step 5:** Commit — `feat: browser-mcp start_ui_walk/check_ui_walk/list_ui_walks/run_teardown tools (#164)`.

### Task 10: Page-first methodology in agents

**Files:**
- Modify: `.claude/agents/recon-agent.md`, `.claude/agents/scan-agent.md`, `.claude/agents/exploit-agent.md`, `.claude/agents/huntbrain.md`, `.claude/agents/report-agent.md`, `CLAUDE.md` (browser-mcp line mentions UI-walk), `ARCHITECTURE.md` (one paragraph)
- Test: `tests/test_ui_walk_agent_wiring.py`

**Content (exact rules to add):**
- recon-agent: "For every in-scope app with a UI, run `start_ui_walk(url, mode="map")` (with the identity's session_file) and poll `check_ui_walk` before declaring recon done. Recon is not complete while an app with UI has no walk. `extract_page_content` remains for reading single pages." Also: if `status=auth_lost`, refresh the session and re-walk; never report the logged-out shell as the authenticated surface.
- scan-agent: "Test the walk inventory's inputs and actions FIRST (each `input`/`action` surface node); URL/param reasoning is secondary."
- exploit-agent: consume `stored-xss`, `reflected-render`, `broken-delete`, `delete-leftover`, `delete-idor-candidate` (→ `idor-mcp replay_authz_matrix` with account B), `cancel-without-revoke-candidate`, `logout-session-survives`, `account-deleted-session-survives`, `reregistration-candidate`; each needs manual confirmation + evidence before CONFIRMED.
- huntbrain: after Pass 1 per app, run `mode="canary"` when the grant file exists (huntbrain never creates it); teardown is never run by huntbrain — only when the human says the engagement is done.
- report-agent: after drafting, tell the human `run_teardown` is available and advise waiting until after triage.
- [ ] **Step 1: Failing test:** each agent file contains its key tool names (`start_ui_walk`, `check_ui_walk`, `run_teardown` where applicable); exploit-agent lists all 9 candidate types; huntbrain contains "never creates" grant + teardown-human-only wording; every tool named in agent files exists on `browser-mcp` `server.app`.
- [ ] **Step 2–4:** FAIL → edit → PASS; `validate-agent-files` frontmatter still valid.
- [ ] **Step 5:** Commit — `docs: page-first UI-walk methodology in agents (#164)`.

### Task 11: Review, audit, prove it runs

- [ ] **Step 1:** Full suite `.venv/bin/python -m pytest tests/ -q` + ruff + `py_compile` + `bash -n scripts/*.sh`. Known pre-existing flake: `test_s_gate_adversarial.py::test_legitimate_job_still_succeeds...` (passes in isolation).
- [ ] **Step 2:** Run `/code-review` and `/security-review` on the #164 diff; fix findings (TDD), commit fixes per concern.
- [ ] **Step 3 (needs session restart for new tools):** Start the fixture app (`python -c` one-liner via `tests/fixtures/ui_walk_app.py` serving on 127.0.0.1), then call the real `mcp__browser-mcp__start_ui_walk` (map) → `check_ui_walk`; `mcp__browser-mcp__screenshot` and `Read` the saved JPEG; with a temporary grant file in an isolated test engagement, `start_ui_walk(mode="canary")` → sinks + broken-delete; `run_teardown` → blocked command → human runs it → teardown candidates. Record `Runtime-verified: ...` in the summary. Never against bentley (active engagement) for verification.
- [ ] **Step 4:** Update memory `project_huntmcp_wiring_issues` (#164 done) and close-out note.
