# Session Keep-Alive Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A captured identity's session renews itself (app re-visit in its dedicated profile → tool refresh_token grant → human only as last resort), proactively and on `auth_lost`, writing fresh state back into its `session_file` and never returning a secret.

**Architecture:** Three new shared modules in `mcp-servers/` — `session_tokens.py` (pure: find/patch token entries, JWT `exp`), `session_refresh.py` (host policy, layer 1 browser renewal, layer 2 HTTP refresh grant, verify, write-back, `refresh_session`), `session_keepalive.py` (scheduler thread, `session_health`, desktop notify). `session_capture.py` learns `renewal_hosts`/`app_url`/`whoami_url` during the human's login. `browser-mcp/server.py` registers 4 tools; `ui_walk.py` calls a refresh on `auth_lost`.

**Tech Stack:** Python 3.12, Playwright (async, persistent context), stdlib `http.server` fixture, existing `http_probe.fetch`, `file_lock`, `budget_guard`, `audit_log`, pytest.

**Spec:** `docs/superpowers/specs/2026-11-20-session-keepalive-design.md`

## Global Constraints

- No new dependencies. `notify-send` is used only if `shutil.which` finds it.
- Agent-facing returns: allow-listed keys only, `_safe_summary`-style assert (fail closed). Allowed set for refresh/health: `identity, status, refreshed, layer, needs_human_login, reason, access_expires_in_s, renewal_hosts, last_refresh, estimated_next_human_login, warning, message, error`.
- `session_file` = `engagement_paths.resolve(f"secrets/sessions/{label}.json")`; holds only in-scope cookies/origins plus the `browser_confirm.SESSION_STORAGE_KEY` sidecar; written only via `browser_confirm._write_private_json` (atomic, 0600) under `file_lock.locked(session_file)`.
- `out_of_scope` always wins. `scope_guard.is_in_scope` is NOT modified.
- Renewal never clicks, types, or submits a form; a document (form) POST aborts the layer.
- One `budget_guard.enforce("browser-mcp")` per `refresh_session` call; audit via `audit_log.log_call("browser-mcp", ["refresh_session", label, layer, outcome], ...)` — never values.
- Keep-alive: default interval 7200 s, clamp minimum 1800 s, ±10 % jitter, refresh 300 s before earliest access-token `exp`; hard cap 48 renewals per identity per UTC day.
- Builtin IdP patterns (exact list): `*.auth0.com, *.okta.com, *.oktapreview.com, login.microsoftonline.com, login.live.com, *.b2clogin.com, accounts.google.com, *.amazoncognito.com, *.onelogin.com, *.pingidentity.com, *.pingone.com`.
- Git: work on `feature/session-keepalive` from `main`; `git add` explicit paths only; never add `data/writeups/hexbrain-*`; **no commit/push/PR without the user's in-the-moment ask**; no AI attribution lines in commits (repo CLAUDE.md).
- Tests: local fixture only, no real target. Browser tests use `requires_browser` from `tests/fixtures/ui_walk_target/ui_walk_app.py` and monkeypatch `browser_confirm._enforce_budget`/`budget_guard.enforce` like `tests/test_ui_walk_pass1.py`.

## Review Focus

1. **App's own redirect bounces through an unknown host mid-renewal** (e.g. IdP → `rogue.localhost`) → layer fails closed with `reason="blocked_host:<host>"`, no request reaches it. Test in Task 4.
2. **Refresh token rotated by layer 1 before layer 2 runs** → layer 2 must read the post-layer-1 file, not the stale one; a reused old RT is rejected by the fixture. Test in Task 5.
3. **Init-script restore clobbering the app's freshly renewed token on the next same-origin navigation** (`/callback` → `/`) → restore runs once per origin per tab. Test in Task 4.
4. **Human capture window still open / profile locked** when keep-alive fires → `status="busy"`, no crash, no file write. Test in Task 6.
5. **Old capture without `app_url`/`renewal_hosts`** (identities.json from before this change) → falls back to `source_login_url`, builtin list only, no KeyError. Test in Task 6.

---

### Task 0: Branch + coordination

- [ ] **Step 1:** `git status --short | grep -v '^?? data/writeups/'` and `git branch --show-current`. Sibling session `ui-walk-sso-surface-even` shares `/home/ankit/HuntMCP`; if it has tracked modifications or is on a non-`main` branch, STOP and ask the user before switching.
- [ ] **Step 2:** `git checkout -b feature/session-keepalive main`. Expected: `Switched to a new branch`.

### Task 1: Fixture app + mini OIDC IdP

**Files:**
- Create: `tests/fixtures/session_refresh_target/__init__.py`, `tests/fixtures/session_refresh_target/oidc_fixture.py`
- Test: `tests/test_session_refresh_fixture.py`

**Interfaces — Produces:**
- `serve(**opts) -> OidcFixture` with `.app_url` (`http://127.0.0.1:<pa>/`), `.idp_base` (`http://idp.localhost:<pb>`), `.rogue_base` (`http://rogue.localhost:<pb>`), `.close()`.
- Options (mutable attributes too): `access_ttl=60`, `sso_valid=True`, `app_silent_renew=True`, `authorize_mode="normal"|"captcha"|"redirect_rogue"`, `client_id="spa"`.
- `.sso_cookie() -> dict` (Playwright cookie for `idp.localhost`, name `idp_sso`, persistent, `expires` = now+5 days); `.seed_state(access_valid: bool, with_rt: bool) -> dict` (a storage_state for `127.0.0.1` whose sidecar holds sessionStorage key `oidc.user:<idp_base>:spa` in oidc-client-ts shape `{access_token,id_token,refresh_token?,token_type,scope,expires_at}`); `.requests: list[(method, host, path)]`; `.used_refresh_tokens: set[str]`; `.valid_access(token) -> bool`.
- IdP endpoints: `/.well-known/openid-configuration` (issuer = `idp_base`, `authorization_endpoint`, `token_endpoint`); `GET /authorize` — `prompt=none`+valid SSO → 302 `redirect_uri?code&state`; `prompt=none` without SSO → 302 `?error=login_required`; no prompt, no SSO → HTML with `<input type="password">`; `authorize_mode="captcha"` → HTML with `<div class="g-recaptcha">`; `redirect_rogue` → 302 to `rogue_base/x`. `POST /token` — `authorization_code` with S256 PKCE check; `refresh_token` with rotation (old RT → 400 `invalid_grant`); CORS `Access-Control-Allow-Origin: <app origin>`. Access tokens are JWTs (`alg: none`, claims `iss, sub="user-A", aud=client_id, exp`).
- App endpoints: `GET /` SPA (reads the sessionStorage entry; valid token → `GET /api/me` with Bearer, renders `<div id="me">`; expired + `app_silent_renew` → hidden iframe `/authorize?prompt=none…&redirect_uri=<app>/callback`, `/callback` postMessages the code to the parent, parent exchanges at `/token` via fetch and stores the entry; `login_required` or no renew → `location = "/login"`); `GET /login` (in-scope login page with a "Sign in" link); `GET /api/me` → 200 `{"sub":"user-A"}` for a valid bearer else 401.

- [ ] **Step 1: Write failing tests** `test_authorize_prompt_none_with_sso_returns_code`, `test_authorize_prompt_none_without_sso_login_required`, `test_token_pkce_mismatch_rejected`, `test_refresh_token_rotates_and_old_one_rejected`, `test_api_me_401_on_expired_token` — pure `urllib` against the fixture (no browser).
- [ ] **Step 2:** `pytest tests/test_session_refresh_fixture.py -v` → FAIL (import error).
- [ ] **Step 3:** Implement the fixture (two `ThreadingHTTPServer`s on `127.0.0.1:0`; the IdP server dispatches on `Host` so `idp.localhost` and `rogue.localhost` share it; Chromium resolves `*.localhost` to loopback).
- [ ] **Step 4:** Re-run → PASS.

### Task 2: `session_tokens.py` (pure)

**Files:** Create `mcp-servers/session_tokens.py`; Test `tests/test_session_tokens.py`

**Interfaces — Produces:**
- `jwt_exp(token: str) -> float | None` (unverified payload decode; None on non-JWT).
- `@dataclass TokenEntry: origin: str; store: Literal["local","session"]; key: str; shape: Literal["oidc-client-ts","auth0-spa-js"]; issuer: str | None; client_id: str | None; refresh_token: str | None; access_exp: float | None`
- `find_token_entries(state: dict) -> list[TokenEntry]` — scans `origins[].localStorage` and the `SESSION_STORAGE_KEY` sidecar. oidc-client-ts key `oidc.user:<authority>:<client_id>`; auth0 key prefix `@@auth0spajs@@::<client_id>::`, value `{"body": {...}, "expiresAt": …}`, issuer from the id_token `iss`.
- `apply_token_response(state: dict, entry: TokenEntry, resp: dict, now: float) -> dict` — returns a new state with that one entry's access/id/refresh token (keeps the old RT if the response has none) and expiry updated in the same shape; other keys untouched.
- `earliest_access_exp(state: dict, authorization: str | None) -> float | None`.

- [ ] **Step 1: Failing tests:** `test_jwt_exp_reads_claim`, `test_jwt_exp_none_for_opaque`, `test_find_oidc_client_ts_entry_in_session_sidecar` (asserts issuer, client_id, refresh_token), `test_find_auth0_entry_in_local_storage`, `test_apply_response_rotates_rt_and_preserves_other_keys`, `test_apply_response_keeps_old_rt_when_absent`, `test_earliest_exp_includes_bearer_header`.
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement. **Step 4:** Run → PASS.

### Task 3: Learn renewal hosts during capture

**Files:** Modify `mcp-servers/session_capture.py` (`_LiveCapture`, `start_capture`, `finish_capture`, `_build_identity_entry`, `_ALLOWED_SUMMARY_KEYS`); Test `tests/test_session_capture_renewal_hosts.py`

**Interfaces — Produces:**
- `_LiveCapture.nav_hosts: set = field(default_factory=set)` (last field, so existing positional constructions still work).
- `_record_nav(nav_hosts: set, request) -> None` — adds `scope_guard._host_of(request.url)` only when `request.is_navigation_request()` and `request.frame.parent_frame is None`; swallows exceptions.
- `learned_renewal_hosts(nav_hosts, engagement) -> list[str]` — sorted hosts that are neither in scope nor matched by `engagement.out_of_scope` (`scope_guard._matches`).
- identities.json entry gains `app_url` (live page URL if in scope, else `login_url`; `None`-page safe), `renewal_hosts`, `whoami_url`; summary gains `renewal_hosts`.

- [ ] **Step 1: Failing tests:** `test_record_nav_ignores_subresources_and_iframes` (fake request objects), `test_learned_hosts_exclude_in_scope_and_out_of_scope`, `test_finish_capture_writes_renewal_hosts_app_url_and_lists_hosts_in_summary` (reuse `_seed_live` pattern from `tests/test_session_capture_core.py`, assert no secret in summary), `test_existing_core_tests_still_pass` = run `tests/test_session_capture_*.py`.
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement; in `start_capture` add `context.on("request", lambda r: _record_nav(nav_hosts, r))` next to the existing auth listener. **Step 4:** `pytest tests/test_session_capture_*.py -v` → PASS.

### Task 4: Host policy + layer 1 (app renews itself) + verify

**Files:** Create `mcp-servers/session_refresh.py`; Test `tests/test_session_refresh_layer1.py`

**Interfaces — Produces:**
- `BUILTIN_IDP_PATTERNS: tuple[str, ...]` (Global Constraints list).
- `@dataclass RenewalPolicy: engagement; learned: list[str]; builtin: tuple = BUILTIN_IDP_PATTERNS` with `in_scope(host) -> bool` (`scope_guard.is_in_scope`) and `allowed(host) -> bool` (`in_scope or learned or builtin`, and False if `out_of_scope` matches).
- `route_decision(method: str, url: str, resource_type: str, is_main_frame: bool, policy) -> tuple[str, str | None]` → `("continue"|"abort", reason)`. Rules: document to a disallowed host → abort `blocked_host:<host>`; document non-GET → abort `form_post`; non-document non-GET → continue only if host is a learned/builtin renewal host, or in scope with a path matching `_TOKEN_PATH_RE = r"/(oauth2?/|connect/)?(token|refresh|renew|silent|session|auth)\b"`, else abort `mutating_call`; non-document GET → continue.
- `@dataclass LayerResult: ok: bool; reason: str | None; state: dict | None; authorization: str | None; sso_expiry: float | None`
- `async layer1_app_renew(profile_dir: str, app_url: str, session_file: str, policy, whoami_url: str | None, timeout_ms: int = 20000) -> LayerResult` — headless `launch_persistent_context(**persistent_context_kwargs(profile_dir, headless=True))`; `context.route("**/*", …)` with `route_decision`; init script restoring in-scope localStorage + sessionStorage from `session_file` **once per origin per tab** (guard flag `__huntmcp_restored` in sessionStorage); sniff in-scope `Authorization` (reuse `session_capture._record_auth`); `goto(app_url)`, `wait_for_load_state("networkidle")`; verify; on success return filtered state (`session_capture._filter_storage_state`) + in-scope sessionStorage sidecar, sniffed authorization, and `sso_expiry` = max `expires` of persistent cookies on renewal (non-in-scope allowed) hosts.
- `async verify_logged_in(page, policy, whoami_url, cookies, authorization) -> str | None` — None = logged in; else reason `login_page` (`ui_walk_logic._LOGIN_PATH_RE` on final path, or main frame host not in scope) / `password_field` / `captcha` (selectors `input[type=password]`; `.g-recaptcha, .h-captcha, .cf-turnstile, iframe[src*=recaptcha], iframe[src*=hcaptcha], iframe[src*=turnstile]`) / `whoami_failed` (via `session_capture._whoami_fetch`-style call using `http_probe.fetch`, 2xx required).

- [ ] **Step 1: Failing tests:** unit `test_policy_out_of_scope_beats_builtin`, `test_route_decision_*` (5 cases: blocked doc host, form post, token POST to learned host ok, in-scope non-token POST aborted, third-party GET ok); `@requires_browser`: `test_layer1_expired_token_silent_renew_succeeds` (profile seeded with `fx.sso_cookie()`, file from `fx.seed_state(False, False)`; asserts ok, new token in the file's sidecar is `fx.valid_access`, file has no `idp.localhost` cookie), `test_layer1_restore_runs_once_per_origin` (renewed token survives `/callback`→`/`), `test_layer1_sso_expired_fails_login_page`, `test_layer1_captcha_fails_captcha`, `test_layer1_redirect_to_rogue_blocked` (and `("GET","rogue.localhost",…)` not in `fx.requests`), `test_layer1_never_types_or_clicks` (no POST to `/login`-like paths; `fx.requests` has no document POST).
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement. **Step 4:** Run → PASS.

### Task 5: Layer 2 (tool refresh_token grant)

**Files:** Modify `mcp-servers/session_refresh.py`; Test `tests/test_session_refresh_layer2.py`

**Interfaces — Produces:**
- `layer2_refresh_grant(state: dict, policy, app_origin: str) -> LayerResult` — for each `session_tokens.find_token_entries(state)` with a refresh_token: discovery `GET <issuer>/.well-known/openid-configuration`, token endpoint host must be `policy.allowed`; `http_probe.fetch(token_endpoint, "POST", {"Content-Type": "application/x-www-form-urlencoded", "Origin": app_origin}, body, 15.0, allow_redirects=False)` with `grant_type=refresh_token&refresh_token=…&client_id=…`; 2xx JSON with `access_token` → `session_tokens.apply_token_response`. First success wins; reasons on failure `no_refresh_token` / `token_endpoint_not_allowed` / `token_refused`.

- [ ] **Step 1: Failing tests:** `test_layer2_refresh_grant_writes_rotated_tokens` (fixture `app_silent_renew=False`, valid RT; asserts new access valid, old RT in `fx.used_refresh_tokens`), `test_layer2_reused_rt_refused` (Review Focus 2), `test_layer2_issuer_not_allowed` (engagement `out_of_scope=["idp.localhost"]` → `token_endpoint_not_allowed`, zero requests to `/token`), `test_layer2_no_rt`.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS.

### Task 6: `refresh_session` orchestration

**Files:** Modify `mcp-servers/session_refresh.py`; Test `tests/test_session_refresh_orchestration.py`

**Interfaces — Produces:**
- `async refresh_session(identity_label: str, slug: str | None = None) -> dict` — `_safe_label`; roster entry + `assert_dedicated_profile_dir`; identities.json entry (fallback `app_url := source_login_url`, `renewal_hosts := []`); `busy` if `(slug,label)` in `session_capture._live_captures` or the persistent launch raises a profile-lock error; daily cap (48) and `engagement.min_request_interval_s` from the refresh-state file; `enforce("browser-mcp")`; under `file_lock.locked(session_file)`: layer 1 → (if fail) layer 2 on the current file → re-verify with layer 1 → write state + update identities.json `cookies`/`authorization`; else `needs_human_login=True`, `reason`, `notify(...)`. Returns allow-listed summary (`layer` ∈ `app|refresh_token|none`, `access_expires_in_s` from `session_tokens.earliest_access_exp`).
- `refresh_state_path(label) -> str` = `engagement_paths.resolve(f"session-refresh/{label}.json")` holding `{day, count, last_refresh, last_layer, last_reason, sso_expiry, rt_expiry}` (non-secret).
- `label_for_session_file(path: str, slug: str | None = None) -> str | None`.
- `notify(title: str, body: str) -> None` (no-op without `notify-send`; text never contains a secret).

- [ ] **Step 1: Failing tests:** `test_refresh_returns_no_secret` (sentinel tokens never in `json.dumps(out)`; keys ⊆ allowed), `test_refresh_busy_when_capture_open` (Review Focus 4), `test_refresh_old_entry_without_app_url` (Review Focus 5), `test_refresh_daily_cap`, `test_refresh_falls_to_layer2_then_human` (monkeypatched layers: L1 fail→L2 ok→`layer="refresh_token"`; both fail→`needs_human_login`, notify called once), `test_refresh_rejects_bad_label`, `test_refresh_budget_enforced_once`, and `@requires_browser` `test_refresh_end_to_end_layer1` against the fixture.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS.

### Task 7: Keep-alive + health

**Files:** Create `mcp-servers/session_keepalive.py`; Test `tests/test_session_keepalive.py`

**Interfaces — Produces:**
- `class KeepAlive(labels, slug, refresh_fn, interval_s=7200, now_fn=time.time, rand_fn=random.random)` with `next_due(label) -> float` (min of `access_exp-300` and `last_refresh+interval·(0.9..1.1)`) and `tick() -> list[str]` (refreshes due labels, skips one already running, returns refreshed labels). `start()`/`stop()` run `tick` in a daemon thread with `threading.Event.wait`.
- `start_keepalive(labels: list[str], interval_s: int = 7200, slug=None) -> dict` (clamps `interval_s >= 1800`, validates labels, replaces an existing keep-alive for the slug), `stop_keepalive(slug=None) -> dict`, `session_health(labels: list[str] | None = None, slug=None) -> dict` — per label: `last_refresh, layer, access_expires_in_s, estimated_next_human_login` (= max(sso_expiry, rt_expiry)), `warning` when < 48 h (notify once per day), `needs_human_login`.

- [ ] **Step 1: Failing tests:** `test_next_due_prefers_access_exp_minus_300`, `test_interval_clamped_to_1800`, `test_tick_skips_running_label`, `test_health_warns_under_48h_and_notifies_once`, `test_health_no_secret`.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS.

### Task 8: Wiring — tools, UI-walk hook, agent instructions

**Files:** Modify `mcp-servers/browser-mcp/server.py` (tools `refresh_session(identity_label)`, `session_health(identity_labels: list[str] | None = None)`, `start_keepalive(identity_labels: list[str], interval_s: int = 7200)`, `stop_keepalive()`, each `json.dumps` of the module result); `mcp-servers/browser-mcp/ui_walk.py` (in the `auth_lost` retry branch, before `self.context.close()`: `label = session_refresh.label_for_session_file(self.session_file)`; if label, `await session_refresh.refresh_session(label)`; result ignored — the existing single retry follows); `.claude/agents/recon-agent.md` (AUTH LOST line: call `refresh_session(<identity>)` first; only on `needs_human_login` ask the human via `start_capture`); `.claude/agents/huntbrain.md` (after a successful `finish_capture` call `start_keepalive` with every captured identity; check `session_health` at phase boundaries and batch `start_capture` for all `needs_human_login` identities together). Tests: `tests/test_session_refresh_wiring.py`.

- [ ] **Step 1: Failing tests:** `test_tools_registered` (the 4 names in `server.app.list_tools()`), `test_recon_agent_refreshes_before_relogin` (`"refresh_session"` in recon-agent.md and `"needs_human_login"`), `test_huntbrain_starts_keepalive_after_capture`, `test_ui_walk_auth_lost_calls_refresh` (monkeypatch `session_refresh.refresh_session` to a fake that rewrites the file to a valid session against the Task 1 fixture or `ui_walk_app`; walk completes, fake called once).
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** `pytest tests/ -q -x` full suite → PASS; `ruff check mcp-servers/ --ignore E402,F811 --target-version py312`; `python -m py_compile` on each changed server file.

### Task 9: Review-and-audit, then prove-it-runs

- [ ] **Step 1:** Run `/code-review` and `/security-review` on the branch diff; fix confirmed findings with a test each; re-run the suite.
- [ ] **Step 2 (prove it runs):** start the Task 1 fixture from a scratch script; create a throwaway roster identity + dedicated profile seeded with `sso_cookie()` and an expired session file in a scratch engagement (`in_scope: [127.0.0.1]`); call the **real** `mcp__browser-mcp__refresh_session` (needs an MCP reload so the new tools load — if not loaded, drive `browser-mcp/server.py` over stdio with the `mcp` client from the scratch script and say so). Evidence: tool output (`refreshed: true, layer: app`), fixture log showing `prompt=none` authorize + `/token`, and `/api/me` 200 with the refreshed file. Repeat with `sso_valid=False` → `needs_human_login: true, reason: login_page`.
- [ ] **Step 3:** Report `Runtime-verified: …` and ask the user before any commit/push/PR.
