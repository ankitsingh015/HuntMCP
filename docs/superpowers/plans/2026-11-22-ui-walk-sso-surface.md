# UI-walk SSO surface (spec 2 of 3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When the IdP host is in scope, the UI-walk records the OAuth/OIDC/SAML flow (authorize, login/consent/MFA pages, callback, token, logout, discovery, every hop) as surface-map nodes and `sso-*` candidates that queue `auth-and-session` checks, without storing any `state`/`nonce`/`code`/token value.

**Architecture:** A pure module `ui_walk_sso_logic.py` classifies URLs, derives flags, redacts secret params, parses discovery documents and derives candidates. A stateful `ui_walk_sso.SsoTracker`, owned by `ui_walk._Walker`, is fed every URL the walker already sees (interceptor, redirect chains, hrefs) and holds first `state`/`nonce` values in memory only for the repeat. The walker maps in-scope IdP pages, runs the bounded repeat and discovery GETs (map mode only), and writes `inv["sso"]`. `ui_walk_store.emit_nodes` and `coverage_manifest.required_classes` turn it into nodes with the SSO battery.

**Tech Stack:** Python 3.12, Playwright 1.62 (async, Chromium), pytest, stdlib `http.server` fixture.

**Spec:** `docs/superpowers/specs/2026-11-22-ui-walk-sso-surface-design.md` (approved 2026-11-22). Read it with this plan, especially "Values policy", "Out-of-scope IdP" and "Decisions settled after builder check".

## Global Constraints

- No new dependency, no new MCP server, no new tool parameter.
- Pass 1 sends nothing state-changing. Repeat and discovery are GETs, in scope only, `await self._budget()` before each, never follow redirects.
- Out-of-scope IdP: the browser's HTTP redirect is followed (not blocked); nothing else is done there (no map, click, fill, discovery, repeat GET, IdP-targeted candidate). JS navigations to out-of-scope hosts stay aborted (#164, unchanged).
- Never stored, logged, hashed or printed (case-insensitive names, query AND fragment): `state, nonce, code, code_verifier, code_challenge, id_token, id_token_hint, access_token, refresh_token, samlrequest, samlresponse, relaystate, login_hint, session_state, client_secret, client_assertion, assertion`.
- Kept values only: `response_type, response_mode, scope, prompt, code_challenge_method, client_id`; `redirect_uri` / `post_logout_redirect_uri` as scheme://host/path only.
- Strength classes: `absent`, `short` (< 16 chars), `low-charset` (digits only, or one char class), `structured` (JWT-like or base64-JSON), `ok`. Length buckets: `<8`, `8-15`, `16-31`, `32+`. Tri-state flags: `True` / `False` / `"unknown"`.
- Caps: repeat ≤ 1 per flow key and ≤ 5 per walk; discovery ≤ 3 GETs per IdP host, ≤ 3 hosts per walk, ≤ 256 KB read; ≤ 10 enqueued pages per IdP host.
- Repeat and discovery run only when `mode == "map"`.
- Callback / SAML-ACS URLs (carrying `code`, `id_token`, `access_token` or `samlresponse`) are never enqueued, never back-navigated to, never a repeat source.
- Inventory `schema_version` 3, additive (`inv["sso"]`, `pages[].sso_role`, `auth_state: "sso"`).
- Target text quarantined in tool output; provenance line last (unchanged helpers in `server.py`).
- Test logins only with fixture/test values on loopback; the walker never types into a login form.
- Commits only with the user's explicit OK, staged file by file, no AI attribution lines (CLAUDE.md). Never stage `data/writeups/hexbrain-*` or `oom`. The "Commit" steps below mean: leave the change uncommitted and note it in the ledger unless the user has said to commit.

## Review Focus

- Secret params in upper/mixed case or in the URL fragment (`#id_token=…&STATE=…`) → still classified and redacted. Test in Task 1.
- A discovery document that is huge, not JSON, or lists `javascript:` / out-of-scope endpoint URLs → those entries ignored or kept as out-of-scope records, never nodes, never a crash. Test in Task 1.
- A redirect chain longer than 20 hops, or one that loops → the tracker records at most the hops it was given and never raises. Test in Task 4.
- Budget or wall clock running out in the middle of a repeat → the walk ends `budget_exhausted` / `time_limit`, no fixture secret appears in the inventory or error text. Test in Task 5.
- The same SSO link on many pages → one flow, one repeat, one node. Test in Task 5.

---

### Task 1: Pure SSO logic (`ui_walk_sso_logic.py`)

**Files:**
- Create: `mcp-servers/browser-mcp/ui_walk_sso_logic.py`
- Test: `tests/test_ui_walk_sso_logic.py`

**Interfaces:**
- Produces:
  - `SECRET_PARAMS: frozenset[str]` (the Global Constraints list, lowercase); `KEPT_PARAMS: tuple[str, ...]`; `LOGOUT_REDIRECT_PARAMS: frozenset[str]` = `post_logout_redirect_uri, redirect_uri, returnto, return_to, returnurl, redirect, redirect_url, next, continue, relaystate, wreply, target, service, url`.
  - `ROLES = ("authorize","callback","saml-request","saml-response","logout","token","discovery","userinfo","jwks","revocation","introspection","registration","device_authorization")`; `PAGE_ROLES = ("login","consent","mfa","idp-page")`.
  - `ENDPOINT_METHOD: dict[str, str]`: `POST` for token, revocation, introspection, registration, device_authorization, saml-response; `GET` otherwise.
  - `redact_sso_params(url: str) -> str`: value of each SECRET_PARAMS name (case-insensitive) in query and fragment replaced by `REDACTED`, order and other params kept; non-http(s) or unparsable → returned unchanged if no `?`/`#`, else scheme://host/path.
  - `redact_urls_deep(obj)` -> same structure with every `str` that starts with `http://`/`https://` passed through `redact_sso_params` (dicts, lists, tuples recursed; returns a new object).
  - `all_params(url: str) -> list[tuple[str, str]]`: query + fragment pairs (fragment parsed as a query string), in-memory use only.
  - `is_callback_url(url: str) -> bool`: any of `code, id_token, access_token, samlresponse` present (query or fragment).
  - `classify_url(url: str, method: str = "GET", body_fields: list[str] | None = None) -> str | None`: role or None. Order: discovery (`/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`) > saml-response (`samlresponse` in params or body_fields) > saml-request > callback (`is_callback_url`, or `error` + `state`) > authorize (`response_type` and `client_id` params, or path ends with one of `/authorize`, `/oauth2/authorize`, `/oauth2/v2.0/authorize`, `/protocol/openid-connect/auth`, `/connect/authorize`, `/o/oauth2/auth`) > logout (path ends with `/logout`, `/end_session`, `/endsession`, `/oauth2/logout`, `/oauth2/v2.0/logout`, `/protocol/openid-connect/logout`, `/v2/logout`, `/connect/endsession`, or contains `singlelogout`) > token (`/token`, `/oauth2/token`, `/oauth2/v2.0/token`, `/protocol/openid-connect/token`, `/connect/token`) > userinfo / jwks (`/jwks`, `/jwks.json`, `/certs`, `/keys` under an oauth/openid path) / revocation / introspection / registration / device_authorization by last path segment. Path matching is on whole trailing segments, case-insensitive.
  - `secret_strength(value: str | None) -> str` and `length_bucket(value: str | None) -> str | None` (classes in Global Constraints; `structured` = 3 dot-separated base64url parts, or base64 that decodes to text starting with `{`).
  - `authorize_flags(url: str) -> dict`: `{"param_names": sorted names, "response_type", "response_mode", "scope", "prompt", "client_id", "code_challenge_method", "redirect_uri": stripped-or-None, "pkce": bool, "state": {"present", "strength", "length_bucket"}, "nonce": {...same}}`. Kept values truncated to 200 chars.
  - `logout_flags(url: str) -> dict`: `{"param_names", "redirect_params": sorted names ∩ LOGOUT_REDIRECT_PARAMS, "post_logout_redirect_uri": stripped-or-None}`.
  - `flow_key(url: str) -> str`: `json.dumps([host.lower(), path, client_id, stripped redirect_uri])`.
  - `secrets_of(url: str) -> dict[str, str]`: `{"state": …, "nonce": …}` for present ones (memory only; never stored by callers).
  - `compare_secrets(first: dict, second: dict | None) -> dict`: `{"state_changes_per_request": tri, "nonce_changes_per_request": tri}`; `"unknown"` when `second` is None or the param is absent in either.
  - `discovery_urls(authorize_url: str) -> list[str]`: `<origin>/.well-known/openid-configuration`, then `<origin><issuer-prefix>/.well-known/openid-configuration` when the authorize path has a prefix before the matched authorize suffix (e.g. `/realms/acme`), deduped, max 2 (the 404 fallback to `oauth-authorization-server` is added by the caller, total ≤ 3).
  - `parse_discovery(body: bytes, *, scope: Callable[[str], bool]) -> dict | None`: None if `len(body) > 262144` or not a JSON object. Returns `{"issuer": str|None, "endpoints": [{"role", "url" (stripped, ≤500), "in_scope": bool}], "supported": {key: [str ≤100] ≤30}}`. Key → role: `authorization_endpoint`→authorize, `token_endpoint`→token, `end_session_endpoint`→logout, `revocation_endpoint`→revocation, `introspection_endpoint`→introspection, `userinfo_endpoint`→userinfo, `jwks_uri`→jwks, `registration_endpoint`→registration, `device_authorization_endpoint`→device_authorization. Non-http(s) URLs dropped. Supported keys: every top-level key ending `_supported` whose value is a list of strings.
  - `sso_page_role(inputs: list[dict], controls: list[dict]) -> str`: `login` if any input type `password`; `mfa` if any input whose name/id/label matches `otp|totp|mfa|2fa|one.?time|verification code` or `autocomplete=one-time-code`-style type; `consent` if a control text matches `^(allow|accept|authori[sz]e|grant|consent)\b`; else `idp-page`.

- [ ] **Step 1: Write the failing tests** in `tests/test_ui_walk_sso_logic.py` (pure, no browser; import pattern as in `tests/test_ui_walk_events_logic.py`):
  - `test_classify_roles`: one URL per role incl. Entra `https://login.microsoftonline.com/t/oauth2/v2.0/authorize?client_id=a&response_type=code`, Okta `/oauth2/default/v1/authorize`, Keycloak `/realms/acme/protocol/openid-connect/auth`, Auth0 `/authorize`, Google `/o/oauth2/auth`, Cognito `/oauth2/authorize`, `/.well-known/openid-configuration` → discovery, `/sso/callback?code=x&state=y` → callback, `?SAMLRequest=x` → saml-request, POST with `body_fields=["SAMLResponse"]` → saml-response, `/protocol/openid-connect/logout` → logout.
  - `test_classify_negatives`: `/author`, `/blog/authorize-payments`, `/tokens/list`, `/logout-tips/article` (not trailing segment) → None.
  - `test_redact_query_and_fragment_case_insensitive`: `https://a/cb?STATE=s1&x=1#id_token=t1&Nonce=n1` → contains `STATE=REDACTED`, `x=1`, `id_token=REDACTED`, `Nonce=REDACTED`; `"s1"`, `"t1"`, `"n1"` not in output.
  - `test_redact_urls_deep_nested`: dict/list structure with URLs at depth 3 redacted; non-URL strings unchanged.
  - `test_authorize_flags_never_hold_secret_values`: authorize URL with `state=SECRETSTATE123456&nonce=SECRETNONCE&code_challenge=CCVALUE&login_hint=a@b.c&redirect_uri=https://app/cb?x=1`; `json.dumps(flags)` contains none of `SECRETSTATE123456`, `SECRETNONCE`, `CCVALUE`, `a@b.c`, `x=1`; `flags["redirect_uri"] == "https://app/cb"`; `flags["pkce"] is True`; `flags["state"] == {"present": True, "strength": "ok", "length_bucket": "16-31"}`.
  - `test_strength_classes`: `None`→absent, `"abc"`→short, `"1234567890123456"`→low-charset, `"eyJhbGciOiJub25lIn0.eyJhIjoxfQ.sig"`→structured, `base64("{\"r\":\"/x\"}")` padded to ≥16 → structured, `secrets.token_urlsafe(24)`→ok.
  - `test_logout_flags`: `/logout?post_logout_redirect_uri=https://evil/x&id_token_hint=T&returnTo=/y` → `redirect_params == ["post_logout_redirect_uri", "returnto"]` (names lowercased), `"T"` not in dump.
  - `test_flow_key_ignores_state`: two authorize URLs differing only in state/nonce → equal keys; different client_id → different.
  - `test_compare_secrets`: equal state → `False`; different → `True`; second None → `"unknown"`; nonce absent in both → `"unknown"`.
  - `test_discovery_urls_root_and_issuer_prefix`: Keycloak authorize → `[".../.well-known/openid-configuration", ".../realms/acme/.well-known/openid-configuration"]`; plain `/authorize` → one URL.
  - `test_parse_discovery`: full doc → roles mapped, `registration` present, `supported["response_types_supported"]` kept; out-of-scope `token_endpoint` → `in_scope False`; `jwks_uri: "javascript:alert(1)"` dropped; `b"not json"` → None; `b"x" * 262145` → None; JSON list → None.
  - `test_sso_page_role`: password input → login; `otp` input → mfa; "Allow" button → consent; neither → idp-page.
  - `test_is_callback_url`: `#access_token=x` → True; `?state=x` alone → False.

- [ ] **Step 2: Run** `cd /home/ankit/HuntMCP && .venv/bin/python -m pytest tests/test_ui_walk_sso_logic.py -q` — Expected: FAIL (`ModuleNotFoundError: ui_walk_sso_logic`).

- [ ] **Step 3: Implement** the Produces list in `mcp-servers/browser-mcp/ui_walk_sso_logic.py` (stdlib only: `urllib.parse`, `json`, `base64`, `re`). Stripping a URL to scheme://host/path reuses `ui_walk_events._clean_url` semantics (copy the 6-line helper rather than importing the recorder module, to keep this module browser-free).

- [ ] **Step 4: Run** the same command — Expected: all pass. Then `ruff check mcp-servers/browser-mcp/ui_walk_sso_logic.py --ignore E402,F811 --target-version py312` — Expected: no errors.

- [ ] **Step 5: Checkpoint** (ledger note; commit only with the user's OK).

---

### Task 2: Fixture — fake IdP and RP flow

**Files:**
- Modify: `tests/fixtures/ui_walk_target/ui_walk_app.py` (add `_get_sso`, `_get_idp`, IdP/RP branches in `_mutate`, host logging, helpers)
- Test: `tests/test_ui_walk_sso_fixture.py` (plain `urllib` against the fixture, no browser)

**Interfaces:**
- Produces (on `FixtureApp`):
  - `host_requests: list[tuple[str, str, str]]` — `(method, host-without-port, raw path incl. query)` for every request (appended in `_log`).
  - `issued_secrets: list[str]` — every `state`, `nonce`, `code`, `code_challenge`, `id_token` value the fixture generated or embedded (static ones too), for "appears nowhere" asserts.
  - `idp_base_url` = `alt_base_url` (`http://localhost:<port>`); RP = `base_url` (`http://127.0.0.1:<port>`).
  - `write_session_file(path: str, *, rp: bool = True, idp: bool = False) -> None` — Playwright storage_state JSON with `sid` (127.0.0.1) and/or `idp_sid` (localhost) cookies, both registered as valid.
  - `requests_to(host: str, path_prefix: str = "") -> list[tuple[str, str]]` helper.
- RP pages (host 127.0.0.1, public, no `sid` required):
  - `GET /sso` — links: "Sign in" → `/sso/login`; "Silent sign in" → `/sso/login-silent`; "Implicit sign in" → `/sso/login-implicit`; "Connect calendar" → `/sso/login-consent`; "Sign in (link)" → authorize URL built server-side with state in the href (path b); a button "SPA sign in" whose onclick sets `location.href` to an authorize URL (path c); "Log out of IdP" → `{idp}/idp/logout?post_logout_redirect_uri={rp}/sso&id_token_hint=<FIXIDTOKEN>`.
  - `GET /sso/login*` → 302 to `{idp}/idp/authorize?response_type=…&client_id=fixture-app&redirect_uri={rp}/sso/callback&scope=openid%20profile&state=…&nonce=…[&code_challenge=…&code_challenge_method=S256][&prompt=login|consent]`. `/sso/login` uses `prompt=login`; `-silent` none; `-consent` `prompt=consent`.
  - Vulnerable: `state` constant `FIXSTATESTATIC01` on every flow and in the href; no PKCE; `/sso/login-implicit` uses `response_type=id_token token` with no nonce; nonce constant `FIXNONCESTATIC01` elsewhere.
  - Patched: fresh `secrets.token_urlsafe(24)` state and nonce per response; PKCE S256; implicit link uses `response_type=code` + nonce.
  - `GET /sso/callback?code&state` → 302 `/sso/home`; `GET /sso/home` → page "Signed in".
- IdP pages (host localhost, under `/idp`):
  - `GET /idp/.well-known/openid-configuration` → JSON: `issuer={idp}/idp`, `authorization_endpoint`, `token_endpoint`, `end_session_endpoint`, `userinfo_endpoint`, `jwks_uri`, `revocation_endpoint`, `response_types_supported`, `code_challenge_methods_supported`; vulnerable adds `registration_endpoint`. Root `/.well-known/openid-configuration` → 404 (exercises the issuer-prefix path).
  - `GET /idp/authorize`: with valid `idp_sid` and `prompt` not `login`/`consent` → 302 `redirect_uri?code=<fresh, recorded>&state=<echo>`; `prompt=consent` with session → 302 `/idp/consent?…`; else → 302 `/idp/login?…` (state etc. carried in query).
  - `GET /idp/login` → form `POST /idp/login` with `username`, `password` inputs and a "Sign in" button, links "Forgot password" `/idp/forgot`, "Create account" `/idp/register`.
  - `GET /idp/consent` → scope list + form `POST /idp/consent` with "Allow" / "Deny" buttons.
  - `GET /idp/forgot`, `/idp/register` → simple pages; `GET /idp/logout` → 200 page (test asserts it is never requested); `GET /idp/userinfo`, `/idp/jwks` → JSON.
  - `POST /idp/login`, `/idp/consent`, `/idp/token` handled in `_mutate` before the `_authed` check → 200.

- [ ] **Step 1: Write failing tests** `tests/test_ui_walk_sso_fixture.py`: `test_rp_login_redirects_to_idp_authorize` (302 Location host localhost, path `/idp/authorize`); `test_vulnerable_state_static_patched_random` (two `/sso/login` responses: vulnerable states equal, patched differ; all recorded in `issued_secrets`); `test_idp_session_bounces_to_callback_with_echoed_state`; `test_discovery_issuer_path_only` (root 404, `/idp/.well-known/...` 200 JSON, `registration_endpoint` only when vulnerable); `test_host_requests_logged` (host field is `localhost` for IdP calls).

- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_ui_walk_sso_fixture.py -q` — Expected: FAIL.

- [ ] **Step 3: Implement** the fixture additions (keep existing routes untouched; `_get_sso`/`_get_idp` dispatch on the second path segment).

- [ ] **Step 4: Run** the new tests plus `tests/test_ui_walk_pass1.py -q` (existing fixture users unaffected) — Expected: all pass.

- [ ] **Step 5: Checkpoint.**

---

### Task 3: Secret redaction in the inventory + callbacks never re-requested

**Files:**
- Modify: `mcp-servers/browser-mcp/ui_walk.py` (`walk()` return path, `_enqueue_ok`, click-loop back-navigation in `_visit_page`, `_log_call` args)
- Modify: `mcp-servers/browser-mcp/ui_walk_store.py` (`emit_nodes`: labels and `meta.endpoint` through `redact_sso_params`)
- Test: `tests/test_ui_walk_sso_redaction.py`

**Interfaces:**
- Consumes: `redact_urls_deep`, `redact_sso_params`, `is_callback_url` (Task 1); fixture (Task 2).
- Produces: `walk()` returns `S.redact_urls_deep(inv)` (every code path that returns an inventory, incl. `_refused`); in-memory consumers during the walk (Pass 2, destroy, `get_log`) still see raw URLs. `_Walker._enqueue_ok(url)` returns False for `is_callback_url(url)`.

- [ ] **Step 1: Write failing tests** (browser, `requires_browser`, scope = `{127.0.0.1, localhost}`, budget patched as in `tests/test_ui_walk_events.py`, start `/sso`, `session_file` from `app.write_session_file(..., rp=True, idp=True)`, `HUNTMCP_UI_WALK_DIR` to tmp):
  - `test_no_fixture_secret_in_inventory_or_output`: for every value in `app.issued_secrets`, it is absent from `json.dumps(inv)` and from `server._format_walk({"inventory": inv, "path": "x"})`.
  - `test_callback_never_requested_twice`: every `code` value in `app.host_requests` for `/sso/callback` appears in at most one request.
  - `test_callback_not_in_queue_or_pages`: no `pages[].url` path equals `/sso/callback`.
  - Unit: `test_enqueue_refuses_callback` on a bare `_Walker` (construct as in `tests/test_ui_walk_pass1.py:253`).
  - Unit: `test_emit_nodes_redacts` — `emit_nodes` on a hand-made inventory whose edge URL has `?code=SECRETC` → stored node label/meta have no `SECRETC` (use a tmp `map_path`).

- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_ui_walk_sso_redaction.py -q` — Expected: FAIL.

- [ ] **Step 3: Implement.** Back-navigation rule: in the click loop, when `S.is_callback_url(page_url)` the walker does not `goto(page_url)` after a click that navigated away; it ends the click loop for that page instead (`rec["nav_error"] = "callback page: not re-requested"`). Audit log: pass `S.redact_sso_params(start_url)`.

- [ ] **Step 4: Run** the new tests + `tests/test_ui_walk_store.py tests/test_ui_walk_pass1.py -q` — Expected: pass.

- [ ] **Step 5: Checkpoint.**

---

### Task 4: `SsoTracker`, IdP page mapping, out-of-scope redirect record, schema 3

**Files:**
- Create: `mcp-servers/browser-mcp/ui_walk_sso.py`
- Modify: `mcp-servers/browser-mcp/ui_walk_events.py` (`Recorder.on_redirect_chain` hook in `_record_redirect`)
- Modify: `mcp-servers/browser-mcp/ui_walk.py` (`SCHEMA_VERSION = 3`, tracker wiring, `_visit_page` IdP branch, `_enqueue_ok` IdP exception, out-of-scope record + honest-limit line)
- Modify: `tests/test_ui_walk_events.py:60`, `tests/test_ui_walk_pass1.py:99` (`== 3`; intentional additive contract change)
- Test: `tests/test_ui_walk_sso_tracker.py` (unit), `tests/test_ui_walk_sso_walk.py` (black-box)

**Interfaces:**
- Consumes: Task 1 functions.
- Produces:
  - `class SsoTracker(scope: Callable[[str], bool])` in `ui_walk_sso.py`, attribute `data: dict` = the future `inv["sso"]`: `{"flows": [], "endpoints": [], "discovery": [], "idp_hosts": [], "repeats": 0, "discovery_gets": 0, "out_of_scope_idp_redirects": []}`.
    - `observe_url(url, *, method="GET", seen_via, page, control_signature, body_fields=None) -> str | None` — classifies; records an endpoint (dedup key `(role, method, endpoint_template(url), page)`), `endpoint = {"role", "method", "url": stripped, "in_scope", "param_names", "seen_via", "page", "control_signature", **role flags}`; for `authorize` also creates/updates a flow `{"key", "authorize": authorize_flags, "idp_host", "idp_in_scope", "page", "control_signature", "seen_via", "state_changes_per_request": "unknown", "nonce_changes_per_request": "unknown", "state_echoed_on_callback": "unknown", "repeat": None}` and keeps `secrets_of(url)` in a private `_first[key]`; adds the authorize/saml host to `idp_hosts`. `seen_via` ∈ `redirect-hop, request, aborted, href, form, discovery`.
    - `observe_chain(urls: list[str], *, page, control_signature) -> None` — each hop through `observe_url(seen_via="redirect-hop")`; a callback hop after an authorize hop in the same chain sets that flow's `state_echoed_on_callback` (in-memory equality); records `_repeat_source[key] = {"kind": "a", "url": <first in-scope hop that is neither authorize nor callback>}` when one exists. Handles any length (processes at most the first 20) and never raises.
    - `note_href_source(key, page, control_signature)` / `note_click_source(...)` — repeat sources b and c (only set if no source yet).
    - `is_idp_host(host: str) -> bool`; `chain_has_authorize(urls) -> bool`.
    - `note_out_of_scope_redirect(url, *, page, control_signature)` → appends `{"host", "url": stripped, "page", "control_signature"}`.
    - `pending_repeats() -> list[tuple[str, dict]]` (flows with a source and `repeat is None`); `finish_repeat(key, second_url: str | None, kind: str) -> None` (sets the tri-state flags via `compare_secrets`, sets `flow["repeat"] = {"kind", "result": "compared"|"unknown"}`, deletes `_first[key]`); `drop_secrets()` clears all in-memory values.
  - `Recorder.on_redirect_chain: Callable[[list[str], str | None], None] | None` — called in `_record_redirect` with the full hop URLs (and `ctl`) before stripping; exceptions swallowed.
  - `_Walker.sso: SsoTracker`; `inv["sso"]` = `self.sso.data` (set at init); `rec["sso_role"]` on IdP pages.
- Behaviour in `_Walker`:
  - `_on_route`: `self.sso.observe_url(url, method=method, seen_via="aborted"|"request", page=…, control_signature=self.current_control, body_fields=list(_body_shape(post) or {}))` for main-frame navigations and `document/xhr/fetch` requests, before any abort/continue.
  - `_visit_page`, right after `goto` and after each click that navigated: build the chain from `resp.request` via `redirected_from` (≤20) and call `observe_chain` (main-frame chains); the recorder hook covers XHR/fetch chains.
  - Out-of-scope landing (existing `not self.scope(page.url)` branch and a click that landed out of scope): `note_out_of_scope_redirect`; append once to `inv["honest_limits"]`: "Following an HTTP redirect to an out-of-scope identity provider sends one GET per hop there, as any browser does; nothing else is done on that host."
  - IdP page: when the landed host `is_idp_host` (or the chain had an authorize/saml-request hop) and the host is in scope, the logged-out branch does not return early: `rec["auth_state"] = "sso"`, `rec["sso_role"] = sso_page_role(inputs, controls)` (computed after the first snapshot), the page is mapped by the normal loop; at the end, if `self.had_session` and not `is_start`, `_session_still_valid()` false → `_Stop("auth_lost", …)`. `is_start` behaviour unchanged.
  - Control hrefs: `observe_url(href, seen_via="href")`; an authorize href → `note_href_source`. A control whose click produced an aborted/continued authorize main navigation → `note_click_source`.
  - `_enqueue_ok`: when `same_origin_only` rejects the origin, allow it if `self.sso.is_idp_host(host)` and fewer than 10 pages were enqueued for that host; always False for callback URLs (Task 3).
  - End of `run()` (finally): `self.sso.drop_secrets()`.

- [ ] **Step 1: Write failing unit tests** `tests/test_ui_walk_sso_tracker.py`: `test_observe_authorize_creates_flow_without_values` (dump of `data` has no state value); `test_chain_sets_echo_and_repeat_source`; `test_chain_25_hops_and_loop_never_raises` (Review Focus); `test_same_flow_on_many_pages_one_flow` (Review Focus); `test_out_of_scope_redirect_recorded_stripped`; `test_drop_secrets_empties_memory`.

- [ ] **Step 2: Write failing black-box tests** `tests/test_ui_walk_sso_walk.py` (module-scoped walks, vulnerable fixture, `session_file` rp+idp, `max_pages=30`):
  - in-scope IdP (`scope` = both hosts): `test_schema_v3_and_sso_section`; `test_idp_login_page_mapped_not_filled` (page `/idp/login` with `auth_state == "sso"`, `sso_role == "login"`, password input recorded; `app.non_get_requests()` has no `/idp/login` POST); `test_consent_page_mapped` (`sso_role == "consent"`); `test_idp_links_followed` (`/idp/forgot`, `/idp/register` in pages despite `same_origin_only=True`); `test_logout_endpoint_recorded_never_requested` (endpoint role logout with `redirect_params` containing `post_logout_redirect_uri`; no `/idp/logout` in `app.host_requests`); `test_echo_flag_true_on_silent_flow`; `test_pass1_zero_non_get`.
  - out-of-scope IdP (`scope` = 127.0.0.1 only): `test_oos_only_followed_gets` (every `localhost` request is a GET whose path is in `{/idp/authorize, /idp/login, /idp/consent}`); `test_oos_no_idp_pages_mapped` (no page on localhost); `test_oos_redirects_recorded` (`out_of_scope_idp_redirects` non-empty, honest-limit line present); `test_oos_spa_button_aborted` (no `localhost` request from the SPA button: count of `/idp/authorize` requests equals the number of HTTP-redirect flows).

- [ ] **Step 3: Run** both files — Expected: FAIL.

- [ ] **Step 4: Implement** per Interfaces.

- [ ] **Step 5: Run** both files, then `tests/test_ui_walk_*.py -q` — Expected: all pass (only the two `schema_version` asserts changed).

- [ ] **Step 6: Checkpoint.**

---

### Task 5: The repeat and discovery (map mode only)

**Files:**
- Modify: `mcp-servers/browser-mcp/ui_walk.py` (`_run_sso_repeats`, `_run_sso_discovery`, keep the Playwright handle as `self._pw` in `run()`)
- Test: `tests/test_ui_walk_sso_repeat.py`

**Interfaces:**
- Consumes: `SsoTracker.pending_repeats/finish_repeat`, `discovery_urls`, `parse_discovery`, `observe_url(seen_via="discovery")`.
- Produces: `inv["sso"]["repeats"]`, `["discovery_gets"]`, `["discovery"]` entries `{"host", "url", "status", "issuer", "endpoints", "supported"}`.
- Behaviour:
  - `_run_sso_repeats()` called after each page's click loop and once after the BFS, only if `self.mode == "map"`, stops at 5 per walk. Per flow:
    - kind a: `url` must pass `self.scope` and not `L.is_mutating_get_url` and not `is_callback_url`; `await self._budget()`; `ctx = await self._pw.request.new_context(storage_state=await self.context.storage_state(), ignore_https_errors=self.mirror_active)`; `resp = await ctx.get(url, max_redirects=0, timeout=10000)`; `Location` resolved with `urljoin`; `await ctx.dispose()` in `finally`; second URL used only if `flow_key(location) == key`.
    - kind b: only if the page is the current page's URL or reachable in scope: `await self._budget()`, `page.goto(page_url)`, re-snapshot, find the control by signature, read its `href`.
    - kind c: only if `flow["idp_in_scope"]`: `await self._budget()`, click the control once, capture the authorize URL via a one-shot `observe` hook in the tracker (`expect_authorize(key)`), go back.
    - anything fails or no match → `finish_repeat(key, None, kind)`; exceptions other than `_Stop` are swallowed and never carry a value (`type(e).__name__` only).
  - `_run_sso_discovery()` after the BFS, before `after_map()`, only if `self.mode == "map"`: for up to 3 in-scope `idp_hosts`, try `discovery_urls(authorize_url)` then `<origin>/.well-known/oauth-authorization-server` on 404, ≤ 3 GETs per host, stop at first 200 JSON. Fresh request context without storage state; `max_redirects=0`; skip body if `content-length` > 262144; `parse_discovery(body, scope=self.scope)`; each endpoint → `observe_url(url, method=ENDPOINT_METHOD[role], seen_via="discovery", page=<the flow's page>)`.

- [ ] **Step 1: Write failing tests** (black-box, vulnerable and patched module walks, IdP in scope):
  - `test_static_state_detected_vulnerable` (`/sso/login` flow `state_changes_per_request is False`); `test_random_state_patched` (`True`); `test_nonce_flags`.
  - `test_repeat_caps` (Review Focus): `inv["sso"]["repeats"] <= 5` and each flow key repeated ≤ 1.
  - `test_repeat_a_does_not_follow_or_touch_cookies`: in `app.host_requests`, the repeat's `/sso/login` GET is not followed by an extra `/idp/authorize` request beyond the browser's own flows (count `/idp/authorize` = flows seen by the browser); walk `status == "complete"` with the session intact.
  - `test_discovery_from_issuer_prefix`: one `discovery` entry with `status == 200`, the root 404 attempt counted; `registration` endpoint present (vulnerable) / absent (patched).
  - `test_discovery_and_repeat_skipped_in_oos_walk`: no `/.well-known` request to `localhost`.
  - `test_budget_exhausted_mid_repeat` (Review Focus): patch `browser_confirm._enforce_budget` to raise `BudgetExceeded` on the Nth call so it lands in a repeat → `status == "budget_exhausted"`, no `issued_secrets` value in `json.dumps(inv)`.
  - `test_canary_mode_no_repeat_or_discovery`: a `CanaryWalker` instance (grant fixture as in `tests/test_ui_walk_pass2.py`) → `repeats == 0`, `discovery_gets == 0`.

- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_ui_walk_sso_repeat.py -q` — Expected: FAIL.

- [ ] **Step 3: Implement** per Interfaces.

- [ ] **Step 4: Run** the file + `tests/test_ui_walk_sso_walk.py tests/test_ui_walk_mirror.py -q` — Expected: pass.

- [ ] **Step 5: Checkpoint.**

---

### Task 6: SSO candidates, surface-map nodes, coverage battery

**Files:**
- Modify: `mcp-servers/browser-mcp/ui_walk_sso_logic.py` (`derive_sso_candidates`)
- Modify: `mcp-servers/browser-mcp/ui_walk.py` (add candidates at end of `run()` via `self._add_candidates`)
- Modify: `mcp-servers/browser-mcp/ui_walk_store.py` (`emit_nodes`)
- Modify: `mcp-servers/coverage_manifest.py` (`required_classes`)
- Test: extend `tests/test_ui_walk_sso_logic.py`, `tests/test_ui_walk_store.py`, `tests/test_coverage_manifest.py` (find the existing file with `grep -l required_classes tests/`), `tests/test_ui_walk_sso_walk.py`

**Interfaces:**
- Produces:
  - `derive_sso_candidates(sso: dict) -> list[dict]`, items `{"type", "page", "control_signature", "detail"}`:
    - `sso-redirect-uri-candidate` (idp in scope, `redirect_uri` set): detail `{client_id, redirect_uri, response_type, idp_host}`.
    - `sso-state-candidate` when `state.strength != "ok"` or `state_changes_per_request is False` or `state_echoed_on_callback is False`: detail `{reasons: [...from "missing","weak:<class>","static","not-echoed"], idp_in_scope}`.
    - `sso-nonce-candidate` when `"id_token" in response_type` and nonce absent, or `nonce_changes_per_request is False`: `{reasons, idp_in_scope}`.
    - `sso-pkce-candidate` (idp in scope, `"code" in response_type`, `pkce` False or method `plain`).
    - `sso-implicit-flow-candidate` (`"token"` in response_type split on spaces).
    - `sso-logout-redirect-candidate` (in-scope logout endpoint with non-empty `redirect_params`).
    - `sso-registration-candidate` (in-scope registration endpoint).
  - `emit_nodes`: pages with `auth_state == "sso"` are emitted like `ok` pages, `meta.sso_role = page["sso_role"]`; every `inv["sso"]["endpoints"]` entry with `in_scope` → `action` node, signature `f"action:{method} {endpoint_template(url)}"`, `meta = {"sso_role", "endpoint", "param_names", "walk_id", plus flags}`, parent = the page node whose `url` equals the endpoint's `page` (fall back to the first emitted page node of that host); api_edges whose URL `classify_url` gives a role are skipped in the generic action loop. Returns counts incl. `"sso_action"`.
  - `required_classes(node)`: if `meta.sso_role`: base = `{"auth"}` for `action` nodes, page battery ∪ `{"auth"}` for `page` nodes; add `"open-redirect"` for authorize/callback/logout; add `"csrf"` for authorize/login/consent; roles jwks/userinfo/discovery get `{"auth"}` only. Precedent union unchanged.

- [ ] **Step 1: Write failing tests:** each candidate rule positive and negative (unit, hand-made `sso` dicts); out-of-scope IdP → no redirect-uri/pkce/registration/logout candidates but state/nonce candidates carry `idp_in_scope: False`; `emit_nodes` on a hand-made v3 inventory makes the SSO page + action nodes with `sso_role` and no generic duplicate for a `POST /idp/token` edge; `required_classes` for authorize-action = `{"auth","open-redirect","csrf"}`, token-action = `{"auth"}`, login-page = `{"xss","access-control","csrf","auth"}`, jwks = `{"auth"}`; black-box: vulnerable walk has `sso-state-candidate` (static), `sso-pkce-candidate`, `sso-implicit-flow-candidate`, `sso-logout-redirect-candidate`, `sso-registration-candidate`, `sso-redirect-uri-candidate`; patched walk has none of state(static)/pkce/implicit/registration.

- [ ] **Step 2: Run** the touched test files — Expected: FAIL.

- [ ] **Step 3: Implement** per Interfaces.

- [ ] **Step 4: Run** touched files + `tests/test_ui_walk_*.py tests/test_coverage_manifest.py -q` — Expected: pass.

- [ ] **Step 5: Checkpoint.**

---

### Task 7: Pass 2 SSO-form refusal, tool output, agent prompts

**Files:**
- Modify: `mcp-servers/browser-mcp/ui_walk_logic.py` (`form_unsafe_reason(submit_controls, action, *, sso_page: bool = False)`)
- Modify: `mcp-servers/browser-mcp/ui_walk_pass2.py:347` (pass `sso_page=self.sso.is_idp_host(urlsplit(self.page.url).hostname or "")`)
- Modify: `mcp-servers/browser-mcp/server.py` `_format_walk` (SSO section)
- Modify: `.claude/agents/recon-agent.md`, `.claude/agents/exploit-agent.md`
- Test: `tests/test_ui_walk_logic.py`, `tests/test_ui_walk_pass2.py`, `tests/test_ui_walk_tools.py`, `tests/test_ui_walk_agent_wiring.py`

**Interfaces:**
- Produces: `form_unsafe_reason` returns `"sso-form"` when `sso_page` is True or `classify_url(action, "POST")` is not None (checked after the existing NEVER_CLICK/destructive checks). `_format_walk` adds, before the provenance line, an `SSO:` block: flows count, per flow `client_id`, idp host (in/out of scope), `response_type`, state/nonce/pkce flags, echo/static flags; endpoints by role; discovery status; out-of-scope IdP redirect hosts; all target-derived strings through the existing quarantine helper.
- Prompts: recon-agent — one line: the UI-walk records in-scope SSO flows itself; no extra step. exploit-agent — `sso-*` candidates are worked with the `auth-and-session` skill (`redirect_uri` parser differentials, state/nonce, PKCE, logout open redirect); never test an out-of-scope IdP; `idp_in_scope: false` leads are tested only against the app's callback.

- [ ] **Step 1: Write failing tests:** `test_form_unsafe_sso_page` / `test_form_unsafe_sso_action`; Pass 2 black-box: a canary walk (grant fixture) over `/sso` with IdP in scope never POSTs `/idp/login` or `/idp/consent` (`app.non_get_requests()`); `_format_walk` on a v3 inventory shows `SSO:` and ends with the provenance line and has no `issued_secrets` value; wiring test asserts the two prompt lines exist (follow the existing pattern in `tests/test_ui_walk_agent_wiring.py`).

- [ ] **Step 2: Run** those files — Expected: FAIL.

- [ ] **Step 3: Implement.**

- [ ] **Step 4: Run** full suite `.venv/bin/python -m pytest tests -q -x` (background, it takes minutes) and the CI checks: `ruff check mcp-servers/ --ignore E402,F811 --target-version py312`, `python -m py_compile` on each changed server file. Expected: all green (baseline before this work: 3645 passed, 1 skipped, 5 xfailed plus #168's additions).

- [ ] **Step 5: Checkpoint.**

---

### After the tasks (outside this plan's TDD loop, per the user's process)

1. "Review and audit": run `/code-review` and `/security-review` on the branch; fix findings TDD.
2. "Prove it runs": ask the user, then `scripts/switch-engagement.sh set ui-walk-proof.localhost --force`; serve the fixture; real `mcp__browser-mcp__start_ui_walk` / `check_ui_walk` (IdP in scope = both loopback hosts); record `Runtime-verified: …`. Honest limit: the real tool uses the default scope check, where both loopback hosts are always in scope, so the out-of-scope-IdP case is proved by the black-box tests only; switch back to `bentley.com`. Never `bentley-com`.
3. Commit / PR only on the user's in-the-moment OK.
