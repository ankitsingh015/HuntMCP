# UI-walk Event Recorder + Burp Mirror Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every page the #164 UI-walk visits carries an ordered, control-attributed event stream (redirects, cookies, headers, WebSocket, postMessage, console, storage, DOM sinks, small events), with candidates derived from it. The walk's real traffic can optionally be mirrored into Burp.

**Architecture:** Pure decisions (parsers, shape summaries, candidate rules, proxy validation) go in a new `ui_walk_events_logic.py`. A new `ui_walk_events.py` `Recorder` attaches to the walker's context and page: Playwright events, one CDP session, one init script reporting through `expose_binding`. `ui_walk._Walker` drives it at page start, around each click, and at page end. The Burp mirror is a launch/context option plus a preflight and a refusal fallback in `ui_walk.walk`.

**Tech Stack:** Python 3.12, Playwright 1.62 (already in `.venv`), stdlib `http.server` fixture, pytest.

**Spec:** `docs/superpowers/specs/2026-11-20-ui-walk-event-recorder-design.md`

## Global Constraints

- Inventory `schema_version` = **2**; all v1 fields keep their meaning (additive only).
- No new dependency, no new MCP server. Existing tool params unchanged; only additive params.
- Never store a cookie value, a storage value, a postMessage/WebSocket payload value, or full console text. Values are dropped in-process. Storage "changed" uses an in-browser short hash, never the value.
- Caps: 300 events/page, 20 console messages/page, 2,000 events/walk; overflow → `events_dropped` count.
- Console text ≤ 300 chars, through `redact.redact_text`, quarantined in tool output.
- Probe origin `https://hm-probe.invalid`; probe watch window ~1.5 s; probe only in **in-scope** frames.
- Canary token format and registry: reuse `ui_walk_logic.make_canary` and `ui_walk_store` (same as Pass 2).
- Proxy: scheme `http`/`https`, host exactly `127.0.0.1` | `localhost` | `[::1]`, a port, no userinfo. Param `upstream_proxy` ("" → env `HUNTMCP_UPSTREAM_PROXY`, else off; `"off"` → off always).
- Mirror mode only: `--proxy-bypass-list=<-loopback>`, `ignore_https_errors=True`, proxy-refusal check, mid-walk `blocked` stop. A non-mirror walk behaves exactly as in #164. The direct fallback relaunches without `ignore_https_errors`.
- Pass 1 still sends nothing state-changing; scope on every navigation and request; payment hosts blocked; provenance line last; budget per page load (the one refusal-comparison load is charged).
- Git: the work lives on its own branch stacked on `fix/wiring-and-testing-159-164` (see Task 0). **Never commit or push without the user's in-the-moment OK.** The commit steps below are checkpoints to run once the user says commit.
- Lint gate: `ruff check mcp-servers/ --ignore E402,F811 --target-version py312`.

## Review Focus

1. **Init-script wrappers break the target page** (a wrapped `innerHTML` setter throws, or a page that freezes prototypes) → the wrappers must always call the original, swallow their own errors, and never change behaviour. Pinned in Task 3 by re-running the whole existing `test_ui_walk_pass1.py` module with the recorder on, unchanged.
2. **The walker's own canary planting trips the sink hooks** (writing `location.hash` is a `location` sink) → planting is excluded from sink reports. Pinned in Task 4 (`test_planting_is_not_a_sink`).
3. **A hash-routed SPA breaks when the canary is appended** → the route is kept and the page still renders its routed view. Pinned in Task 4 (`test_hash_canary_keeps_spa_route`).
4. **Odd Set-Cookie input** (several cookies joined by `\n` from CDP, commas inside `Expires`, attribute casing, no `=`) → every cookie is parsed and no value survives. Pinned in Task 1.
5. **Async events after a click are attributed to the next control** (a `setTimeout` cookie write) → events carry the control active when the event fired, and the walker waits for the existing settle before switching controls. Pinned in Task 2 (`test_delayed_event_attributed_to_its_click`).

---

### Task 0: Branch (precondition, needs a decision)

The checkout `/home/ankit/HuntMCP` is shared with the in-flight #164 session on `fix/wiring-and-testing-159-164`. A side session must not switch branches there. Before any code:

Decided (2026-11-20, option a): #164 is open as PR ankitsingh015/HuntMCP#166 (base `main`). Wait until the user says #166 is merged. Until then, no branch switch and no commit in this folder.

- [ ] **Step 1:** After the user confirms #166 is merged: `git fetch origin`, check `git status` is clean apart from the untracked spec/plan/hexbrain files, then `git switch main && git pull --ff-only && git switch -c feat/ui-walk-event-recorder`.
- [ ] **Step 2:** Run `git status`, `git branch --show-current`, `git log --oneline -1`. Expected: on `feat/ui-walk-event-recorder`, and `main` contains the #164 commits (e.g. `git merge-base --is-ancestor 5dd1622d HEAD` exits 0).

### Task 1: Pure event logic

**Files:**
- Create: `mcp-servers/browser-mcp/ui_walk_events_logic.py`
- Test: `tests/test_ui_walk_events_logic.py`

**Interfaces — Produces:**
- `parse_set_cookie(raw: str) -> list[dict]` — splits on `\n`; each dict `{name, domain, path, secure: bool, httponly: bool, samesite: str|None, persistent: bool, partitioned: bool}`; **no value key**.
- `parse_cookie_assignment(s: str) -> dict` — same shape, for a `document.cookie = s` string (`httponly` always False).
- `is_authish_name(name: str) -> bool` — case-insensitive substring list: `sess, sid, auth, token, jwt, remember, login, csrf, xsrf, refresh, access, id_token, bearer`.
- `data_shape(obj) -> dict` — `{"type": str, "keys": sorted top-level keys (dict only, ≤30), "length": int}`; never values.
- `storage_diff(before: dict[str, dict[str, str]], after: same) -> list[dict]` — input `{origin: {key: hash}}`; output `{origin, key, change: "added"|"removed"|"changed"}`.
- `redirect_param_names(hops: list[dict]) -> list[str]` — hop = `{url, location}`; names of query params of hop *n* whose value occurs in hop *n*'s `location` (values compared in memory, only names returned).
- `security_headers(headers: dict[str, str]) -> dict` — lowercased-key input; `{csp (≤500 chars), xfo, frame_ancestors, acao, acac: bool, acam, hsts: bool}`.
- `validate_proxy_url(url: str) -> str | None` — error string or None.
- `resolve_upstream_proxy(param: str, env: str | None) -> str | None` — `"off"` → None; `""` → env or None; else param. Validation is separate.
- `derive_candidates(page: dict, *, scope: Callable[[str], bool]) -> list[dict]` — reads `page["events"]`, `page["api_edges"]`, `page["controls"]`, `page["url"]`; returns candidate dicts `{type, page, control_signature, detail}` of types `cookie-flags-candidate`, `postmessage-wildcard-target-candidate`, `postmessage-no-origin-check-candidate`, `storage-token-candidate`, `redirect-param-candidate`, `clickjacking-candidate`, `cors-candidate`, `tabnabbing-candidate`, `dom-sink-candidate`, `dom-xss-candidate`. Every XSS-type candidate (`dom-*`) gets `detail.csp` from the page's `headers` events.

- [ ] **Step 1: Write failing tests.** At least:
  - `test_parse_set_cookie_drops_value_and_reads_flags`: `"SID=s3cr3t; Path=/; Secure; HttpOnly; SameSite=Lax"` → `[{"name": "SID", "secure": True, "httponly": True, "samesite": "Lax", "path": "/", ...}]`, and `"s3cr3t" not in json.dumps(result)`.
  - `test_parse_set_cookie_multiple_and_expires_comma`: `"a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT\nb=2"` → names `["a", "b"]`, `a.persistent is True`, `b.persistent is False`.
  - `test_parse_set_cookie_attribute_casing_and_no_equals`: `"x=1; secure; HTTPONLY; samesite=none"` and `"novalue"` both parse without error.
  - `test_data_shape_never_returns_values`: `data_shape({"token": "abc123", "n": 1})` → `{"type": "object", "keys": ["n", "token"], "length": 2}`, `"abc123" not in str(...)`.
  - `test_storage_diff`: added/removed/changed cases.
  - `test_redirect_param_names`: hops `[{"url": "https://a.test/go?next=https://b.test/x&z=1", "location": "https://b.test/x"}]` → `["next"]`.
  - `test_validate_proxy_url`: accepts `http://127.0.0.1:8080`, `http://localhost:8080`, `http://[::1]:8080`; rejects `http://10.0.0.5:8080`, `http://burp.example:8080`, `http://u:p@127.0.0.1:8080`, `socks5://127.0.0.1:1080`, `http://127.0.0.1` (no port).
  - `test_resolve_upstream_proxy_off_beats_env`.
  - Candidate rules, positive **and** negative per type: `SID` without Secure on https → candidate; `theme` cookie without flags → none; `SameSite=None` without Secure → candidate; a page with a non-GET edge and no XFO/frame-ancestors → clickjacking; the same page with `frame-ancestors 'none'` → none; `acac True` + `acao "*"` → cors; `acao` fixed allow-list origin not equal to the page origin → none; `_blank` to an out-of-scope host without noopener → tabnabbing, in-scope → none; a `dom_sink` event with `executed True` → `dom-xss-candidate` carrying `detail.csp`.
- [ ] **Step 2:** Run `.venv/bin/python -m pytest tests/test_ui_walk_events_logic.py -v`. Expected: FAIL (module missing).
- [ ] **Step 3:** Implement the interfaces above. Parse `Set-Cookie` by splitting on `\n` first, then `;`. Cookie *name* = text before the first `=`. `Expires`/`Max-Age` → persistent.
- [ ] **Step 4:** Rerun. Expected: PASS. Ruff clean.
- [ ] **Step 5: Commit checkpoint** (only on user OK): `git add mcp-servers/browser-mcp/ui_walk_events_logic.py tests/test_ui_walk_events_logic.py`.

### Task 2: Recorder core — network-side events + schema v2

**Files:**
- Create: `mcp-servers/browser-mcp/ui_walk_events.py`
- Modify: `mcp-servers/browser-mcp/ui_walk.py` (`SCHEMA_VERSION` :36, `_open` :287-295, `_on_ws` :247-252, `_visit` :305-441, `_click` :469-478, `_refused` :586-589)
- Modify: `tests/fixtures/ui_walk_target/ui_walk_app.py` (new `/ev/*` routes)
- Test: `tests/test_ui_walk_events.py`

**Interfaces:**
- Consumes: Task 1 parsers.
- Produces: `class Recorder` with `async attach(context, page, *, scope: Callable[[str], bool]) -> None`; `begin_page(rec: dict) -> None` (sets `rec["events"] = []`, `rec["events_dropped"] = 0`); `set_control(sig: str | None) -> None`; `record(event: dict) -> None` (stamps `control_signature`, `t_ms`, applies caps); `async end_page(rec: dict) -> None`. Event dicts use `type` ∈ `redirect, set_cookie, headers, websocket, console` in this task.
- The `_Walker` owns `self.recorder = Recorder()`. `_visit` calls `begin_page` after `rec` is built, `set_control(sig)` wherever `self.current_control` is set, and `end_page` before `_shoot`. `_on_ws` records per-frame `{direction: "client", opcode, size, json_keys}` and still increments `ws_frames_blocked`.

Fixture routes (vulnerable / patched where it matters):
- `/ev/cookies` sets `SID` (vulnerable: no flags; patched: `Secure; HttpOnly; SameSite=Lax`) plus `theme=dark`.
- `/ev/redirect?next=/ev/landed` → 302 to `/ev/hop2?next=...` → 302 to the `next` value.
- `/ev/console` has a button whose click throws an error and logs `console.error`. `/ev/delayed` has a button that sets a cookie via a response 400 ms after the click.
- `/ev/ws` opens a WebSocket and sends a JSON client frame `{"op":"sub","token":"FIXTURESECRET"}` on click.
- `/api/cors` returns `Access-Control-Allow-Origin: <echoed Origin>` + `-Credentials: true` (patched: fixed `http://allowed.test`).
- Every secret-looking value the fixture sets uses the literal string `FIXTURESECRET`, so tests can grep for it.

- [ ] **Step 1: Failing tests:**
  - `test_inventory_schema_v2` — `inv["schema_version"] == 2` and every page has `events` and `events_dropped`.
  - `test_redirect_chain_recorded` — the `/ev/redirect` page has a `redirect` event with 2+ hops, each hop with `in_scope`.
  - `test_set_cookie_names_and_flags_only` — `set_cookie` events for `SID` and `theme`. The CDP path is present: the event has a `blocked` key (list, possibly empty).
  - `test_headers_event_on_api_response` — `headers` event for `/api/cors` with `acac True`.
  - `test_console_error_tied_to_click` — `console` event whose `control_signature` is the button's signature, text ≤ 300.
  - `test_ws_client_frame_metadata_only` — `websocket` event with `json_keys == ["op", "token"]`. Fixture server received zero WS frames.
  - `test_delayed_event_attributed_to_its_click` (Review Focus 5).
  - `test_no_secret_value_anywhere` — `"FIXTURESECRET" not in json.dumps(inv)`.
  - `test_pass1_suite_unchanged_with_recorder` — run `pytest tests/test_ui_walk_pass1.py tests/test_ui_walk_pass2.py tests/test_ui_walk_destroy.py tests/test_ui_walk_teardown.py` as a step (not a new test). Expected: all pass unchanged, except tests that pin `schema_version == 1`, which update to 2: an intentional contract change, noted in the diff.
- [ ] **Step 2:** Run `.venv/bin/python -m pytest tests/test_ui_walk_events.py -v`. Expected: FAIL.
- [ ] **Step 3:** Implement:
  - `redirect` from `context.on("response")`: when `response.request.redirected_from` exists, walk the chain back to build hops.
  - `set_cookie` from a CDP session (`context.new_cdp_session(page)`, `Network.enable`, `Network.responseReceivedExtraInfo` → `headers["set-cookie"]` + `blockedCookies[].blockedReasons`). Parse at once, drop the raw string.
  - `headers` from the same response events for document/xhr/fetch.
  - `console` from `page.on("console")` (type `error`) and `page.on("pageerror")`.
  - Pass the per-walk cap counter in the Recorder.
- [ ] **Step 4:** Rerun the new tests and the existing ui_walk suite. Expected: PASS.
- [ ] **Step 5: Commit checkpoint** (user OK).

### Task 3: Init-script events — postMessage, JS cookies, IndexedDB, storage, small events

**Files:**
- Modify: `mcp-servers/browser-mcp/ui_walk_events.py` (add `INIT_JS`, `expose_binding("__hmEvent", ...)`, `snapshot_storage(page)`)
- Modify: fixture (`/ev/pm-send`, `/ev/pm-listen`, `/ev/pm-listen-safe`, `/ev/jscookie`, `/ev/idb`, `/ev/storage`, `/ev/blank`, `/ev/sw`)
- Test: `tests/test_ui_walk_events.py`

**Interfaces — Produces:** event types `postmessage` (`{direction: "send"|"listen", target_origin?, shape?, listeners?, frame_origin, frame_in_scope}`), `js_cookie`, `indexeddb` (`{db, stores: [...]}`), `storage` (Task 1 `storage_diff` rows), `window_open` (`{url, noopener: bool, via: "anchor"|"window.open"}`), `service_worker` (`{script_url, scope}`). `Recorder.snapshot_storage(page) -> dict[str, dict[str, str]]` is called by the walker before and after each click; `{origin: {key: hash}}` is computed in-browser (FNV-1a hex of the value). Only in-scope frames are snapshotted.

`INIT_JS` (via `context.add_init_script`, all frames) wraps:
- `window.postMessage` (send: targetOrigin + shape) and `addEventListener` (type `message` → listen count). It keeps a hidden registry of the listener's frame so Task 4's probe can target it.
- the `document.cookie` setter (passes the assignment string to Python; Python parses with `parse_cookie_assignment`. **The Python side must parse and drop the value immediately; the binding payload is never logged**).
- `indexedDB.open` + `createObjectStore`.
- `window.open` (the `noopener` feature flag), and anchor `_blank` scan at enumeration time (`rel` contains `noopener` or `noreferrer`).
- `navigator.serviceWorker.register` (records, then returns a rejected promise; registration stays blocked).

Every wrapper: try/catch around its own logic, always calls through to the original, keeps `toString` of the original (Review Focus 1).

- [ ] **Step 1: Failing tests:** `test_postmessage_send_wildcard_shape`, `test_postmessage_listener_registered_in_scope_frame`, `test_js_cookie_names_flags_no_value`, `test_indexeddb_store_names`, `test_storage_diff_per_click` (click writes `authToken` → `storage` event `added` attributed to the click), `test_blank_link_noopener_flag`, `test_service_worker_registration_recorded_and_still_blocked`, plus `test_no_secret_value_anywhere` extended to these pages.
- [ ] **Step 2:** Run. Expected: FAIL.
- [ ] **Step 3:** Implement as above. The binding sends a single JSON object per event; Python routes it to `record()` with the current control.
- [ ] **Step 4:** Rerun the new tests and the full existing ui_walk suite. Expected: PASS.
- [ ] **Step 5: Commit checkpoint** (user OK).

### Task 4: postMessage probe + DOM sink hooks + zero-traffic sources

**Files:**
- Modify: `mcp-servers/browser-mcp/ui_walk_events.py` (sink wrappers in `INIT_JS`, `async probe_postmessage(page, rec)`, `async plant_sources(page, url, rec)`)
- Modify: `mcp-servers/browser-mcp/ui_walk.py` (`_visit`: after the click loop and before `end_page`, call `plant_sources` then `probe_postmessage`)
- Modify: fixture (`/ev/dom-hash` vulnerable `innerHTML` / patched `textContent`; `/ev/dom-name` `window.name` → `document.write`; `/ev/pm-dom` `event.data` → `innerHTML` with no origin check, patched with check; `/ev/spa#/route` hash-routed view)
- Test: `tests/test_ui_walk_dom.py`

**Interfaces — Produces:**
- `dom_sink` event `{source: "hash"|"window.name"|"postmessage", sink, frame_origin, script_url, line, executed: bool, token}`.
- `postmessage_probe` per page: `{"probed_frames": int, "reactions": [{frame_origin, kind: "dom"|"navigation"|"request"|"storage"|"console"}], "result": "reaction"|"no-reaction"|"skipped-out-of-scope"|"no-listener"}`, stored at `rec["postmessage_probe"]`.
- Canary: `ui_walk_logic.make_canary()`. The payload form is `hm…"'><img src=x onerror=alert('hm…')>`, as in Pass 2. Tokens are registered via `ui_walk_store` with `source` set.
- Sink wrappers fire only when the written value contains a registered `hm` token from this walk. A flag set during planting suppresses sink reports for the walker's own writes (Review Focus 2).
- Hash planting: if the current hash starts with `#/` or `#!`, append `&hm=<canary>` (or `?hm=` if the route has no `?`); otherwise set `#hm=<canary>`. Navigate in-page (no reload when only the hash changes), then call `dispatchEvent(new HashChangeEvent(...))` only if the page itself did not fire one.
- `window.name` planting: set it, then reload the same URL. That is a GET page load; budget-charged.
- Execution detection reuses the dialog/title marker path the walker already has (`on_dialog`). Pass 1's `_Walker.on_dialog` must now record token matches into the recorder too.

- [ ] **Step 1: Failing tests:** `test_hash_source_innerhtml_vulnerable_is_dom_xss`, `test_hash_source_textcontent_patched_no_candidate`, `test_window_name_document_write_sink`, `test_postmessage_probe_reaction_vulnerable`, `test_postmessage_probe_patched_no_reaction`, `test_probe_skips_out_of_scope_frames` (a listener in the fixture's `alt_base_url` iframe, out of scope in the test's `_scope`, gives `skipped-out-of-scope` and zero requests to that origin after probing), `test_planting_is_not_a_sink`, `test_hash_canary_keeps_spa_route` (the routed view's marker text is still present after planting), `test_pass1_still_zero_non_get` (fixture `non_get_requests() == []` after a walk over all `/ev/*` pages).
- [ ] **Step 2:** Run `.venv/bin/python -m pytest tests/test_ui_walk_dom.py -v`. Expected: FAIL.
- [ ] **Step 3:** Implement. Probe: for each in-scope frame with a registered listener, dispatch `new MessageEvent("message", {data: <shape-like object carrying the payload canary, else {type: "hm…"}>, origin: "https://hm-probe.invalid"})` on that frame's `window`. Watch 1.5 s via MutationObserver plus the recorder's request/storage/console streams.
- [ ] **Step 4:** Rerun the new tests and the full ui_walk suite. Expected: PASS.
- [ ] **Step 5: Commit checkpoint** (user OK).

### Task 5: Candidates into the inventory + Pass 2 events

**Files:**
- Modify: `mcp-servers/browser-mcp/ui_walk.py` (`end_page` result → `self.inv["candidates"].extend(derive_candidates(rec, scope=self.scope))`)
- Modify: `mcp-servers/browser-mcp/ui_walk_pass2.py` (`_p2` scratch records: route their recorder events into `self.inv["pass2_events"]` with `page_template`; `forward_sent` :174-193 parses `resp.headers_array()` `set-cookie` entries with `parse_set_cookie` → `set_cookie` events, `via: "route.fetch"`)
- Modify: `ui_walk._refused` and the inv init: add `"pass2_events": []`, `"burp_mirror": {"requested": False, "active": False, "reason": None}`.
- Test: `tests/test_ui_walk_events_candidates.py` (module fixture walks **both** `serve(vulnerable=True)` and `serve(vulnerable=False)`)

- [ ] **Step 1: Failing tests:** for each candidate type of Task 1, `test_<type>_on_vulnerable_only` asserts ≥1 on the vulnerable walk and 0 on the patched walk (tabnabbing and storage-token use pages that are identical in both variants and assert presence only). Plus `test_pass2_submit_cookie_recorded`: under a test grant (the same way `test_ui_walk_pass2.py` builds it), the fixture's `/api/contact` POST response sets `SID` → a `pass2_events` `set_cookie` event with `via == "route.fetch"`, and no value.
- [ ] **Step 2:** Run. Expected: FAIL.
- [ ] **Step 3:** Implement. Make the fixture's `/api/contact` set a rotated `SID` cookie in the vulnerable variant.
- [ ] **Step 4:** Rerun the new tests and the full ui_walk suite. Expected: PASS.
- [ ] **Step 5: Commit checkpoint** (user OK).

### Task 6: Burp mirror

**Files:**
- Modify: `mcp-servers/browser_launch.py` (`launch_kwargs(headless=True, proxy: str | None = None)`; when `proxy` is set: `kwargs["proxy"] = {"server": proxy}` and `"--proxy-bypass-list=<-loopback>"` appended to args)
- Modify: `mcp-servers/browser-mcp/ui_walk.py` (`walk(..., upstream_proxy: str = "")`; `_Walker.run` launches with the proxy; `_open` adds `ignore_https_errors=True` only in mirror mode; preflight + refusal + mid-walk `blocked`)
- Modify: `mcp-servers/browser-mcp/ui_walk_teardown.py` `execute(..., upstream_proxy: str = "")` → same launch path
- Test: `tests/test_ui_walk_mirror.py`; a stand-in proxy helper `tests/fixtures/ui_walk_target/standin_proxy.py` (stdlib threading HTTP forward proxy, plain-HTTP absolute-URI requests only; it logs `(method, url)`, adds `Via: 1.1 hm-standin`, and can be stopped)
- Modify: fixture `refuse_proxied: bool` → 403 with a WAF-looking body (one that `tool_resolver.classify_block` returns `waf` for) when the `Via` header is present

**Interfaces — Produces:** `inv["burp_mirror"] = {"requested": bool, "active": bool, "proxy": str|None, "reason": str|None}` with reasons exactly `"proxy unreachable"`, `"target refused proxied traffic"`, `"blocked mid-walk"`. Walk status `"blocked"` (mirror mode only).

Flow inside `walk()`:
1. `p = resolve_upstream_proxy(upstream_proxy, os.environ.get("HUNTMCP_UPSTREAM_PROXY"))`.
2. `validate_proxy_url(p)` error → `_refused(..., f"upstream_proxy refused: {err}")`.
3. TCP preflight (`socket.create_connection`, 2 s). Fail → direct, reason `proxy unreachable`.
4. The start page loads via the proxy. A connection/TLS error, or status ∈ {403, 429, 503} with `classify_block(body) in {"waf", "rate_limit"}`, triggers **one** budget-charged direct load (fresh context, no `ignore_https_errors`). Direct OK → the whole walk continues direct, reason `target refused proxied traffic`. Task 7's `_format_walk` adds one line for this reason: the block appears only through the proxy, so it is a proxy/tooling artifact (likely the proxy's outbound TLS fingerprint), not a finding. If the programme allows it, the human can change their Burp's outbound TLS settings and re-run. The walker itself never alters TLS fingerprints. Direct also blocked → normal #164 behaviour.
5. Mid-walk in mirror mode: a page that returns the block signature → `_Stop("blocked", ...)`, reason `blocked mid-walk`. No mode switch.

- [ ] **Step 1: Failing tests:**
  - `test_mirror_every_sent_request_went_through_proxy` — the set of `(method, path)` the fixture received equals the set the stand-in logged.
  - `test_mirror_aborted_requests_never_reach_proxy` — no non-GET in the stand-in log.
  - `test_mirror_unreachable_falls_back_direct_loudly`.
  - `test_mirror_refused_falls_back_direct` (`refuse_proxied=True`).
  - `test_mirror_mid_walk_block_stops` (the fixture starts refusing after N requests).
  - `test_remote_proxy_refused`.
  - `test_off_sentinel_beats_env` (monkeypatch env).
  - `test_non_mirror_walk_unchanged` (`burp_mirror.requested False`; no proxy kwargs in `launch_kwargs()`).
  - `test_direct_fallback_has_tls_checks` (the fallback context options lack `ignore_https_errors`; assert via a spy on `_new_page` context_options).
- [ ] **Step 2:** Run. Expected: FAIL.
- [ ] **Step 3:** Implement. Check whether `route.fetch()` (Pass 2 `forward_sent`) goes through the browser proxy: add `test_pass2_real_submit_reaches_proxy` under a test grant. If Playwright's `route.fetch` bypasses it, add `inv["honest_limits"]` text `"Pass-2 real submits are sent by Playwright's fetch and do not appear in Burp"` and make the test assert that limit is present. **Do not assume either way.**
- [ ] **Step 4:** Rerun the new tests and the full ui_walk suite. Expected: PASS.
- [ ] **Step 5: Commit checkpoint** (user OK).

### Task 7: Tool surface, output, prompts

**Files:**
- Modify: `mcp-servers/browser-mcp/server.py` — `start_ui_walk(..., upstream_proxy: str = "")` :563 (docstring: mirror is optional, localhost-only, `"off"` sentinel); `run_teardown(..., upstream_proxy: str = "")` :627; `_run_walk`/`_run_teardown_job` pass it through; `_format_walk` :518 adds the lines `Events: <type>=<n>, ... (dropped: n)`, `Burp mirror: ON via <proxy>` / `Burp mirror: OFF (<reason>)` (when requested) / omitted when not requested, and `Pass-2 events: n`; `_target_detail` :497 adds per-page `event`/`candidate` lines (quarantined). Provenance stays last.
- Modify: `.claude/agents/exploit-agent.md` (consume the new candidate types: what each means and which skill to load: `csrf-cors-origin` for postmessage/cors/clickjacking, `xss` for dom-*, `auth-and-session` for cookie-flags/storage-token, `open-redirect` for redirect-param); `.claude/agents/recon-agent.md` (mention `upstream_proxy` for Burp mirroring when the human runs Burp).
- Modify: `CLAUDE.md` browser bullet (one clause: event recorder + optional Burp mirror).
- Test: `tests/test_ui_walk_tools.py` (extend), `tests/test_ui_walk_agent_wiring.py` (extend)

- [ ] **Step 1: Failing tests:** `test_format_walk_shows_event_counts_and_mirror_status`, `test_format_walk_provenance_last`, `test_format_walk_quarantines_console_text` (fixture console text appears only inside the quarantine block), `test_start_ui_walk_rejects_remote_proxy_before_starting_job`, `test_exploit_agent_mentions_new_candidate_types`, `test_tool_output_has_no_secret` (FIXTURESECRET absent from `_format_walk` output).
- [ ] **Step 2:** Run. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the full suite: `.venv/bin/python -m pytest tests/ -q`, ruff, and `python -m py_compile mcp-servers/browser-mcp/*.py`. Expected: all green, apart from failures that already happen on the #164 tip (record any such failure with its cause).
- [ ] **Step 5: Commit checkpoint** (user OK).

### Task 8: Review and audit, then prove it runs

- [ ] **Step 1:** Run `/code-review` and `/security-review` on the branch diff (repo shortcut "review and audit"). Fix confirmed findings with TDD, rerun the suite.
- [ ] **Step 2:** Prove it runs. The user restarts Claude Code so browser-mcp reloads. Then set up a throwaway engagement (never `bentley-com`) scoped to `127.0.0.1` / `localhost` and start the fixture (vulnerable). Call the real `mcp__browser-mcp__start_ui_walk` → `check_ui_walk`:
  - (a) without a mirror;
  - (b) with `upstream_proxy=http://127.0.0.1:8080`: real Burp if the user has it running (check its HTTP history shows the fixture requests), else the stand-in proxy on a free port.
  Capture the real output: event counts, candidates, mirror line, inventory path. `Read` one screenshot.
- [ ] **Step 3:** Write the summary line `Runtime-verified: <what ran> → <real result>`, and leave a hand-over note in the shared notes folder. Ask the user before any commit/push/PR.
