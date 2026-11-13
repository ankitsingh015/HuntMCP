# Session-Capture Subsystem Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn a human-driven browser login into scoped, structured identity data written to disk, such that no secret (cookie value, bearer token, storage_state, OTP, mailbox password) ever passes through the agent's tool inputs or outputs.

**Architecture:** New logic module `mcp-servers/session_capture.py` plus thin `@app.tool()` wrappers in `mcp-servers/browser-mcp/server.py`, reusing `browser_launch`/`browser_confirm`'s Playwright machinery. A global test-identity roster (allowlist) maps each label to a dedicated persistent browser profile (SSO reuse) and an optional read-only IMAP mailbox. Capture is two-phase and human-TTY-gated; output is domain-scoped to in-scope hosts and referenced by path via `identity_store.py`.

**Tech Stack:** Python 3.12, FastMCP, Playwright (existing dep), Python stdlib `imaplib`/`email`/`ssl` (no new dep), pytest, ruff.

**Spec:** `docs/superpowers/specs/2026-11-13-session-capture-design.md`

## Global Constraints

- No new runtime dependency (Playwright already present; mail via stdlib only).
- Every secret-bearing file is written mode `0600` under `data/engagements/<slug>/secrets/` (wholesale-gitignored).
- Agent-facing return values carry **only** allow-listed non-secret keys (`identity`, `captured`, `cookie_count`, `has_bearer`, `whoami`, `otp_applied`, `magic_link_opened`, `captured_params` counts) — never a value.
- Output cookies/session filtered to the active engagement's in-scope hosts (`scope_guard.is_in_scope`).
- Mail is read-only: the module must not import `smtplib` and must expose no send function.
- Human login/captcha/2FA/SSO is never automated; only post-login extraction is.
- Preserve Tier-2 scope gate (`scope_guard`), `budget_guard.enforce("browser-mcp")`, `audit_log.log_call`, engagement isolation on every target-touching tool.
- Target/mail free text that ever reaches agent-visible output goes through `injection_boundary.quarantine`.
- Lint clean: `ruff check mcp-servers/ --ignore E402,F811 --target-version py312`; `py_compile` the changed server.
- Never commit/push without an explicit in-the-moment human ask.

## Review Focus

- **No-display environment:** `start_capture` on a headless box (no X display) must fail with a clear "needs a real display, run from your own machine" message, not a cryptic Playwright crash. → Task 3.
- **Concurrent/duplicate capture for one label:** a second `start_capture` for a `(slug,label)` already open must refuse, not launch a second window or corrupt the registry. → Task 3.
- **Stale/forged confirmation token:** `finish_capture` must refuse an expired token, a token whose fingerprint does not match the open window, or a token the agent tried to write (non-TTY). → Task 4.
- **Wildcard subdomain scope:** a cookie whose `domain` is a sibling host NOT matched by `in_scope` (e.g. `accounts.google.com` while scope is `*.target.com`) must be excluded from output. → Task 3.
- **Mailbox misconfig / no OTP:** a missing `password_env` var, an IMAP connection failure, or no matching message must return a clear non-secret error and apply nothing — never hang, never leak. → Task 6.

---

### Task 1: Test-identity roster + `identity_store` reader

**Files:**
- Create: `mcp-servers/session_capture.py` (roster functions only this task)
- Create: `mcp-servers/identity_store.py`
- Test: `tests/test_session_capture_roster.py`, `tests/test_identity_store.py`

**Interfaces:**
- Produces:
  - `session_capture.load_roster(path: str | None = None) -> dict` — reads YAML at `path` or `$HUNTMCP_TEST_IDENTITIES` or `~/.config/huntmcp/test-identities.yaml`; returns `{}` if absent.
  - `session_capture.list_identities(path: str | None = None) -> list[dict]` — `[{"label": str, "note": str, "has_mailbox": bool}]` — **no** `profile_dir`, **no** mailbox creds.
  - `session_capture.roster_entry(label: str, path: str | None = None) -> dict` — internal full entry (`profile_dir`, optional `mailbox`); raises `KeyError` for an unknown label.
  - `identity_store.get_session_file(label: str, slug: str | None = None) -> str | None` — path to `secrets/sessions/<label>.json` if it exists.
  - `identity_store.get_headers(label: str, slug: str | None = None) -> dict` — in-process only: `{"Cookie": ..., "Authorization": ...}` read from `identities.json`; `{}` if none. (For a future idor-mcp follow-up; not wired into other servers here.)

- [ ] **Step 1: Write failing tests**

```python
# tests/test_session_capture_roster.py
def test_list_identities_hides_secrets(tmp_path, monkeypatch):
    roster = tmp_path / "ids.yaml"
    roster.write_text(
        "identities:\n"
        "  22bcs:\n"
        "    note: work-email\n"
        "    profile_dir: /x/22bcs\n"
        "    mailbox: {imap_host: imap.gmail.com, username: a@b.com, password_env: HUNTMCP_MAIL_22BCS}\n")
    monkeypatch.setenv("HUNTMCP_TEST_IDENTITIES", str(roster))
    out = session_capture.list_identities()
    assert out == [{"label": "22bcs", "note": "work-email", "has_mailbox": True}]
    # no path/host/username/env-name leaks into the agent-facing listing
    blob = json.dumps(out)
    for leaked in ("/x/22bcs", "imap.gmail.com", "a@b.com", "HUNTMCP_MAIL_22BCS"):
        assert leaked not in blob

def test_roster_entry_unknown_label_raises(tmp_path, monkeypatch):
    (tmp_path / "ids.yaml").write_text("identities: {xyz: {note: t, profile_dir: /x/xyz}}\n")
    monkeypatch.setenv("HUNTMCP_TEST_IDENTITIES", str(tmp_path / "ids.yaml"))
    with pytest.raises(KeyError):
        session_capture.roster_entry("not-a-label")
```

```python
# tests/test_identity_store.py
def test_get_headers_reads_from_identities_json(tmp_path, monkeypatch):
    # seed a secrets/identities.json via engagement_paths override, assert headers built
    ...  # uses HUNTMCP_* path override env; asserts Cookie/Authorization assembled, {} when absent
```

- [ ] **Step 2: Run tests, verify they fail** — `pytest tests/test_session_capture_roster.py tests/test_identity_store.py -v` → FAIL (module/func missing).
- [ ] **Step 3: Implement** `load_roster`, `list_identities`, `roster_entry` in `session_capture.py` (YAML via `yaml.safe_load`; `yaml` is already used across the repo's agent/writeup frontmatter tooling — confirm it's importable in the venv, else parse the tiny fixed schema without it) and `get_session_file`/`get_headers` in `identity_store.py` (resolve paths via `engagement_paths.resolve`).
- [ ] **Step 4: Run tests, verify pass.**
- [ ] **Step 5: Commit** (`git add` the two modules + two tests; message `feat: test-identity roster + identity_store reader (#128)`).

---

### Task 2: Profile isolation guard + robust browser resolution (#137)

**Files:**
- Modify: `mcp-servers/browser_launch.py` (add functions; do not change existing ones)
- Modify: `mcp-servers/browser-mcp/requirements.txt` (pin `playwright`)
- Test: `tests/test_browser_launch_persistent.py`

**Interfaces:**
- Produces:
  - `browser_launch.DEFAULT_PROFILE_ROOTS: list[str]` — OS-default Chrome/Chromium profile dirs.
  - `browser_launch.assert_dedicated_profile_dir(profile_dir: str) -> str` — returns the expanded absolute path; raises `ValueError` if it equals or is nested within any `DEFAULT_PROFILE_ROOTS` entry.
  - `browser_launch.persistent_context_kwargs(user_data_dir: str, headless: bool = False) -> dict` — kwargs for `chromium.launch_persistent_context` (reuses `STEALTH_ARGS`, `--no-sandbox`, `executable_path` when a system browser is found).
  - `browser_launch.resolve_executable_or_raise() -> str` — returns a system-browser path; if none AND Playwright's bundled browser is unresolvable, raises `RuntimeError` with the actionable message (run `playwright install chromium` / set `HUNTMCP_CHROME_PATH`), honoring `HUNTMCP_CHROME_PATH` override first.

- [ ] **Step 1: Write failing tests** — assertions:
  - `assert_dedicated_profile_dir("~/.config/google-chrome/Default")` raises `ValueError`; a path under `~/.config/huntmcp/browser-profiles/xyz` returns its abspath.
  - `persistent_context_kwargs("/tmp/p")` has `headless is False` and `user_data_dir == "/tmp/p"`.
  - `resolve_executable_or_raise()` returns `$HUNTMCP_CHROME_PATH` when set to an existing executable; raises `RuntimeError` mentioning `playwright install` when nothing resolves (monkeypatch `find_browser_executable` → None and the env unset).
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** the four names in `browser_launch.py`; pin `playwright==<current installed major.minor.patch>` in `browser-mcp/requirements.txt` with a one-line comment that `playwright install chromium` must re-run on bump (#137).
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** (`feat: dedicated-profile guard + loud browser resolution (#128, #137)`).

---

### Task 3: Capture core + domain-scoped output + **secret-never-returned** (headline)

**Files:**
- Modify: `mcp-servers/session_capture.py` (capture registry + flow)
- Test: `tests/test_session_capture_core.py`

**Interfaces:**
- Consumes: Task 1 `roster_entry`; Task 2 `assert_dedicated_profile_dir`, `persistent_context_kwargs`, `resolve_executable_or_raise`; `scope_guard.load_engagement`, `scope_guard.is_in_scope`, `scope_guard._host_of`; `budget_guard.enforce`; `audit_log.log_call`; `engagement_paths.resolve`.
- Produces:
  - `session_capture._safe_summary(label: str, **facts) -> dict` — returns only keys in a module `_ALLOWED_SUMMARY_KEYS` frozenset; raises `AssertionError` if a non-allowed key is passed (fail-closed).
  - `session_capture._filter_cookies_in_scope(cookies: list[dict], engagement) -> list[dict]` — keeps a cookie only when its `domain` host `is_in_scope`.
  - `session_capture._fingerprint(slug, label, login_url, nonce) -> str` — 32-hex.
  - `async start_capture(identity_label: str, login_url: str, slug: str | None = None) -> dict`
  - `async finish_capture(identity_label: str, slug: str | None = None) -> dict`
  - Writes `secrets/identities.json` (per-label entry, 0600) and `secrets/sessions/<label>.json` (filtered storage_state, 0600).

- [ ] **Step 1: Write failing tests** (monkeypatch Playwright with a fake context exposing `.cookies()` and request-listener hooks; drive `finish_capture`'s extraction path directly, bypassing the live window where needed):

```python
SENTINEL_COOKIE = "S3NTINEL_COOKIE_VALUE"
SENTINEL_BEARER = "Bearer S3NTINEL_TOKEN"

def test_finish_capture_returns_no_secret(fake_ctx, engagement_in_scope):
    # fake_ctx holds an in-scope cookie == SENTINEL_COOKIE and a sniffed SENTINEL_BEARER
    out = run(session_capture.finish_capture("xyz"))          # with a pre-seeded confirmed token
    blob = json.dumps(out)
    assert SENTINEL_COOKIE not in blob and "S3NTINEL_TOKEN" not in blob
    assert set(out) <= session_capture._ALLOWED_SUMMARY_KEYS | {"identity"}
    assert out["captured"] is True and out["cookie_count"] >= 1 and out["has_bearer"] is True
    # and the secret DID reach disk, 0600
    data = json.loads(read(identities_json_path))
    assert any(c["value"] == SENTINEL_COOKIE for c in data["xyz"]["cookies"])
    assert oct(os.stat(identities_json_path).st_mode)[-3:] == "600"

def test_domain_scoping_excludes_out_of_scope_cookie(fake_ctx_mixed, engagement_in_scope):
    # fake_ctx_mixed holds a target.com cookie AND an accounts.google.com cookie; scope = *.target.com
    run(session_capture.finish_capture("xyz"))
    data = json.loads(read(identities_json_path))
    domains = {c["domain"] for c in data["xyz"]["cookies"]}
    assert not any("google.com" in d for d in domains)

def test_safe_summary_rejects_secret_key():
    with pytest.raises(AssertionError):
        session_capture._safe_summary("xyz", cookie_value="x")

def test_duplicate_start_capture_refuses(monkeypatch):
    # second start for same (slug,label) while one is open → dict with "error", no second launch
    ...

def test_start_capture_no_display_message(monkeypatch):
    # persistent launch raises a display-less error → returned dict message mentions a real display
    ...
```

- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** the registry (in-process `dict` keyed by `(slug,label)`, reservation-before-await like `browser_confirm._live_interventions`), `start_capture` (validate label → validate `login_url` in scope → `enforce` budget → `assert_dedicated_profile_dir` → launch persistent context headed → attach request listener recording latest in-scope `Authorization` per host → register with fingerprint → return BLOCKED-style message with the `confirm-capture.sh` command), and `finish_capture` (token check is Task 4's `verify_confirmation`; here assume it, gated behind it in Task 4 wiring) → enumerate `context.cookies()` → `_filter_cookies_in_scope` → assemble entry → write both files `0600` → `_safe_summary`. `log_call("browser-mcp", [...], ...)` on both. Headless-display failure and duplicate-registration return `{"error": ...}`.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** (`feat: human-driven capture core, domain-scoped, secret-never-returned (#128)`).

---

### Task 4: Human TTY confirmation gate

**Files:**
- Create: `mcp-servers/capture_confirm.py`
- Create: `scripts/confirm-capture.sh`
- Modify: `mcp-servers/session_capture.py` (wire `verify_confirmation` into `finish_capture`)
- Test: `tests/test_capture_confirm.py`

**Interfaces:**
- Produces:
  - `capture_confirm.confirmation_token_path(slug: str, label: str) -> str` — under `secrets/`.
  - `capture_confirm.write_confirmation(slug, label, fingerprint) -> None` — writes `{fingerprint, ts}` 0600; **refuses (SystemExit) when `sys.stdin.isatty()` is False** (agent cannot satisfy).
  - `capture_confirm.verify_confirmation(slug, label, fingerprint, ttl_s: int = 600) -> bool` — True only if a token exists, matches the fingerprint, and is within `ttl_s`.
  - `scripts/confirm-capture.sh <slug> <label> <fingerprint>` → `exec python3 capture_confirm.py` (same wrapper shape as `confirm-state-change.sh`); prints label + roster note + target host + fingerprint before prompting.
- Consumes: Task 3 `_fingerprint`/registry (to read the open window's fingerprint + target host for the printed prompt).

- [ ] **Step 1: Write failing tests:**
  - `write_confirmation` raises `SystemExit` when `isatty()` monkeypatched False.
  - `verify_confirmation` → False for missing token, mismatched fingerprint, and an aged token (ts older than ttl); True for a fresh matching one.
  - `finish_capture` returns `{"error": ...}` (and writes nothing) when `verify_confirmation` is False.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** `capture_confirm.py` + the shell wrapper; wire `finish_capture` to call `verify_confirmation` first and bail on False.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** (`feat: human TTY confirmation gate for capture (#128)`).

---

### Task 5: whoami auto-label + credential-lifecycle intake

**Files:**
- Modify: `mcp-servers/session_capture.py`
- Test: `tests/test_session_capture_whoami.py`

**Interfaces:**
- Consumes: `credential_lifecycle.record_intake`; optional engagement-config `whoami_url`.
- Produces: `finish_capture` gains a `whoami` block in both the on-disk entry and the summary (`{"user_id","role","org"}` labels only — never the token); records `credential_lifecycle.record_intake("session", obtained_via="session-capture", path=...)` metadata (no secret value).

- [ ] **Step 1: Write failing test** — with a fake `whoami` fetch returning `{"user_id":"42","role":"admin"}`, `finish_capture` summary `out["whoami"] == {"user_id":"42","role":"admin","org":None}` and no token in the blob; `record_intake` called once.
- [ ] **Step 2: Run, verify fail.** → **Step 3: Implement.** → **Step 4: verify pass.** → **Step 5: Commit** (`feat: whoami auto-label + lifecycle intake on capture (#128)`).

---

### Task 6: Incoming-auth-mail reader (IMAP, read-only) — OTP + magic-link

**Files:**
- Modify: `mcp-servers/session_capture.py` (mail helpers + apply tools)
- Test: `tests/test_session_capture_mail.py`

**Interfaces:**
- Consumes: Task 1 `roster_entry` (mailbox config); Task 3 registry (the open window to type into / navigate).
- Produces:
  - `session_capture._read_latest_code(mailbox: dict, since_ts: float, pattern: str) -> str | None` — IMAP-over-TLS (`imaplib.IMAP4_SSL`), password from `mailbox["password_env"]` env var; returns the matched code **in-process only**; `None` on no match. Connection/auth errors raise `MailError`.
  - `session_capture._read_latest_link(mailbox: dict, since_ts: float, link_host: str) -> str | None`.
  - `async apply_pending_otp(identity_label: str, slug: str | None = None, pattern: str = r"\b[0-9]{4,8}\b") -> dict` — types the code into the open window's focused field; returns `{"otp_applied": bool}` (never the code).
  - `async open_pending_magic_link(identity_label: str, link_host: str, slug: str | None = None) -> dict` — host-validates then navigates the open window; returns `{"magic_link_opened": bool}`.

- [ ] **Step 1: Write failing tests (fake IMAP stub + fake open window):**
  - module-level invariant: `"smtplib" not in session_capture source imports`; `session_capture` exposes no attribute whose name contains `send`.
  - `apply_pending_otp` with a stub inbox containing code `123456` → returns `{"otp_applied": True}`; the returned blob does **not** contain `123456`.
  - missing `password_env` var / IMAP failure → `{"otp_applied": False, "error": "...non-secret..."}`, nothing typed.
  - no matching message → `{"otp_applied": False}`.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** the stdlib IMAP helpers + the two apply tools (read-only; no `smtplib` import anywhere in the module). Quarantine any mail free text that could reach output.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** (`feat: read-only IMAP OTP/magic-link apply (#128)`).

---

### Task 7: OAuth redirect-code capture (#133)

**Files:**
- Modify: `mcp-servers/session_capture.py`
- Test: `tests/test_session_capture_oauth.py`

**Interfaces:**
- Consumes: Task 2 launch helpers; `scope_guard`; Task 4 gate (same human-TTY confirmation before the code is written).
- Produces: `async capture_oauth_redirect(identity_label: str, start_url: str, callback_host: str, slug: str | None = None) -> dict` — fresh cookie-less context, human consents, watches navigation to `callback_host`, extracts query params (optionally route-intercepts the app's follow-up), writes them to `secrets/oauth/<label>-<ts>.json` (0600), returns `{"captured_params": <count>, "callback_host": host}` — **not** the code values.

- [ ] **Step 1: Write failing test** — simulate a navigation to `callback_host?code=SENTINEL_CODE&state=x`; assert the return contains neither `SENTINEL_CODE` nor a `code` value, `captured_params == 2`, and the on-disk file (0600) does contain `SENTINEL_CODE`.
- [ ] **Step 2–4:** fail → implement → pass.
- [ ] **Step 5: Commit** (`feat: OAuth redirect-code capture, by-path (#128, closes #133)`).

---

### Task 8: MCP tool wrappers, scope-gate registration, runtime verification, regression

**Files:**
- Modify: `mcp-servers/browser-mcp/server.py` (new `@app.tool()` wrappers)
- Modify: `scripts/hooks/scope_gate_hook.py` (add new tool names to the browser-mcp TIER2 entry)
- Test: `tests/test_session_capture_tools.py` (wrapper-level: returns are `_safe_summary`-shaped)

**Interfaces:**
- Consumes: all prior tasks.
- Produces MCP tools: `list_test_identities`, `start_capture`, `finish_capture`, `apply_pending_otp`, `open_pending_magic_link`, `capture_oauth_redirect` — each a thin wrapper returning the module's non-secret dicts, docstring stating "human does the login; Tier-2, scope-gate first."

- [ ] **Step 1: Write failing test** — import the server module, call each wrapper with monkeypatched `session_capture` functions, assert each return is JSON-serializable and contains no value-shaped secret; assert the six tool names are registered on `app`.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** the wrappers in `server.py`; add the tool names to `scope_gate_hook.py`'s per-tool TIER2 list for `browser-mcp`.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Regression + lint** — `pytest tests/ -q`; `ruff check mcp-servers/ --ignore E402,F811 --target-version py312`; `python -m py_compile mcp-servers/browser-mcp/server.py mcp-servers/session_capture.py mcp-servers/identity_store.py mcp-servers/capture_confirm.py`.
- [ ] **Step 6: Runtime verification ("prove it runs")** — against a **local** login fixture only: real headed persistent-context window, hand-login, `confirm-capture.sh` in a real TTY, real `finish_capture` MCP call; show the returned summary (no secret), `identities.json`/session_file (0600, in-scope only), and a `render_dom` using `session_file=` rendering the authed view. Mail path against a local/stub IMAP. Record `Runtime-verified: <what ran> → <result>` or state explicitly what could not run and why. (No commit/push without an explicit human ask.)

---

## Self-review notes

- **Spec coverage:** G1–G10 map to Tasks 1–8; I1 (Task 3 headline), I2 (Task 3), I3 (Task 4), I4 (Task 2), I5 (Task 6), I6 (Task 8), I7 (Tasks 3/6). N1 reader shipped (Task 1) without wiring other servers. #133→Task 7, #137→Task 2+8. #136/#132 intentionally untouched.
- **Review Focus:** no-display→T3; duplicate capture→T3; stale/forged token→T4; wildcard-subdomain scope→T3; mailbox misconfig/no-OTP→T6 — each has an owning test above.
- **Types:** `start_capture`/`finish_capture`/`_safe_summary`/`_filter_cookies_in_scope`/`roster_entry`/`assert_dedicated_profile_dir`/`verify_confirmation` names used consistently across tasks.
