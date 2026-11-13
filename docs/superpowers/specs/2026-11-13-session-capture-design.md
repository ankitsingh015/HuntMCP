# Session-Capture Subsystem — Design

**Issue:** #128 (Browser-assisted identity/session capture — secrets must never pass through chat)
**Folds in:** #133 (OAuth redirect-code capture), #137 (Playwright binary-version drift)
**References (stay separate):** #136 (pre-engagement identity/account checklist), #132 (state-change gate fast-path)
**Date:** 2026-11-13
**Status:** DESIGN — awaiting human approval. No product code written yet.

---

## 1. Intent & why

Every authenticated engagement (IDOR, vertical/horizontal authz, session testing) needs a
human-owned login turned into usable identity data for the agent. Today that handoff is a
manual DevTools copy/paste into the chat transcript, which (observed live, Manatal VDP,
2026-11-05) caused three concrete problems:

1. Repeated manual token extraction on every refresh — real time cost, context-switch away
   from testing.
2. Secret/PII leakage into the transcript — full cookie-jar pastes dragged in *unrelated*
   live session cookies for Google/Facebook/LinkedIn (credentials to other services).
3. Slow attribute lookups — confirming one cookie's `SameSite` (needed to score a CORS
   finding) took three round trips.

The fix is a capture flow where **the human still does the login by hand in a visible
window** (captcha/2FA/SSO unchanged — never automated), and the tool automates only the
**extraction afterwards**, writing scoped identity data to disk such that **no secret ever
appears in the agent's input or output**. Around that core, this engagement surfaced
adjacent friction worth solving in the same coherent subsystem: SSO re-login on every
capture, OTP/verification-email round trips, OAuth-code capture races, and the risk of a
capture window accidentally opening the operator's personal/company account.

## 2. Goals / Non-goals / Anti-goals

**Goals**
- G1. Human-driven login in a real visible window; tool automates extraction only.
- G2. The captured secret (cookies, bearer token, storage_state, OTP) **never** passes
  through the agent's tool-call inputs or tool results. Agent sees only non-secret
  summaries (`{identity, captured, cookie_count}`-shaped).
- G3. Output is **domain-scoped** to the active engagement's in-scope hosts — unrelated
  cookies (Google/FB/LinkedIn) are never written to the engagement file.
- G4. Completion is **human-gated** via a TTY confirm script the agent cannot satisfy
  (same footing as `scripts/confirm-state-change.sh`).
- G5. SSO/Google login is captured once and **reused** across captures via a persistent,
  dedicated per-identity browser profile — no re-login every time.
- G6. A declared **test-identity roster/allowlist** (operator's standing test accounts,
  e.g. `xyz`, `adminvikram`, `22bcs`) with per-label notes; capture refuses any label not
  on the roster and **structurally refuses** the OS-default browser profile (personal/
  company-account protection).
- G7. **Incoming-auth-mail** (OTP, email verification code, magic-link) is read for a
  roster identity's own test mailbox over **IMAP, read-only**, and applied directly into
  the open capture window — never returned through chat.
- G8. OAuth redirect-code capture (#133) folded into the same capture family.
- G9. Robust Playwright browser resolution so a package/browser revision drift (#137)
  fails loudly with a clear message, not a cryptic mid-task launch error.
- G10. Re-capture is one call for an existing label (expired token → refresh), with
  expiry bookkeeping tied to `credential_lifecycle.py`.

**Non-goals**
- N1. Consuming identities by label inside `idor-mcp` / `ws-rpc-mcp` (those take inline
  `cookie_header`/`bearer_token` params today). A shared `identity_store.py` reader is
  provided so this is a clean *follow-up*; wiring the other servers is out of scope here.
- N2. The pre-engagement account-topology checklist (#136) — a process/doc step in
  `engagement-setup`, different surface. Cross-referenced, not built here.
- N3. The state-change gate fast-path (#132) — a different gate; we only reuse its TTY
  confirm pattern.

**Anti-goals (would make this a failure even if it "works")**
- A1. Any path that sends mail (SMTP) or auto-submits a report. Mail is **read-only by
  construction** — no send code exists in this subsystem. Report-sending stays 100% manual
  (operator sends; agent never does).
- A2. Automating the login/captcha/anti-bot step itself. The human always logs in.
- A3. Any code path that could echo a cookie value, bearer token, storage_state blob, OTP,
  or mailbox password into a tool result or accept one as an inline tool param.
- A4. Touching the operator's real Chrome/Chromium profile or any already-running browser.
- A5. Weakening scope gates, budget guards, audit logging, or engagement isolation.

## 3. Constraints

- Repo rules: `CLAUDE.md`, `.claude/rules/security.md`, `.claude/rules/testing.md`,
  `mcp-servers/CLAUDE.md`. Tier-2 scope gate on every target-touching op; preserve budget
  guard, audit log, engagement isolation. No new runtime dependency.
- `playwright` is already a dependency; IMAP/email parsing use the Python **stdlib**
  (`imaplib`, `email`, `ssl`) — **no new dependency** required.
- Secrets convention: engagement files under `data/engagements/<slug>/secrets/`, `0600`,
  already gitignored (`data/engagements/` is gitignored wholesale).
- Reuse existing abstractions: `browser_confirm.py` (headed launch, storage_state,
  intervention registry), `engagement_paths.resolve()/resolve_dir()`, `scope_guard`
  (`load_engagement`, `is_in_scope`, `_host_of`), `credential_lifecycle.py`,
  `injection_boundary.quarantine`, `audit_log`, `budget_guard`.

## 4. Approaches considered

**4.1 Where it lives — new `session-capture-mcp/` server vs new tools in `browser-mcp`.**
A separate server would duplicate the headed-launch / storage_state / intervention-registry
machinery that already lives in `browser_confirm.py`, giving two independent browser
registries that can drift and more memory/process surface. *Chosen: new tools inside
`browser-mcp`*, with new logic in a sibling module (`session_capture.py`) imported by
`browser-mcp/server.py`. The issue's wording ("a new session-capture MCP tool, similar
footing to browser-mcp") is satisfied — it is Playwright-backed, same footing — without a
parallel server. Rejected the separate server as pure duplication.

**4.2 How the secret is referenced downstream — return-value vs file-by-path.**
Returning the secret (even once) violates G2 and re-creates the transcript-leak problem.
*Chosen: file-by-path.* Capture writes `identities.json` + a per-identity Playwright
`session_file`; the agent references them by **label/path**, never by value. `browser-mcp`
tools already accept `session_file` (a path), so authenticated browsing is immediately
leak-free. Rejected any "return the token just once" convenience.

**4.3 Session persistence — storage_state file vs persistent user-data-dir.**
`storage_state` (cookies+localStorage JSON) is enough to *resume* a session but is a weak
substitute for *SSO login reuse* — Google device-trust and multi-domain cookies survive far
more reliably in a full browser profile. *Chosen: persistent per-identity `user-data-dir`*
(`chromium.launch_persistent_context`) for the login/SSO reuse, and we still emit a
domain-scoped `storage_state` as the per-identity `session_file` for downstream tools.
Rejected storage_state-only (would force Google re-login per capture).

**4.4 Scope of output — whole-context export vs domain-filtered.**
A raw `storage_state` export includes every cookie in the context, i.e. exactly the
Google/FB/LinkedIn leak. *Chosen: build the output ourselves from `context.cookies()`
filtered to in-scope hosts*, and write a **filtered** session_file too. Rejected raw export.

**4.5 Mail/OTP — IMAP read vs own catch-all mail server.**
Running a catch-all mail server (MX/DNS, maintenance) is heavy for the actual need (OTP to
the operator's existing test mailboxes). *Chosen: IMAP read-only* against a roster
identity's configured mailbox, stdlib only. Rejected the mail-server approach as
disproportionate; may revisit if fully-controlled throwaway addresses are ever needed.

**4.6 Completion signal — agent-called vs human TTY gate.**
The existing `finish_manual_intervention` is agent-called (agent decides "done"), which the
agent could trigger prematurely. *Chosen: a human TTY confirm* (`scripts/confirm-capture.sh`)
that refuses when stdin is not a TTY and writes a fingerprint-bound token; `finish_capture`
refuses unless that fresh, matching token exists. Rejected agent-called completion for the
capture flow (keeps browser-mcp's existing pair as-is for its own non-secret uses).

## 5. The design (decided)

New module `mcp-servers/session_capture.py` (logic) + thin `@app.tool()` wrappers in
`mcp-servers/browser-mcp/server.py`. New shared reader `mcp-servers/identity_store.py`.
New human-gate `scripts/confirm-capture.sh` → `mcp-servers/capture_confirm.py`.

### 5.1 Test-identity roster (allowlist)
A global, reusable roster file (default `~/.config/huntmcp/test-identities.yaml`, override
via `HUNTMCP_TEST_IDENTITIES`). **No secret values in it** — only references:

```yaml
identities:
  xyz:         { note: "test account 1",                profile_dir: "~/.config/huntmcp/browser-profiles/xyz" }
  adminvikram: { note: "admin-role test account",       profile_dir: "~/.config/huntmcp/browser-profiles/adminvikram" }
  22bcs:       { note: "work-email / 3rd account",       profile_dir: "~/.config/huntmcp/browser-profiles/22bcs",
                 mailbox: { imap_host: "imap.gmail.com", username: "22bcs...@gmail.com", password_env: "HUNTMCP_MAIL_22BCS" } }
```

- `mailbox.password_env` names an **environment variable** holding the IMAP app-password —
  the password itself is never in the file, never in chat, never returned.
- `start_capture(label=...)` refuses any label not in `identities`.
- A new `list_test_identities()` tool returns labels + notes **only** (no secrets, no
  mailbox creds) so the agent/human can pick.

### 5.2 Persistent per-identity profile + isolation guard + binary resolution (#137)
- Launch via `chromium.launch_persistent_context(user_data_dir=<profile_dir>, headless=False, ...)`.
  The profile persists SSO/Google login across captures (G5).
- **Isolation guard (hard refuse, not convention):** before launch, resolve `profile_dir`
  to an absolute real path and refuse if it is equal to or nested within any OS-default
  browser profile dir (`~/.config/google-chrome`, `~/.config/chromium`,
  `~/Library/Application Support/Google/Chrome`, `%LOCALAPPDATA%/Google/Chrome/User Data`,
  and Chromium equivalents). Never use `channel="chrome"` against a default profile; never
  attach to a running browser. This is what makes "won't open my personal/company account"
  true in code (G6).
- **Binary resolution (#137):** reuse/extend `browser_launch` (shared with playwright-mcp)
  to resolve a system Chrome/Chromium `executable_path`; if Playwright's own bundled
  revision is requested but missing, fail with a clear, actionable message
  ("run `playwright install chromium`, or set `HUNTMCP_CHROME_PATH`") instead of the raw
  cryptic error. Pin the `playwright` version in `browser-mcp/requirements.txt` and document
  the re-install requirement.

### 5.3 Capture flow (two-phase, human-gated)
1. `start_capture(identity_label, login_url)` — validates label against roster; validates
   `login_url` host is in scope (`scope_guard`); enforces Tier-2 budget; launches the
   headed persistent-context window at `login_url`; attaches a **request listener** that
   records (in-process only) the most recent `Authorization` header seen per in-scope host;
   registers the open capture keyed by `(slug,label)` with a **fingerprint** binding
   `slug|label|login_url|launch-nonce`. Returns a BLOCKED-style message instructing the
   human to log in by hand, then run the printed `scripts/confirm-capture.sh <slug> <label>
   <fingerprint>` in **their own terminal**. Returns no secret.
2. Human logs in (captcha/2FA/SSO by hand). Optionally triggers OTP (see 5.6).
3. Human runs `confirm-capture.sh` → `capture_confirm.py`: refuses if not a TTY; prints the
   **label + roster note + target host + fingerprint** for the human to read; on `yes`
   writes a `0600` confirmation token (fingerprint + timestamp) under the engagement
   `secrets/` dir.
4. `finish_capture(identity_label)` — refuses unless a **fresh** (≤ configurable TTL, e.g.
   10 min) confirmation token matching the open window's fingerprint exists. Then, itself:
   enumerate `context.cookies()` **filtered to in-scope hosts** with full attributes; take
   the recorded in-scope `Authorization` header; optionally call a configured `whoami`
   endpoint to label `user_id`/`role`/`org`; write `identities.json` + a domain-scoped
   `session_file`; record intake/expiry in `credential_lifecycle.py`; close the window.
   Returns **only** `{"identity": label, "captured": true, "cookie_count": N,
   "has_bearer": bool, "whoami": {...non-secret labels...}}`.

### 5.4 Domain-scoped output
- `data/engagements/<slug>/secrets/identities.json` (`0600`), keyed by label. Per entry:
  `cookies: [{name, value, domain, path, httpOnly, secure, sameSite, expires}]`
  (in-scope hosts only), `bearer_present: bool`, `captured_at`, `source_login_url`,
  `whoami` labels. The **value** lives only in this `0600` on-disk file.
- `data/engagements/<slug>/secrets/sessions/<label>.json` — a **filtered** Playwright
  `storage_state` (`0600`) for direct `session_file=` use by browser-mcp tools.
- Solves the C2b round-trip: `SameSite`/`HttpOnly`/`Secure`/`Expires` are captured once.

### 5.5 Authorization-header sniff + whoami
- The request listener is attached at window open and keeps only the latest in-scope
  `Authorization` value in memory; at finish it is written to disk, never returned.
- Optional `whoami_url` (configurable per engagement/roster) is called with the captured
  identity to auto-label `user_id`/`role`/`org` — removing manual profile-ID bookkeeping.
  Only the **labels** (not the token) appear in the return value.

### 5.6 Incoming-auth-mail reader (IMAP, read-only) — G7, A1
- `session_capture.py` gets a read-only IMAP helper: connect over TLS using the roster
  mailbox config (`password` from `password_env`), search recent messages, extract an OTP
  (configurable regex, default a 4–8 digit / alnum code) or a magic-link URL.
- **No SMTP / no send path exists anywhere in the module** — read-only by construction (A1).
- Applied, not returned: a tool `apply_pending_otp(identity_label)` reads the latest OTP and
  **types it into the open capture window's active field**; a tool
  `open_pending_magic_link(identity_label, link_host)` navigates the open window to the
  magic-link (host-validated). The agent sees only `{otp_applied: true}` /
  `{magic_link_opened: true}`. The human still initiated the login and the OTP send; this
  only removes the mailbox copy/paste round trip. Captcha/anti-bot stays human (A2).
- Mailbox is read **only** for a roster label with a configured mailbox — never an arbitrary
  address, never the operator's personal/company inbox.

### 5.7 OAuth redirect-code capture (#133)
- `capture_oauth_redirect(identity_label, start_url, callback_host)` — launches a
  **fresh, cookie-less** context (no stored app session), human completes consent by hand,
  the tool watches for navigation to `callback_host` and extracts the query parameters,
  optionally using route interception to block the app's own follow-up so the code is
  captured before consumption (no human race). The code is written to the engagement
  `secrets/` dir and referenced by path — not read off the address bar, not returned.

### 5.8 Consume-by-path/label (`identity_store.py`) — now vs follow-up
- `identity_store.py`: a small reader over `identities.json` exposing `get_session_file(label)`
  and `get_headers(label)` for *in-process* use by tools that already run server-side.
  `browser-mcp` tools consume via `session_file` path **today** (no change needed to their
  contracts).
- Wiring `idor-mcp`/`ws-rpc-mcp` to accept `identity_label` and read headers from
  `identity_store` (so the agent never passes raw `cookie_header`/`bearer_token`) is a
  **follow-up issue** (N1) — the reader is designed now so that change needs no re-design.

### 5.9 Expiry / re-capture
- `finish_capture` records `captured_at` and (if known) token expiry via
  `credential_lifecycle.py`. A stale/expired identity surfaces through the existing
  lifecycle bookkeeping; refreshing is just `start_capture`+`finish_capture` again for the
  same label (persistent profile means usually no re-login).

### 5.10 Secret-never-returned invariant
A single choke-point: every `@app.tool()` wrapper for this subsystem returns a dict built by
a `_safe_summary()` helper that is **allow-listed** to non-secret keys only. A module-level
rule + test guarantees no cookie value / bearer / storage_state / OTP / password can be in
any return path.

## 6. Security model & invariants (non-negotiable)

- I1. No secret in any tool input or output (G2/A3) — enforced by `_safe_summary()` +
  tests that assert known secret sentinels never appear in returns.
- I2. Output domain-scoped to in-scope hosts (G3) — filtered against `scope_guard`.
- I3. Human TTY gate required for capture completion (G4) — `finish_capture` refuses without
  a fresh fingerprint-matched token; `capture_confirm.py` refuses non-TTY.
- I4. Profile isolation (G6/A4) — hard refuse OS-default/running-browser profiles.
- I5. Mail is read-only, no send path (A1) — structural, verified by a test asserting the
  module imports no SMTP and exposes no send function.
- I6. Tier-2 scope gate + budget + audit log preserved on every target-touching tool
  (register in `scope_gate_hook.py` TIER2_MCP_SERVERS tool list, as browser-mcp already is).
- I7. Target/mail content quarantined (`injection_boundary.quarantine`) if any of it ever
  reaches agent-visible text (e.g. a whoami label echoed) — treated as untrusted data.

## 7. Test plan (TDD)

Headline (required by the task): **a test proving no secret is returned in tool output.**

- T1 (headline). Seed a context with a known cookie value `SENTINEL_COOKIE` and a bearer
  `SENTINEL_BEARER`; run the capture finish path against a local fixture; assert the tool
  return contains neither sentinel (nor any storage_state blob), only the allow-listed
  summary keys. Also assert `identities.json` on disk *does* contain them (capture worked)
  and is mode `0600`.
- T2. Domain-scoping: a context holding both an in-scope cookie and an out-of-scope
  `google.com` cookie → `identities.json` and the session_file contain only the in-scope
  one.
- T3. Human-gate: `finish_capture` refuses when no/zero stale/mismatched-fingerprint token;
  `capture_confirm.py` refuses when stdin is not a TTY (isatty() false).
- T4. Roster allowlist: `start_capture` refuses an unknown label; `list_test_identities`
  returns notes but no mailbox creds / no secrets.
- T5. Profile isolation: resolving a `profile_dir` inside an OS-default browser dir refuses.
- T6. Mail read-only invariant: module exposes no send function and does not import
  `smtplib`; OTP helper returns application result only (`{otp_applied: true}`), never the
  code; mailbox password is read from env, never from the roster file, never returned.
- T7. OAuth capture (#133): redirect params extracted and written to `secrets/`, not
  returned.
- T8. `_safe_summary()` unit: given a dict containing secret-shaped keys, output is the
  allow-listed subset only.
- T9. Binary resolution (#137): a simulated revision mismatch yields the clear actionable
  error, not the raw Playwright error.
- Regression: full `tests/` suite + `ruff check mcp-servers/ --ignore E402,F811
  --target-version py312` + `py_compile` on changed servers.

Fixtures are local/controlled (a `data:`/local page, a fake IMAP via a stub, monkeypatched
Playwright where a real browser is unavailable) — no real external target, per
`.claude/rules/testing.md`.

## 8. Runtime verification ("prove it runs")

Per `CLAUDE.md` shortcut: a runtime-dependent feature is not done until run end-to-end.
- Launch a real headed persistent-context window against a **local** login fixture
  (localhost), log in by hand, run `confirm-capture.sh` in a real TTY, call the real
  `finish_capture` MCP tool, and show: the returned summary (no secret), the on-disk
  `identities.json`/session_file (0600, in-scope only), and a follow-on `render_dom` using
  `session_file=` that renders the authenticated view. Mail path verified against a local/
  stub IMAP. State `Runtime-verified: <what ran> → <real result>` in the summary, or state
  explicitly what could not be run and why.

## 9. What's left to the builder

- Exact roster YAML parsing + default path handling and `HUNTMCP_TEST_IDENTITIES` override.
- Confirmation-token TTL value (proposed 10 min) and token file name/location under
  `secrets/`.
- OTP default regex and the "latest message since start_capture" selection heuristic.
- Whether `whoami_url` lives in roster vs engagement config (builder's call; proposed:
  engagement config, since it is target-specific).
- `scope_gate_hook.py` TIER2 tool-name registration for the new tool names.

## 10. Scope boundaries / follow-ups

- Follow-up issue (new): wire `idor-mcp`/`ws-rpc-mcp` to consume `identity_label` via
  `identity_store` (N1).
- #136 stays separate (process step in `engagement-setup`); cross-reference from there to
  the roster.
- #132 stays separate; this subsystem only reuses the TTY-confirm pattern.
- Implementation lands **incrementally and TDD** within this one design (roster+isolation →
  capture core + headline secret test → domain-scope → human-gate → mail → OAuth →
  binary-pin), each part verified before the next; nothing committed/pushed without an
  explicit in-the-moment ask.
