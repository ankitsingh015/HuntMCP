# Session Keep-Alive (silent renewal for captured identities) — Design

**Date:** 2026-11-20
**Builds on:** #128 session capture (`mcp-servers/session_capture.py`), #164 session_file
sessionStorage sidecar + UI-walk `auth_lost` (`mcp-servers/browser-mcp/browser_confirm.py`,
`ui_walk.py`)
**Prior art:** `~/.config/huntmcp/refresh_bentley_tokens.py` (Bentley-only, outside the repo:
OIDC `prompt=none` + PKCE using the long-lived SSO cookie)
**Status:** DESIGN — awaiting human approval. No product code written yet.

---

## 1. Intent & why

Every authenticated engagement runs on identities the human captured by hand
(`start_capture` → human logs in → `confirm-capture.sh` → `finish_capture`). Access tokens
expire (often hourly), and today every expiry means another manual login, even though the
identity's dedicated browser profile still holds a long-lived SSO cookie and/or the app holds a
refresh token that could mint a fresh session with zero human effort. The Bentley script proved
this works; it is target-specific and lives outside the repo.

The user wants to log in by hand **once every few days per identity**, not on every expiry,
and to do **nothing extra** (write no config, run no new command) to get that.

## 2. Goals / Non-goals / Anti-goals

**Goals**
- G1. One call (`refresh_session(identity)`) renews an expired/expiring session for any target,
  with no per-target configuration, and writes the refreshed state back into that identity's
  `session_file` (cookies + localStorage + sessionStorage sidecar).
- G2. Renewal is tried in layers (§5) and the human is asked to log in **only** when every layer
  fails.
- G3. Proactive: tokens are refreshed shortly before they expire, and the SSO session is kept warm
  by a periodic light visit — not only after `auth_lost`.
- G4. The UI-walk's existing `auth_lost` retry calls the refresh before re-reading the file.
- G5. Advance warning of the next forced human login (e.g. "adminvikram: SSO cookie expires in
  ~2 days"), plus a desktop notification when a human login is actually needed; several
  identities needing login can be re-captured in one sitting.
- G6. The IdP/login hosts a renewal must pass through are learned **automatically** from the
  human's own login (§4) — the user writes nothing.

**Non-goals**
- N1. Migrating the Bentley script or its `~/.config/huntmcp/sessions/*` files (can be dropped
  once this lands; separate cleanup).
- N2. MSAL / other complex token-cache formats for the tool-driven refresh_token layer
  (layer 2). Layer 1 (app renews itself) still covers them.
- N3. Surviving across MCP-server restarts: keep-alive runs while browser-mcp runs.

**Anti-goals (a failure even if it "works")**
- A1. The tool types a password, autofills-and-submits a saved password, or solves/bypasses a
  CAPTCHA. Any login form, password field or CAPTCHA seen during renewal = renewal failed.
- A2. A token, cookie value, refresh token or storage blob is ever returned to the agent.
- A3. Scope quietly widens: renewal hosts become visible to scanners/probes, or a redirect to an
  arbitrary host is followed.
- A4. The existing human gate on capture (`confirm-capture.sh`) is weakened or removed.
- A5. Hammering the target: renewal ignores budget_guard / `min_request_interval_s`.

## 3. Constraints

- Secrets contract identical to `session_capture.py`: allow-listed summary keys only
  (`_safe_summary` style, fail closed); secrets only in 0600 files under
  `data/engagements/<slug>/secrets/`.
- `session_file` keeps invariant I2: only in-scope cookies/origins. IdP cookies (e.g.
  `*.auth0.com`) are **not** written to it — they live only in the dedicated profile.
- `out_of_scope` in `engagement.yaml` always wins over every allowance below.
- Every renewal: `enforce("browser-mcp")`, audit-logged (identity, layer, outcome, hosts — never
  values), honours `min_request_interval_s`.
- No new dependencies (Playwright, stdlib, existing `http_probe`, `notify-send` if present).
- Tests use a local fixture app + fixture IdP only; no real target.

## 4. Scope boundary for login hosts (decided by the user: "B + C combined")

1. **Learned renewal hosts.** During the human's `start_capture` login, record the hosts of
   **main-frame document navigations and their redirect chain** that are not in scope (e.g.
   `app.t.com → t.auth0.com → app.t.com` records `t.auth0.com`). Subresources (CDN, analytics,
   fonts) are not recorded. Stored per identity as `renewal_hosts` in `identities.json`;
   `finish_capture`'s summary lists the host names (non-secret) so the human sees them.
2. **Built-in IdP allowlist** (user-approved addition): well-known login providers
   (`*.auth0.com`, `*.okta.com`, `*.oktapreview.com`, `login.microsoftonline.com`,
   `login.live.com`, `*.b2clogin.com`, `accounts.google.com`, `*.amazoncognito.com`,
   `*.onelogin.com`, `*.pingidentity.com`, `*.pingone.com`) are also allowed during renewal even
   if not learned. Self-hosted IdPs (Keycloak etc.) are covered by learning, not the list.
3. These hosts are usable **only** by the refresh code path, through its own check
   (`in_scope OR learned OR builtin`, minus `out_of_scope`). `scope_guard.is_in_scope` is not
   changed; scanners/probes never see them.
4. During renewal a route guard allows document navigations (main frame and iframes) and
   XHR/fetch only to `in_scope ∪ renewal_hosts ∪ builtin`; any other document navigation is
   aborted and, if it was the main frame, the layer fails. A **document** POST (i.e. a form
   submission) to any host aborts the layer; the app's own fetch/XHR to a renewal host (e.g.
   its `/token` code exchange) is allowed, since that is the app renewing itself. The page is
   never clicked or typed into. Headless renewal that an IdP's bot-detection blocks simply fails
   to layer 3.

## 5. Renewal layers (in order; stop at the first that yields a verified logged-in session)

**Layer 1 — let the app renew itself (generic, covers most apps).** Launch the identity's
dedicated persistent profile **headless** (it holds the IdP SSO cookie), restore the
`session_file`'s sessionStorage sidecar via init script, open the recorded `app_url`, wait for
the page to settle. The app's own code does its silent renew (iframe `prompt=none`, its own
refresh_token call, or a plain cookie session). Then verify (§6), extract `storage_state` +
sessionStorage filtered to in-scope, and write `session_file` atomically.

**Layer 2 — tool uses a stored refresh token.** If layer 1 did not verify and the (latest,
post-layer-1) state holds a refresh token in a recognised shape — `oidc-client-ts`
(`oidc.user:<authority>:<client_id>`) and `auth0-spa-js` (`@@auth0spajs@@::…`) in
localStorage/sessionStorage — POST `grant_type=refresh_token` to the token endpoint from the
issuer's `/.well-known/openid-configuration` (issuer host must pass the §4 check), with the app's
`Origin`. Write the new access/id/refresh token (rotation!) and expiry back into the **same
entry, same shape**, then re-run layer 1's verify with the updated file.

**Layer 3 — human.** Return `needs_human_login: true` with a plain reason (SSO expired / login
page shown / CAPTCHA / token endpoint refused). Fire a desktop notification. The agent then
calls `start_capture` (one or many identities at once); the existing `confirm-capture.sh` gate
is unchanged.

**Proactive + keep-alive.** `start_keepalive(identities)` runs in the browser-mcp process:
for each identity, refresh ~5 min before the earliest in-scope access-token `exp` (JWT decoded
in-process, unverified, never returned) and otherwise do a layer-1 visit every 2 h (± jitter;
minimum 30 min) to keep sliding SSO sessions alive. `stop_keepalive`, and `session_health`
reporting per identity: `last_refresh`, `layer`, `access_expires_in_s`,
`estimated_next_human_login` (from the latest-expiring persistent cookie on a renewal host /
refresh-token `exp`, labelled an estimate). Agent instructions (huntbrain / exploit-agent): call
`start_keepalive` right after a successful `finish_capture`.

**UI-walk hook.** On `auth_lost`, call `refresh_session` in-process before the existing
re-read-and-retry-once.

## 6. "Is it actually logged in?" (verification)

A layer counts as success only if all hold: final main-frame URL is in scope; not a login path
(`ui_walk_logic._LOGIN_PATH_RE`); no visible password input or CAPTCHA frame; and, if a
`whoami_url` was recorded at capture, it returns 2xx with the new session. Otherwise it is a
failure, never a guess.

## 7. Data recorded at capture (additions to `finish_capture`)

`identities.json[label]` gains `app_url` (the in-scope page URL the human ended on),
`renewal_hosts` (§4.1), `whoami_url` (if given). Existing captures without these: `app_url`
falls back to `source_login_url`; `renewal_hosts` empty (builtin list still applies).

## 8. Concurrency & safety details

- A persistent profile can't be opened twice: refresh returns `status: "busy"` if a capture
  window is open for that identity or the profile is locked.
- Per-identity lock around read-modify-write of `session_file`; writes are atomic
  (`browser_confirm._write_private_json`).
- One renewal per identity at a time; keep-alive skips an identity whose refresh is running.
- Fixed upper bound per identity per day (e.g. 48 renewals) as an extra brake.

## 9. Approaches considered

| Approach | Trade-off |
|---|---|
| A. Protocol-level only (generalised Bentley script: `prompt=none`+PKCE / refresh grant over HTTP) | Fast, no browser — but needs per-target client_id/redirect_uri/endpoints and writing tokens into each app's storage format; the user would have to configure every target. |
| B. Browser re-visit only (layer 1) | Fully generic, zero config; misses apps whose silent renew is broken/absent but which still hold a usable refresh token. |
| **C. Layered: browser re-visit → tool refresh_token → human (picked)** | Generic by default, recovers extra cases for the two most common SPA token libraries, human only last. More code than B. |

Picked C with the user (they asked for maximum automation and refresh-token support).

## 10. Left to the builder

- Module layout (proposal: `mcp-servers/session_refresh.py` next to `session_capture.py`;
  tools registered in `browser-mcp/server.py`: `refresh_session`, `session_health`,
  `start_keepalive`, `stop_keepalive`).
- Keep-alive mechanism (asyncio task in the server loop vs `job_runtime` thread job).
- Fixture: stdlib `http.server` app on `app.localhost` + mini OIDC IdP on `idp.localhost`
  (discovery, `/authorize` honouring `prompt=none` + SSO cookie, `/token` with
  authorization_code+PKCE and rotating refresh_token, configurable lifetimes/expiry, a login page
  with a password field and a fake CAPTCHA marker for the layer-3 paths) and a hand-written SPA
  page storing tokens in sessionStorage in `oidc-client-ts` shape.

## 11. Branch

The sidecar and `auth_lost` exist only on `fix/wiring-and-testing-159-164` (not yet on `main`).
Implementation branches from `main` once that branch is merged; if it is not merged by then,
ask the user before stacking on its tip.

## 12. Implementation notes (found while building)

- **Redirect hops are policy-checked by a trampoline.** Playwright's `route` handler only sees
  the first URL of a redirect chain, so an allowed IdP that 302s onward would be followed
  unchecked. Layer 1 therefore fetches every document itself with `max_redirects=0`, checks the
  `Location` against §4, and hands an allowed hop back as a tiny page that script-navigates
  there (a fresh, routed navigation), passing the redirect's `Set-Cookie` through (sliding SSO
  cookies still land — tested).
- **Verification needs positive evidence (§6 tightened).** A page shell that merely stays on an
  in-scope URL is not "logged in": if the session holds recognised SPA token entries their
  earliest access token must now be fresh (`token_not_renewed` otherwise), and an in-scope
  API call ending 401/403 with no later 2xx fails the layer (`unauthorized_api`). Found by
  prove-it-runs: without this, a renewal that silently failed would have been reported as
  refreshed and the stale token written back.
- **Local Network Access.** A route-fulfilled document has no IP address space, so Chromium
  treats it as public; its fetch to a private/loopback host is then blocked. Real public targets
  are unaffected, and the check stays ON in production (it stops a target page reaching the
  operator's localhost, e.g. Burp). Consequence: for a target on a private network, layer 1's
  cross-origin renewal call can fail and the refresh falls through to layer 2 / human. The
  loopback test fixture disables the check via the test-only `_EXTRA_LAUNCH_ARGS`.
- **Agent wiring.** HuntBrain has no `mcp__browser-mcp` tools, so the keep-alive instructions
  live in exploit-agent and recon-agent; HuntBrain only passes identity labels and is told an
  expiry is not a reason to ask for a new login.
- **Strict renewal host policy (review-and-audit).** `RenewalPolicy` does NOT use
  `scope_guard.is_in_scope`: that function's safe-test-host shortcut treats loopback, RFC1918,
  link-local (cloud metadata) and some real TLDs (`.sh`, `.py`, `.md`, `.zip`) as always in
  scope, which a target page could otherwise reach through the renewal browser. In scope here =
  an explicit `engagement.in_scope` match; learned/builtin hosts must resolve to public
  addresses and are never IP literals; a non-public host is usable only when `in_scope` names it
  explicitly. Layer 2's token endpoint must be on the issuer's host, explicitly in scope, or a
  builtin IdP. Learned hosts = only the capture window's own main-frame hosts before its last
  landing back on the app (no popups, no later browsing), at most 5.
  (The `is_safe_test_host` TLD issue itself is pre-existing and affects scope_guard generally —
  tracked separately, not changed here.)
