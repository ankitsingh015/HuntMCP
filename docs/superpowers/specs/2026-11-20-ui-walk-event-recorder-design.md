# UI-walk event recorder + Burp mirror — Design (spec 1 of 3)

Date: 2026-11-20
Status: Approved (2026-11-20)
Size: Project
Builds on: #164 UI-walk (`docs/superpowers/specs/2026-11-19-page-comprehension-ui-walk-design.md`)
Followed by: spec 2 (in-scope SSO / auth flows as surface), spec 3 (Burp-style
parameter + request mutation). Both read this spec's event stream.

## Intent and the why

The user wants the walker to capture "every corner, every small browser
event" so nothing on a page goes untested. Today the #164 walker records
inputs, controls and UI→API edges (method, URL, body field names), but it
never captures what happens *in the browser* when a control is clicked:
which redirects were followed, which cookies were set and with what flags,
what a WebSocket carried, which `postMessage` traffic moved between frames,
which errors fired, which storage keys changed. Those events are where a
whole family of client-side and session bugs live (postMessage without an
origin check, session cookies missing Secure/HttpOnly/SameSite, tokens
parked in localStorage, redirect hops through attacker-influenced params).

The user also wants the walk's real traffic to land in **Burp** as well as in
the HuntMCP inventory ("burp me bhi save ho"). Burp is a mirror the human can
browse and replay from. It is never the source the walker relies on, and it
stays optional, because some targets refuse proxied traffic.

Success: after a map walk, every page in the inventory carries an ordered
event list, each event tied to the control that caused it. The useful ones
show up as candidates for exploit-agent, and with the mirror on, everything
the walker really sent is in Burp's HTTP history.

## Goals

1. Per-page **event recorder** in the walker (Pass 1 and Pass 2 alike),
   inventory `schema_version` 1 → 2. Each event is tied to the control
   signature active when it happened (`null` = page load). Event types:
   - `redirect` — the full hop chain of every document/XHR/fetch that
     redirected: each hop's URL, status and whether it was in scope.
   - `set_cookie` — cookie **name + attributes only** (domain, path, Secure,
     HttpOnly, SameSite, expiry class session/persistent, partitioned), the
     URL that set it, and, via CDP, whether Chrome blocked it and why.
     The value is never stored.
   - `websocket` — URL, direction, frame count, opcode and size per frame,
     plus the top-level JSON keys when a frame is JSON. Client→server frames
     are still never forwarded in Pass 1 (unchanged #164 behaviour); so in
     Pass 1 this records attempted client frames only.
   - `postmessage` — both directions: a page/frame sending (`targetOrigin`,
     data shape) and a listener being registered (which frame, how many
     listeners). Shape = type + top-level keys + length, never values.
   - `console` — `error` level messages and uncaught page errors: text
     truncated (≤300 chars), redacted, quarantined, plus source URL.
   - `storage` — localStorage/sessionStorage keys added, removed or changed
     per origin, diffed before/after each click. Key names only.
2. **Candidates** derived from events (each a candidate, never auto-confirmed):
   - `cookie-flags-candidate` — a cookie whose name looks session/auth-ish
     (heuristic list: sess, sid, auth, token, jwt, remember, …) set on HTTPS
     without Secure, or without HttpOnly, or with `SameSite=None` and no
     Secure, or with SameSite missing.
   - `postmessage-no-origin-check-candidate` — from the active probe (Goal 3).
   - `postmessage-wildcard-target-candidate` — a page posts a message with
     `targetOrigin "*"` whose data has token/auth-ish keys.
   - `storage-token-candidate` — a token/auth-ish key written to
     localStorage/sessionStorage (names only; tells exploit-agent where an
     XSS would steal from).
   - `redirect-param-candidate` — a redirect hop whose `Location` contains the
     value of a query parameter of the previous hop (open-redirect lead). The
     comparison happens in memory; only the parameter name is stored.
3. **postMessage probe (browser-only, no server traffic of its own).** For each
   page with at least one `message` listener, dispatch a synthetic
   `MessageEvent` inside the page with a foreign origin
   (`https://hm-probe.invalid`) and a data value shaped like the ones the
   page actually received (or a generic `{type: "hm<token>"}` if none were
   seen). Watch for a reaction in a short window: DOM mutation, navigation,
   network request, storage change, or a new console error. A reaction makes
   the candidate. Any request the probe triggers goes through the existing
   interceptor (non-GET aborted, out-of-scope navigation aborted, budget
   charged).
4. **Burp mirror (optional, off by default).** A new `upstream_proxy`
   parameter on `start_ui_walk` (default empty; falls back to the
   `HUNTMCP_UPSTREAM_PROXY` env var) makes the walk's browser send its traffic
   through that proxy, e.g. Burp at `http://127.0.0.1:8080`, so every request
   the walker *really sent* appears in Burp history. Requests the walker
   aborts never leave the browser, so they never reach Burp; they are in the
   inventory only.

5. **JS-set cookies and IndexedDB.** The init script also wraps the
   `document.cookie` setter (cookie name + attributes from the assigned
   string, value dropped) and records IndexedDB database/object-store names
   created or opened. Both are event types (`js_cookie`, `indexeddb`) and feed
   the same `cookie-flags-candidate` / `storage-token-candidate` rules. This
   closes a gap: cookies set by JavaScript never appear in a `Set-Cookie`
   header.
6. **Security response headers per page and per API response** (`headers`
   event): CSP (raw policy, truncated), `X-Frame-Options`, the
   `frame-ancestors` directive, `Access-Control-Allow-Origin` /
   `-Credentials` / `-Methods`, HSTS presence. These are not secrets, so
   values are kept. New candidates:
   - `clickjacking-candidate` — a page with at least one state-changing
     action (a non-GET UI→API edge or a `destructive`/`submit` control) and
     neither `X-Frame-Options` nor `frame-ancestors`.
   - `cors-candidate` — an API response with `Allow-Credentials: true` and
     `Allow-Origin` either `*` or equal to the page's own Origin header
     echoed back (a lead only; testing a foreign Origin is spec 3's job).
   CSP is also attached to every XSS-type candidate so exploit-agent knows
   what an XSS can reach.
7. **DOM XSS: sink hooks + zero-traffic sources.** The init script wraps the
   dangerous sinks: `innerHTML`/`outerHTML` setters, `insertAdjacentHTML`,
   `document.write`/`writeln`, `eval`, `Function`, string-form
   `setTimeout`/`setInterval`, `location`/`location.href`/`assign`/`replace`,
   and `src`/`href` setters on script/iframe/anchor elements. The walker
   plants a canary (same `hm…` token format and registry as Pass 2) in sources
   that never reach the server:
   - the URL `#hash` (for hash-routed SPAs, the route is kept and the canary
     is appended as an extra hash parameter),
   - `window.name`,
   - the postMessage probe's data (Goal 3).
   A canary reaching a sink is recorded as a `dom_sink` event (source, sink,
   frame, stack top: script URL and line). If the payload form of the canary
   executes (dialog/title marker, same check as Pass 2), it becomes a
   `dom-xss-candidate`; if it only reaches the sink, a `dom-sink-candidate`.
   The `?query` source is **spec 3** (putting a canary there is a mutated GET
   that reaches the server); spec 3 reuses these same sink hooks.
8. **Small events:** `target=_blank` links/`window.open` calls without
   `noopener` (`tabnabbing-candidate`, only for links to out-of-scope hosts),
   and attempted service-worker registrations (`service_worker` event: script
   URL and scope; registration stays blocked as in #164).

## Non-goals

- Making Burp the walker's data source, or reading Burp history back. Burp is
  a mirror only.
- Any attempt to defeat a target's bot protection, TLS checks or proxy
  detection. If a target refuses proxied traffic, the mirror is switched off
  for that walk and the human is told (see Proxy refusal).
- Storing any cookie value, storage value, postMessage payload value,
  WebSocket payload value or full console text.
- New MCP server, new Python dependency (CDP is in Playwright 1.62).
- New surface-map node kinds. Events become candidates and inventory data;
  specs 2/3 decide whether they also need nodes.
- DOM-XSS sources that reach the server (`?query`, path, form values) — spec 3.
- Diffing events between two identities (A vs B) — later, after specs 2 and 3.

## Anti-goals (failure even if it "works")

- A secret value (cookie, token, storage value) ends up in the inventory, the
  tool output, an audit log or Burp-unrelated files.
- The probe or the recorder sends something Pass 1 would otherwise not send
  (a non-GET, an out-of-scope navigation).
- The mirror sends traffic to a non-local proxy, i.e. target traffic leaks
  to a remote host.
- A walk with the mirror on silently drops traffic or silently runs without
  the mirror. The user must always see whether the mirror was on.
- Any #164 contract changes silently (tool params, inventory fields consumers
  read, provenance line last, quarantine).

## Approaches considered

| | Approach | Trade-off | Verdict |
|---|---|---|---|
| A | Recorder inside the walker using Playwright events + one init script | Ties every event to the click that caused it; sees postMessage/storage/console; no Chrome-only APIs | Base of the chosen design |
| **B** | **A + a CDP session for cookie detail** | Adds raw `Set-Cookie` attributes and Chrome's own "blocked cookie" reasons; a bit more code, Chromium-only (we only run Chromium) | **User-picked**, with the Burp mirror included |
| C | Proxy everything through Burp and read its history afterwards | Burp sees requests, but not postMessage, storage or console, and can't tell which click caused what | Rejected as the source; Burp kept as an optional mirror |

User decisions recorded in conversation (2026-11-20):
- Approach **B**, with the Burp mirror included.
- All four additions accepted: JS-set cookies + IndexedDB, security headers
  (clickjacking/CORS leads), DOM-XSS sink hooks with zero-traffic sources,
  tabnabbing + service-worker events.
- Burp is a mirror ("save rah sakta hai usme"), not the walker's main source.
- For spec 3: mutated **GET** variants may be sent **without** the grant file
  (still scope, budget, payment-host block, mutating-keyword GET block);
  non-GET variants only under the Pass-2 grant. Recorded here because spec 3
  depends on it.
- Branch: stacked on `fix/wiring-and-testing-159-164` (the #164 code is not on
  `main` yet), rebased onto `main` once #164 merges.

## Design

### Where the code goes

- `ui_walk_logic.py` — pure helpers (unit-tested, no browser): cookie
  attribute parsing from a raw `Set-Cookie` string (returns name + attrs,
  drops the value), the auth-ish name heuristic, data-shape summariser,
  storage diff, redirect-param matcher, candidate rules, proxy-URL validator.
- New `ui_walk_events.py` — the recorder: attaches listeners to a
  page/context, owns the init script, the CDP session, the per-page event
  buffer and caps, and the postMessage probe. `ui_walk._Walker` creates one
  per walk and calls it at page start, before/after each click, and at page
  end. Pass 2 (`CanaryWalker`) inherits it unchanged.
- `ui_walk.py` — `SCHEMA_VERSION = 2`; `rec["events"]` per page;
  `inv["burp_mirror"]` status; launch options get the proxy.
- `browser_launch.launch_kwargs` gains an optional `proxy` argument (default
  none, so every other browser tool is unchanged).
- `server.py` — `start_ui_walk(..., upstream_proxy: str = "")`; `_format_walk`
  prints event counts per type, the mirror status line, and the new
  candidates (quarantined), provenance line still last.

### Event capture (how each type is seen)

- **redirect** — `response` events: when `request.redirected_from` exists,
  walk the chain back to build hops. Includes main-frame navigations and
  XHR/fetch.
- **set_cookie** — CDP `Network.responseReceivedExtraInfo` gives the raw
  `Set-Cookie` headers and `blockedCookies` with reasons. Parsed in-process
  by the pure parser; the raw string is discarded right after parsing and is
  never logged.
- **websocket** — the existing `route_web_socket` handler records
  per-frame metadata instead of only a counter (`ws_frames_blocked` stays,
  for compatibility).
- **postmessage / storage** — an init script (added with
  `context.add_init_script`, runs in every frame before page scripts) wraps
  `window.postMessage` and `addEventListener('message', …)`, and exposes a
  storage-key snapshot function. Reported to Python via
  `context.expose_binding`. The script sends only shapes, never values.
- **console** — `page.on("console")` (error level) and `page.on("pageerror")`.

Each event: `{type, control_signature, t_ms (since page load), frame_origin,
…type fields}`. Caps: 300 events per page, 20 console messages per page,
2,000 per walk; overflow counted as `events_dropped`.

### postMessage probe

Runs once per page after the click loop, only if a `message` listener was
seen. The init script dispatches the synthetic event in the frame that
registered the listener. Watch window ~1.5 s via MutationObserver plus the
existing request, storage and console hooks. No reaction → recorded as
`probe: no-reaction` (not a candidate). Budget: no extra page load; any
request it triggers is charged like any other.

### Burp mirror

- `upstream_proxy` must be `http://` or `https://` with host exactly
  `127.0.0.1`, `localhost` or `[::1]` and a port; anything else → walk
  refused with a clear reason. This keeps target traffic from being sent to
  a remote proxy.
- When set: Chromium launched with that proxy; the context uses
  `ignore_https_errors=True` **only in mirror mode**, because Burp re-signs
  TLS with its own CA. Stated in `honest_limits`. Burp itself still sees and
  validates the real server certificate.
- **Preflight:** TCP connect to the proxy. Unreachable → walk runs direct, and
  `inv["burp_mirror"] = {"requested": true, "active": false, "reason":
  "proxy unreachable"}` is printed loudly in `check_ui_walk`.
- Scope, budget, interception: unchanged and still enforced *in the browser*,
  before the proxy. Burp's own intercept/scope settings are the human's.

### Proxy refusal (the user's question)

Some targets block or challenge requests that come through an intercepting
proxy. Handling:

1. With the mirror on, the start page loads through the proxy first.
2. If that load fails at connection/TLS level, or returns a block page
   (403/429/503 whose body `tool_resolver.classify_block` flags as `waf` or
   `rate_limit`), the walker makes **one** direct load of the start page
   (budget-charged) to compare.
3. Direct load fine → the walk continues **direct**, with
   `burp_mirror.active = false, reason = "target refused proxied traffic"`
   shown loudly. Nothing is tried to get around the target's check.
4. Direct load also blocked → it's a normal block, not a proxy problem; the
   walk stops as today and a human looks.
   The note shown to the human says what the comparison proved: the block
   happens only through the proxy, so the likely cause is the proxy's own
   outbound connection to the target (for example its TLS fingerprint), not
   the application. It is a tooling artifact, never a finding. If the
   programme's rules allow it, the human may change their own Burp's outbound
   TLS settings and re-run with the mirror on. The walker never changes or
   imitates TLS fingerprints itself.
5. Mid-walk: if a page that loaded fine starts returning block pages, the
   walk does **not** switch modes mid-way (that would mix evidence). It stops
   with status `blocked` and says so; the human can re-run with the mirror
   off.

### Inventory (schema_version 2)

Additive only: `pages[].events`, `pages[].events_dropped`,
`pages[].postmessage_probe`, `inv.burp_mirror`. All v1 fields keep their
meaning, so v1 readers keep working. `ui_walk_store` writes it as today.

### Safety & constraints (unchanged from #164 unless stated)

- Pass 1 still sends nothing state-changing; the recorder and probe add no
  non-GET traffic. Scope checked on every navigation and request (unchanged
  interceptor). Payment hosts still blocked.
- No secret values anywhere: parsers drop values in-process; console text
  passes `redact.py` and is truncated; quarantine on all target text in tool
  output; provenance line last.
- Budget guard per page load unchanged; the one proxy-refusal comparison
  load is charged.

## Verification

- **Unit (pure logic):** Set-Cookie parser (values dropped, every attribute,
  odd casing, multiple cookies); auth-ish heuristic; each candidate rule with
  positive and negative cases; storage diff; redirect-param matcher; data-shape
  summariser never returns values; proxy URL validator (accepts localhost
  forms, refuses remote hosts, userinfo, other schemes).
- **Black-box on the local fixture** (`tests/fixtures/ui_walk_target/ui_walk_app.py`),
  vulnerable and patched variants:
  - postMessage listener with no origin check that writes to the DOM
    (vulnerable) vs one that checks `event.origin` (patched) → candidate only
    on vulnerable.
  - session cookie without Secure/HttpOnly/SameSite (vulnerable) vs with all
    (patched).
  - 2-hop redirect chain whose final `Location` echoes a `next` param.
  - a click that writes `authToken` to localStorage; a page that posts
    `targetOrigin "*"` with a token key; a console error on click; a
    WebSocket page sending a client frame.
  - a cookie set by JavaScript without flags; an IndexedDB store named
    `tokens`.
  - a page with a delete action and no framing protection (vulnerable) vs
    `frame-ancestors 'none'` (patched); an API echoing Origin with
    credentials (vulnerable) vs a fixed allow-list (patched).
  - DOM XSS: a page that writes `location.hash` into `innerHTML`
    (vulnerable) vs `textContent` (patched); a page that writes
    `window.name` into `document.write`; a message listener that puts
    `event.data` into `innerHTML`.
  - an out-of-scope `target=_blank` link without `noopener`; a page that
    tries to register a service worker.
  - Assertions: events tied to the right control; no cookie/storage/message
    value appears anywhere in the inventory file or tool output (grep for the
    fixture's known secret values); Pass 1 still sends zero non-GETs.
- **Mirror:** a stdlib forwarding proxy in the test (stands in for Burp) logs
  what it sees → every request the fixture received came through it, and no
  aborted request reached it. Refusal: the fixture's `refuse_proxied` mode
  returns a block page when the stand-in proxy's `Via` header is present →
  walk falls back to direct with the reason shown. Unreachable proxy port →
  direct + loud status. Remote proxy URL → refused.
- **Prove it runs:** after a session restart, real
  `mcp__browser-mcp__start_ui_walk` / `check_ui_walk` against the fixture on a
  throwaway engagement (never `bentley-com`), once with
  `upstream_proxy=http://127.0.0.1:8080` (real Burp if running, else the
  stand-in) and once without.

## Decisions settled after builder check (author's calls)

1. **Pass 2 events.** Pass 2 uses scratch page records that are thrown away,
   so its events go to a new `inv.pass2_events` list (same event shape plus
   `page_template`). `forward_sent` (real submits via `route.fetch`) parses
   `Set-Cookie` from the fetched response itself, so cookies set or rotated by
   real submits are recorded even if CDP doesn't fire for them. Whether
   `route.fetch` goes through the upstream proxy is checked during the build.
   If it doesn't, that is fixed or stated as an honest limit; it is never
   assumed.
2. **`run_teardown` takes `upstream_proxy` too**, so its real state-changing
   requests can also be mirrored to Burp.
3. **postMessage probe: in-scope frames only.** Listeners in third-party
   (out-of-scope) frames are recorded as events but never probed, so the
   probe can never cause traffic to, or a candidate about, a non-target.
4. **Block detection is mirror-mode only.** The proxy-refusal check and the
   mid-walk `blocked` stop apply only when the mirror is active. A walk
   without the mirror behaves exactly as in #164.
5. **Turning the mirror off:** `upstream_proxy="off"` disables it even when
   `HUNTMCP_UPSTREAM_PROXY` is set. Empty means "use the env var, else off".
   Additive parameter; no existing parameter changes.
6. **Loopback through the proxy.** Chromium bypasses a proxy for loopback by
   default, so in mirror mode only, the launch adds
   `--proxy-bypass-list=<-loopback>`. This makes the local fixture (and any
   locally served target) appear in Burp too.
7. **Fallback to direct relaunches the browser context without
   `ignore_https_errors`**, so a direct walk never runs with TLS checks
   disabled.

## Addendum 2026-11-21: auto mode (user decision)

The user wants the mirror decided by the tool, not by asking them or making
the agent pick ("agent apne according off on kare, mujhse na puche"). This
replaces "off by default":

- `upstream_proxy=""` (and no `HUNTMCP_UPSTREAM_PROXY`) now means **auto**: at
  walk start the walker makes one GET to `http://127.0.0.1:8080/` (no proxy,
  2 s timeout, at most 64 KB read). It is the proxy's own page, so nothing about
  the target is sent. If the body says "Burp Suite", the mirror turns on
  through that listener. Otherwise (nothing listening, or some other program
  on 8080) the walk runs direct, and the inventory records
  `burp_mirror.auto = "no Burp detected"`.
- The identity check is the safety rule: target traffic is never routed to an
  unknown local program just because a port is open.
- `"off"` still disables it. An explicit URL, or `HUNTMCP_UPSTREAM_PROXY`,
  still wins, unchanged. `"auto"` may also be passed explicitly.
- The auto port is read from `HUNTMCP_BURP_AUTO_PORT` (default 8080) at call
  time. The test suite's autouse fixture points it at a closed port, so tests
  never route through a developer's running Burp.
- Every other rule is unchanged: loopback only, TLS-ignore only while the
  mirror is active, proxy-refusal fallback, no evasion.

## Left to the builder

- Exact auth-ish name list, event/console caps, probe watch window, the field
  names inside each event type.
- Whether the probe uses data shapes from observed messages or only the
  generic shape when both are available.
- How `_format_walk` lays out the new counts.
