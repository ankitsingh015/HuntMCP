---
name: engagement-setup
description: How to start a HuntMCP engagement -- assessment mode selection, /goal focus mode, target fingerprinting, and the ROI-based testing order. Converted from master-pentest-prompt.md Phases 0.1/0.2/0.5/0.9. Use at the very start of an engagement, before any live testing.
---

# Engagement setup

This is the "before Phase 1" checklist HuntBrain works through once per
engagement, after scope/authorization is confirmed (see `AGENT-BRIEF.md`
and `engagement.yaml` -- those are the enforced scope boundary; this skill
is about *how* to run the engagement inside that boundary, not whether
you're allowed to).

## When to use

At the very start of an engagement, right after Phase 0 scope
confirmation and before spawning recon-agent. Also re-read the ROI
priority order section any time you're deciding what to test next.

## Assessment mode

Ask the user to pick ONE mode, once, then never ask again during the
engagement:

- **FULL BLACKBOX PENTEST** -- use every phase/skill, plus the learning
  phases (see `knowledge-loading` skill). Deep, recursive, slow.
- **NORMAL SECURITY ASSESSMENT** -- lightweight, focused, hard time cap;
  skip the learning phases and heavy fuzzing.

If the mode is unspecified, don't proceed until the user chooses.

Scope is the exact domain plus all subdomains and everything related. If
a subdomain is given, still run the whole engagement against the apex
domain too. Subdomain enumeration is mandatory regardless of mode
(subfinder / crt.sh / amass -- see recon-agent). Spend real time on one
domain before moving to the next; thoroughly test one endpoint before the
next rather than skimming many shallowly.

Rate-limit policy: no artificial per-request delay by default -- run at
real recon/scan speed. `tool_resolver.run_tool()` is purely reactive:
`classify_block()` only ever triggers a delay (5s, then exactly one
retry) after an actual 429/rate-limit signal is detected in a tool's
output, never as a blanket sleep-between-requests policy (a proactive
per-request delay would trade away real speed for a problem that mostly
doesn't happen). Don't hand-add your own throttling on top of this. If a
request/scan hangs for a long time, abandon it and move on rather than
blocking the whole engagement.

## Goal focus mode (`/goal`)

If the user issues `/goal <objective>` (e.g. "achieve RCE on target.com"):

- The objective becomes the highest-priority task of the engagement.
- All recon, payload generation, endpoint discovery, chaining, and
  exploitation revolve around that goal.
- Ignore low-value findings, info-only issues, and unrelated vulns while
  the goal is active.
- Continuously self-reason: "What is blocking the goal?", "What extra
  access/primitive is needed?", "Can another vuln lead to the goal?"
- If the goal is reachable by chaining several issues, prioritize the
  exploit chain (see chain-planner). Pivot automatically when a path
  fails.
- On success, output exactly "GOAL ACHIEVED", then provide: exploitation
  path, proof/evidence, impact, reproduction steps, root cause.
- If exhausted, exit goal focus mode gracefully and resume the normal
  phased assessment.
- `/goal` overrides scan priority but never overrides scope, legality, or
  authorization boundaries -- the scope gate (`scope_guard.py` +
  `scripts/hooks/scope_gate_hook.py`) still applies unconditionally.
- Execution priority: 1) the goal, 2) exploit chains toward the goal,
  3) recon supporting the goal, 4) normal assessment tasks.

## Target resolution and fingerprint

Normalize the URL: test `http://`, `https://`, and a `www.` prefix;
follow redirects (`-L`) to find the canonical host. If a bare domain is
given, also infer `www.`.

Full initial fingerprint (every header, body, and stats):

```bash
curl -s -i -L -k -A "<browser UA>" https://canonical/ \
  -w "\nHTTP:%{http_code} Time:%{time_total}s Size:%{size_download} IP:%{remote_ip} SSL:%{ssl_verify_result}"
```

Map headers to tech stack to a targeted playbook:

| Header signal | Stack |
|---|---|
| `Server: nginx` / `Apache` | nginx-specific / Apache-specific |
| `X-Powered-By: PHP/x` | PHP payloads |
| `PHPSESSID` | PHP |
| `JSESSIONID` | Java |
| `ASP.NET_SessionId` | .NET |
| `CF-RAY` | Cloudflare -- WAF bypass needed, see `waf-bypass` skill |
| `X-Amz-Cf-Id` | CloudFront |
| `X-Served-By` | Fastly |

Save the full response; extract every URL, JS file, form, parameter, and
inline script *before* any exploit attempt -- map the building before
testing it. For every discovered subdomain/endpoint/version string:
research public CVEs/exploits (writeup-mcp's `fetch_cves`), then actually
attempt exploitation, not just note it.

## Account/identity topology (before authenticated testing)

When the VDP/scope implies authenticated or multi-account testing (IDOR,
vertical/horizontal privilege checks, session testing), decide the account
**topology** up front -- BEFORE the human creates accounts -- not mid-hunt.
State, in one line, what the planned tests actually need:

- **Cross-tenant / cross-org IDOR** -> **two SEPARATE organizations** (two
  accounts, each in its own tenant).
- **Vertical privilege escalation** -> **ONE organization with at least two
  different role levels** (e.g. an admin AND a low-privilege member).
- **Horizontal same-tenant IDOR** -> **two users in the SAME organization**.

Derive it from the VDP text first, then refine it against the app's real role
model as recon reveals it (roles, org/tenant boundaries, invite flows). Getting
this wrong costs a full round trip of account setup -- observed live (Manatal,
#136): two admins in the *same* company were set up first (useless for either
test), then one had to be demoted mid-engagement to make the vertical check
possible at all.

Tie-in: once the human has the right accounts, register them in the
test-identity roster and capture each with `start_capture`/`finish_capture`
(see the session-capture setup). Authenticated tools then consume each identity
by **label** (e.g. idor-mcp's `owner_label`/`other_label`), so no credential is
pasted into the transcript. The two-account owner-vs-other procedure itself is
in the `access-control-and-idor` skill.

## ROI priority order

This is an ORDERING rule -- every phase/skill still runs in full on
every target. Nothing is skipped or deprioritized out of existence. Based
on confirmed-findings frequency across real engagements, test in this
order:

1. **Financial IDOR / access control** (wallet, payout, ledger, order,
   refund, invoice `/show/{id}`) -- highest confirmed payout class.
2. **Debug mode / verbose-500 / error-trace leaks** (source, SQL
   bindings, env, paths, secrets).
3. **Payment & token flows** (test/live keys, client-side amount,
   callback signature/amount verification, token replay/idempotency).
4. **Auth / OTP / reset flows** (OTP in response, rate-limit/lockout,
   reset 500-vs-302 enumeration, MFA bypass).
5. **Secrets in client bundles / HTML** (grep and use every key --
   `secrets-mcp` automates the grep step).
6. **CORS / cross-origin** (origin reflection + credentials, WS hijack).
7. **Staging / UAT / preprod exposure + subdomain takeover** (dangling
   CNAME) -- cheap, often accepted.
8. **EOL / unpatched components** (version fingerprint -> CVE -> exploit).
9. Everything else -- every remaining skill/phase, in full.

Reality check: this order is a starting point, not a cage. If recon
reveals a different high-value surface first (an exposed admin panel, a
live payment API, an upload endpoint, a debug console), hit it first and
record why -- the order follows the target, not the list.
