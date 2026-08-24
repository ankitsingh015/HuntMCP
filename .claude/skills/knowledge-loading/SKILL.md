---
name: knowledge-loading
description: How to load prior knowledge before testing a target -- public bug-bounty report learning, offensive skill-file references, the Lessons Registry feedback loop, and tech-stack-based keyword lookup into it. Converted from master-pentest-prompt.md Phases 0/0.3/0.4/0.8/0.8.1. Use right after engagement-setup, before Phase 1 recon, and again once recon returns a tech stack.
---

# Knowledge loading

Three knowledge sources exist and each answers a different question (see
`ARCHITECTURE.md`'s "Knowledge Layer" section for the full picture):
Writeup RAG ("what worked on similar *public* writeups?"), Memory DB
("what did *we* find on *this* target before?"), and the Lessons Registry
("what confirmed technique matches *this target's* tech stack, from *our
own* past engagements?"). This skill covers loading the Lessons Registry
and the research-repository/report-learning steps that feed it.

## When to use

At engagement start (report/skill-file learning, tooling repos) and again
immediately after Phase 1 recon returns a tech stack (the keyword-matched
Lessons Registry lookup -- guessing keywords before the stack is known
wastes context).

## Tooling & research repositories

Cross-reference findings against these researcher knowledge bases:

- PayloadsAllTheThings (swisskyrepo) -- payloads for every technique
- HackTricks -- methodology + tricks
- Bug Bounty Reference (ngalongc) -- real-world writeups
- PortSwigger Web Security Academy -- lab techniques
- OWASP WSTG (v4.3) -- 90+ tests, 12 domains
- OWASP Top 10:2025 (A01 Broken Access Control, A02 Security
  Misconfiguration, A03 Software Supply Chain Failures, A04 Cryptographic
  Failures, A05 Injection, A06 Insecure Design, A07 Authentication
  Failures, A08 Software/Data Integrity Failures, A09 Security Logging &
  Alerting Failures, A10 Mishandling of Exceptional Conditions)
- OWASP LLM Top 10:2025 (System Prompt Leakage, Vector/Embedding
  Weaknesses, Excessive Agency among them)
- MITRE CWE Top 25 + CAPEC attack patterns
- HackerOne Hacktivity / GitHub Security Advisories for real CVEs

Scan with: nuclei (all templates), wappalyzer, ffuf.

## Bug-bounty report learning (full blackbox mode only)

Before/while scanning, study real-world disclosed reports and apply them
-- not optional in full blackbox mode:

- Fetch https://github.com/reddelexc/hackerone-reports/tree/master/tops_by_bug_type
  and read every bug-type file.
- From each file, extract every `hackerone.com/reports/...` URL embedded
  inside, then open and read each report directly.
- If a report is private/unavailable/blocked, mark it unavailable and
  move to the next.
- Extract from each: vuln type, affected feature, root cause,
  exploitation steps, payloads, bypasses, impact, remediation.
- Learning objective: HOW the bug was found (entry points, endpoints,
  parameters, headers), bypass techniques, and how small misconfigs
  chained into critical impact.
- Application: map learned patterns onto the live target immediately,
  reuse payload styles, prioritize tests by real-world success rates.
- Skipping this in full blackbox mode makes the engagement incomplete.

## Offensive skill-file learning (per-vuln, full blackbox mode)

For each vuln class below, fetch the matching offensive skill file, learn
it, adapt it, apply it on the target:

- JWT: `SnailSploit/Claude-Red` `Skills/offensive-jwt/SKILL.md`
- Open redirect: `SnailSploit/Claude-Red` `Skills/offensive-open-redirect/SKILL.md`
- Request smuggling: `SnailSploit/Claude-Red` `Skills/offensive-request-smuggling/SKILL.md`
- SQLi: `SnailSploit/Claude-Red` `Skills/offensive-sqli/SKILL.md`
- SSTI: `SnailSploit/Claude-Red` `Skills/offensive-ssti/SKILL.md`
- IDOR: `SnailSploit/Claude-Red` `Skills/offensive-idor/SKILL.md`

Read the full file, extract the technique, adapt to the target's actual
endpoints/params, test it, then move on -- never read without acting.

## The Lessons Registry feedback loop

This is HuntMCP's self-improvement loop: what was confirmed as a real bug
on a past target becomes a standing technique for every future target.
It's already automated in `mcp-servers/lessons-mcp` (`append_lesson()`,
`read_lessons()`) -- exploit-agent calls `append_lesson()` immediately
after every CONFIRMED or CLOSED-FP decision (see the exploit-agent
skill's Phase 1.5), not batched for later.

**Mandatory read**: at the start of every engagement, `read_lessons()`
with no keyword first (a cheap header skim of every class), then again
with `keyword="<tech signal>"` once recon returns a tech stack -- loads
only the matching class blocks, never the whole registry. Mentally map
every loaded technique onto the current target; a loaded-but-unapplied
class is wasted context.

The registry itself (`chat-logs/lessons-learned.md`, gitignored,
workstation-private, never this repo) holds the exact confirmed bugs from
real reports plus the method that found each one. Below is the generic,
redacted priority order distilled from real recurring classes across
engagements -- test every class in this order when the registry surfaces
it as a match, but never skip a class on a fresh target just because a
past target's version of it was closed as a false positive (see the
no-skip guard below):

1. **Debug / verbose-500 leaks**: trigger 500s (invalid types, empty
   values, malformed JSON, extra params, nulls) and harvest stack traces,
   source code, SQL bindings, env var names, absolute paths, class/method
   names. Follow every leaked secret to the next step.
2. **OTP / verify code in response body + no rate limit**: after
   register/resend/verify, read the response body for the code. Test the
   full keyspace (4-digit = 10k) with no lockout and the endless-resend
   window. Chain register-with-victim-identity -> read OTP -> verify ->
   ATO.
3. **IDOR on sequential integer IDs -- financial = critical**: enumerate
   sequential IDs on wallet/payout/ledger/order/setting/show routes and
   swap IDs across two accounts. One IDOR found usually means the pattern
   exists on every `/show/{id}` route on that app -- sweep all of them.
4. **Payment bypass**: hunt test keys in checkout JS, tamper the
   client-side amount, replay purchase tokens (missing idempotency),
   verify the callback actually checks signature + paid amount.
5. **Unauthenticated Laravel Ignition**: `/_ignition/execute-solution`
   with no signature check executes runnable solutions = RCE
   precondition. Probe `/_ignition/*` before `/admin`.
6. **Reflected XSS via unescaped HTML concatenation**: inject an
   attribute-breaker (`" onload="`) into path/param segments concatenated
   raw into HTML attributes.
7. **Subdomain takeover via dangling CNAME**: full CNAME sweep every
   engagement, flag claimable strings (Amplify/CloudFront 403 on a
   deleted app, "There isn't a GitHub Pages site here", NoSuchBucket,
   expired S3/ELB/Fastly).
8. **Staging / UAT / preprod hosts exposed**: test the weaker environment
   first (same app, less hardening, unauth debug routes, test data).
9. **Secrets in client bundles / HTML**: download every JS + page source,
   grep key patterns (`VITE_`, `sk-`, `pk_`, `AKIA`, `AIza`, `client_secret`,
   `projectId`, Sentry DSN, Firebase), then use each key against the
   target's APIs -- `secrets-mcp` automates the grep step.
10. **CORS wildcard/reflection + credentials**: OPTIONS preflight with an
    arbitrary Origin; flag origin reflection + `Access-Control-Allow-
    Credentials: true` + auth headers allowed cross-origin.
11. **Spring Boot Actuator exposed**: `/health` + `/actuator/*` reveal
    the full stack. Probe actuator paths before `/api` enumeration.
12. **WP REST `/wp-json` unauth**: users (enum), media, search
    (`search=password|confidential|internal|secret|test`),
    `xmlrpc.php` `system.multicall` brute amplification.
13. **EOL CMS / plugin fingerprint -> CVE -> exploit**: version
    fingerprint via `lib/upgrade.txt`, generator meta, `readme.html`,
    then map to a CVE (writeup-mcp's `fetch_cves`) and attempt
    exploitation.
14. **Vault `/v1/sys/{health,seal-status,init,leader,metrics}` unauth**:
    leaks cluster id/name, internal leader IP (SSRF pivot), KMS/storage
    backend, mount counts.
15. **Password-reset enumeration oracle**: 500-vs-302 / different-body
    responses across valid vs invalid emails is a reliable user-existence
    oracle. Also check reset-500 responses for token/hash leaks.

**Write-back rule**: every time a real bug is confirmed on any target,
`append_lesson()` immediately (vuln name, method, exact payload/request,
impact chain, bypasses) -- the next engagement starts stronger. Also
append triager-closed/false-positive items so the registry learns what
NOT to report. A lesson applied and confirmed on the current target is a
new method -- write it back before moving on. Tool/technique
advancements (curl flag combos, working one-liners, new subagent
techniques) go in the TOOLS/SCRIPTS section the same way.

**No-skip guard**: anything ruled-out/verified-not-exploitable/
triager-closed is only true for that target and that context -- it NEVER
means "skip this test on any other target." Every new target gets every
test run in full. The registry only makes the NEXT hunt smarter, never
shorter.

## Target-type keyword lookup (how the registry actually gets read)

Immediately after Phase 1 fingerprint/recon tells you the stack (not
before -- guessing keywords blind wastes context), match recon signals to
keywords and load only the matching classes:

| Recon signal | Keywords | Loads |
|---|---|---|
| Laravel / `_ignition` / debug page | `ignition\|debug\|verbose 500\|stack trace` | Classes 1, 5 |
| Login / OTP / verify / reset flow | `OTP\|verify\|reset oracle\|enum` | Classes 2, 15 |
| `/show/{id}`, `/wallet`, sequential ints | `IDOR\|seq-sweep\|sequential` | Class 3 |
| Payment / checkout / cart / amount | `payment\|amount\|TEST key\|replay` | Class 4 |
| SPA / Vite / JS bundles / Next.js | `secrets\|VITE_\|bundle\|client_secret` | Class 9 |
| WordPress / `/wp-json` / xmlrpc | `wp-json\|wordpress\|xmlrpc\|user enum` | Class 12 |
| Moodle / CMS / plugins / `upgrade.txt` | `EOL\|CVE\|upgrade.txt` | Class 13 |
| Spring Boot / actuator / `/health` | `actuator\|spring\|heapdump\|jolokia` | Class 11 |
| Vault / HashiCorp / `/v1/sys` | `vault\|consul\|/v1/sys` | Class 14 |
| Staging / preprod / qa / UAT subdomains | `staging\|UAT\|preprod` | Class 8 |
| CNAME records / subdomain enum results | `takeover\|CNAME\|Amplify\|SAN` | Class 7 |
| Reflected params / search echo / iframe | `XSS\|onload\|concat\|CSP\|sandbox` | Class 6 |
| API with auth headers / OPTIONS preflight | `CORS\|origin reflection\|credentials` | Class 10 |
| Version banners / info-disclosure surface | `info-disclosure\|one-liner\|server header` | (archive) |
| Any target, always | `TOOLS / SCRIPTS` + `Open items` | toolchain + unfinished threads |

Rules:

- Match by tech stack, never by target name -- the same stack on a new
  domain gets the same confirmed techniques.
- Multiple signals -> union of keywords, more classes load.
- Nothing matches (a fresh stack, a novel framework) -> load only
  TOOLS/SCRIPTS + Open items and explore fresh: the new stack has no
  prior class yet, which is exactly what the write-back rule will create.
- The archive (older, single-target-confirmed entries, once the active
  registry is rotated) is read exactly like the active registry -- never
  loaded whole, always matched by keyword. It never expires; only its
  load is on-demand.
