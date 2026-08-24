---
name: autonomous-research-loops
description: Structured autonomous-research methodology for when standard phases stop yielding findings -- six research loops (technology-driven, disclosed-report mining, research-blog learning, behavior-driven fuzzing, passive asset intelligence, business-logic/privilege attacks) plus a hypothesis-driven ideate/evaluate/weaponize/cascade research cycle modeled on Kettle's HTTP Terminator approach. Converted from master-pentest-prompt.md Phases 32.5 and 32.6. Use when all standard phases are exhausted with no new findings across two full passes, or when a technology has no matching playbook.
---

# Autonomous expansion mode & AI-augmented research

## When to use

Trigger conditions: all standard phases/skills have run with no new
findings across two full passes; a fingerprinted technology has no
matching playbook; a partial finding needs a custom exploit built for
it; unusual behavior suggests a vuln class nothing else covers. This is
the engagement's escape hatch from checklist-driven testing into
genuinely open-ended research -- not a replacement for the phased
skills, a continuation once they're exhausted.

Run 3 full loops from the six below; each loop must end with at least
one new curl test actually executed against the target, not just
research read. Stop only when 3 consecutive loops yield nothing new or
the Tier-2 tool-call budget (`budget_guard.py`) is hit.

## The six research loops

**Loop A -- technology-driven research**: for every fingerprinted
technology, search `"<tech> <version> vulnerability <year>"`, `"<tech>
CVE exploit writeup"`, `"site:hackerone.com <framework>"`,
`"site:medium.com <framework> bug bounty"`,
`"site:portswigger.net/research <tech>"`. Fetch the best article in
full, extract the exact technique, adapt it to the target, test it with
curl, log the result. Never read without acting on it.

**Loop B -- disclosed report mining**: search `"hackerone disclosed
reports <company>"`, `"site:hackerone.com/reports <tech>"`,
`"site:medium.com <company> bug bounty"`. For each report found, extract
the specific pattern (parameter type, endpoint shape, triggering
behavior) and hunt the same pattern on the current target. If a bug hit
API v1, test v2 too.

**Loop C -- research-blog learning**, in priority order: PortSwigger
(web-security academy + research), HackerOne disclosed reports,
Assetnote, ProjectDiscovery blog, Bishop Fox, WatchTowr Labs, SRC:INC,
Intigriti Bug Bytes, GitHub CVE PoCs, Medium bug-bounty tags. Read,
extract the technique, then implement it manually against the live
target (replicate Burp-only techniques by hand in curl).

**Loop D -- behavior-driven fuzzing**:
- Response-time anomaly: baseline first, then `SLEEP(5)`/`WAITFOR
  DELAY`/`pg_sleep`/`Thread.sleep`/MongoDB `$where` sleep. A delta over
  4s against baseline signals an injection point.
- Undocumented params: POST a body with every plausible hidden flag at
  once (`debug`, `verbose`, `test`, `admin`, `internal`, `preview`,
  `bypass`, `override`, `dev`, `force`, all `true`); any response change
  reveals an undocumented param worth testing fully.
- Type confusion: string->int/array/object, null, negative, zero, an
  oversized 10k-char string, float, unicode, empty, whitespace-only.
  Document any 500/stack-trace/behavior change.
- HTTP verb tampering on every endpoint (GET/POST/PUT/PATCH/DELETE/
  OPTIONS/HEAD/TRACE/CONNECT) -- flag any 200 where 405 was expected,
  and flag data differences per method.

**Loop E -- passive asset intelligence**:
- JS deep dive: grep bundles for staging/dev/internal/qa/test hostnames,
  S3 buckets, hardcoded creds, client-controlled feature flags
  (`isAdmin=false` sent from the client), commented-out endpoints,
  `postMessage` handlers, DOM sinks, exposed source maps.
- Subdomain intel via search: `site:target.com`, `inurl:api|admin|
  internal|staging`, `filetype:pdf|xlsx|docx`.
- Wayback Machine: fetch `web.archive.org/web/*/target.com/api/*` --
  old endpoints often lack current patches, so test deleted endpoints
  anyway rather than assuming they're gone.
- GitHub recon: `"site:github.com <domain> api key|secret|token"`,
  config/env/credential file searches, Pastebin/Gist for company
  keywords; validate any leaked creds directly against the live API.

**Loop F -- business logic & privilege attacks** (the hall-of-fame
category):
- Price/quantity abuse: negative quantity, zero price, `0.001`, integer
  overflow, currency-swap tricks, discount/coupon stacking, gift-card
  reuse, refund abuse.
- Workflow step-skipping: map every multi-step flow (checkout,
  onboarding, 2FA, verification, plan upgrade) and call step N+2
  directly without completing step N.
- Mass assignment: send read-only fields back in POST/PUT (`role:
  admin`, `isAdmin: true`, `plan: enterprise`), including inside nested
  objects.
- Cross-tenant/org access: with 2 accounts in 2 separate orgs, use Org
  B's session to access Org A's resources (projects, members, invoices)
  across numeric, UUID, and slug identifiers -- a hit here is a critical
  tenant-isolation bug.
- Rate limit & brute-force: OTP brute force (10 codes with no lockout is
  brute-forceable), reset-token brute force (especially numeric/short
  tokens), login brute force -- always document the exact evidence.

## AI-augmented autonomous research (the HTTP Terminator cycle)

Model any genuinely novel-attack hunt on this four-stage cycle, credited
to Kettle's HTTP Terminator research approach:

1. **Ideation**: generate hypotheses (novel desync classes, parser
   differentials, cache-key gaps, framework-specific quirks) as
   structured candidates, scored by impact x likelihood x test-cost.
   Pull new idea sources from recent PortSwigger research, framework
   release notes, CVE diffs, and HackerOne disclosed reports for the
   same stack.
2. **Evaluation**: for each hypothesis, build the minimal single-request
   probe that discriminates it, run it against the live target, and
   record the exact request, response, and diff against baseline.
3. **Weaponization**: on any positive signal, chain it into real impact
   (smuggling -> request-queue poisoning/cache poison -> stored XSS;
   CRLF desync -> request splitting -> victim session hijack; internal
   cache poison -> account-agnostic page takeover) and re-test
   end-to-end with a real browser where possible.
4. **Cascade**: after one success, generate the next family of
   candidates from it -- a 0.CL win implies probing CL.0/H2.TE next; a
   cache-key gap implies probing unkeyed header families; a parser
   differential implies probing the mirror-image discrepancy. Never stop
   testing at the first hit.

**Budget discipline**: hard-cap probes per hypothesis (default 20); each
loop must end with at least one logged curl test; stop when 3
consecutive loops yield no new signal. Log every candidate, result, and
decision into the report. Tooling: Burp's HTTP Request Smuggler v3.0 /
HTTP Terminator output can feed hypothesis candidates directly; feed
every discovered token/param back into the next loop automatically.
