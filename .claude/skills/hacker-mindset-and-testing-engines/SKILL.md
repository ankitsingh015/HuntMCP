---
name: hacker-mindset-and-testing-engines
description: General manual-testing mindset and reasoning "engines" (memory, response-analysis, attack-chaining, payload-mutation, application-mapping, data-flow, role-comparison, anomaly-detection) that apply across every vuln class, not just one. Converted from master-pentest-prompt.md Phase 9.5. Use throughout an engagement, not just at one phase -- this is how to think while testing, not a specific technique list.
---

# Hacker mindset & dynamic engines (manual, not scanner)

## When to use

Throughout the entire engagement. This isn't a phase to run once --
apply these reasoning patterns to every other skill/phase, since
automation finds what everyone already found and manual reasoning is
what finds the harder bugs.

## Manual hacking mindset

Read responses like documents: field names, JSON shape, what's absent.
Map the application like a building *before* attacking it. Every feature
that does more than one thing is 2+ attack surfaces (an image resize
feature is also potential ImageMagick CVEs; a PDF export is also a
headless browser, which is also potential SSRF; a search that emails on
no-result is also an email-header-injection point).

Follow application memory: input set in step 1 that reappears in step 4
is an injectable path (a classic stored-XSS candidate in logs or
reviews).

Test the transitions, not just the states: unauthenticated <->
authenticated, free <-> paid, pending <-> confirmed, pre- <-> post-
verification. Send requests that assume the transition already happened
(skip payment, hit a post-reset endpoint without resetting, call
post-verification APIs before verifying).

Study rejections: a fast rejection usually means client-side/WAF, a slow
one means it hit the DB, a partial one means partial sanitization. Use
rejection behavior to map the architecture.

Findings cluster: one IDOR means the pattern likely exists everywhere.
Pull the thread -- never stop at 1-2 findings while the surface is still
unexplored.

## The engines

- **Memory engine**: track every tested endpoint+param+payload, which
  payload->response behaviors worked, and every failure plus why. Reuse
  winning payloads across similar endpoints/params/structures. Assume a
  detected pattern (IDOR on `/api/user/ID`) exists elsewhere and
  enumerate aggressively.
- **Response analysis engine**: structure, reflected input, hidden
  fields, error/stack traces, timing, size, missing-vs-present fields,
  reflection points, conditional responses. A response that reveals logic
  should be exploited immediately; a response that changes should prompt
  "why did it change? auth? role? input?"
- **Attack chaining engine**: combine low-impact into high-impact --
  XSS + localStorage token -> ATO; CORS + credentials -> exfiltration;
  IDOR + sensitive data -> compromise; open redirect + OAuth -> token
  theft; SSRF -> internal service -> RCE. Finding one vuln should trigger
  hunting for a second to chain it with.
- **Payload mutation engine**: adapt to the tech stack, context, and
  filters actually observed. If blocked, try encoding (URL/double/
  unicode), case variation, obfuscation, alternative syntax -- generate
  payloads dynamically for what's actually in front of you, not from a
  static list alone.
- **Application mapping engine**: build a mental model of features,
  flows, roles, dependencies, entry points, critical actions, and state
  transitions. Don't test randomly -- test from understanding.
- **Data flow engine**: track where input goes -- stored, rendered, sent
  onward, logged, emailed. If it reappears later, that's a stored-XSS,
  injection, or leakage candidate.
- **Aggressive discovery loop**: a bug found means assume similar bugs
  exist; expand horizontally (other endpoints) and vertically (same
  endpoint, deeper).
- **Developer mindset simulation**: infer the backend implementation;
  predict missing authz checks, reused insecure patterns, forgotten
  endpoints, exposed internal-only features. Ask "what did the developer
  assume would never happen?" then do exactly that.
- **Hidden attack surface engine**: undocumented params, alternate
  methods, versioned APIs, debug/staging endpoints, mobile routes,
  backup/legacy endpoints, feature flags. Add/remove/randomize params;
  fuzz names.
- **Type abuse engine**: string->array, array->object, negative/float/
  large numbers, boolean->string, null/undefined; JSON vs. form vs. query
  encoding; duplicated params; nested objects that bypass validation or
  trigger unexpected behavior.
- **Role comparison engine**: replay the same request as user A vs. user
  B vs. admin -> BAC/IDOR/BOLA/BFLA, privilege escalation (see the
  `access-control-and-idor` skill's two-account procedure).
- **Anomaly detection**: flag inconsistent responses, unexpected fields,
  partial failures, timing differences, silent success. Investigate every
  anomaly deeply rather than dismissing it.
- **Self-review engine**: after testing, ask "what did I miss?"; revisit
  critical endpoints/params/partially-tested flows from a different
  angle.
- **Pattern expansion**: an IDOR on `/api/user/ID` should prompt testing
  `/api/order/ID`, `/api/file/ID` -- apply the root-cause pattern across
  every similar feature.
- **Signal over noise**: do not report theoretical, low-confidence, or
  non-exploitable issues. Only confirmed vulns or strong evidence with
  real impact -- think like a strict triager (this is the same discipline
  exploit-agent's Phase 1.5 rationalizations-to-reject check enforces
  structurally).

## Form handling

Every form is an attack surface. Fully map each one (action, method,
input names, hidden fields, CSRF tokens, defaults, client-side
validation, field dependencies), then test both normal and adversarial
submission. A registration form present means create an account and
attack it; a login form present means the same. Break both as hard as
possible.

## Credential usage rules

Authenticate as soon as possible and test the authenticated surface too.
With 2+ roles available, compare behavior for horizontal and vertical
escalation and missing authz (see `access-control-and-idor`). If a
session expires mid-test, re-authenticate rather than treating the
expiry itself as a finding.
