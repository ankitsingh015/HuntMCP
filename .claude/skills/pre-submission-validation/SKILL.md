---
name: pre-submission-validation
description: Final report-worthiness and evidence-hygiene gate for a CONFIRMED finding -- "should this be reported at all" (real issue vs expected behavior, real vs theoretical impact, already publicly known, minimal/reproducible PoC, would a reasonable triager accept it) plus PII/credential/session-token redaction before evidence goes in a report. Use right before report-agent drafts a finding -- this is the last gate before submission, not a substitute for exploit-agent's own confirmation logic.
---

# Pre-submission validation

## When to use / when not to use

Use this once per finding, at the handoff point between exploit-agent and
report-agent (`.claude/agents/report-agent.md`) -- after a finding is
CONFIRMED with a confidence tag and evidence attached, before it becomes a
report section. Not during recon, scanning, or exploit-agent's own
validation work.

**This is not a rerun of exploit-agent's Phase 1.5.** By the time a finding
reaches this gate, "is this technically real" is already answered --
CONFIRMED status, a reproduced proof capsule, evidence attached via
`case-mcp add_evidence`, and a HIGH/MEDIUM confidence tag are all
prerequisites `exploit-agent.md` already enforces (see its rationalizations-
to-reject checklist: reflected-vs-executed XSS, tool-flagged-vs-manually-
reproduced, URL-accepts-a-URL-vs-confirmed-SSRF, different-user-ID-vs-actual-
IDOR). Re-litigating that here is wasted work and, worse, gives a false
sense that two independent gates checked the same thing when only one
actually did. This skill asks a different pair of questions instead:
*given that it's real, should it be reported, and is the evidence about to
go in front of a human triager clean.*

It's also not `mcp-servers/dedupe_check.py`. That check is a fast,
engagement-scoped exact-match: has this precise
`vuln_class+endpoint+parameter` fingerprint already been confirmed earlier
in *this* engagement (catching two scan passes surfacing the same bug).
This skill's "already known" question below is a different, broader check
that a hash lookup can't do: is this already publicly documented,
acknowledged, or accepted behavior *for this program specifically* --
which requires actually looking at disclosed reports and docs, not
comparing fingerprints against your own prior work.

## Part 1 -- Should this be reported at all

Five questions, run in order on every CONFIRMED finding before report-agent
touches it. A "no" answer kills or downgrades the finding -- write the
reason into the finding's notes and push it through `lessons-mcp
append_lesson(...)` the same way exploit-agent does for a CLOSED-FP, so the
registry learns what NOT to report even when the technical reproduction
was solid. Don't silently drop a killed finding; a documented kill is what
stops the next engagement from re-discovering and re-validating the same
dead end.

### Q1: Is this an actual security issue, or expected/intended behavior?

A confirmed reproduction proves the *mechanism* works, not that the
mechanism is a bug. "Admin can do X" is centralization, not a
vulnerability, on almost every program. A field returning more data than
you expected is only a finding if that data is actually sensitive and
actually crosses a trust boundary -- not because the response was larger
than you assumed. If the behavior is documented in the target's API docs,
changelog, or is the obvious consequence of a role the account legitimately
holds, this isn't a security issue -- kill it here, before it costs
report-agent a write-up.

### Q2: Is the impact real, or only theoretical?

Exploit-agent's confidence tag already tells you whether the *reproduction*
required judgment (MEDIUM) or was clean and deterministic (HIGH) -- that's
a different axis from whether the *impact* is demonstrated or inferred.
A HIGH-confidence reproduction can still have a theoretical impact: "the
parameter accepts a URL" is not "SSRF reached an internal service,"
"sqlmap flagged time-based blind" is not "data was exfiltrated," "the
payload appears in the response" is not "it executed." If exploit-agent's
proof capsule stops at the primitive and doesn't show the attacker actually
walking away with something concrete (data read, state changed, session
hijacked), this finding's severity is inflated relative to what's proven --
downgrade to match what's actually demonstrated, don't kill outright if the
primitive itself is real and reportable at a lower severity.

### Q3: Is this already publicly known, documented, or previously disclosed for this program?

Check before writing a duplicate report against a program that will just
close it as informative or known-issue:

- `mcp__writeup-mcp`'s disclosed-report search (`disclosed_reports.py`-
  backed) for this program + this vuln class + this endpoint pattern.
- The target's own changelog / API docs / security.txt for an
  acknowledgment of this exact behavior.
- `mcp__hackerone-mcp`'s scope-sync data, if this engagement already
  pulled it, for a self-duplicate flag.

This is deliberately separate from `dedupe_check.py` -- that script answers
"did I confirm this exact fingerprint earlier this engagement" from local
state; this question answers "does the program already know about this,"
which needs an actual lookup against external/historical data, not a hash
comparison.

### Q4: Is the PoC minimal and reproducible by someone who isn't you?

Exploit-agent's proof capsule requirement (an exact curl command or
request/response pair, attached before CONFIRMED is granted) guarantees a
capsule *exists*. It doesn't guarantee the capsule is *minimal* -- a proof
capsule padded with unrelated headers, cookies from a half-finished chain
attempt, or steps that only worked because of leftover session state from
earlier testing will cost the triager time and cost you credibility. Before
handoff, re-read the capsule as if you'd never seen the target: can someone
follow these exact steps, in this order, from a fresh session, and land the
same result? If not, trim it or re-capture it now, not after report-agent
has already built a report section around the messy version.

### Q5: Would a reasonable triager accept this, or is it noise?

The honest gut-check after Q1-Q4 pass individually: does this finding, as
it now stands, actually move the needle for the program, or is it the kind
of submission that gets closed as informative regardless of how correctly
it was reproduced (missing security headers with no PoC of exploitation,
self-XSS with no chain, an open redirect with no OAuth token theft
demonstrated, rate-limiting absence on a non-critical form)? This mirrors
`report-agent.md`'s own triager-honesty rule ("does this finding, as
written, increase acceptance odds?") -- the difference is this question
gets asked *before* report-agent invests time writing the section, not
after.

**Optional escalation:** if Q2 or Q5's answer is genuinely close, this is
a good candidate for `mcp__second-opinion-mcp` `get_second_opinion(...)`
-- the same mechanism exploit-agent uses on MEDIUM-confidence technical
calls applies just as well to a business-impact/acceptance judgment call,
since a model with no stake in having found the bug is less likely to
share your motivated reasoning about whether it's worth reporting. Not
required for every finding; treat the verdict as another input, not an
override.

## Part 2 -- Evidence hygiene before it reaches a report

Exploit-agent attaches evidence to a finding via `case-mcp add_evidence`
(`request`/`response`/`callback`/`screenshot`/`dns`/`source`/`metadata`)
before CONFIRMED is granted. That evidence proves the bug to *you*. Before
any of it is copied into the report body report-agent writes to
`data/reports/`, sweep it for anything that shouldn't leave your machine.

### What must be redacted

- Session cookie values (`session`, `sid`, `auth`, `__Secure-*`, and any
  target-specific name) in request/response dumps and screenshots.
- `Authorization` header values -- Bearer tokens, JWTs, API keys.
- CSRF tokens bound to your session.
- Any other user's real PII appearing in a response body or screenshot --
  name, email, phone, physical address, date of birth, government ID,
  profile photo/face -- even when the whole point of the evidence is
  proving cross-account access. Redact the *values*, keep the *fact* that
  the field was returned (`"email": "<REDACTED>"` still proves the leak).

### What's safe to leave visible

Your own test account's identifiers, trace/request IDs, response field
names and shapes, the endpoint URL and method, server/framework headers.
These are what let a triager actually correlate and reproduce -- stripping
them along with the sensitive values makes the report harder to verify for
no security benefit.

### Never use a real third party as your PoC victim

This is a different rule from redaction, and it comes first: redaction
hides sensitive data you already captured, but the better fix is not
capturing real victim data at all when it's avoidable. If a finding needs
a second account to demonstrate cross-account access (IDOR, BOLA, broken
tenant isolation), use a second account *you* control for the engagement,
not a real user's live account or data surfaced during recon. If a real
second account genuinely can't be avoided (e.g. the flaw only reproduces
against pre-existing data), redact every identifying value from that
account's data before it goes anywhere near the report.

### Pre-attachment sweep

Before report-agent's output file is written, for each piece of evidence
being copied in:

```
[ ] Cookie / Set-Cookie / Authorization values replaced with <REDACTED>
[ ] Any other-user PII in the response body masked, field name kept
[ ] Screenshot has no visible cookie/storage/devtools panel in frame
[ ] No "copy as curl" output with live credentials visible
[ ] Test-account credentials shown are ones you're prepared to rotate
    once this report is submitted -- if not, don't show them
```

If a sweep finds something that needs fixing, fix the evidence file
`case-mcp` holds for that finding before report-agent reads it, not the
report text after the fact -- otherwise the raw evidence still exists
unredacted elsewhere in the case data and the next reader of that finding
inherits the same leak.

## After this gate

Findings that pass both parts go to report-agent unchanged. Findings
killed or downgraded here get the same lessons-registry treatment as an
exploit-agent CLOSED-FP -- record why, so the pattern is recognized faster
next time instead of being re-validated from scratch on a future target or
engagement.
