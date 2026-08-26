---
name: bounty-report-writing
description: H1/Bugcrowd report title, tone, and severity-argument conventions -- VRT classification, how to counter a triager who downgrades severity or closes as OOS/duplicate/informative, and what separates a report that gets triaged in a day from one that sits for weeks. Distinct from methodology-framework-mapping (CVSS/CWE/MITRE/WSTG framework IDs) and report-agent.md (report structure/sections mechanics) -- this is platform tone and rebuttal knowledge. Use whenever report-agent is drafting the final writeup for HackerOne or Bugcrowd, especially when a finding's severity is disputable or a triager might push back.
---

# Bounty report writing -- platform tone and triager pushback

## When to use / when not to use

Use this while report-agent is writing the platform-facing version of a
CONFIRMED finding, right before a human submits it -- especially when the
severity is arguable or the finding resembles something a triager might
reflexively downgrade or close.

Not for:
- **Report structure/sections** (Summary, Steps to Reproduce, PoC, CVSS
  vector, Remediation) -- that's `report-agent.md`'s job, already fixed.
- **Mapping a finding to MITRE ATT&CK / PTES / WSTG / CWE / CISA KEV** --
  that's the `methodology-framework-mapping` skill.
- **Deciding whether a finding is real enough to report at all** -- that
  call already happened in exploit-agent's confirmation step; a finding
  reaching this skill is already confirmed, not a candidate.

This skill covers the part neither of those touch: how the same confirmed
finding, worded two different ways, gets accepted in a day at one severity
or argued down to Low a week later at the other.

## The rule under every sentence: prove it, don't hedge

Never write "could potentially," "could be used to," or "may allow."
Either the PoC demonstrates the impact or it doesn't. Hedged language is
the triager's own signal that a report is theoretical, and theoretical
reports get closed as Informative/N/A regardless of the underlying bug's
real severity.

```
BAD:  This vulnerability could potentially allow an attacker to access
      user data.

GOOD: An attacker can read any user's order history by changing the
      user_id parameter to the target's ID. Confirmed with two test
      accounts: attacker@test.com (ID 123) retrieved victim@test.com's
      (ID 456) orders, including shipping address and payment method
      last 4 digits.
```

If exploit-agent's proof capsule only supports the hedged version,
report the smaller, demonstrated claim -- "IDOR on /api/users/{uid}
reading email + role" -- not the larger, undemonstrated one -- "IDOR
chained to potential admin takeover." Downgrade the claim to match the
evidence; never split the difference with qualifying language.

## Title conventions, by platform

**HackerOne** rewards a title that states the impact in one line:

```
[Bug Class] in [exact endpoint] allows [attacker role] to [impact]
```

Good: `IDOR in /api/v2/invoices/{id} allows authenticated user to read
any customer's invoice data`

Bad: `IDOR vulnerability found`, `Broken access control`, `Security
issue in API` -- these tell the triager nothing and sort to the bottom
of a busy queue.

**Bugcrowd** rewards the same impact-first content but triagers there
also skim titles to pre-guess the VRT bucket, so lead with the asset:

```
[asset/endpoint] | [bug class] | [impact]
```

Good: `Unauthenticated SSRF on /preview?url= -> AWS metadata
[REDACTED_IP] reachable`

Same finding, title done badly, gets opened last in the queue; done
well, gets opened first. Queue position is triage speed.

## What a triager actually reads, in order

1. **Title** (~3 seconds) -- decides queue position.
2. **First paragraph / summary** (~15 seconds) -- decides whether they
   keep reading.
3. **The curl command or raw HTTP request block** (~30 seconds) --
   decides whether they believe it's real.
4. **Steps to reproduce** -- only if the first three were convincing.
5. **Everything else** -- generally only on a follow-up pass.

Front-load the report accordingly: the exact impact goes in sentence
one, not at the end of a narrative build-up. A triager who's convinced
by step 3 will rubber-stamp the rest; one who isn't, won't reach step 5
no matter how good the remediation section is.

## Tone: write to a person, not past one

- Say "I" -- you found it, own it. Never "the researcher" or passive
  voice ("it was observed that...").
- Skip the lecture. A triager knows what IDOR is; don't spend a
  paragraph defining it.
- Short paragraphs, numbered steps, no filler adjectives
  ("comprehensive," "seamless," "leverage") -- those read as
  AI-generated and get a report skimmed less carefully, not more.
- Keep the whole body under ~600 words. Triagers skim long reports;
  push detailed evidence into attachments instead of prose.

## VRT classification (Bugcrowd)

Bugcrowd requires picking one Vulnerability Rating Taxonomy node, and
its dropdown auto-suggests a severity bound to that node -- pick the
wrong node and the form silently proposes P4 for something that's
really P2. VRT defaults are not fixed constants: Bugcrowd revises the
schema across versions and individual programs can remap defaults, so
treat any P-value below as a typical baseline, not a promise -- always
read what the live form suggests for *this* program.

**Search hierarchy** -- try in this order, take the highest-severity
node that still accurately describes the bug:

1. The bug's primary class (`IDOR`, `XSS`, `SSRF`, `auth bypass`)
2. The data category exposed (`PII`, `sensitive data exposure`)
3. The control bypassed (`broken access control`, `authentication
   bypass`)
4. The endpoint type (`no rate limiting on form > login`)
5. The generic parent node (`Broken Access Control > Other`)

Never pick a higher-severity VRT node that doesn't actually describe
the bug just to inflate the default -- triagers reassign it and the
misrepresentation costs credibility on every future report. Pick the
most specific *accurate* node, then argue the severity explicitly (next
section) if the default still undersells it.

**Common mappings worth knowing:**

| Finding type | First-choice VRT | Fallback |
|---|---|---|
| ATO via missing 2FA on password change | Broken Auth & Session Mgmt -> 2FA/MFA -> Bypass | Broken Auth -> Authentication Bypass -> Other |
| Password oracle, no rate limit | Broken Auth -> Authentication Bypass -> Other | Server Security Misconfig -> No Rate Limiting on Form -> Login |
| GraphQL introspection/allowlist bypass | Server Security Misconfig -> Other (justify in body) | Broken Access Control -> Other |
| Handle -> real-name/PII enumeration | Sensitive Data Exposure -> PII Leakage / Disclosure of Secrets | Broken Access Control -> Other |
| Token brute-force (OTP, password reset) | Broken Auth -> Authentication Bypass -> Other | Server Security Misconfig -> No Rate Limiting on Action |

If nothing fits, pick the closest generic parent (`Server Security
Misconfiguration -> Other`) and open the description body with a "VRT
mapping note" explaining why that's the closest available match.

## Arguing for higher severity when a triager downgrades

Bugcrowd's own submission form states outright that the VRT-suggested
severity isn't guaranteed -- it has a manual **Technical Severity**
field for exactly this. HackerOne triagers set severity from your
report's evidence, not a dropdown, so the same argument works there as
plain prose in the Impact section.

**Override when:**
- The chained outcome is more severe than the standalone bug class.
- The VRT category is only approximate and its default example doesn't
  match this bug's actual impact.
- The program's own Focus Areas list this outcome at a higher severity
  than the VRT default.
- The data exposed is more sensitive than the VRT category's example
  use case (real name + SSN last 4, not just a username).

**Lead the body with a severity-request paragraph, not a footnote at
the end.** This is the first thing read and pre-empts the reflex close
that happens when a triager sees a low auto-suggested severity before
reading anything else:

```markdown
## Severity request -- please review before applying the VRT default

The closest VRT category is "[chosen VRT]," which defaults to
**P[N]**. I'm requesting evaluation at **P[M]** for the following
reasons:

1. **[Impact axis]** -- [specific reason this exceeds the VRT
   default's example case]
2. **[Impact axis]** -- [reason, ideally citing the program's own
   Focus Areas by name]
3. **[Impact axis]** -- [reason, e.g. comparing to the historical
   bounty payout for the same data class on this program]
```

**Counter specific downgrade language directly** rather than repeating
yourself louder:

| Triager says | Counter with |
|---|---|
| "Requires authentication" | "Only a free account -- no special role or permission is needed to reach this." |
| "Limited impact" | State the number: "[N] users affected / [PII type] exposed / $[amount] at risk," not "significant impact." |
| "Already known" | "Please share the report number -- I searched Hacktivity/the program's disclosed list and found none matching." |
| "By design" | "Please point me to the documentation stating this is intended behavior." |
| "Low severity/CVSS" | "The CVSS vector doesn't capture the business impact -- an attacker can extract [X] in [Y] minutes with no rate limiting." |
| "Not exploitable" | Paste the exact response showing the victim's data returned to the attacker's session -- let the evidence answer, not adjectives. |

**Don't over-claim.** Requesting P1/Critical on a finding that only
demonstrates a P3-level primitive burns trust for every report after
it. If a chain reaches Critical only by assuming a separately-unproven
step (a stolen cookie, a second bug), file the primitive at its real
standalone severity and argue the chain explicitly with cross-references
(below) rather than inflating the primitive itself.

## Common rejection reasons and how to preempt them

Write the rebuttal into the report *before* submission rather than
waiting for the triager to raise the objection -- a pre-empted
objection reads as thoroughness; the same argument made after a close
reads as arguing with the ref.

**"Rate limiting / brute-force on non-authentication endpoints" (OOS)**
-- when the endpoint IS the auth check (login, password verify, OTP
verify, token validate):

```markdown
## In-scope justification

The OOS list excludes rate-limiting issues on non-authentication
endpoints. `[endpoint]` accepts a password/token/OTP and returns
whether it matches the stored credential -- by definition this is an
authentication primitive, so the "non-authentication" qualifier does
not apply here.
```

**"Debug information disclosure"** -- when schema/introspection
exposure is really a control bypass (e.g. a GraphQL allowlist bypass
that unlocks the mutation surface, not just leaks the schema):

```markdown
## In-scope justification

This isn't a debug-information finding. The [allowlist/introspection
gate] acts as an authorization control on [surface]; the bypass turns
that gate into a no-op, making [N] mutations reachable that official
clients cannot invoke. The schema disclosure is incidental -- the
impact is mutation-surface unlock.
```

**"User enumeration, low-risk information"** -- when more than a
bare exists/doesn't-exist boolean leaks:

```markdown
## In-scope justification

The excluded category is enumeration of low-risk, insignificant
information. This leaks [full real name / phone / partial SSN], the
same data class the program's own account-recovery and fraud checks
rely on -- this is PII disclosure, not handle enumeration.
```

**"Theoretical / not exploitable"** -- when the PoC already shows the
full path end-to-end, restate that plainly rather than re-describing
the bug abstractly:

```markdown
## In-scope justification

This is exploitable end-to-end as shown in the PoC: [one-sentence
summary of the proven path]. The PoC includes [N HTTP request/response
pairs with cookies redacted] showing the attacker's session reading
[victim data]. The "theoretical, not demonstrably exploitable" clause
does not apply.
```

If you genuinely don't have end-to-end proof yet, that objection is
correct -- go get the missing evidence before filing rather than
writing a rebuttal for something that hasn't actually been shown.

**"Duplicate"** -- ask for the report number and check it against
Hacktivity or the program's own disclosed list rather than conceding;
"already known" is sometimes just asserted.

## Chained findings on Bugcrowd

Bugcrowd's rule is one fix, one bounty: file each independently-fixable
primitive as its own report at its own standalone severity, then file
the chain's full-impact narrative as a separate "consumer" report that
cross-references the primitives by submission UUID. File primitives
first (a UUID only exists once something is submitted), the consumer
second with the real UUIDs filled in, then edit each primitive
afterward to backfill the consumer's UUID -- Bugcrowd allows
post-submission body edits. Never claim each primitive is
independently Critical; the elevated severity belongs to the consumer
report alone.

## What makes a report triage fast vs. slow

**Fast:** impact-stated-in-sentence-one, a copy-paste-ready curl/HTTP
block, two distinct test accounts (not one account testing itself),
severity claim that matches the demonstrated impact exactly, and any
disputable severity pre-argued in a lead paragraph instead of left for
the triager to raise as a question.

**Slow:** vague titles, narrative build-up before the impact is
stated, hedged language ("could," "may," "seems to"), a severity
claim that doesn't match what the PoC shows (this reads as either
naive or dishonest and triggers a full re-review either way), missing
reproduction steps that force a round-trip question, and reports that
bury the real ask (a severity request, an OOS rebuttal) somewhere in
the middle instead of leading with it.

## Pre-submit check

Before a human submits, confirm: title follows the platform formula;
sentence one states the exact impact; the HTTP request/response block
is copy-paste ready; two accounts were used where the bug requires
cross-user proof; the severity claimed matches what's demonstrated,
not what's hoped for; no "could potentially" or "may allow" survives
anywhere in the body; and any anticipated pushback (downgrade, OOS,
duplicate) already has its rebuttal written in, not left for the
follow-up thread.
