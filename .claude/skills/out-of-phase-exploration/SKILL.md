---
name: out-of-phase-exploration
description: The standing background mandate that nothing gets skipped just because no phase or skill named it -- explore every discovered surface, follow every anomalous lead up to 4 levels deep, exploit rather than just note, invent new tests when no playbook matches, and only consider an engagement complete after two full passes of every surface (phased and unphased) yield nothing new. Converted from master-pentest-prompt.md Phase 37. Use continuously, in parallel with every other skill/phase, for the entire engagement.
---

# Out-of-phase exploration -- zero stone unturned

## When to use

Continuously, in parallel with every other skill or phase, for the
entire engagement -- not a phase to run once and move past. The phased
skills are the base map, not the whole territory; anything they don't
name still gets tested.

## Explore everything

Any host, path, param, header, cookie, token, file, port, protocol,
tech, behavior, error, feature, transition, config, or version string
that surfaces during testing gets a test pass, even when no skill or
phase specifically names it. "Not in the phases" is never a reason to
skip something.

## Follow every thread

Any field, header, error text, response difference, hidden param, or
odd behavior is a lead. Chase it up to 4 levels deep -- if it looks
unusual, it is the attack surface, not a distraction from it.

## Test every discovery

For each newly discovered endpoint, file, param, or feature, run the
full triage ladder -- injection, authorization, information leak,
business logic, method tampering, encoding bypass, chaining -- even when
the phases that led you there only covered a subset of that ladder.
Apply payloads from other skills to surfaces those skills never
explicitly listed.

## Exploit, don't just note

Every candidate finding gets a real exploitation attempt with at least
3 distinct bypass tries before being written off. Document every
ruled-out lead so it's never re-tested from scratch.

## Invent new tests

When something has no matching playbook anywhere in the skill set,
design a brand-new probe and run it. On any positive signal, write the
technique into the Lessons Registry (see the `knowledge-loading` skill)
and treat it as a candidate for a new skill, rather than a one-off. Never
stop testing just because the existing skills ran out of specific
guidance -- extend from what's actually in front of you on the target.

## Cross-check the unexpected

Unusual responses -- a 200 where 405 was expected, a silent success, an
extra field in the response, an empty-body 500, a redirect that behaves
differently than expected, a timing anomaly -- get investigated to root
cause. Never dismissed as noise.

## Sweep all parallel surfaces

Even when no phase references them directly: mobile/API-only features,
admin tooling, feature flags, data exports, PDF/email/print rendering
pipelines, third-party integrations and callback endpoints, async
workers, queues, WebSockets, and anything the UI hides behind
client-side JS.

## End condition

An engagement is only complete when two full passes of every discovered
surface -- both phased and unphased -- yield nothing new. Any surface
still holding untested combinations keeps the engagement open.

## No-skip guard

Nothing in this skill, in any other skill, or in the Lessons Registry
ever authorizes skipping a test on a fresh target. Ruled-out/negative
results apply only to the specific target that produced them -- every
new target gets the full test run regardless of what a prior engagement
found.
