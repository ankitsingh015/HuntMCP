---
name: writing-great-skills
description: Conventions for writing HuntMCP's own Claude Code Skills, especially the ongoing conversion of knowledge/master-pentest-prompt.md's [PHASE N] sections into skills/<topic>/SKILL.md files. Use this before creating or editing any file under skills/.
---

# Writing HuntMCP's skills

This is the meta-skill referenced by `ARCHITECTURE.md`'s Phase 2.8 backlog
("Methodology as Claude Code Skills") — write it before converting phases,
not after, so all ~39 resulting skill files are consistent instead of each
looking different depending on when it was written.

## Why this conversion exists

`knowledge/master-pentest-prompt.md` is a single ~1800-line file with 59
`[PHASE N]`-indexed sections that agents currently reach with `grep`. That
still works — the OpenCode harness keeps using it exactly this way, since
Skills are a Claude-Code-native feature with no OpenCode equivalent — but
in Claude Code, a proper Skill lets the agent find the right technique by
matching the skill's `description` against what it's currently doing,
instead of the agent having to already know the right grep pattern.

**`master-pentest-prompt.md` stays the source of truth for OpenCode and is
never deleted.** `skills/` is an additional, Claude-Code-only front door
onto the same technique content — converting a phase means writing a new
skill file, not removing the phase from the master prompt.

## One skill = one coherent testing concern, not one phase

Some `[PHASE N]` sections are one clean vuln-class technique (Phase 5
SSRF, Phase 11 XXE) and become one skill each. Others are thin
process/meta phases that only make sense grouped with their neighbors
(Phase 0.1 mode selection + 0.2 goal focus + 0.5 fingerprint + 0.9 ROI
order are all "how to start an engagement," not four separate skills).
Group by what a reader would actually reach for, not by mechanically
preserving the phase numbering.

## Required frontmatter

```yaml
---
name: kebab-case-matching-the-directory-name
description: One or two sentences. State what it covers AND when to reach for it -- this is the only text Claude sees before deciding whether to load the skill, so a vague description ("XSS testing techniques") is much weaker than a specific one ("Reflected/stored/DOM/blind/mutation XSS testing techniques and bypass payloads. Use when a parameter reflects user input in an HTML/JS/attribute context.").
---
```

No other frontmatter fields are required. Don't invent extra ones without
a concrete reason.

## Body structure

1. **When to use / when not to use** — a short section right after the
   title. Skills that skip this get loaded when they're not actually
   relevant, wasting the agent's context on the wrong technique.
2. **The technique content itself** — this is usually lifted near-verbatim
   from the corresponding `[PHASE N]` section(s), reformatted for
   readability, not rewritten from scratch. The source content was already
   reviewed and battle-tested across real engagements; the conversion's
   job is better packaging, not new content, unless something is
   genuinely missing.
3. **Reference back**, not duplication: if a technique needs a payload
   list already tracked in `knowledge/payloads/<class>.txt`, link to that
   file rather than copying its contents into the skill.

## What NOT to carry over

- **No resume-points / checkpoint-resume mechanic.** The source material
  references a `RESUME-POINT.md` pattern (write one exact next action
  when an engagement ends incomplete) inspired by `N0RMXL Framework`'s
  "checkpoint resume" — this was flagged as unwanted and should not appear
  in any converted skill, including whichever skill inherits that
  section's other content.
- No content invented for the conversion that wasn't in the source phase
  or an existing project file — if a skill feels thin, that's a signal to
  question whether it should be merged into a neighboring skill, not
  padded with generic advice.

## Verifying a conversion didn't lose content

Before considering a phase "converted," confirm every concrete technique,
payload example, and tool name that appeared in the source `[PHASE N]`
section(s) is still present somewhere in the new skill file. A shorter,
better-organized skill is the goal; a skill that's shorter because
something was silently dropped is not.

## Skill-with-eval-file (when it applies)

For a skill that's more than a static reference doc — one with a
non-obvious decision procedure a future edit could quietly break — add a
small `evals/evals.json` alongside `SKILL.md`: a handful of
input/expected-behavior pairs a human can eyeball after an edit. Most of
the phase-conversion skills are reference material and don't need this;
reach for it on skills like the WAF-bypass decision tree or the
low-hanging-fruit priority order, where getting the sequence wrong has a
real cost.
