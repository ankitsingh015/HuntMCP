# Novel-Discovery / Zero-Day Escalation Ladder — Design (Proposed)

Date: 2026-11-19
Status: **Proposed** — future capability, NOT part of the #159-164 batch.
Depends on: #159 coverage manifest (provides the `is_exhausted()` entry seam).
Built mostly from existing machinery (CEM, autonomous-research-loops,
second-opinion) — this is a wiring/orchestration design, not from scratch.

## Intent and the why

The coverage manifest (#159) guarantees **breadth over the KNOWN battery** — it
stops the engagement from tunneling on one vuln class. But a fixed battery +
precedent is, by construction, capped at *what has already been documented*:
"the battery is the ceiling" (see #159's Limitations). The maintainer's ask
(2026-11-19): after the rule book is covered, the agent should **also reason
beyond it** — toward novel / zero-day-shaped findings that no battery or
writeup names. Explicitly not a promise of guaranteed zero-day discovery; a
*structured search that raises the ceiling* and stops the agent from treating
"known battery covered" as "done".

## The escalation ladder

`is_exhausted()` (from #159 — the known battery is covered or N/A for every
node) is the **entry** to this ladder, not the end of the engagement. Per node,
climb only as far as needed; each tier logs to case-mcp (auditable + feeds
coverage).

### Tier 0 — Fixed playbooks (the battery)
#159's floor: fixed steps/payloads per vuln class. Breadth guarantee. *(done)*

### Tier 1 — Broader known rulebooks, dynamically
Beyond the hardcoded battery, pull additional **known-technique** sources
matched to the node's observed signature/tech:
- Existing: writeup RAG (`query_rag`, `search_disclosed_reports`), CVE/KEV
  (`fetch_cves`).
- New: tech-matched technique retrieval (research blogs / HackTricks / fresh
  nuclei-templates), signature-driven. Still *known* techniques, just broader
  than our own list.

### Tier 2 — Behavior-driven novel reasoning (the core "zero-day" engine)
When Tier 0+1 (all known) found nothing, stop matching named classes and reason
from the **target's own behavior**. Reuses existing case-mcp CEM machinery:
- `mine_invariants(target)` → what the app assumes is always true (order total
  positive; object belongs to one tenant; token expires in 1h); then
  systematically **try to violate** each. A violated-but-shouldn't-be invariant
  is a novel bug regardless of named class. **This is the core engine —
  target-specific, not signature-based.**
- CEM loop: `log_hypothesis → log_experiment → run_counterfactual` (does the
  suspected cause actually produce the effect?) + `order_experiments`
  (info-gain prioritization, P4-BM). + the `autonomous-research-loops` skill's
  ideate→evaluate→weaponize→cascade cycle.

### Tier 3 — Universal probes + novelty-triage + disclosure path
- **Universal probes** (behavior-agnostic, tried on every node; any anomaly
  becomes a hypothesis):
  - every param: type-confusion (array/null/nested/huge/unicode), encoding
    differential, parser/implementation differential (same request two ways,
    diff the handling)
  - every state-changing op: replay, reorder, skip-a-step (payment skip,
    one-time-token reuse)
  - every ownership-bound object: cross-identity replay (generalizes IDOR to
    "any ownership assumption")
  - economic invariants: quantity/price/balance negative/overflow, coupon
    stacking
  - time/race: any check-then-act → concurrent fire
- **Novelty detection** — NOT by signature: a finding is `potentially-novel`
  when it has **confirmed impact AND no known precedent** (nothing similar in
  the writeup RAG / CVE index). This is how "zero-day-shaped" is detected.
- **Disclosure / CVE path** — the system never assigns a CVE (vendor/CNA/human
  process) and never auto-submits (existing rule). It produces the
  **submission-ready package**: `minimize_poc` + `evidence_bundle` +
  `suggest_root_cause` + affected product/version. App-logic novel → strong
  bounty; product/version-level novel → CVE-submission candidate for a human.
- **Self-expanding toolkit:** when a wanted probe has no tool, log it to
  `tool_gaps.py` (the bounded first step already seeded in the repo).
- **Cross-model creativity:** `second-opinion-mcp` as a bounded
  hypothesis-generator ("what would a top researcher try here that we
  haven't?"), always disciplined by the CEM evidence/counterfactual gate.

## Honest limits (non-negotiable to state)

- **No guarantee.** No system finds novel/zero-day on demand. This raises
  probability and prevents stopping at the rule book; it is not a promise.
- **Hypothesis flood / false novelty.** Tier 2/3 generate many hypotheses, most
  false. The CEM evidence + `run_counterfactual` + second-opinion gate is
  mandatory (benchmark rule: zero false causal conclusions) so "novel!" isn't
  spammed. `potentially-novel` is a human-review flag, never a claim.
- **Scope/budget.** "Universal probes" must stay scope-gated and budget-bounded
  by the existing guards — "try everything" must never break rate limits or go
  out of scope.
- **Novelty detection can be wrong** (RAG/CVE index incompleteness → false
  "novel"), hence human-review-flag only.
- **Disclosure is human-gated.** No auto-submit; the system only prepares the
  package.

## Scope boundary with #159

- #159 ships the floor + the `is_exhausted()` seam. It must NOT be blocked on
  this ladder.
- This ladder is its own future issue (file as e.g. #166) with its own
  brainstorm→plan→TDD→review cycle. It is listed here so the #159 seam has a
  documented purpose and the idea is preserved.

## What's left (when this is picked up)

- Decide the per-node "novel pass done" bar (how much Tier 2/3 is "enough"
  before a node is truly exhausted vs. info-gain-bounded).
- The universal-probe set as real tools vs. agent-driven recipes.
- The novelty-triage threshold (what counts as "no precedent").
- The disclosure-package format.
