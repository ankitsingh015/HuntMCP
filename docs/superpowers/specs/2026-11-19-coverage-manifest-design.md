# Coverage Manifest — surface × vuln-class breadth gate — Design

Date: 2026-11-19
Status: Draft (awaiting approval)
Size: Project
Issue: #159 (depends on #161 surface-map, now wired; feeds from #164 later)

## Intent and the why

Operator-/agent-driven engagements silently collapse to a narrow subset of
vuln classes (observed live in the bentley-com engagement: heavy
access-control/IDOR focus, with XSS/SQLi/SSRF/CVE/open-redirect skipped unless
the human prompted for each). The "comprehensive methodology" that is supposed
to run does not actually run — breadth is optional, so it gets dropped.

`coverage_signal.py` already reports which `(endpoint × vuln_class)` pairs were
tested (evidence-backed, anti-gaming), but its own docstring states the gap:
it is "what we tried, not what fraction of what exists — there is no
independent endpoint inventory to divide by." The surface-map
(`surface_map.py`, wired into Claude Code by #161) **is** that missing
inventory: a per-engagement model of discovered nodes
(host/endpoint/feature/flow/tech), each with a signature and test state.

**This design bridges the two** into a coverage *manifest*: for each
discovered node × its required vuln-class battery, is that cell **covered**
(evidence-backed finding exists), **N/A** (explicitly exempted with a reason),
or **open**? And a **gate**: a surface is not "exhausted" while any cell is
open. Breadth becomes enforced, not optional.

## Goals

1. A per-node **required vuln-class battery**: a fixed, reviewable map keyed on
   node kind/signature, UNIONed with the classes the node's bound precedent
   surfaces.
2. A derived **manifest**: each discovered surface node × its required classes
   → `{covered | na | open}`, where `covered` reuses `coverage_signal`'s
   evidence-backed bar (≥1 evidence row for an `(endpoint, vuln_class)`
   finding), and `na` requires a stored reason.
3. An **exhaustion gate** tool: reports NOT-exhausted while any cell is `open`,
   lists the open `(node, class)` gaps, and is wired into huntbrain's reporting
   phase so the engagement doesn't declare done with open cells.
4. A way to mark a cell **N/A-with-reason** (the escape valve), stored on the
   surface-map node, auditable.
5. Tests, and honest limitations stated in-module (repo convention).

## Non-goals

- The 4 named vuln-class checks (CVE-2025-29927, CVE-2024-23331, broken-delete,
  cancel-without-revoke) — deferred to a separate follow-up (tactical
  detections, orthogonal to the breadth mechanism). Once they exist as
  vuln-class tags, the manifest requires them automatically.
- Page/UI as the unit of coverage — that is #164; the manifest keys on
  surface-map nodes as they are today (endpoint-level), and #164 later makes
  "page+inputs" a node kind feeding the same manifest, no manifest change
  needed.
- Replacing `coverage_signal.py` / `compute_coverage_matrix` — this consumes
  them, it does not redefine them.
- A true "fraction of the whole attack surface" claim — see Limitations.

## Constraints

- No new network, scope, or budget interaction — the manifest is offline,
  read-only over `surface_map` (local JSON) + `case_store` (read-only export),
  same pattern as `coverage_signal.py`.
- Reuse the anti-gaming "covered = evidence-backed" bar; never weaken it to a
  bare-finding or self-asserted flag (`.claude/rules/benchmarks.md`: a cost/
  efficiency change must not reduce required security quality).
- Protected-benchmark methodology untouched — this is a wiring/coverage
  instrument, distinct from the security-detection benchmarks (#163 family).
- Honest limits stated in-module, not silently overclaimed (repo convention,
  cf. `coverage_signal.py`'s own boundary note).

## Approaches considered

1. **Extend the surface-map node schema with a stored per-node coverage dict**
   (`{vuln_class: state}`) the agent writes directly. Rejected as the covered
   source: a self-written status flag is exactly the gameable signal
   `compute_coverage_matrix` was built to avoid (an agent sets "tested" without
   testing). Covered-ness must be *derived* from evidence, not stored.
2. **Derive the manifest by joining `surface_map` (inventory) with
   `coverage_signal`/`case_store` (evidence-backed tested pairs) at query
   time** — covered-ness comes from evidence, never a flag. Store on the node
   only the two things that *aren't* derivable: the N/A-with-reason exemptions
   (an operator/agent decision) and, optionally, a cached battery. **Chosen.**
3. **Advisory-only report** (no gate). Rejected: `coverage_signal` is already
   advisory and read-only, and the engagement still tunneled — advisory is the
   status quo that failed.

Chosen: **#2**, hard gate with N/A-with-reason escape valve, battery =
fixed-per-kind UNION precedent (all three decided with the maintainer
2026-11-19).

## Design

### 1. Required vuln-class battery (`coverage_manifest.py`, new module)

`required_classes(node) -> set[str]`:
- A module-level `BATTERY_BY_KIND: dict[str, set[str]]` — the fixed floor,
  keyed on node `kind` (and optionally a signature-prefix refinement). Initial
  map (reviewable, extendable in one place):
  - `endpoint` → `{xss, sqli, idor, access-control, ssrf, open-redirect, csrf}`
  - `feature`/`flow` → `{access-control, business-logic, auth, idor}`
  - `host` → `{info-disclosure, security-misconfig, subdomain-takeover}`
  - `tech` → `{known-cve}`
  (exact seed lists settled in the plan; names align with case_store
  `vuln_class` values already in use.)
- UNIONed with classes surfaced by the node's **bound precedent** (parse the
  node's stored `precedent` text for known vuln-class tags). A node with no
  precedent still gets the floor; precedent only widens, never narrows.

### 2. Manifest derivation (`compute_manifest(db_path, map_path) -> dict`)

Offline, read-only. For each node in the surface map, for each class in
`required_classes(node)`:
- **covered** iff `coverage_signal.compute_coverage_matrix` has a `covered=True`
  cell for this node's `(endpoint, vuln_class)` — i.e. ≥1 evidence-backed
  finding. (Reuse the existing function; do not re-derive the evidence rule.)
- **na** iff the node records an N/A exemption for this class (with reason).
- **open** otherwise.

Join key: the node's endpoint representation ↔ the finding's `endpoint`.
**Normalization is a first-class concern** (see Limitations / Review Focus):
define one `_normalize_endpoint()` used on both sides (lowercase host, strip
default ports, drop trailing slash, drop query/fragment) and test the join
against mismatched-but-equivalent forms.

Returns: per-node cells, `open_cells` (the gaps), counts, and
`exhausted: bool` (= no open cells).

### 3. N/A-with-reason (surface-map extension)

Add `surface_map.mark_na(node_id, vuln_class, reason)` — stores
`{vuln_class: reason}` under a new `na` field on the node (empty reason
rejected). Exposed as a `mark_na` tool on `surface-map-mcp`. Auditable: the
reason is retained and shown in the manifest.

### 4. The gate (tools on a manifest MCP surface)

Expose on `surface-map-mcp` (it already owns the map; keeps one coverage
surface):
- `coverage_status()` → the manifest summary + the list of open
  `(node, class)` cells, most-precedent-bound first.
- `is_exhausted()` → `False` with the open list while any cell is open; `True`
  only when every required cell is covered-or-N/A.

**`is_exhausted()` is a designed handoff seam, not an end-state.** Reaching it
means the *known battery* is covered — the entry point for the future
novel-discovery / zero-day ladder
([2026-11-19-novel-discovery-ladder-design.md](2026-11-19-novel-discovery-ladder-design.md),
Proposed, its own issue). #159 only guarantees the floor and leaves this seam;
it does not implement the ladder.

### 5. Engagement wiring (huntbrain)

huntbrain's loop already drives recon→scan→exploit and decides when a surface
is done. Add to its "before reporting / before declaring exhausted" step:
call `is_exhausted()`; while it returns False, treat the open cells as
remaining work (route each `(node, class)` to the owning specialist) rather
than proceeding to report. State plainly in the agent doc that an open cell is
unfinished work, and N/A requires a recorded reason — not a silent skip.

## Limitations (stated honestly, in-module)

- **Coverage ≠ security.** A fully-covered manifest means "every required
  class was tried with evidence," never "the target is clean." Framed as "what
  we tried," like `coverage_signal`.
- **Denominator is bounded by discovery.** The ratio is only as good as the
  surface-map inventory; under-discovery shows high coverage over a small
  surface (the same anti-gaming concern `coverage_signal.py` flagged). #164
  improves discovery; the limit is inherent.
- **The battery is the ceiling.** A class in neither the fixed map nor the
  node's precedent is never required — a blind spot. Precedent-union widens it;
  the map is reviewable/extendable; but you cannot require what you have not
  enumerated.
- **N/A is agent-assertable.** The gate forces a *recorded reason* per N/A and
  keeps covered-ness evidence-backed, so skipping is auditable and bare
  rubber-stamping is visible — but an LLM can still write a plausible reason.
  Irreducible; mitigated by auditability, not eliminated.
- **The gate is a tool signal, not a kernel-level block.** Like scope-gate it
  returns an authoritative verdict and huntbrain is instructed to honor it; it
  cannot physically force the model not to stop early. The evidence bar +
  N/A-reason make honoring it the path of least resistance and skipping
  auditable.

## What's left to the builder

- Final `BATTERY_BY_KIND` seed lists + exact `vuln_class` string alignment with
  `case_store`'s existing values (settle in the plan from a grep of real
  finding rows).
- The precedent→class tag parser (reuse any existing vuln-class token set).
- Exact `_normalize_endpoint()` rules, pinned by tests.
