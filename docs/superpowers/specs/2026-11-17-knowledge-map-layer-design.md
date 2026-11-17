# Knowledge-Map Layer — Design

Date: 2026-11-17
Status: Draft (awaiting approval)
Size: Project (multi-phase)

## Intent and the why

Today a HuntMCP engagement leans too hard on the agent's own reasoning. The
agent definitions *do* tell each specialist to consult the writeup RAG and
load skills (`huntbrain.md` step 5/7, `scan-agent.md` step 2,
`exploit-agent`, `chain-planner` step 8), and the RAG is populated and
working (27,780 chunks; a test query returns on-point real reports). But in
practice these consults get **skipped**: they are one buried line in a
150-line agent file, nothing forces them, and when the agent *does* query,
it queries from its **own hypothesis** — so the RAG only returns what the
agent already suspected. The agent's blind spots stay blind.

The whole value of this system over a human pentester is that **it can hold
15,000+ disclosed reports, exploited-in-the-wild CVEs and zero-day precedent
that no human can keep in their head** — but only if that knowledge is
applied *systematically to every feature and flow*, including the ones the
agent would never think to test. A human maps an app, then tests each part
against everything they've ever seen. We want the agent to do the same, with
a far larger memory.

So we build a **knowledge-map layer**: a living, per-engagement model of the
target (domains → subdomains → features → flows → tech), where **each node
carries the historical precedent for things like it** (writeups, disclosed
reports, KEV/EPSS CVEs), retrieval is driven by the node's **observed
signature** (not the agent's guess), and the map also holds **test state**
so vulnerabilities that only emerge from **combining** nodes (chains) can be
found.

## Goals

1. Build a structured, persistent **surface map** per engagement, grown
   progressively (interleaved with testing), covering all in-scope
   domains/subdomains and the features/flows/tech found on them.
2. Bind **precedent** to each node by its signature (feature/flow/tech),
   surfacing vuln classes real reports found in similar things — including
   classes the agent did not propose.
3. **Push** a node's precedent into the testing sub-agent at the moment it
   tests that node, and **gate** so a node is not marked tested until its
   precedent was consulted (soft first, hard later).
4. Use the map's whole state (tested / to-test / findings) to drive
   **cross-node correlation** → candidate chains for `chainer-mcp`.
5. Let the agent operate "above human level" by applying the full local
   knowledge base (RAG + disclosed reports + CVE/KEV/EPSS) to every node.

## Non-goals

- Not replacing the existing recon → scan → exploit → report flow; this is a
  layer *under* it, feeding it.
- Not building a new knowledge *corpus* here. Feeding the corpus (e.g. the
  HexBrain `.md` feeder) is a **separate, parallel workstream** (tracked
  separately), not part of this design.
- Not perfect semantic "understanding" of every business flow on day one;
  flow modeling starts heuristic and improves (see Phases).

## Anti-goals (would make this a failure even if it "works")

- **Breaking or regressing a live engagement.** If this layer, half-built or
  empty, changes existing agent behavior or bricks a running hunt, it has
  failed. Backward compatibility and isolation are non-negotiable.
- Surgery on `case-mcp`'s existing schema/tools that risks the finding
  lifecycle live engagements depend on.
- A gate that hard-blocks before it is proven stable.
- Bypassing scope/budget/rate guards to build or populate the map.
- Speculative architecture: a large new server where an isolated file +
  small additive tools suffice.

## Constraints

- Real authorized engagements run on this; **budget-guard, scope-guard,
  rate limits, dedupe and audit must all keep working unchanged** and the
  map-building itself must respect them (no uncounted requests — reuse
  `research_http`, never raw urllib; issues #131/#137).
- Solo maintainer — keep new surface area small and testable.
- Per-engagement isolation already exists via `engagement_paths.resolve()`
  (`data/engagements/<slug>/…`); the map must use it, so switching/pausing
  targets never mixes maps.
- Project rules: minimal/verifiable changes, per-task TDD + "review and
  audit" + "prove it runs", no commit/push without an explicit in-the-moment
  ask, no Co-Authored-By line.

## Approaches considered

**A — Lightweight, file-only map.** Map is a JSON artifact huntbrain
maintains via a helper module; retrieval primitive added to `writeup-mcp`;
chain-planner reads the file. *Cheapest, but state is weakly queryable and
agents touch the file format directly (coupling, easy to corrupt).*

**B — Extend `case-mcp` to be the map.** Reuses case-mcp's persistence and
correlation primitives (`group_root_cause`, `suggest_root_cause`). *Max
reuse, but it is the store live engagements depend on — additive-only or
not, it carries regression risk, which violates the top "nothing breaks"
priority.*

**C — Isolated additive layer (CHOSEN).** Map lives in its own
per-engagement store resolved through `engagement_paths` (so **case-mcp is
untouched**), behind a **new small MCP server** (`surface-map-mcp`) that
agents call. Retrieval is a **new** `writeup-mcp` tool (existing `query_rag`
untouched). Push + gate are wired **additively** with a **soft→hard**
rollout. chain-planner additively reads the map for correlation.

**Chosen: C.** It is the only option that *guarantees* existing servers
cannot regress (isolation), while still reusing the real assets we already
have (RAG, disclosed-reports cache, CVE store, engagement_paths, chainer).
We borrow B's idea only where safe — the retrieval primitive goes on
writeup-mcp as a pure add. Pick B/A later only if C's isolation proves
unnecessary.

## The design (decided parts)

### Map store (isolated)
- A new shared module `mcp-servers/surface_map.py` owns the schema +
  read/write, resolving the file via
  `engagement_paths.resolve("surface-map.json", "HUNTMCP_SURFACE_MAP_PATH")`
  → `data/engagements/<slug>/surface-map.json` (gitignored, like other
  per-engagement state).
- Node shape (initial):
  `{id, kind: host|endpoint|feature|flow|tech, label, signature, parent_id,
    state: discovered|precedent-bound|testing|tested, precedent: [...],
    findings: [finding_ids], meta}`.
- Writes are append/update, atomic (temp-file rename), and tolerate an
  absent/empty file (returns empty map — this is what makes "empty = behaves
  like today" true).

### `surface-map-mcp` (new, additive server)
Thin wrapper over `surface_map.py`. Tools (names illustrative):
- `add_node(kind, label, signature, parent_id?, meta?)` — recon/exploration
  writes discovered surface.
- `bind_precedent(node_id)` — calls the retrieval primitive for the node's
  signature and stores top precedent on the node.
- `get_node(node_id)` / `next_untested(kind?, priority?)` — read + prioritize.
- `set_state(node_id, state)` / `attach_finding(node_id, finding_id)`.
- `correlations()` — returns candidate cross-node combinations (tested +
  to-test + findings) for chain-planner.
Registered in `opencode.jsonc` disabled-by-default; each agent that needs it
re-enables `"surface-map-mcp*": true` in its frontmatter (same pattern as
every other MCP). **No existing agent is forced to enable it** — absence =
old behavior.

### Retrieval primitive (new `writeup-mcp` tool)
- `plan_feature(feature, program="", limit=6)` (and/or
  `precedent_for(signature)`): signature/feature-driven retrieval over the
  **existing** sources — writeup RAG + `disclosed_reports` cache + CVE store
  (NVD/KEV/EPSS) — returning the vuln classes/reports/CVEs seen in *things
  like this*, ranked. Mirrors HexBrain's `plan_tests`, on local data.
- Pure addition; `query_rag`, `search_disclosed_reports`, `fetch_cves`
  unchanged.

### Push + gate (soft → hard)
- **Push:** huntbrain, when dispatching a scan/exploit sub-agent for a node,
  includes that node's bound precedent in the sub-agent's prompt (it already
  composes sub-agent prompts) — the agent starts with precedent in context,
  rather than being told to go fetch it.
- **Gate:** a new check (modeled on `scope_gate_hook.py`) that a node had
  `bind_precedent` consulted before `set_state(...,"tested")`. **Ships in
  advisory mode** (logs/warns only, exit 0) and only flips to hard-block
  after it is proven stable on real runs. Advisory-first is what makes it
  brick-proof.

### Correlation
- `chain-planner` additively calls `surface-map-mcp` `correlations()` and
  feeds candidates into the existing `chainer-mcp` flow. No change to
  chainer-mcp itself.

### "Nothing breaks" guarantees (explicit)
1. `case-mcp` and every existing server: **zero code change** (except
   writeup-mcp, which only *gains* a tool).
2. Empty/absent map ⇒ agents behave exactly as today.
3. New server is disabled-by-default; opt-in per agent.
4. Gate is advisory until proven; cannot block a live hunt.
5. Map-building goes through `research_http`/existing guards — no
   scope/budget/rate bypass, no uncounted requests.
6. Each phase is independently shippable and leaves the system green.

## Phases (each: implement → required tests → review and audit → prove it runs → ask before commit)

- **Phase 0 — Primitive.** `writeup-mcp` `plan_feature`/`precedent_for` +
  tests. Runtime-verify against the local RAG/CVE store. (Useful on its own;
  nothing else depends on being finished first.)
- **Phase 1 — Map store + server.** `surface_map.py` + `surface-map-mcp`
  (add/get/state/bind/next_untested) + tests + registration (disabled by
  default). Runtime-verify the MCP tools actually read/write an isolated
  per-engagement file.
- **Phase 2 — Recon populates the map.** recon-agent writes discovered
  hosts/endpoints/tech as nodes (opt-in). Verify a real recon pass fills the
  map without touching other engagements' state.
- **Phase 3 — Push + advisory gate.** huntbrain injects node precedent into
  sub-agent prompts; advisory gate added. Verify precedent reaches a
  sub-agent and the gate warns (never blocks) when skipped.
- **Phase 4 — Feature/flow signatures.** Heuristic feature/flow detection
  (upload, auth, redirect, invite/role, refund, …) → richer signatures →
  better `plan_feature` hits. Verify blind-spot classes surface that the
  agent did not propose.
- **Phase 5 — Correlation.** chain-planner consumes `correlations()` →
  chainer-mcp. Verify a cross-node candidate chain is produced from map
  state.
- **Phase 6 — Harden the gate.** Flip gate to hard-block only after Phases
  1–5 are stable on real runs; keep an explicit override for edge cases.

Branching per project rules: a feature branch on the main checkout, one PR
the user merges (no worktrees; no commit/push/PR without an in-the-moment
ask).

## What's left to the builder

- Exact tool names/arg shapes for `surface-map-mcp` and the retrieval
  primitive (settle during Phase 0/1; keep consistent with existing MCP
  conventions).
- The node `signature` format and how `plan_feature` maps a signature to RAG
  queries + disclosed-report filters + CVE lookups (Phase 0/4).
- Priority function for `next_untested` (severity/bounty/precedent-strength).
- Heuristics for feature/flow detection in Phase 4 (start from the skills'
  own feature vocabulary: upload, auth/session, redirect, CSRF/CORS, IDOR,
  SSRF, etc.).
- Gate stability criteria before the Phase 6 hard flip.

## Related (separate) workstream

- **HexBrain → own DB feeder.** A throttled fetcher (like `h1_fetch.py`)
  pulling HexBrain's normalized `/report/<id>.md` into `data/writeups/` for
  self-owned, offline corpus enrichment with clean class labels. Enriches
  what this layer retrieves, but is independent and gated by its own
  approval.
