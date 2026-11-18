# OpenCode Stack Removal → Claude-Code Single Source of Truth — Design

Date: 2026-11-18
Status: Draft (awaiting approval)
Size: Project (cross-cutting destructive refactor; ~40+ files, 5 tests, CI)
Issues: #160 (primary), #161 (subsumed), supports #159/#163

## Intent and the why

The repo runs two parallel agent stacks — `.claude/` (Claude Code) and
`.opencode/` (OpenCode) — that have **drifted**. The 6 agent definitions
share names across both trees but all 6 now differ. MCP config is split:
Claude Code reads `.mcp.json` (31 servers) + `.claude/settings.local.json`;
OpenCode reads `opencode.jsonc` (34 servers). New tooling kept landing
OpenCode-first (surface-map, recon-agent opt-ins, the #138 work) and so
**never ran in the real engagement path**, which is Claude Code. Dual
maintenance keeps breaking: fix one runtime, the other silently drifts.

**Maintainer decision (issue #160 comment, 2026-11-18):** permanently
remove the OpenCode stack and make Claude Code the single source of truth.
Rebuild OpenCode later only if genuinely needed.

**Iron rule from the maintainer:** removal must verify every capability
already exists in the Claude path *before* deleting — nothing lost. If a
capability cannot be preserved, STOP and ask the maintainer.

## Goals

1. Every capability currently reachable only via the OpenCode stack is
   first ported into the Claude Code path and verified reachable there.
2. `.opencode/` and `opencode.jsonc` are deleted.
3. Every reference to the OpenCode stack across docs/code/CI/ignore files is
   updated or removed, so the repo describes one stack truthfully.
4. The 5 tests that read `opencode.jsonc` are rewritten to validate
   `.mcp.json` (+ `.claude/settings.local.json`) as the single source; the
   drift test now asserts every `mcp-servers/<name>` is wired into the
   Claude path (this is also #163's drift-blind-spot fix).

## Non-goals

- Rebuilding an OpenCode compatibility layer, generator, or symlink.
- Changing MCP server behavior/code (only their *registration*).
- The new capabilities in #159/#164/#163/#162 (separate specs; this spec
  only makes the Claude path the sole, correct source they build on).
- Touching `.claude/skills` / `.opencode/skills` — already single-source
  (`.opencode/skills` is a symlink → `.claude/skills`); the symlink is
  removed only as part of deleting the `.opencode/` tree, losing nothing.

## Constraints

- **No silent capability drop** (iron rule above).
- MCP servers only load into a Claude Code session at **startup** — newly
  added `.mcp.json` servers cannot be hot-loaded mid-session. Verification
  of in-session loading therefore requires a session restart (see
  Verification).
- Repo git rules: commit per concern; no AI-attribution lines; do not push
  without an explicit in-the-moment ask; one feature branch
  `fix/wiring-and-testing-159-164`.
- Protected benchmarks must not be weakened (`.claude/rules/benchmarks.md`).

## Approaches considered

1. **Generate/symlink OpenCode artifacts from Claude Code** (keep both
   runtimes, one source). Rejected by maintainer: still carries OpenCode
   as a runtime, still needs per-field translation (`opencode.jsonc` array
   command form vs `.mcp.json` string+args form; tool-scoping syntax
   differs), and the symlink approach only works for skills, not agents/MCP.
2. **Remove OpenCode entirely, Claude Code sole source** (chosen). Simplest
   to keep correct; eliminates drift by construction. Cost: a one-time
   capability-parity port + a large reference sweep.
3. **Leave as-is, add CI drift assertion only.** Rejected: does not fix the
   capabilities that already never run in Claude Code (#161), only detects
   future drift.

Chosen: **#2**, per the maintainer decision.

## Capability-parity port (must land BEFORE any deletion)

Audit source: issue #160 comment + verification this session (2026-11-18).

### A. MCP servers — OpenCode-only (3), must be added to `.mcp.json` + enabled in the committed `.claude/settings.json`

- `surface-map-mcp` (also closes #161) — absent from `.mcp.json`.
- `discspec-mcp` — absent from `.mcp.json`.
- `ws-rpc-mcp` — absent from `.mcp.json`; referenced by
  `.claude/agents/exploit-agent.md` tool allowlist.

`.mcp.json` entry shape to mirror existing working entries:
`{"command": "${CLAUDE_PROJECT_DIR:-.}/scripts/venv-python.sh", "args":
["${CLAUDE_PROJECT_DIR:-.}/mcp-servers/<name>/server.py"]}`.

**Enablement home (decided with maintainer, 2026-11-18):** the issue said
"enable in `.claude/settings.local.json`", but that file is **gitignored**
(per-user) — enablement there never ships, so on a fresh clone / in CI the
servers would be registered-but-disabled and the capability silently
dropped the moment `opencode.jsonc` (today's committed enablement source,
asserted by `ci.yml`) is deleted. Therefore enablement moves to the
committed, shared `.claude/settings.json`
(`enabledMcpjsonServers`/`disabledMcpjsonServers`), which ships and is
CI-readable — the true single source of truth. `settings.local.json`
remains a valid optional per-user override. (Editing `settings.json`
triggers `confirm-hook-edit.sh` — expected.)

### B. Agents — all 6 differ, reconcile BEFORE deleting `.opencode/agents`

`huntbrain, recon-agent, scan-agent, exploit-agent, report-agent,
chain-planner` all diverge. For each: diff the two copies, identify logic
that exists **only** in the `.opencode` copy, and fold it into the `.claude`
copy. The `.claude` copy is authoritative where they are merely stylistic;
only genuinely-missing *capability/instruction* content gets ported. Record
per-agent what (if anything) was folded in the PR.

### C. Slash commands — 4 OpenCode-only (`chain, ingest, learn, watch`)

`.claude/commands/` has only `audit.md`. Port each into `.claude/commands/`
unless it maps to an existing Claude Code mechanism; if consciously dropped,
say why in the PR. Decision recorded per command during implementation.

### D. scope-gate parity

`.opencode/plugin/scope-gate.ts` vs `scripts/hooks/scope_gate_hook.py`
(already wired via `.claude/settings.json` PreToolUse). Verify parity of
`_is_rm_command` + scope checks; port anything the TS plugin enforces that
the Python hook does not.

## Deletion + reference sweep (AFTER parity verified)

- Delete: `.opencode/` (entire tree), `opencode.jsonc`.
- Update every `opencode` reference (67 files outside `.opencode/`): docs
  (`README.md`, `ARCHITECTURE.md`, `CLAUDE.md`, `AGENTS.md` — fold uniques
  into `CLAUDE.md`, `PHASE1*`, `IMPLEMENTATION-TASK-TRACKER.md`, `docs/**`,
  `knowledge/**`), code (`mcp-servers/*.py`, `mcp-servers/*/server.py`,
  `scripts/*.sh`), CI (`.github/workflows/ci.yml`), ignore files
  (`.gitignore`, `.dockerignore`).
- **`internal-research/**` and other opencode-around research/docs:** per
  maintainer (2026-11-18), these may be **updated or have their OpenCode
  content removed/changed** as needed — the goal is the repo describing one
  stack truthfully, not preserving a stale OpenCode narrative. Where a file
  is purely historical record (dated audits/roadmap history) and rewriting
  would destroy legitimate history, prefer a short "superseded: OpenCode
  removed 2026-11-18, see #160" note over silent edits; elsewhere, change
  the content to match the single-stack reality.

## Tests to rewrite (do before/with deletion so CI stays green)

`test_agent_mcp_registry_drift`, `test_agent_tool_scoping`,
`test_sandbox_runner`, `test_surface_map_mcp`, `test_hook_tamper_resistance`.
The drift test must assert **every `mcp-servers/<name>` is present in
`.mcp.json` and enabled in `.claude/settings.local.json`** (or is a
documented, explicit single-stack exception) — closing the #163 blind spot.

## Verification (prove-it-runs + prove-it-wired)

1. After wiring the 3 servers + config, **pause for a session restart**
   (maintainer chose this). On restart, call a real tool on each of
   `mcp__surface-map-mcp__*`, `mcp__discspec-mcp__*`, `mcp__ws-rpc-mcp__*`
   and capture the real response → proof of in-session loading.
2. Run the 5 rewritten tests + the focused suite; `ruff`/`py_compile`/
   `bash -n` as CI does.
3. `review and audit` (both /code-review + /security-review) on the diff.
4. PR includes a capability-parity table: each OpenCode-only capability →
   where it now lives in the Claude path → how it was proven reachable.

## What's left to the builder

- Per-agent fold decisions (B) and per-command port/drop decisions (C):
  settle during implementation, record each in the PR.
- Exact CI job edits once the drift test's new contract is written.
