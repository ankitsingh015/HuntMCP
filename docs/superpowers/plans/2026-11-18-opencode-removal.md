# OpenCode Stack Removal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the OpenCode stack and make Claude Code the single source of truth, porting every OpenCode-only capability into the Claude path first so nothing is silently dropped.

**Architecture:** Wire the 3 OpenCode-only MCP servers into `.mcp.json` + `.claude/settings.local.json`; reconcile the 6 drifted agent copies into `.claude/agents`; port/drop the 4 OpenCode slash commands; confirm scope-gate parity; then delete `.opencode/` + `opencode.jsonc` and sweep every reference; rewrite the 5 tests that read `opencode.jsonc` to make `.mcp.json` (+ settings.local) the single registration source (which also closes #163's drift blind spot).

**Tech Stack:** Python 3.12, FastMCP servers, pytest, Claude Code `.mcp.json`/`.claude/settings.local.json`, GitHub Actions CI, JSONC.

**Spec:** [docs/superpowers/specs/2026-11-18-opencode-removal-design.md](../specs/2026-11-18-opencode-removal-design.md)

## Global Constraints

- **No silent capability drop:** every OpenCode-only capability must be proven reachable in the Claude path BEFORE any deletion; if one can't be preserved, STOP and ask the maintainer.
- Branch: `fix/wiring-and-testing-159-164`. Commit per concern. No AI-attribution lines in commits/PRs. Do not push/PR without an explicit in-the-moment ask.
- `.mcp.json` entry shape (copy verbatim from existing entries): `{"command": "${CLAUDE_PROJECT_DIR:-.}/scripts/venv-python.sh", "args": ["${CLAUDE_PROJECT_DIR:-.}/mcp-servers/<name>/server.py"]}`.
- Editing `.claude/settings.local.json` and hook files triggers `confirm-hook-edit.sh` — expected, not an error.
- MCP servers load only at Claude Code startup; in-session verification of the 3 new servers requires a maintainer-triggered restart (Task 1 ends in that checkpoint).
- Protected security-detection benchmarks and their ground truth must not be weakened (`.claude/rules/benchmarks.md`). This plan touches only registration/wiring tests, not detection benchmarks.
- 6 MCP servers are intentionally disabled in settings.local (`second-opinion-mcp`, `azure-postexploit-mcp`, `aws-postexploit-mcp`, `gcp-postexploit-mcp`, `local-privesc-mcp`, `ad-recon-mcp`) — these remain a documented disabled-exception set, present in `.mcp.json` but not enabled.

## Review Focus

- **A `mcp-servers/<name>` dir added later but never put in `.mcp.json`** (the exact #161/#163 bug): drift test Task 2 must FAIL for this, not pass.
- **An agent frontmatter `tools:` referencing a server disabled in settings.local**: tool-scoping test Task 3 must flag it (tool-blind at runtime).
- **A dynamic specialist agent `.md` with an empty/missing `tools:` allowlist**: Task 3 must fail (born tool-blind).
- **A High/Critical detecting server dropped from its owning agent during the fold**: Task 3's coverage-mapping test must catch it.
- **The scope-gate hook no longer protecting a security-critical Claude-path file after `.opencode` deletion**: Task 8 must re-point protections to `.mcp.json`/`.claude/settings.json`/`scope_gate_hook.py`, with Task 8's test asserting it.

---

### Task 1: Wire the 3 OpenCode-only MCP servers into the Claude path (closes #161)

**Files:**
- Modify: `.mcp.json` (add `surface-map-mcp`, `discspec-mcp`, `ws-rpc-mcp`)
- Modify: `.claude/settings.local.json` (`enabledMcpjsonServers` += the 3)

**Interfaces:**
- Produces: 3 servers registered + enabled in the Claude path; relied on by Task 2's drift test and the whole deletion.

- [ ] **Step 1:** Add the 3 entries to `.mcp.json` `mcpServers` using the exact entry shape above.
- [ ] **Step 2:** Add the 3 names to `enabledMcpjsonServers` in `.claude/settings.local.json`.
- [ ] **Step 3 (out-of-session smoke):** For each, start `scripts/venv-python.sh mcp-servers/<name>/server.py` as a stdio subprocess and confirm it initializes without import/boot error. Expected: process starts, no traceback.
- [ ] **Step 4: Commit** (`.mcp.json`, `.claude/settings.local.json`): "feat: wire surface-map/discspec/ws-rpc MCP servers into Claude Code config (#160, #161)".
- [ ] **Step 5: RESTART CHECKPOINT** — pause and ask the maintainer to restart the session. On restart, call a real tool on each and capture the response:
  - `mcp__surface-map-mcp__next_untested` (local sqlite; safe — returns nodes or empty).
  - `mcp__ws-rpc-mcp__enumerate_ddp_methods` on a tiny local JS fixture (safe — no network).
  - `mcp__discspec-mcp__discover_from_openapi` with a dummy/out-of-scope URL (safe — a graceful scope/validation error response still proves the tool is loaded and callable).
  Expected: each returns a real MCP response (success or graceful error), proving in-session loading. This is the #161 close.

### Task 2: Rewrite the drift test — `.mcp.json` is the single registration source (closes #163 blind spot)

**Files:**
- Modify: `tests/test_agent_mcp_registry_drift.py`

**Interfaces:**
- Consumes: Task 1's wiring (the 3 servers now in `.mcp.json`).
- Produces: the drift contract every later task relies on.

- [ ] **Step 1: Write the failing/updated tests.** Replace `_registered_server_names()` so "registered" = a key in `.mcp.json` `mcpServers` (drop the `opencode.jsonc` read). Keep `_claude_agent_mcp_refs`. Delete `_opencode_agent_mcp_refs` and `test_opencode_agent_mcp_refs_all_registered_or_known_exception` (no `.opencode/agents` post-removal). Add:
  - `test_every_mcp_servers_dir_is_registered_in_mcp_json()` — every `mcp-servers/<name>-mcp` directory is a key in `.mcp.json` (this is the bug that let surface-map stay orphaned). Allow `_KNOWN_UNTRACKED_PERSONAL_SERVERS` (obscura-mcp, burp).
  - `test_every_registered_server_is_enabled_or_documented_disabled()` — every `.mcp.json` server is in `enabledMcpjsonServers` of `.claude/settings.local.json`, except the documented `_KNOWN_DISABLED` set (the 6 above), asserting that set is not stale (none of the 6 are also enabled).
  - Keep `test_claude_agent_mcp_refs_all_registered_or_known_exception()`, now resolving against the `.mcp.json`-based registry.
- [ ] **Step 2: Run** `pytest tests/test_agent_mcp_registry_drift.py -v`. Expected: PASS (fails before Task 1 wiring; passes after).
- [ ] **Step 3: Commit:** "test: drift test validates .mcp.json as single MCP source + every server-dir registered (#163)".

### Task 3: Rewrite the tool-scoping test against the Claude path

**Files:**
- Modify: `tests/test_agent_tool_scoping.py`

- [ ] **Step 1: Rewrite.** `AGENTS_DIR` → `.claude/agents`. Replace `_load_opencode_config()` with a reader of `.claude/settings.local.json` `enabledMcpjsonServers` for the enabled set. Replace `_reenabled_servers(fm)` with a parser of the comma-separated `tools:` string that extracts `mcp__<name>` tokens (reuse the drift test's `_claude_agent_mcp_refs` logic). Then:
  - DROP `test_global_disable_covers_every_enabled_mcp_server` and `test_global_tools_map_only_disables_never_enables` (no central "global tools map" exists in Claude Code).
  - KEEP, retargeted to `.claude/agents` + settings.local enabled set: `test_every_agent_declares_a_nonempty_scoped_allowlist`, `test_agent_allowlists_reference_only_real_enabled_servers`, `test_no_agent_reenables_all_servers`, `test_orchestrator_is_tightly_scoped` (huntbrain's 7-server set), `test_no_orphan_mcp_server` (every ENABLED server reachable by ≥1 agent), `test_high_critical_detection_tools_available_to_owning_agent` (the `HIGH_CRIT_COVERAGE` map unchanged).
- [ ] **Step 2: Run** `pytest tests/test_agent_tool_scoping.py -v`. Expected: PASS. If `test_no_orphan_mcp_server` or the coverage map fails, it is a real wiring gap to fix in the agent frontmatter (or document), not a test to weaken.
- [ ] **Step 3: Commit:** "test: tool-scoping invariants validate .claude agents + settings.local (#160)".

### Task 4: Rewrite surface-map test + fix sandbox_runner test's opencode reference

**Files:**
- Modify: `tests/test_surface_map_mcp.py`, `tests/test_sandbox_runner.py`

- [ ] **Step 1:** In `test_surface_map_mcp.py`, replace `_opencode_cfg()`/the opencode registration assertion with: surface-map-mcp is a key in `.mcp.json` AND in `enabledMcpjsonServers`. In `test_sandbox_runner.py`, update the line-88 docstring/comment that references `opencode.jsonc` to describe the `.mcp.json`/no-network contract (comment-only; assertions unchanged unless they read opencode).
- [ ] **Step 2: Run** `pytest tests/test_surface_map_mcp.py tests/test_sandbox_runner.py -v`. Expected: PASS.
- [ ] **Step 3: Commit:** "test: surface-map + sandbox_runner tests drop opencode.jsonc references (#160)".

### Task 5: Reconcile the 6 drifted agents — fold `.opencode`-only logic into `.claude`

**Files:**
- Modify: `.claude/agents/{huntbrain,recon-agent,scan-agent,exploit-agent,report-agent,chain-planner}.md`

- [ ] **Step 1:** For each agent, `diff .claude/agents/<a>.md .opencode/agents/<a>.md`. Identify content present ONLY in the `.opencode` copy that is genuine capability/instruction (not OpenCode-runtime syntax, not stylistic). Fold that into the `.claude` copy. The `.claude` copy stays authoritative for format and for Claude-Code-specific mechanics.
- [ ] **Step 2:** Re-run `pytest tests/test_agent_tool_scoping.py tests/test_agent_mcp_registry_drift.py -v` after edits (frontmatter `tools:` must still satisfy scoping + drift). Expected: PASS.
- [ ] **Step 3:** Record per-agent in a scratch note what (if anything) was folded, for the PR's parity table.
- [ ] **Step 4: Commit:** "refactor: fold opencode-only agent logic into .claude agents before removal (#160)".

### Task 6: Port or consciously drop the 4 slash commands + confirm scope-gate parity

**Files:**
- Create (per port decision): `.claude/commands/{chain,ingest,learn,watch}.md`
- Reference: `.opencode/commands/*.md`, `.opencode/plugin/scope-gate.ts`, `scripts/hooks/scope_gate_hook.py`

- [ ] **Step 1 (commands):** For each of `chain/ingest/learn/watch`: read the `.opencode/commands/<c>.md`. If it maps to a capability a Claude Code slash command can carry, port it into `.claude/commands/<c>.md` (Claude Code command format). If it only made sense under OpenCode (or is already covered by an MCP tool / `audit.md`), consciously drop it and record the reason. Default bias: PORT, since these are user-facing engagement verbs (`/chain`, `/ingest`, `/learn`, `/watch`) with live MCP backends (chainer-mcp, writeup-mcp ingest, lessons/writeup learn, watch-mcp).
- [ ] **Step 2 (scope-gate parity):** Diff `scope-gate.ts` against `scope_gate_hook.py` for `_is_rm_command` + scope-check behavior. Port anything the TS plugin enforces that the Python hook does not. If parity already holds, record that.
- [ ] **Step 3:** `bash -n scripts/*.sh` and `ruff check`/`py_compile` any touched Python. Expected: clean.
- [ ] **Step 4: Commit:** "feat: port opencode slash commands to .claude/commands + verify scope-gate parity (#160)".

### Task 7: Delete `.opencode/` + `opencode.jsonc` and sweep every reference

**Files:**
- Delete: `.opencode/` (entire tree), `opencode.jsonc`
- Modify: the 67 files referencing `opencode` outside `.opencode/` — docs (`README.md`, `ARCHITECTURE.md`, `CLAUDE.md`, `AGENTS.md`→fold uniques into `CLAUDE.md` then remove, `PHASE1*.md`, `IMPLEMENTATION-TASK-TRACKER.md`, `docs/**`, `knowledge/master-pentest-prompt.md`), code (`mcp-servers/*.py`, `mcp-servers/{httpx,target-discovery,surface-map,playwright}-mcp/server.py`, `scripts/*.sh`), CI (`.github/workflows/ci.yml`), ignore (`.gitignore`, `.dockerignore`), and `internal-research/**` per the spec (superseded-note for pure history, content edit elsewhere).

- [ ] **Step 1:** Delete the two targets.
- [ ] **Step 2:** `grep -rniE 'opencode' . | grep -v node_modules` and update every live reference so the repo describes one stack. Fold AGENTS.md uniques into CLAUDE.md. Remove the OpenCode `validate-config`/opencode-reading CI job steps; ensure the drift/scoping tests run in CI.
- [ ] **Step 3: Verify no dangling refs:** `grep -rniE 'opencode\.jsonc|\.opencode/' . | grep -v node_modules | grep -v docs/superpowers/specs/2026-11-18 | grep -v internal-research/.*history` returns only intentional historical/superseded notes. Expected: no live wiring reference remains.
- [ ] **Step 4:** `bash -n scripts/*.sh`; `ruff check mcp-servers/ --ignore E402,F811 --target-version py312`; `python -m py_compile` touched servers. Expected: clean.
- [ ] **Step 5: Commit:** "refactor!: remove OpenCode stack; Claude Code is the single source of truth (#160)".

### Task 8: Re-point the scope-gate tamper protection + fix its test

**Files:**
- Modify: `scripts/hooks/scope_gate_hook.py` (or `confirm-hook-edit.sh` — whichever holds the protected-path list), `tests/test_hook_tamper_resistance.py`

**Interfaces:**
- Consumes: Task 7's deletion (the old protected paths `.opencode/plugin/scope-gate.ts` and `opencode.jsonc` no longer exist).

- [ ] **Step 1:** Find where the hook enumerates protected paths (currently includes `.opencode/plugin/scope-gate.ts`, `opencode.jsonc`). Replace those with the Claude-path security-critical files: `scripts/hooks/scope_gate_hook.py` itself, `.claude/settings.json`, and `.mcp.json`. Rewrite `test_main_blocks_edit_of_opencode_dispatch_plugin`/`test_main_blocks_edit_of_opencode_jsonc` to assert edits to the new protected paths are blocked; update the line-697 curl-write case.
- [ ] **Step 2: Run** `pytest tests/test_hook_tamper_resistance.py -v`. Expected: PASS.
- [ ] **Step 3: Commit:** "fix: scope-gate hook protects Claude-path config after OpenCode removal (#160)".

### Task 9: Full #160 verification + parity table

- [ ] **Step 1:** Run the focused suite: `pytest tests/test_agent_mcp_registry_drift.py tests/test_agent_tool_scoping.py tests/test_surface_map_mcp.py tests/test_sandbox_runner.py tests/test_hook_tamper_resistance.py -v`. Expected: all PASS.
- [ ] **Step 2:** Run the broader suite `pytest tests/ -q` (or the repo's CI-equivalent subset). Record failures + causes.
- [ ] **Step 3:** `review and audit` (both /code-review + /security-review) on the #160 diff. Fix findings.
- [ ] **Step 4:** Assemble the capability-parity table (each OpenCode-only capability → where it now lives in the Claude path → how proven reachable) for the final PR. #161 marked closed (surface-map proven in-session at Task 1 restart).

## Self-Review notes

- **Spec coverage:** servers (Task 1), agents (Task 5), commands+scope-gate (Task 6), deletion+sweep (Task 7), 5 test rewrites (Tasks 2,3,4,8), verification/parity (Tasks 1,9). All spec sections mapped.
- **#163 blind-spot** is Task 2's new `test_every_mcp_servers_dir_is_registered_in_mcp_json` — the one assertion that would have caught surface-map's orphaning.
- **Ordering:** all ports/folds/test-rewrites precede deletion (Task 7); you cannot fold from deleted files, and tests must be deletion-safe first. Task 8 follows deletion because it re-points away from now-deleted paths.
- **Not weakening tests:** the dropped tests (opencode-agent drift, global-tools-map) assert OpenCode-only constructs that cease to exist; they are replaced by stronger Claude-path contracts, not removed to pass.
