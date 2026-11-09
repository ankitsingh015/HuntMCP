# P3-FANOUT: Bounded, dedupe-aware parallel fan-out for discovery

Status: draft, pending human approval.
Tracker reference: `IMPLEMENTATION-TASK-TRACKER.md` §3 row `P3-FANOUT`, §9 dependency graph (depends only on
`P2-BENCH`, already `[x]`), §13 ("Bounded, dedupe-aware parallel fan-out (concurrency for discovery only).
Guardrail: bounded; unrestricted parallelism remains rejected").

## Intent and why

Today, recon-agent and scan-agent start one discovery job (httpx/nuclei/ffuf/dalfox/nmap via
`job_runtime.start_job()`), poll it to completion, then move to the next target. That serialization is an
*agent-instruction convention* — `job_runtime.py` itself already runs each job as an independent sandboxed
subprocess and has no built-in cap, and the shared guards it calls through (`budget_guard`, `dedupe_check`,
`work_registry`) are already file-lock-protected and safe under concurrent calls. Nothing in the mechanism
stops an agent from starting many jobs before polling any of them — the convention is purely "don't do that"
in the agent markdown.

P3-FANOUT replaces that convention with a small, deterministic, bounded worker pool so recon/scan hunts finish
faster, **without** trusting an LLM-driven loop to correctly count concurrency or to notice a target starting
to block.

## Goals

- Run independent discovery tool calls (same tool, many independent hosts/endpoints) concurrently, up to a
  **per-tool** cap, instead of one at a time.
- Skip a host/endpoint that already has work in flight (reuse `work_registry.list_active_work()`).
- Back off automatically — reduce effective concurrency for that batch — the moment a worker's result carries
  a `block` signal (`classify_block()` returning `"rate_limit"` or a WAF signature), so a burst of parallel
  requests never silently turns into a run of false negatives against a target that started throttling/blocking.
- Keep every existing safety call (`budget_guard.enforce()`, `scope_gate_hook`, `dedupe_check`) exactly as it
  runs today, once per underlying tool call, unchanged.
- Enforcement is deterministic Python (a semaphore + thread pool), never an LLM-counted loop — the same
  "guard code the model can't talk its way around" philosophy as `budget_guard`/`scope_gate_hook`.

## Non-goals

- Exploit/validation-phase concurrency. Anything feeding CEM evidence (exploit-agent, chain-planner) stays
  strictly sequential — causal-evidence integrity there matters more than speed, and the tracker scopes
  P3-FANOUT to "concurrency for discovery only."
- Unbounded/unrestricted parallelism. There is always a hard per-tool ceiling; raising it requires an explicit
  env var change, same convention as `budget_guard`'s `HUNTMCP_MAX_TOOL_CALLS`.
- Changing any existing tool's schema or contract (`mcp-servers/CLAUDE.md` compatibility rule). `start_X()` /
  `check_scan()` for a single target keep working exactly as they do today; fan-out is additive.
- **httpx.** Corrected after builder-check: `httpx-mcp.probe_hosts()` already accepts a multi-host list and
  fans out *internally*, inside one `start_job()` call, via `-threads N` — one budget charge, one sandboxed
  subprocess for the whole batch. Wrapping it in a job-per-host `fanout.start_batch()` pool would turn one
  budget charge into N and spin up N containers instead of 1 — slower and heavier than today, not faster.
  httpx needs no job-per-target pool at all; if its concurrency needs tuning, that's a `-threads` knob
  question, unrelated to `fanout.py`, and out of scope here. Nuclei is the sole first-pass target: its
  `scan_target()`/`scan_with_templates()` each start one `start_job()` **per endpoint already**, so a
  job-per-target pool is the right mechanism, not a mismatch.
- Covering every MCP server. First pass is nuclei only, both its entry points (`scan_target` for the
  default/severity-filtered template set and `scan_with_templates` for a specific list — both route through
  the same `fanout.start_batch()`, differing only in `build_args`, so adding both costs little). ffuf/dalfox
  extension is left to the implementation plan, not required for this design to be considered complete.

## Anti-goals (would make this a failure even if it "works")

- A batch that silently drops coverage because a worker got blocked and nobody noticed — a cap that doesn't
  react to a block signal defeats the entire point.
- Any per-call bypass of `budget_guard`/`scope_gate_hook`/`dedupe_check` "because it's inside a batch now."
- A fan-out layer that duplicates a job against a host another in-flight job (parallel or not) is already
  covering.

## Constraints

- Reuse `job_runtime.start_job()`/`poll_job()` as-is underneath — a fan-out batch is just many ordinary jobs
  managed by a pool, not a new execution path. `_enforce_budget()` keeps firing per job exactly as it does
  for every other `start_job()`-based scanner (`job_runtime.py:131`).
- No new runtime dependency — a bounded pool is `threading`/`concurrent.futures` (already used by
  `job_runtime`'s existing `_ThreadJob` pattern), stdlib only.
- Per-tool cap env vars follow the existing `HUNTMCP_<NAME>` convention (`budget_guard.py:46`).

**Corrected after builder-check:** `work_registry.start_work()` has zero callers anywhere in the repo today —
nothing currently registers a host as "in flight" when any `start_job()` runs, batched or not. So
`list_active_work()` would always return empty as the code stands; the dedupe goal is unreachable unless
something starts producing entries. `fanout.py` becomes that producer: each worker calls
`work_registry.start_work("fanout", target, task=tool_name)` immediately before `start_job()` and
`work_registry.complete_work(work_id)` right after that job's `poll_job()` reports terminal, then checks
`list_active_work(host=target)` before launching the *next* worker for that target. **Known boundary:** this
only catches collisions *between* fanout-launched jobs — a manually started single-target `start_job()` call
elsewhere (outside `fanout.py`) still doesn't register anything, so a batch and a concurrent manual call
against the same host aren't caught by this. Closing that repo-wide is a pre-existing gap, not introduced by
P3-FANOUT, and out of scope here.

## Architecture (my call, open to challenge)

Add one new shared module, `mcp-servers/fanout.py`, next to `job_runtime.py`.

**No new threading.** `job_runtime.start_job()` already returns immediately (the launch itself is fast; the
real tool runs as a background subprocess) and `poll_job()` is already non-blocking. So "N jobs in flight at
once" is achieved by having N real sandboxed subprocesses running concurrently — the Python-level bookkeeping
that manages *which* targets currently hold a slot can stay single-threaded and poll-driven, exactly like
every other job in this codebase, rather than introducing Python threads (which `job_runtime.py`'s own
docstring explicitly avoided introducing for a similar composite case, since nothing here needs to block
inside a thread the way `start_thread_job()`'s `fn` does).

- `start_batch(tool_name: str, targets: list[str], build_args: Callable[[str], list[str]], batches: dict) -> str`
  — creates a `_Batch` record (pending targets, empty in-flight map, empty results) under a fresh `batch_id`
  in the caller's `batches` dict, then calls the shared `_fill_slots()` helper (below) once to launch the
  first wave up to that tool's effective cap, and returns `batch_id` immediately. Mirrors `start_job()`'s
  "do the fast part now, return an id" shape.
- `_fill_slots(batch, tool_name, jobs)` (internal) — while the batch has free capacity (effective cap minus
  current in-flight count) and pending targets remain: pop the next target, check
  `work_registry.list_active_work(host=target)`; if non-empty, record `"skipped_in_flight"` for it and
  continue (no job started, slot not consumed); otherwise call `work_registry.start_work("fanout", target,
  task=tool_name)` then `job_runtime.start_job(tool_name, build_args(target), ..., jobs)`, and record the
  returned `job_id` against that target in the batch's in-flight map. The effective cap is
  `min(tool's default cap, current persistent-backoff cap for (tool_name, target-prefix))` — see backoff
  below.
- `check_batch(batch_id: str, batches: dict, jobs: dict) -> dict` — non-blocking: for every target currently
  in-flight, calls `job_runtime.poll_job(job_id, jobs)`; any that report terminal get
  `work_registry.complete_work(work_id)` called, their result (including `block`) recorded, and — if `block`
  is truthy — update the persistent backoff state (below) before the freed slot is reused. Then calls
  `_fill_slots()` again to backfill from the pending queue. Returns per-target status
  (`running`/`done`/`skipped_in_flight`) and, once pending is empty and nothing is in-flight, `status: "done"`
  with every target's final result. Mirrors `poll_job()`'s "never blocks, pop when fully done" shape.
- **Backoff is persistent, not per-batch-only (decided after discussion — the real risk is WAF/rate-limit
  state, which doesn't reset between batches).** A WAF that started throttling 30 seconds ago is still
  throttling at the start of the *next* batch; resetting to full cap every time a new `start_batch()` call
  begins just means paying the same false-negative cost again instead of once. `fanout.py` keeps a small
  per-engagement state file (same `engagement_paths.resolve()` + `file_lock` pattern as `budget_guard.json`/
  `work_registry.json`), keyed by `(tool_name, host_or_target_prefix)`, recording the last-seen block kind and
  a cooldown timestamp. `_fill_slots()`'s effective cap reads this state fresh every call (same "no cached
  mutable state" pattern as `scope_guard.load_engagement()`) — a target under an active cooldown gets the
  already-reduced cap instead of the tool's full default, ramping back up only once the cooldown window
  passes with no further block. This is the deliberate trade for the stated priority ("don't miss anything")
  over simplicity.
- Default per-tool caps as module constants, each overridable via its own env var (e.g.
  `HUNTMCP_FANOUT_MAX_HTTPX`, `HUNTMCP_FANOUT_MAX_NUCLEI`), sized to how heavy each tool already is per call:
  httpx highest (lightweight single probe), nuclei/ffuf/dalfox mid (each already fans out requests
  internally per target), nmap lowest (heaviest, most likely to trip IDS/rate-limiting) — exact numbers are
  an implementation-plan decision, not fixed here.

`httpx-mcp` and `nuclei-mcp` each gain two new tool functions, `start_batch_probe()`/`check_batch()` (names
TBD in the plan), thin wrappers calling `fanout.start_batch()`/`check_batch()` with that server's own
`build_args`. Existing `probe_host()`/`run_scan()`/`check_scan()` are untouched.

## What's left to the builder (implementation plan)

- Exact env var names and default per-tool caps, and the exact cooldown window length for persistent
  per-(tool, host) backoff state (e.g. a fixed number of minutes, or an exponential cooldown on repeated
  blocks against the same target).
- Exact new-tool names/schemas for `httpx-mcp`/`nuclei-mcp` (and whether to extend to ffuf/dalfox in the same
  pass or a follow-up).
- Whether `check_batch()` returns partial per-target stdout/stderr immediately as each finishes, or only the
  done/running/skipped status until the whole batch is terminal (affects agent-instruction wording in
  recon-agent.md/scan-agent.md for how to consume partial results).
- Test plan: unit tests for `fanout.py`'s pool (bounded concurrency respected, dedupe skip, block-triggered
  backoff, no double budget-check), plus a fixture-based integration test with N simulated targets where one
  is rigged to return a rate-limit signal, asserting effective concurrency drops and no target is silently
  dropped from the batch result.
- Updated recon-agent.md/scan-agent.md wording replacing the "one target at a time" convention with "use
  start_batch for independent same-tool calls across multiple targets."
