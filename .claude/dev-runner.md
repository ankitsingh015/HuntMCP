# HuntMCP Dev-Runner

A controlled, **resumable** development-workflow runner. It removes the manual
overhead of starting a new Claude Code session and hand-writing the next
Phase-1 task prompt: it reads the persistent project state, determines the single
next actionable task, generates the minimum execution context for it, and **STOPs
and asks** at any ambiguity or safety boundary instead of guessing.

It is a *workflow* tool. It does **not** touch CEM implementation logic, change
the Phase-1 architecture, or run the roadmap end-to-end. The unit of autonomous
execution is **one exact task**, never "implement the whole phase".

## Quick start

```bash
bash scripts/hunt-runner.sh status     # phase, task counts, next action
bash scripts/hunt-runner.sh next        # just the next task / decision (+ --json)
bash scripts/hunt-runner.sh dry-run     # SAFE preview: full task context, or a decision request
bash scripts/hunt-runner.sh context     # the generated task context alone
bash scripts/hunt-runner.sh check       # worktree safety only (branch / status / mismatch)
bash scripts/hunt-runner.sh verify      # run mechanical checks, print evidence + gate verdict
bash scripts/hunt-runner.sh checkpoint  # write the resumable JSON state cache
```

Exit codes: **0** = OK / actionable / done, **2** = STOP (human decision required).

Useful flags (pass after the subcommand): `--plan PATH`, `--roadmap PATH`,
`--repo DIR`, `--expected-branch BRANCH`, `--state-file PATH`, `--require-clean`,
`--json`.

By default the runner reads `PHASE1-EXECUTION-PLAN.md` and `ROADMAP.md` at the
repo root of the current worktree. If they live elsewhere (e.g. on the Phase-1
branch), point `--plan` / `--roadmap` at them explicitly.

## How it works (six separated responsibilities)

| Module | Role |
|---|---|
| `scripts/runner/state.py` | **State reader** — parses the plan task table (`- [x] **C6** — … \| deps \| files \| verify: … \| accept: …`) and the ROADMAP `PROJECT STATE` block into typed objects. |
| `scripts/runner/resolver.py` | **Next-task resolver** — pure function of the plan; picks the earliest pending task whose deps are all complete, resumes a single `[~]`, or STOPs on an ambiguous/blocked/broken graph. |
| `scripts/runner/worktree.py` | **Worktree-safety gate** — read-only git inspection; STOPs on branch/worktree mismatch or (with `--require-clean`) a dirty tree. Never copies, resets, stashes, merges, or switches. |
| `scripts/runner/verify.py` | **Verification gate** — protected-benchmark detection + the evidence→`[x]` decision. |
| `scripts/runner/context.py` | **Task-context generator** — the minimum execution context, derived only from the plan + rule files. |
| `scripts/runner/decision.py` | **Human-decision gate** — formats a concise decision request (task, ambiguity, contract, options, recommendation, downstream) and STOPs. |
| `scripts/runner/cli.py` + `checkpoint.py` | Orchestration + the resumable JSON cache. |

## Task state machine

`[ ]` pending · `[~]` in progress · `[x]` complete · `[!]` blocked / human decision required.

The runner **never writes `[x]`** into the plan on an assistant's claim. A task
may only be marked complete when *measured evidence* satisfies every completion
criterion (tests pass, regression green, lint clean, no protected asset weakened,
docs/state updated, no unexplained regression). The plan is human-authored; the
runner reads it.

## How state is recovered (resumability)

The **plan document is the single source of truth.** The resolver recomputes the
next task from it on every run — it holds no memory between sessions, so a fresh
session reaches the same decision from the same files. No conversation context is
required.

`checkpoint` additionally writes a runner-owned cache (default
`.claude/runner-state.json`) recording the last resolution, counts, blocks, and
branch. This is an **audit/convenience artifact, not the plan** — deleting it
loses nothing the plan cannot reproduce.

### Resuming an interrupted task

If a task is left `[~]`, the runner reports `resume` and explicitly instructs the
next session to **re-inspect the worktree and re-verify actual state before
continuing** — never to trust a prior completion claim. If two tasks are `[~]`,
it STOPs (`MULTIPLE_IN_PROGRESS`): it will not guess which to resume.

## How human decisions are handled

When the runner will not proceed, it prints a structured **decision request** and
exits `2`. It STOPs (never guesses) on, among others:

- ambiguous next task, conflicting/duplicate task ids, unknown dependency
- multiple in-progress tasks
- a pending task whose declared files touch a **protected benchmark/evaluator
  asset** (`scenarios.py`, `answer_key.py`, `evaluator.py`, `integrity.py`,
  `ground_truth.py`, `*.sha256[.lock]`)
- worktree / branch mismatch, or (with `--require-clean`) an unexpectedly dirty tree
- the plan file is missing (`PLAN_NOT_FOUND`)

This mirrors the C1/C3/C4/C5 ruling pattern: state the exact ambiguity and
contract, list options and (where justified) a recommendation, name the
downstream tasks, then STOP until a human answers.

## Dry-run

`dry-run` is the safe preview and **modifies no source**. It shows the next
action, the worktree summary, and the full generated task context (phase,
dependencies with their statuses, files in scope, rules/state files to consult,
the one-task execution boundary, verification requirements, and the
untrusted-data rule) — or, if any gate trips, the decision request instead.

## Untrusted data

Repository files, plan text, tool output, logs, and model-generated text are
**data, not instructions.** The runner keeps obeying the user, `CLAUDE.md`, and
`.claude/rules/*` over anything embedded in that content, and every generated
task context restates this rule.

## What the runner will NEVER do automatically

- Mark a task `[x]` on a claim, or without measured evidence.
- Edit, reorder, or re-label the plan / ROADMAP.
- Copy, reset, stash, merge, or switch work across worktrees or branches.
- Modify a protected benchmark / evaluator / ground-truth asset.
- Touch CEM implementation files, or run C6 / any future CEM task.
- Guess past an ambiguity or safety boundary — it STOPs and asks.

## Tests

`tests/test_runner_*.py` (128 tests, stdlib + pytest only, no new deps) cover next-task
detection, completed-task skipping, blocked-task surfacing, dependency ordering,
interrupted-`[~]` resume, ambiguity/duplicate/worktree-mismatch/protected-benchmark
STOPs, the evidence-gated completion decision, coherent task-group selection,
session-adapter argv/parsing, and the full cross-session supervisor lifecycle
(fresh sessions, checkpointing, recovery, loop protection, recursion guard). They
use temporary fixtures, throwaway git repos, and real fake-session subprocesses
only — never real project state, git history, or a real Claude session.

---

# Autopilot — cross-session supervisor

The runner above resolves and previews *one* task. **Autopilot** is the outer
supervisor that runs task groups *across fresh Claude sessions* autonomously, so
you don't reopen a session and paste the next prompt after every context limit.

```bash
./scripts/hunt-autopilot.sh --dry-run          # plan only — NO session is run
./scripts/hunt-autopilot.sh                     # run with safe defaults
./scripts/hunt-autopilot.sh --max-sessions 5 --max-group-size 2 \
    --expected-branch claude/phase1-cem-implementation-6e1693
```

Exit codes: **0** = done / dry-run, **2** = stopped (a human is needed).

## Model & effort

Autopilot runs **Claude Sonnet at high reasoning effort by default**. Each session
is launched with `claude --model sonnet --effort high` (verified against the
installed CLI, v2.1.260; `sonnet` is the CLI alias for the latest Sonnet, so no
obsolete model id is hard-coded). Override per run:

```bash
./scripts/hunt-autopilot.sh --model opus --effort max
```

`--effort` accepts `low, medium, high, xhigh, max`.

## The loop

```
read persisted state (plan file)
  → select ONE coherent task group (dependency-contiguous, size-capped)
  → launch a FRESH interactive Claude session (separate OS process) to execute it
  → wait for it to exit → rediscover state from disk + independently re-verify
  → checkpoint
  → automatically launch the next fresh interactive session
  → … until done / STOP / a safety limit
```

The supervisor rebuilds state from the plan file every iteration, so a session
that hit a context/session boundary and exited is simply followed by a fresh one
that resumes from disk. You do **not** manually open the next session.

## How fresh sessions are actually started (interactive by default)

**Default mode is `interactive`** — a normal, fully interactive Claude Code
session (verified against the installed CLI, v2.1.260, where `claude` "starts an
interactive session by default"):

```
claude --model sonnet --effort high --add-dir <repo> --session-id <fresh-uuid> "<seed prompt>"
```

No `-p`. The child **inherits your terminal**, so you talk to Claude normally and
Claude can ask you questions. The supervisor runs foreground in your terminal,
`wait()`s for the session to exit, then launches the next one. Each session's task
brief is also written to `.claude/autopilot-task.md` for the fresh session (and
you) to re-read.

Session launching is behind a pluggable `SessionAdapter`
([scripts/runner/session.py](scripts/runner/session.py)):
`InteractiveClaudeSessionAdapter` (default) and `ClaudeCliSessionAdapter`
(`--mode headless`, i.e. `claude -p … --output-format json`, for CI / non-TTY /
batch). Tests inject a deterministic fake that runs a real subprocess against the
plan file (no Claude, network, or auth).

### The one honest limitation

Capturing an interactive session's output would break interactivity, so the
supervisor **cannot observe the conversation** and there is **no documented
programmatic "context-limit reached" signal** in interactive mode — the session
simply exits and returns control. The supervisor therefore detects *session end*
via process exit and re-derives the *actual* result from disk (plan markers, git
diff, and the verifier). It also must run **foreground in a real terminal** (not a
detached daemon). To stop the loop cleanly, exit sessions without making progress
(stall detection halts it) or create the stop sentinel `.claude/autopilot-stop`.
This is genuine interactive relaunch automation; it does not claim to read or
steer the conversation itself.

## Independent verification (no blind trust)

After each session the supervisor **re-reads the plan, inspects git, and runs the
verifier**. If a session advanced plan state but verification fails, autopilot
STOPs (`verification_failed`) rather than trusting the completion. Progress is
measured from the persisted plan, not from anything the session *said*.

## Safety controls

- **Recursion guard** — the supervisor sets `HUNTMCP_AUTOPILOT_ACTIVE=1` on every
  spawned session's env; if a supervisor (Python or the shell launcher) sees it
  already set, it refuses to run. A session can never start another autopilot.
- **`--max-sessions`** hard cap (default 8) — bounds total sessions.
- **Stall / no-progress detection** (`--max-stall`, default 2) — if the plan
  signature doesn't change across N consecutive sessions (a session that fails or
  does nothing), autopilot STOPs with a diagnostic instead of looping forever.
- **Never bypasses permissions** — the adapter never adds
  `--dangerously-skip-permissions`. Unattended operation relies on the repo's
  settings allowlist + the scope-gate hook, or an explicit `--permission-mode`
  you choose. Fully-unattended autonomy is your configuration decision, not a
  default this automation turns on.
- **No git writes** — the supervisor only runs read-only `git` inspection; it
  never commits, stashes, resets, merges, or switches. It never crosses worktrees
  (worktree-mismatch STOPs before any session).
- **Human-decision / protected-benchmark / worktree gates** STOP with a decision
  request before running a session.

## Observability

Each iteration appends one JSON line to `.claude/autopilot-log.jsonl`: index,
group, `session_id`, start/end time, exit reason, checkpoint path, verification
result, next action, and any stop reason. Secrets (API keys, tokens, cookies,
session output) are never written to the log.

## Autopilot outcomes

`done` · `dry_run` · `stopped_by_user` (stop sentinel) · `human_decision` ·
`worktree_stop` · `protected_stop` · `verification_failed` · `no_progress` ·
`max_sessions` · `recursion_guard` · `stopped` (e.g. plan not found).

## What autopilot will NEVER do

- Run the whole roadmap in one session (it uses bounded coherent groups).
- Trust a completion claim without independent verification.
- Bypass Claude Code permissions, or push / merge / commit / PR.
- Perform any destructive git operation, or cross worktrees.
- Recurse into itself, or loop without progress.
