"""Autonomous session supervisor for the HuntMCP dev-runner.

The supervisor is the OUTER process that removes the manual overhead of opening a
new Claude Code session per Phase-1 task. It loops:

    read persisted state (plan file)
      -> select ONE coherent task group
      -> run a FRESH Claude session (separate process) to execute it
      -> independently re-verify + checkpoint (never trust the session's claim)
      -> decide whether another session is needed
      -> run the next fresh session
      -> ... until done / STOP / a safety limit

It runs each session through a pluggable :class:`SessionAdapter`, so the whole
lifecycle is testable with a deterministic fake (a real subprocess) and no real
Claude / network / auth.

Safety controls (all mandatory, none bypassable by this code):
* recursion guard -- refuses to run inside a spawned session
  (``HUNTMCP_AUTOPILOT_ACTIVE`` env);
* ``max_sessions`` hard cap;
* stall / no-progress detection (``max_stall``);
* worktree + protected-benchmark gates STOP before executing;
* human-decision graph states STOP with a decision request;
* an unverified completion claim STOPs (independent verification, not trust);
* the supervisor performs NO git writes -- only read-only ``git`` inspection.
"""
from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from . import checkpoint as ckpt
from . import context as ctxmod
from . import decision as decmod
from . import resolver as resmod
from . import state as statemod
from . import verify as verifymod
from . import worktree as wtmod
from .session import (
    EFFORT_LEVELS,
    RECURSION_GUARD_ENV,
    ClaudeCliSessionAdapter,
    InteractiveClaudeSessionAdapter,
)

# Autopilot runs Claude Sonnet at high reasoning effort by default (operator may
# override via --model / --effort). "sonnet" is the CLI's alias for the latest
# Sonnet, so no obsolete model id is hard-coded.
DEFAULT_MODEL = "sonnet"
DEFAULT_EFFORT = "high"


@dataclass
class SupervisorConfig:
    repo: str
    plan_path: str
    roadmap_path: str | None = None
    state_file: str | None = None
    log_path: str | None = None
    max_sessions: int = 8
    max_stall: int = 2            # consecutive no-progress iterations before STOP
    max_group_size: int = 3
    expected_branch: str | None = None
    require_clean: bool = False
    dry_run: bool = False
    session_timeout: int | None = None
    stop_sentinel: str | None = None   # if this file exists, stop the loop cleanly
    verbose: bool = False              # print inter-session banners to the terminal


@dataclass
class IterationRecord:
    index: int
    group: list[str]
    session_id: str | None = None
    start_time: str = ""
    end_time: str = ""
    exit_reason: str = ""          # session exit reason or gate outcome
    checkpoint: str | None = None
    verification_ok: bool | None = None
    next_action: str = ""
    stop_reason: str | None = None


@dataclass
class SupervisorReport:
    outcome: str                   # see module docstring
    iterations: list[IterationRecord] = field(default_factory=list)
    decision_request: decmod.DecisionRequest | None = None
    reason: str = ""


# verifier: (repo, changed_files, plan_path) -> (ok: bool, evidence: dict)
Verifier = Callable[..., tuple]
# build_prompt: (group_tasks, plan, project_state) -> str
PromptBuilder = Callable[..., str]


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _progress_sig(plan: statemod.Plan) -> tuple:
    """A deterministic signature of plan progress (task id -> marker)."""
    return tuple((t.id, t.marker) for t in plan.tasks)


def _default_verifier(repo, changed_files, plan_path) -> tuple:
    evidence = verifymod.run_verification(repo_dir=repo, changed_files=changed_files)
    ok = (
        evidence.get("tests_pass")
        and evidence.get("regression_pass")
        and evidence.get("lint_pass")
        and evidence.get("protected_unchanged")
    )
    return bool(ok), evidence


def _default_prompt(group_tasks, plan, project_state) -> str:
    lead = group_tasks[0]
    ctx = ctxmod.build_context(task=lead, plan=plan, project_state=project_state)
    ids = ", ".join(t.id for t in group_tasks)
    header = [
        "You are a fresh HuntMCP dev session started by the autopilot supervisor.",
        "Rediscover state from the repository -- do NOT rely on any prior conversation.",
        f"Execute ONLY this coherent task group, in order: {ids}.",
        (
            "For each task: work under TDD, run the required tests + regression, and only then "
            "flip its plan marker to [x] with evidence. STOP and surface a decision request on any "
            "genuine ambiguity or safety boundary instead of guessing."
        ),
        "",
    ]
    return "\n".join(header) + ctxmod.render(ctx)


def _changed_files(repo: str) -> list[str]:
    info = wtmod.git_context(repo)
    files = []
    for line in info.changes:
        path = line[3:].strip() if len(line) > 3 else line.strip()
        if "->" in path:
            path = path.split("->")[-1].strip()
        if path:
            files.append(path)
    return files


def _load_project_state(roadmap_path: str | None) -> dict:
    if not roadmap_path:
        return {}
    try:
        with open(roadmap_path, "r", encoding="utf-8") as fh:
            return statemod.parse_project_state(fh.read())
    except (FileNotFoundError, IsADirectoryError):
        return {}


def _log_iteration(log_path: str | None, rec: IterationRecord) -> None:
    if not log_path:
        return
    # Only structured, secret-free fields are persisted (never env or output tail).
    payload = {
        "index": rec.index,
        "group": rec.group,
        "session_id": rec.session_id,
        "start_time": rec.start_time,
        "end_time": rec.end_time,
        "exit_reason": rec.exit_reason,
        "checkpoint": rec.checkpoint,
        "verification_ok": rec.verification_ok,
        "next_action": rec.next_action,
        "stop_reason": rec.stop_reason,
    }
    os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload) + "\n")


def _counts(plan: statemod.Plan) -> dict:
    from collections import Counter

    c = Counter(t.status for t in plan.tasks)
    return {k: c.get(k, 0) for k in ("complete", "pending", "in_progress", "blocked")} | {"total": len(plan.tasks)}


def _write_checkpoint(cfg: SupervisorConfig, plan, group, wt_branch) -> str | None:
    if not cfg.state_file:
        return None
    data = ckpt.build_checkpoint(
        plan_source=cfg.plan_path,
        decision="execute",
        next_task=(group.tasks[0].id if group.tasks else None),
        next_task_title=(group.tasks[0].title if group.tasks else None),
        counts=_counts(plan),
        blocked_tasks=[t.id for t in group.blocked_tasks],
        stop_codes=[],
        worktree_branch=wt_branch,
    )
    os.makedirs(os.path.dirname(os.path.abspath(cfg.state_file)), exist_ok=True)
    ckpt.write_checkpoint(cfg.state_file, data)
    return cfg.state_file


def _persist_task_brief(cfg: SupervisorConfig, prompt: str) -> None:
    """Write the current session's task brief to disk next to the state file, so
    the fresh session (and the user) have a durable on-disk copy of the assigned
    context -- not just the launch-time seed prompt."""
    if not cfg.state_file:
        return
    brief = os.path.join(os.path.dirname(os.path.abspath(cfg.state_file)), "autopilot-task.md")
    os.makedirs(os.path.dirname(brief), exist_ok=True)
    with open(brief, "w", encoding="utf-8") as fh:
        fh.write(prompt if prompt.endswith("\n") else prompt + "\n")


def run_autopilot(
    config: SupervisorConfig,
    adapter,
    verifier: Verifier | None = None,
    build_prompt: PromptBuilder | None = None,
    env: dict | None = None,
) -> SupervisorReport:
    env = os.environ if env is None else env
    verifier = verifier or _default_verifier
    build_prompt = build_prompt or _default_prompt
    report = SupervisorReport(outcome="stopped")

    # --- recursion guard: never run inside a spawned session ---
    if env.get(RECURSION_GUARD_ENV) == "1":
        report.outcome = "recursion_guard"
        report.reason = (
            f"{RECURSION_GUARD_ENV} is set: this process is already inside an autopilot-launched "
            "session. Refusing to start a nested supervisor (infinite-recursion guard)."
        )
        return report

    stall = 0
    session_count = 0

    while True:
        # user stop sentinel: a clean, explicit way to halt the loop between
        # sessions (the user, or Claude on a genuine decision, can create it).
        if config.stop_sentinel and os.path.exists(config.stop_sentinel):
            report.outcome = "stopped_by_user"
            report.reason = f"Stop sentinel present ({config.stop_sentinel}); halting the autopilot loop."
            return report

        # safety cap
        if session_count >= config.max_sessions:
            report.outcome = "max_sessions"
            report.reason = f"Reached max_sessions={config.max_sessions}; stopping to avoid runaway sessions."
            return report

        # 1. read persisted state
        try:
            plan = statemod.load_plan(config.plan_path)
        except statemod.PlanNotFoundError:
            report.outcome = "stopped"
            report.decision_request = decmod.DecisionRequest(
                task_id="(none)",
                ambiguity=f"Plan file not found at {config.plan_path}.",
                contract="The supervisor needs PHASE1-EXECUTION-PLAN.md to determine the next group.",
                options=["Point --plan at the authoritative plan", "Restore the plan into this worktree"],
                recommendation=None,
                downstream=["all subsequent sessions"],
                stop_codes=["PLAN_NOT_FOUND"],
            )
            report.reason = report.decision_request.ambiguity
            return report

        project_state = _load_project_state(config.roadmap_path)

        # 2. worktree safety gate (read-only)
        wt_info = wtmod.git_context(config.repo)
        wt_check = wtmod.assess(wt_info, expected_branch=config.expected_branch, require_clean=config.require_clean)
        if not wt_check.ok:
            report.outcome = "worktree_stop"
            report.decision_request = decmod.DecisionRequest(
                task_id="(pre-session)",
                ambiguity=wt_check.reason,
                contract="Worktree isolation (.claude/rules/git-worktrees.md).",
                options=["Switch to the correct worktree/branch manually", "Reconcile changes intentionally"],
                recommendation=None,
                downstream=["all subsequent sessions"],
                stop_codes=wt_check.stop_codes,
            )
            report.reason = wt_check.reason
            return report

        # 3. select a coherent task group
        group = resmod.select_task_group(
            plan, max_size=config.max_group_size, protected_check=verifymod.detect_protected_touch
        )

        if group.decision == "done":
            report.outcome = "done"
            report.reason = "All tasks complete; nothing left to execute."
            return report

        if group.decision == "stop":
            report.outcome = "human_decision"
            report.decision_request = decmod.DecisionRequest(
                task_id="(undetermined)",
                ambiguity=group.reason,
                contract="PHASE1-EXECUTION-PLAN.md task graph (states + deps).",
                options=["Reconcile the plan graph", "Resolve the blocking dependency / conflict"],
                recommendation=None,
                downstream=[t.id for t in group.blocked_tasks],
                stop_codes=group.stop_codes,
            )
            report.reason = group.reason
            return report

        lead = group.tasks[0]

        # 4. protected-benchmark gate on the lead task itself
        protected = verifymod.detect_protected_touch(lead.files)
        if protected:
            report.outcome = "protected_stop"
            report.decision_request = decmod.DecisionRequest(
                task_id=lead.id,
                ambiguity=f"Task {lead.id} touches protected benchmark asset(s): {', '.join(protected)}",
                contract="Protected benchmark methodology (.claude/rules/benchmarks.md).",
                options=["Obtain explicit human approval", "Re-scope the task off protected assets"],
                recommendation=None,
                downstream=[lead.id],
                stop_codes=["PROTECTED_BENCHMARK_TOUCH"],
            )
            report.reason = report.decision_request.ambiguity
            return report

        group_ids = [t.id for t in group.tasks]
        rec = IterationRecord(index=len(report.iterations) + 1, group=group_ids, start_time=_now())

        # 5. dry-run: plan only, perform NO session execution and write NOTHING
        # to disk (no log, no checkpoint, no task brief) -- a pure preview.
        if config.dry_run:
            rec.exit_reason = "dry_run"
            rec.next_action = f"would run session for group {group_ids}"
            rec.end_time = _now()
            report.iterations.append(rec)   # in-memory only
            report.outcome = "dry_run"
            report.reason = f"Dry run: next group would be {group_ids}; no session executed."
            return report

        # 6. run a FRESH session (separate process) for this group
        sig_before = _progress_sig(plan)
        prompt = build_prompt(group.tasks, plan, project_state)
        _persist_task_brief(config, prompt)
        if config.verbose:
            print(
                f"\n=== autopilot: launching fresh session #{session_count + 1} for group {group_ids} ===",
                flush=True,
            )
        # base env carries the recursion guard so the child cannot spawn another autopilot
        base_env = dict(env)
        base_env[RECURSION_GUARD_ENV] = "1"

        session_count += 1
        result = adapter.run_session(
            prompt=prompt,
            repo=config.repo,
            timeout=config.session_timeout,
            base_env=base_env,
            group_ids=group_ids,
        )
        rec.session_id = result.session_id
        rec.exit_reason = result.exit_reason
        rec.end_time = _now()

        # 7. rediscover actual state + independently verify (never trust the claim)
        plan_after = statemod.load_plan(config.plan_path)
        sig_after = _progress_sig(plan_after)
        progressed = sig_after != sig_before

        verify_ok, _evidence = verifier(config.repo, _changed_files(config.repo), config.plan_path)
        rec.verification_ok = verify_ok

        if progressed and not verify_ok:
            # the session advanced plan state but verification does not support it
            rec.next_action = "STOP: unverified completion"
            rec.stop_reason = "verification_failed"
            report.iterations.append(rec)
            _log_iteration(config.log_path, rec)
            report.outcome = "verification_failed"
            report.decision_request = decmod.DecisionRequest(
                task_id=lead.id,
                ambiguity=(
                    f"Session {result.session_id} advanced plan state for {group_ids} but independent "
                    "verification failed. Not trusting the completion."
                ),
                contract="Completion requires measured evidence (.claude/rules/testing.md).",
                options=["Inspect the failing verification and fix", "Revert the unverified plan change"],
                recommendation=None,
                downstream=group_ids,
                stop_codes=["VERIFICATION_FAILED"],
            )
            report.reason = report.decision_request.ambiguity
            return report

        if progressed:
            stall = 0
            rec.checkpoint = _write_checkpoint(config, plan_after, group, wt_info.branch)
            rec.next_action = "continue: next fresh session"
            report.iterations.append(rec)
            _log_iteration(config.log_path, rec)
            continue

        # no progress this iteration (session failed / did nothing)
        stall += 1
        rec.next_action = f"no progress (stall {stall}/{config.max_stall})"
        report.iterations.append(rec)
        _log_iteration(config.log_path, rec)
        if stall >= config.max_stall:
            report.outcome = "no_progress"
            report.reason = (
                f"No plan progress across {stall} consecutive sessions "
                f"(last exit_reason={result.exit_reason}); stopping to avoid a runaway loop."
            )
            return report
        # else: loop again (bounded by stall cap and max_sessions)


# --------------------------------------------------------------------------- #
# CLI entrypoint (used by scripts/hunt-autopilot.sh)                          #
# --------------------------------------------------------------------------- #

_EXIT_OK = 0
_EXIT_ATTENTION = 2


def _summarize(report: SupervisorReport) -> str:
    lines = [f"AUTOPILOT OUTCOME: {report.outcome}"]
    if report.reason:
        lines.append(f"Reason: {report.reason}")
    lines.append(f"Sessions run: {len([r for r in report.iterations if r.exit_reason != 'dry_run'])}")
    for r in report.iterations:
        lines.append(
            f"  [{r.index}] group={r.group} session={r.session_id} exit={r.exit_reason} "
            f"verified={r.verification_ok} next={r.next_action}"
        )
    if report.decision_request is not None:
        lines.append("")
        lines.append(decmod.format_decision_request(report.decision_request))
    return "\n".join(lines)


def build_parser():
    import argparse

    p = argparse.ArgumentParser(
        prog="hunt-autopilot",
        description="Outer supervisor that runs coherent HuntMCP task groups across fresh Claude sessions.",
    )
    p.add_argument("--repo", default=".")
    p.add_argument("--plan", default=None)
    p.add_argument("--roadmap", default=None)
    p.add_argument("--state-file", default=None)
    p.add_argument("--log", default=None)
    p.add_argument("--max-sessions", type=int, default=8)
    p.add_argument("--max-stall", type=int, default=2)
    p.add_argument("--max-group-size", type=int, default=3)
    p.add_argument("--session-timeout", type=int, default=None)
    p.add_argument("--expected-branch", default=None)
    p.add_argument("--require-clean", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--mode", default="interactive", choices=["interactive", "headless"],
                   help="Session mode. 'interactive' (default) launches a normal interactive "
                        "Claude session on your terminal so Claude can ask you questions; "
                        "'headless' uses `claude -p` (batch, for CI / non-TTY).")
    p.add_argument("--model", default=DEFAULT_MODEL,
                   help=f"Model for each session (passed to `claude --model`). Default: {DEFAULT_MODEL} "
                        "(alias for the latest Sonnet).")
    p.add_argument("--effort", default=DEFAULT_EFFORT, choices=list(EFFORT_LEVELS),
                   help=f"Reasoning effort for each session (passed to `claude --effort`). "
                        f"Default: {DEFAULT_EFFORT}.")
    p.add_argument("--permission-mode", default=None,
                   help="Passed to `claude --permission-mode`. The supervisor never adds "
                        "--dangerously-skip-permissions.")
    p.add_argument("--claude-bin", default="claude")
    return p


def build_adapter(args):
    """Construct the session adapter from parsed args (never bypasses permissions).

    Interactive mode (the default) launches a normal interactive Claude session;
    headless mode uses `claude -p` for CI / non-TTY / batch use.
    """
    if getattr(args, "mode", "interactive") == "headless":
        return ClaudeCliSessionAdapter(
            claude_bin=args.claude_bin,
            model=args.model,
            effort=args.effort,
            permission_mode=args.permission_mode,
        )
    return InteractiveClaudeSessionAdapter(
        claude_bin=args.claude_bin,
        model=args.model,
        effort=args.effort,
        permission_mode=args.permission_mode,
    )


def main(argv=None, adapter=None) -> int:
    args = build_parser().parse_args(argv)

    repo = args.repo
    plan = args.plan or os.path.join(repo, "PHASE1-EXECUTION-PLAN.md")
    roadmap = args.roadmap or os.path.join(repo, "ROADMAP.md")
    state_file = args.state_file or os.path.join(repo, ".claude", "runner-state.json")
    log_path = args.log or os.path.join(repo, ".claude", "autopilot-log.jsonl")
    stop_sentinel = os.path.join(os.path.dirname(os.path.abspath(state_file)), "autopilot-stop")

    cfg = SupervisorConfig(
        repo=repo,
        plan_path=plan,
        roadmap_path=roadmap,
        state_file=state_file,
        log_path=log_path,
        max_sessions=args.max_sessions,
        max_stall=args.max_stall,
        max_group_size=args.max_group_size,
        session_timeout=args.session_timeout,
        expected_branch=args.expected_branch,
        require_clean=args.require_clean,
        dry_run=args.dry_run,
        stop_sentinel=stop_sentinel,
        verbose=True,
    )

    if adapter is None:
        adapter = build_adapter(args)

    report = run_autopilot(cfg, adapter=adapter)
    print(_summarize(report))
    return _EXIT_OK if report.outcome in ("done", "dry_run", "stopped_by_user") else _EXIT_ATTENTION


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
