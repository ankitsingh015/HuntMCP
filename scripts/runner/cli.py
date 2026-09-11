"""Command-line orchestration for the HuntMCP dev-runner.

Ties together the state reader, next-task resolver, worktree-safety gate,
protected-benchmark gate, task-context generator, verification gate, and
human-decision gate.

Commands (all read-only except ``checkpoint``, which writes a runner-owned JSON
cache -- never the plan):

    status      one-line-ish summary: phase, counts, next action, blocks
    next        just the next task / decision (``--json`` for machine output)
    dry-run     safe preview: full task context, or a decision request if STOP
    context     the generated task context for the next (or ``--task``) task
    check       worktree safety only (branch / status / mismatch)
    verify      run mechanical checks, print evidence + completion-gate verdict
    checkpoint  write the resumable JSON state cache

Exit codes: 0 = OK / actionable / done, 2 = STOP (human decision required).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter

from . import checkpoint as ckpt
from . import context as ctxmod
from . import decision as decmod
from . import resolver as resmod
from . import state as statemod
from . import verify as verifymod
from . import worktree as wtmod

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_STOP = 2


# --------------------------------------------------------------------------- #
# assessment: combine resolver + worktree + protected gates                   #
# --------------------------------------------------------------------------- #

class Assessment:
    def __init__(self):
        self.status = "ok"                      # "ok" | "stop" | "done"
        self.resolution: resmod.Resolution | None = None
        self.plan: statemod.Plan | None = None
        self.project_state: dict = {}
        self.worktree_info: wtmod.WorktreeInfo | None = None
        self.decision_request: decmod.DecisionRequest | None = None
        self.protected_touched: list[str] = []
        self.counts: dict = {}


def _counts(plan: statemod.Plan) -> dict:
    c = Counter(t.status for t in plan.tasks)
    return {
        "complete": c.get("complete", 0),
        "pending": c.get("pending", 0),
        "in_progress": c.get("in_progress", 0),
        "blocked": c.get("blocked", 0),
        "total": len(plan.tasks),
    }


def _load_project_state(roadmap_path: str) -> dict:
    try:
        with open(roadmap_path, "r", encoding="utf-8") as fh:
            return statemod.parse_project_state(fh.read())
    except (FileNotFoundError, IsADirectoryError):
        return {}


def _assess(args) -> Assessment:
    a = Assessment()

    # 1. read state
    try:
        plan = statemod.load_plan(args.plan)
    except statemod.PlanNotFoundError:
        a.status = "stop"
        a.decision_request = decmod.DecisionRequest(
            task_id="(none)",
            ambiguity=f"Plan file not found at {args.plan}.",
            contract="The runner needs PHASE1-EXECUTION-PLAN.md to determine the next task.",
            options=[
                "Point --plan at the authoritative plan file",
                "Restore/commit the plan into this worktree",
            ],
            recommendation=None,
            downstream=["every subsequent task selection"],
            stop_codes=["PLAN_NOT_FOUND"],
        )
        return a

    a.plan = plan
    a.counts = _counts(plan)
    a.project_state = _load_project_state(args.roadmap)

    # 2. resolve next task
    res = resmod.resolve_next(plan)
    a.resolution = res

    if res.decision == "done":
        a.status = "done"
        return a

    if res.decision == "stop":
        a.status = "stop"
        a.decision_request = decmod.DecisionRequest(
            task_id="(undetermined)",
            ambiguity=res.reason,
            contract="PHASE1-EXECUTION-PLAN.md task graph (states + deps).",
            options=[
                "Reconcile the plan so exactly one task is [~] or the next [ ] is unblocked",
                "Resolve the blocking dependency / conflict, then re-run",
            ],
            recommendation=None,
            downstream=[t.id for t in (res.blocked_tasks or [])],
            stop_codes=res.stop_codes,
        )
        return a

    # decision is execute / resume -> apply safety gates before proceeding
    task = res.task

    # 3. worktree safety
    a.worktree_info = wtmod.git_context(args.repo)
    wcheck = wtmod.assess(
        a.worktree_info,
        expected_branch=args.expected_branch,
        require_clean=args.require_clean,
    )
    if not wcheck.ok:
        a.status = "stop"
        a.decision_request = decmod.DecisionRequest(
            task_id=task.id,
            ambiguity=wcheck.reason,
            contract="Worktree isolation (.claude/rules/git-worktrees.md).",
            options=[
                "Switch to the correct worktree/branch manually",
                "Reconcile uncommitted changes intentionally, then re-run",
            ],
            recommendation=None,
            downstream=[task.id],
            stop_codes=wcheck.stop_codes,
        )
        return a

    # 4. protected-benchmark gate
    a.protected_touched = verifymod.detect_protected_touch(task.files)
    if a.protected_touched:
        a.status = "stop"
        a.decision_request = decmod.DecisionRequest(
            task_id=task.id,
            ambiguity=(
                f"Task {task.id} declares changes to protected benchmark/evaluator asset(s): "
                + ", ".join(a.protected_touched)
            ),
            contract="Protected benchmark methodology (.claude/rules/benchmarks.md).",
            options=[
                "Obtain explicit human approval to modify the protected asset",
                "Re-scope the task so it does not touch protected assets",
            ],
            recommendation=None,
            downstream=[task.id],
            stop_codes=["PROTECTED_BENCHMARK_TOUCH"],
        )
        return a

    a.status = "ok"
    return a


# --------------------------------------------------------------------------- #
# command handlers                                                            #
# --------------------------------------------------------------------------- #

def _cmd_status(args) -> int:
    a = _assess(args)
    res = a.resolution
    if args.json:
        payload = {
            "status": a.status,
            "decision": res.decision if res else "stop",
            "next_task": (res.task.id if res and res.task else None),
            "counts": a.counts,
            "stop_codes": (a.decision_request.stop_codes if a.decision_request else []),
            "blocked": [t.id for t in (res.blocked_tasks if res else [])],
        }
        print(json.dumps(payload, indent=2))
    else:
        phase = a.project_state.get("CURRENT PHASE", "(unknown)")
        print(f"Phase:   {phase}")
        print(f"Tasks:   {a.counts}")
        if a.status == "done":
            print("Decision: done — every task complete.")
        elif a.status == "stop":
            print("Decision: STOP — human decision required.")
            print()
            print(decmod.format_decision_request(a.decision_request))
        else:
            print(f"Decision: {res.decision} — {res.task.id}: {res.task.title}")
            print(f"Reason:   {res.reason}")
        if res and res.blocked_tasks:
            print("Blocked:  " + ", ".join(t.id for t in res.blocked_tasks))
    return EXIT_STOP if a.status == "stop" else EXIT_OK


def _cmd_next(args) -> int:
    a = _assess(args)
    res = a.resolution
    if args.json:
        payload = {
            "decision": res.decision if res else "stop",
            "next_task": (res.task.id if res and res.task else None),
            "title": (res.task.title if res and res.task else None),
            "stop_codes": (a.decision_request.stop_codes if a.decision_request else []),
        }
        print(json.dumps(payload, indent=2))
    else:
        if a.status == "stop":
            print("STOP: " + ", ".join(a.decision_request.stop_codes))
        elif a.status == "done":
            print("done — every task complete.")
        else:
            print(f"{res.decision}: {res.task.id} — {res.task.title}")
            if res.decision == "resume":
                print(res.reason)
    return EXIT_STOP if a.status == "stop" else EXIT_OK


def _cmd_dry_run(args) -> int:
    a = _assess(args)
    if a.status == "stop":
        print(decmod.format_decision_request(a.decision_request))
        return EXIT_STOP
    if a.status == "done":
        print("done — every task complete; nothing to execute.")
        return EXIT_OK

    res = a.resolution
    print(f"DRY RUN — no source will be modified. Next action: {res.decision}")
    if res.decision == "resume":
        print(f"RESUME NOTE: {res.reason}")
    if a.worktree_info:
        print(f"Worktree: branch={a.worktree_info.branch or '(none)'} "
              f"dirty={a.worktree_info.dirty}")
    print()
    ctx = ctxmod.build_context(
        task=res.task,
        plan=a.plan,
        project_state=a.project_state,
        repo_dir=args.repo,
    )
    print(ctxmod.render(ctx))
    return EXIT_OK


def _cmd_context(args) -> int:
    a = _assess(args)
    if a.status == "stop":
        print(decmod.format_decision_request(a.decision_request))
        return EXIT_STOP
    if a.status == "done":
        print("done — every task complete.")
        return EXIT_OK
    res = a.resolution
    ctx = ctxmod.build_context(
        task=res.task, plan=a.plan, project_state=a.project_state, repo_dir=args.repo
    )
    print(ctxmod.render(ctx))
    return EXIT_OK


def _cmd_check(args) -> int:
    info = wtmod.git_context(args.repo)
    check = wtmod.assess(
        info, expected_branch=args.expected_branch, require_clean=args.require_clean
    )
    print(f"Branch:    {info.branch or '(unknown / not a git repo)'}")
    print(f"Toplevel:  {info.toplevel or '(unknown)'}")
    print(f"Dirty:     {info.dirty} ({len(info.changes)} change(s))")
    if info.worktrees:
        print("Worktrees:")
        for path, br in info.worktrees:
            print(f"  - {br}: {path}")
    for w in check.warnings:
        print(f"WARN: {w}")
    if not check.ok:
        print("STOP: " + ", ".join(check.stop_codes))
        print(check.reason)
        return EXIT_STOP
    return EXIT_OK


def _changed_files(repo: str) -> list[str]:
    info = wtmod.git_context(repo)
    files = []
    for line in info.changes:
        # porcelain "XY path" (path may be renamed "old -> new"); take the last token
        path = line[3:].strip() if len(line) > 3 else line.strip()
        if "->" in path:
            path = path.split("->")[-1].strip()
        if path:
            files.append(path)
    return files


def _cmd_verify(args, run=None) -> int:
    changed = _changed_files(args.repo)
    evidence = verifymod.run_verification(
        repo_dir=args.repo,
        changed_files=changed,
        python=sys.executable,
        run=run,
    )
    gate = verifymod.evaluate_completion(evidence)
    print("Evidence:")
    for k in verifymod.REQUIRED_EVIDENCE:
        print(f"  {k}: {evidence.get(k, '(missing)')}")
    if evidence.get("protected_touched"):
        print("  protected_touched: " + ", ".join(evidence["protected_touched"]))
    print()
    print(gate.reason)
    print(
        "\nNote: 'no_unexplained_regression' and 'docs_updated' require explicit human "
        "confirmation — the runner never marks [x] on a bare claim."
    )
    return EXIT_OK if gate.permitted else EXIT_STOP


def _cmd_checkpoint(args) -> int:
    a = _assess(args)
    if a.status == "stop" and a.decision_request and "PLAN_NOT_FOUND" in a.decision_request.stop_codes:
        print(decmod.format_decision_request(a.decision_request))
        return EXIT_STOP

    res = a.resolution
    data = ckpt.build_checkpoint(
        plan_source=args.plan,
        decision=(res.decision if res else "stop"),
        next_task=(res.task.id if res and res.task else None),
        next_task_title=(res.task.title if res and res.task else None),
        counts=a.counts,
        blocked_tasks=[t.id for t in (res.blocked_tasks if res else [])],
        stop_codes=(a.decision_request.stop_codes if a.decision_request else []),
        worktree_branch=(a.worktree_info.branch if a.worktree_info else None),
    )
    state_file = args.state_file
    os.makedirs(os.path.dirname(os.path.abspath(state_file)), exist_ok=True)
    ckpt.write_checkpoint(state_file, data)
    print(f"Checkpoint written: {state_file}")
    print(f"  decision={data['decision']} next_task={data['next_task']}")
    return EXIT_OK


# --------------------------------------------------------------------------- #
# argument parsing / entrypoint                                              #
# --------------------------------------------------------------------------- #

def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--repo", default=".", help="Repository/worktree directory (default: cwd).")
    p.add_argument("--plan", default=None, help="Path to PHASE1-EXECUTION-PLAN.md.")
    p.add_argument("--roadmap", default=None, help="Path to ROADMAP.md (for PROJECT STATE).")
    p.add_argument("--expected-branch", default=None, help="Branch the task must run on.")
    p.add_argument("--state-file", default=None, help="Checkpoint JSON path.")
    p.add_argument("--require-clean", action="store_true", help="STOP if the tree is dirty.")
    p.add_argument("--json", action="store_true", help="Machine-readable output where supported.")


def _finalize_paths(args) -> None:
    if args.plan is None:
        args.plan = os.path.join(args.repo, "PHASE1-EXECUTION-PLAN.md")
    if args.roadmap is None:
        args.roadmap = os.path.join(args.repo, "ROADMAP.md")
    if args.state_file is None:
        args.state_file = os.path.join(args.repo, ".claude", "runner-state.json")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hunt-runner",
        description="Controlled, resumable autonomous development runner for HuntMCP.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("status", "next", "dry-run", "context", "check", "verify", "checkpoint"):
        sp = sub.add_parser(name)
        _add_common(sp)
    return parser


def main(argv=None, run=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _finalize_paths(args)

    if args.command == "status":
        return _cmd_status(args)
    if args.command == "next":
        return _cmd_next(args)
    if args.command == "dry-run":
        return _cmd_dry_run(args)
    if args.command == "context":
        return _cmd_context(args)
    if args.command == "check":
        return _cmd_check(args)
    if args.command == "verify":
        return _cmd_verify(args, run=run)
    if args.command == "checkpoint":
        return _cmd_checkpoint(args)
    parser.error(f"unknown command: {args.command}")
    return EXIT_USAGE


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
