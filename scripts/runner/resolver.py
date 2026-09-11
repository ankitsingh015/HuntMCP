"""Next-task resolver for the HuntMCP dev-runner.

Given a parsed :class:`~runner.state.Plan`, decide the single next action. The
resolver is a pure function of the plan -- it holds no memory between calls, so
a fresh session that re-parses the same plan reaches the same decision.

Decisions:

* ``execute`` -- one pending task whose dependencies are all complete.
* ``resume``  -- exactly one ``[~]`` in-progress task (re-inspect before continuing).
* ``done``    -- every task complete.
* ``stop``    -- an ambiguous / blocked / broken graph. Never guessed past.

STOP codes are explicit so the human-decision gate can explain precisely why the
runner will not proceed:

* ``PLAN_EMPTY``          -- no tasks parsed.
* ``DUPLICATE_TASK_IDS``  -- the same task id defined twice (conflicting state).
* ``UNKNOWN_DEPENDENCY``  -- a task depends on an id that does not exist.
* ``MULTIPLE_IN_PROGRESS``-- more than one ``[~]`` task (which one to resume?).
* ``NO_ACTIONABLE_TASK``  -- pending tasks exist but none can start (deps unmet /
  blocked), and nothing is in progress.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .state import Plan, Task


@dataclass
class Resolution:
    decision: str  # "execute" | "resume" | "done" | "stop"
    task: Task | None = None
    reason: str = ""
    stop_codes: list[str] = field(default_factory=list)
    blocked_tasks: list[Task] = field(default_factory=list)
    in_progress_tasks: list[Task] = field(default_factory=list)
    unmet_deps: dict[str, list[str]] = field(default_factory=dict)


def _deps_complete(task: Task, by_id: dict[str, Task]) -> bool:
    for dep in task.deps:
        d = by_id.get(dep)
        if d is None or d.status != "complete":
            return False
    return True


def _unmet_dep_ids(task: Task, by_id: dict[str, Task]) -> list[str]:
    unmet = []
    for dep in task.deps:
        d = by_id.get(dep)
        if d is None or d.status != "complete":
            unmet.append(dep)
    return unmet


def resolve_next(plan: Plan) -> Resolution:
    by_id = {t.id: t for t in plan.tasks}
    blocked = [t for t in plan.tasks if t.status == "blocked"]
    in_progress = [t for t in plan.tasks if t.status == "in_progress"]

    # --- graph-integrity STOP conditions (checked before selection) ---
    if not plan.tasks:
        return Resolution(
            decision="stop",
            reason="Plan contains no tasks; the next task cannot be determined.",
            stop_codes=["PLAN_EMPTY"],
        )

    if plan.duplicate_ids:
        return Resolution(
            decision="stop",
            reason=(
                "Duplicate task id(s) "
                + ", ".join(plan.duplicate_ids)
                + " -- conflicting project-state; cannot determine next task unambiguously."
            ),
            stop_codes=["DUPLICATE_TASK_IDS"],
            blocked_tasks=blocked,
            in_progress_tasks=in_progress,
        )

    unknown = {}
    for t in plan.tasks:
        missing = [d for d in t.deps if d not in by_id]
        if missing:
            unknown[t.id] = missing
    if unknown:
        detail = "; ".join(f"{tid} -> {', '.join(ms)}" for tid, ms in unknown.items())
        return Resolution(
            decision="stop",
            reason=f"Task(s) depend on undefined ids ({detail}); plan is inconsistent.",
            stop_codes=["UNKNOWN_DEPENDENCY"],
            blocked_tasks=blocked,
            in_progress_tasks=in_progress,
            unmet_deps=unknown,
        )

    # --- in-progress handling ---
    if len(in_progress) > 1:
        ids = ", ".join(t.id for t in in_progress)
        return Resolution(
            decision="stop",
            reason=(
                f"Multiple tasks are in progress ({ids}); cannot decide which to resume. "
                "Reconcile the plan to a single [~] before continuing."
            ),
            stop_codes=["MULTIPLE_IN_PROGRESS"],
            blocked_tasks=blocked,
            in_progress_tasks=in_progress,
        )
    if len(in_progress) == 1:
        t = in_progress[0]
        return Resolution(
            decision="resume",
            task=t,
            reason=(
                f"Task {t.id} is in progress ([~]). Re-inspect the worktree and re-verify its "
                "actual state before continuing -- do not trust a prior completion claim."
            ),
            blocked_tasks=blocked,
            in_progress_tasks=in_progress,
        )

    # --- no in-progress: pick earliest actionable pending task ---
    pending = [t for t in plan.tasks if t.status == "pending"]
    if not pending:
        return Resolution(
            decision="done",
            reason="Every task is complete ([x]); nothing left to execute.",
            blocked_tasks=blocked,
        )

    for t in pending:  # document order == plan.tasks order
        if _deps_complete(t, by_id):
            return Resolution(
                decision="execute",
                task=t,
                reason=f"Task {t.id} is the earliest pending task with all dependencies complete.",
                blocked_tasks=blocked,
            )

    # pending tasks remain but none are actionable
    unmet = {t.id: _unmet_dep_ids(t, by_id) for t in pending}
    return Resolution(
        decision="stop",
        reason=(
            "Pending tasks remain but none can start -- their dependencies are unmet or blocked. "
            "Human attention required to unblock the graph."
        ),
        stop_codes=["NO_ACTIONABLE_TASK"],
        blocked_tasks=blocked,
        unmet_deps=unmet,
    )


@dataclass
class TaskGroup:
    decision: str  # "execute" | "resume" | "done" | "stop"
    tasks: list[Task] = field(default_factory=list)
    reason: str = ""
    stop_codes: list[str] = field(default_factory=list)
    blocked_tasks: list[Task] = field(default_factory=list)

    @property
    def ids(self) -> list[str]:
        return [t.id for t in self.tasks]


def select_task_group(plan, max_size: int = 3, protected_check=None):
    """Select the next coherent task group -- the unit of one autonomous session.

    Starts from :func:`resolve_next`. For an ``execute`` decision it greedily
    extends the group with the following pending tasks whose dependencies are all
    satisfied by ``completed ∪ group-so-far`` (a dependency-contiguous frontier),
    in document order, up to ``max_size``. It never crosses a task that needs its
    own human gate: a protected-benchmark touch (via ``protected_check``) or a
    ``| all |`` final-gate task. ``resume`` / ``done`` / ``stop`` are passed
    through unchanged (resume/execute carry their task(s)).
    """
    r = resolve_next(plan)
    if r.decision == "done":
        return TaskGroup(decision="done", reason=r.reason)
    if r.decision == "stop":
        return TaskGroup(
            decision="stop",
            reason=r.reason,
            stop_codes=list(r.stop_codes),
            blocked_tasks=list(r.blocked_tasks),
        )
    if r.decision == "resume":
        return TaskGroup(decision="resume", tasks=[r.task], reason=r.reason)

    # execute: build the group starting from the lead task
    lead = r.task
    group = [lead]
    satisfied = {t.id for t in plan.tasks if t.status == "complete"}
    satisfied.add(lead.id)

    if max_size > 1:
        for t in plan.tasks:
            if len(group) >= max_size:
                break
            if t.status != "pending" or t.id in {g.id for g in group}:
                continue
            if t.deps_all:  # final-gate task -- never fold into a normal group
                break
            if protected_check is not None and protected_check(t.files):
                # a protected-benchmark task needs its own approval gate
                continue
            if all(d in satisfied for d in t.deps):
                group.append(t)
                satisfied.add(t.id)

    ids = ", ".join(g.id for g in group)
    return TaskGroup(
        decision="execute",
        tasks=group,
        reason=f"Coherent group [{ids}] — earliest actionable task plus its dependency-contiguous run.",
    )
