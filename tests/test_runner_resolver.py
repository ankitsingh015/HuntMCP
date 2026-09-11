"""Tests for the dev-runner next-task resolver (scripts/runner/resolver.py).

The resolver consumes a parsed Plan and decides the single next action:
execute / resume / stop / done. It never guesses past an ambiguity -- ambiguous
or blocked graph states resolve to STOP with explicit codes.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

from runner import resolver, state  # noqa: E402


def _plan(text):
    return state.parse_plan(text)


def test_selects_first_pending_task_with_satisfied_deps():
    plan = _plan(
        "- [x] **A1** — done. | none | f | verify: v | accept: a. **DONE.**\n"
        "- [ ] **A2** — next. | A1 | f | verify: v | accept: a.\n"
    )
    r = resolver.resolve_next(plan)
    assert r.decision == "execute"
    assert r.task.id == "A2"


def test_skips_completed_tasks():
    plan = _plan(
        "- [x] **A1** — done. | none | f | verify: v | accept: a. **DONE.**\n"
        "- [x] **A2** — done. | A1 | f | verify: v | accept: a. **DONE.**\n"
        "- [ ] **A3** — next. | A2 | f | verify: v | accept: a.\n"
    )
    r = resolver.resolve_next(plan)
    assert r.decision == "execute"
    assert r.task.id == "A3"


def test_respects_dependency_order_not_document_order():
    # B1 appears before A2 but depends on A2 (not done); the earliest ACTIONABLE
    # task is A2, so A2 is selected, not B1.
    plan = _plan(
        "- [x] **A1** — done. | none | f | verify: v | accept: a. **DONE.**\n"
        "- [ ] **B1** — needs A2. | A2 | f | verify: v | accept: a.\n"
        "- [ ] **A2** — startable. | A1 | f | verify: v | accept: a.\n"
    )
    r = resolver.resolve_next(plan)
    assert r.decision == "execute"
    assert r.task.id == "A2"


def test_in_progress_task_is_resumed():
    plan = _plan(
        "- [x] **A1** — done. | none | f | verify: v | accept: a. **DONE.**\n"
        "- [~] **A2** — interrupted. | A1 | f | verify: v | accept: a.\n"
        "- [ ] **A3** — later. | A2 | f | verify: v | accept: a.\n"
    )
    r = resolver.resolve_next(plan)
    assert r.decision == "resume"
    assert r.task.id == "A2"
    # resume must warn that worktree/verification state has to be re-inspected.
    assert "inspect" in r.reason.lower() or "verify" in r.reason.lower()


def test_multiple_in_progress_is_ambiguous_stop():
    plan = _plan(
        "- [~] **A1** — one. | none | f | verify: v | accept: a.\n"
        "- [~] **A2** — two. | none | f | verify: v | accept: a.\n"
    )
    r = resolver.resolve_next(plan)
    assert r.decision == "stop"
    assert "MULTIPLE_IN_PROGRESS" in r.stop_codes


def test_blocked_task_is_surfaced():
    plan = _plan(
        "- [x] **A1** — done. | none | f | verify: v | accept: a. **DONE.**\n"
        "- [!] **A2** — blocked. | A1 | f | verify: v | accept: a.\n"
        "- [ ] **A3** — needs A2. | A2 | f | verify: v | accept: a.\n"
    )
    r = resolver.resolve_next(plan)
    assert r.decision == "stop"
    assert "NO_ACTIONABLE_TASK" in r.stop_codes
    assert "A2" in [t.id for t in r.blocked_tasks]


def test_independent_actionable_task_runs_while_blocked_surfaced():
    # A2 is blocked, but A3 depends only on A1 (done) -> A3 is actionable.
    plan = _plan(
        "- [x] **A1** — done. | none | f | verify: v | accept: a. **DONE.**\n"
        "- [!] **A2** — blocked. | A1 | f | verify: v | accept: a.\n"
        "- [ ] **A3** — independent. | A1 | f | verify: v | accept: a.\n"
    )
    r = resolver.resolve_next(plan)
    assert r.decision == "execute"
    assert r.task.id == "A3"
    assert "A2" in [t.id for t in r.blocked_tasks]  # still surfaced


def test_all_complete_is_done():
    plan = _plan(
        "- [x] **A1** — done. | none | f | verify: v | accept: a. **DONE.**\n"
        "- [x] **A2** — done. | A1 | f | verify: v | accept: a. **DONE.**\n"
    )
    r = resolver.resolve_next(plan)
    assert r.decision == "done"
    assert r.task is None


def test_empty_plan_stops():
    plan = _plan("# just a heading, no tasks\n")
    r = resolver.resolve_next(plan)
    assert r.decision == "stop"
    assert "PLAN_EMPTY" in r.stop_codes


def test_duplicate_ids_stop():
    plan = _plan(
        "- [ ] **A1** — first. | none | f | verify: v | accept: a.\n"
        "- [x] **A1** — dupe. | none | f | verify: v | accept: a. **DONE.**\n"
    )
    r = resolver.resolve_next(plan)
    assert r.decision == "stop"
    assert "DUPLICATE_TASK_IDS" in r.stop_codes


def test_unknown_dependency_stops():
    plan = _plan(
        "- [x] **A1** — done. | none | f | verify: v | accept: a. **DONE.**\n"
        "- [ ] **A2** — bad dep. | ZZ9 | f | verify: v | accept: a.\n"
    )
    r = resolver.resolve_next(plan)
    assert r.decision == "stop"
    assert "UNKNOWN_DEPENDENCY" in r.stop_codes


def test_deps_all_gate_task_not_selected_while_others_pending():
    plan = _plan(
        "- [x] **A1** — done. | none | f | verify: v | accept: a. **DONE.**\n"
        "- [ ] **B1** — real next. | A1 | f | verify: v | accept: a.\n"
        "- [ ] **P1** — final gate. | all | - | verify: verifier | accept: gates pass.\n"
    )
    r = resolver.resolve_next(plan)
    assert r.decision == "execute"
    assert r.task.id == "B1"


def test_deps_all_gate_task_selected_once_everything_else_done():
    plan = _plan(
        "- [x] **A1** — done. | none | f | verify: v | accept: a. **DONE.**\n"
        "- [x] **B1** — done. | A1 | f | verify: v | accept: a. **DONE.**\n"
        "- [ ] **P1** — final gate. | all | - | verify: verifier | accept: gates pass.\n"
    )
    r = resolver.resolve_next(plan)
    assert r.decision == "execute"
    assert r.task.id == "P1"


def test_resolution_is_recomputed_from_plan_each_call():
    # State survives across "sessions": two independent parses of the same text
    # yield the same decision, proving the resolver holds no hidden memory.
    text = (
        "- [x] **A1** — done. | none | f | verify: v | accept: a. **DONE.**\n"
        "- [ ] **A2** — next. | A1 | f | verify: v | accept: a.\n"
    )
    r1 = resolver.resolve_next(state.parse_plan(text))
    r2 = resolver.resolve_next(state.parse_plan(text))
    assert r1.decision == r2.decision == "execute"
    assert r1.task.id == r2.task.id == "A2"
