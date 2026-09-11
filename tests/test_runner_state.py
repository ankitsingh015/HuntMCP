"""Tests for the dev-runner state reader (scripts/runner/state.py).

The state reader parses the persistent PHASE1-EXECUTION-PLAN.md task table and
the ROADMAP.md PROJECT STATE block into typed objects. These tests use inline
markdown fixtures only -- they never read or mutate the real project plan or git
history.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

from runner import state  # noqa: E402


# --- fixtures: minimal markdown mirroring the real plan's two field styles ---

PLAN_LABELED = """\
# Plan

- [x] **A1** — Resolve UD-1..UD-4 with human; record rulings. | deps: none | files: this doc | verify: rulings written | accept: all 4 resolved. **DONE 2026-09-04.**
- [ ] **A2** — Create isolated worktree. | deps: A1 | files: - | verify: git status | accept: not on main.
"""

PLAN_BARE = """\
# Plan

- [x] **C1** — SuccessSignature + evaluate_signature. | A4 | cem_engine.py, test_cem_engine.py | verify: pytest | accept: matcher covers each case. **DONE 2026-09-05.**
- [ ] **C6** — alternates + interaction detection. | C5 | cem_engine.py | verify: pytest | accept: >=2 sets when planted.
"""


def test_parses_status_markers_into_named_states():
    plan = state.parse_plan(PLAN_LABELED)
    assert plan.get("A1").status == "complete"
    assert plan.get("A1").marker == "x"
    assert plan.get("A2").status == "pending"
    assert plan.get("A2").marker == " "


def test_parses_all_four_markers():
    text = (
        "- [ ] **T1** — pending. | none | f | verify: v | accept: a.\n"
        "- [~] **T2** — in progress. | T1 | f | verify: v | accept: a.\n"
        "- [x] **T3** — complete. | T2 | f | verify: v | accept: a. **DONE.**\n"
        "- [!] **T4** — blocked. | T3 | f | verify: v | accept: a.\n"
    )
    plan = state.parse_plan(text)
    assert plan.get("T1").status == "pending"
    assert plan.get("T2").status == "in_progress"
    assert plan.get("T3").status == "complete"
    assert plan.get("T4").status == "blocked"


def test_extracts_task_id_and_title():
    plan = state.parse_plan(PLAN_BARE)
    c6 = plan.get("C6")
    assert c6.id == "C6"
    assert "alternates" in c6.title
    # title must not swallow the pipe-delimited metadata
    assert "verify:" not in c6.title
    assert "|" not in c6.title


def test_parses_deps_from_labeled_and_bare_field_styles():
    labeled = state.parse_plan(PLAN_LABELED)
    bare = state.parse_plan(PLAN_BARE)
    assert labeled.get("A1").deps == []            # "deps: none" -> no deps
    assert labeled.get("A2").deps == ["A1"]
    assert bare.get("C1").deps == ["A4"]           # bare 2nd field is deps
    assert bare.get("C6").deps == ["C5"]


def test_deps_field_strips_checkmarks_and_multiple_ids():
    text = "- [ ] **F2** — share cap. | A1 ✔, E2 | file | verify: pytest | accept: ok.\n"
    plan = state.parse_plan(text)
    assert plan.get("F2").deps == ["A1", "E2"]


def test_deps_range_is_expanded():
    # "C3..C7" in the real plan means C3,C4,C5,C6,C7
    text = "- [ ] **C8** — assemble bundle. | C3..C7 | cem_engine.py | verify: pytest | accept: ok.\n"
    plan = state.parse_plan(text)
    assert plan.get("C8").deps == ["C3", "C4", "C5", "C6", "C7"]


def test_deps_all_keyword_is_flagged_and_expands_to_prior_tasks():
    # The real plan uses "| all |" for final gate tasks (O1/P1): they depend on
    # every task, so they must never look prematurely actionable.
    text = (
        "- [x] **A1** — first. | none | f | verify: v | accept: a. **DONE.**\n"
        "- [ ] **B1** — middle. | A1 | f | verify: v | accept: a.\n"
        "- [ ] **P1** — final gate. | all | - | verify: verifier | accept: gates pass.\n"
    )
    plan = state.parse_plan(text)
    p1 = plan.get("P1")
    assert p1.deps_all is True
    assert set(p1.deps) == {"A1", "B1"}   # every other task, not itself


def test_deps_all_false_for_normal_tasks():
    plan = state.parse_plan(PLAN_BARE)
    assert plan.get("C1").deps_all is False


def test_parses_files_verify_accept_fields():
    plan = state.parse_plan(PLAN_BARE)
    c1 = plan.get("C1")
    assert "cem_engine.py" in c1.files
    assert "test_cem_engine.py" in c1.files
    assert c1.verify == "pytest"
    assert c1.accept.startswith("matcher covers each case")


def test_completion_note_is_detected():
    plan = state.parse_plan(PLAN_BARE)
    assert plan.get("C1").has_done_note is True
    assert plan.get("C6").has_done_note is False


def test_preserves_document_order_and_line_numbers():
    plan = state.parse_plan(PLAN_BARE)
    assert [t.id for t in plan.tasks] == ["C1", "C6"]
    assert plan.get("C1").line_no < plan.get("C6").line_no


def test_get_unknown_task_returns_none():
    plan = state.parse_plan(PLAN_BARE)
    assert plan.get("ZZ9") is None


def test_ignores_non_task_lines_containing_brackets():
    # The plan legend line mentions the markers but is not a task.
    text = (
        "Status: `[ ]` PENDING · `[~]` IN PROGRESS · `[x]` COMPLETE · `[!]` BLOCKED.\n"
        "- [ ] **A1** — real task. | none | f | verify: v | accept: a.\n"
    )
    plan = state.parse_plan(text)
    assert [t.id for t in plan.tasks] == ["A1"]


def test_duplicate_task_ids_are_recorded_as_conflict():
    text = (
        "- [ ] **A1** — first. | none | f | verify: v | accept: a.\n"
        "- [x] **A1** — dupe. | none | f | verify: v | accept: a. **DONE.**\n"
    )
    plan = state.parse_plan(text)
    assert "A1" in plan.duplicate_ids


def test_load_plan_reads_from_file(tmp_path):
    p = tmp_path / "PHASE1-EXECUTION-PLAN.md"
    p.write_text(PLAN_BARE, encoding="utf-8")
    plan = state.load_plan(str(p))
    assert plan.get("C1").status == "complete"
    assert plan.source_path == str(p)


def test_load_plan_missing_file_raises_plannotfound(tmp_path):
    missing = tmp_path / "nope.md"
    with pytest.raises(state.PlanNotFoundError):
        state.load_plan(str(missing))


# --- ROADMAP PROJECT STATE block ---

ROADMAP = """\
# ROADMAP

## PROJECT STATE

```
CURRENT PHASE:        Phase 1 — CEM vertical slice
CURRENT MILESTONE:    Phase 1a hardening COMPLETE
STATUS:               PLANNING
NEXT STEP:            Human G0 approval then begin CEM engine
BLOCKED:              Awaiting human G0 approval
```

Trailing prose.
"""


def test_parses_project_state_block():
    ps = state.parse_project_state(ROADMAP)
    assert ps["CURRENT PHASE"].startswith("Phase 1")
    assert ps["STATUS"] == "PLANNING"
    assert "G0" in ps["NEXT STEP"]


def test_parses_project_state_returns_empty_when_absent():
    ps = state.parse_project_state("# ROADMAP\n\nNo state block here.\n")
    assert ps == {}


# --- set_task_status: the plan-write a SESSION performs to record its own progress ---

_SETPLAN = (
    "# Plan\n"
    "- [x] **A1** — done. | none | f | verify: v | accept: a. **DONE.**\n"
    "- [ ] **C6** — alternates. | A1 | cem_engine.py | verify: pytest | accept: >=2 sets.\n"
    "- [ ] **C7** — minimize. | C6 | cem_engine.py | verify: pytest | accept: dropped.\n"
)


def test_set_task_status_flips_only_the_target_marker():
    out = state.set_task_status(_SETPLAN, "C6", "x")
    plan = state.parse_plan(out)
    assert plan.get("C6").marker == "x"
    assert plan.get("C7").marker == " "   # untouched
    assert plan.get("A1").marker == "x"   # untouched


def test_set_task_status_preserves_rest_of_line():
    out = state.set_task_status(_SETPLAN, "C6", "~")
    # deps/files/accept metadata on the C6 line must survive
    assert "cem_engine.py" in out
    assert ">=2 sets" in out
    plan = state.parse_plan(out)
    assert plan.get("C6").marker == "~"
    assert plan.get("C6").deps == ["A1"]


def test_set_task_status_unknown_id_raises():
    import pytest as _pytest
    with _pytest.raises(KeyError):
        state.set_task_status(_SETPLAN, "ZZ9", "x")


def test_set_task_status_invalid_marker_raises():
    import pytest as _pytest
    with _pytest.raises(ValueError):
        state.set_task_status(_SETPLAN, "C6", "q")


def test_set_task_status_duplicate_id_raises():
    dup = _SETPLAN + "- [ ] **C6** — dupe. | A1 | f | verify: v | accept: a.\n"
    import pytest as _pytest
    with _pytest.raises(ValueError):
        state.set_task_status(dup, "C6", "x")
