"""Tests for coherent task-group selection (scripts/runner/resolver.py).

A "coherent task group" is the unit of one autonomous session: the next
actionable task plus a bounded, dependency-contiguous run of following tasks. The
group must never span a task requiring its own human gate (protected-benchmark
touch, a `| all |` final-gate task), and never exceed the size cap.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

from runner import resolver, state, verify  # noqa: E402


def _plan(text):
    return state.parse_plan(text)


CHAIN = (
    "- [x] **C5** — done. | none | cem_engine.py | verify: pytest | accept: ok. **DONE.**\n"
    "- [ ] **C6** — alternates. | C5 | cem_engine.py | verify: pytest | accept: >=2 sets.\n"
    "- [ ] **C7** — minimize. | C6 | cem_engine.py | verify: pytest | accept: dropped.\n"
    "- [ ] **C8** — bundle. | C7 | cem_engine.py | verify: pytest | accept: fields.\n"
)


def test_group_of_one_when_max_size_is_one():
    g = resolver.select_task_group(_plan(CHAIN), max_size=1)
    assert g.decision == "execute"
    assert [t.id for t in g.tasks] == ["C6"]


def test_group_extends_along_dependency_chain_up_to_max():
    g = resolver.select_task_group(_plan(CHAIN), max_size=3)
    assert [t.id for t in g.tasks] == ["C6", "C7", "C8"]


def test_group_respects_max_size_cap():
    g = resolver.select_task_group(_plan(CHAIN), max_size=2)
    assert [t.id for t in g.tasks] == ["C6", "C7"]


def test_group_stops_before_protected_benchmark_task():
    text = (
        "- [x] **A1** — done. | none | f | verify: pytest | accept: ok. **DONE.**\n"
        "- [ ] **B1** — normal. | A1 | cem_engine.py | verify: pytest | accept: ok.\n"
        "- [ ] **B2** — rescore. | B1 | tests/fixtures/cem_target/evaluator.py | verify: pytest | accept: ok.\n"
    )
    g = resolver.select_task_group(_plan(text), max_size=5, protected_check=verify.detect_protected_touch)
    assert [t.id for t in g.tasks] == ["B1"]   # B2 excluded (protected)


def test_group_stops_before_deps_all_gate_task():
    text = (
        "- [x] **A1** — done. | none | f | verify: pytest | accept: ok. **DONE.**\n"
        "- [ ] **B1** — normal. | A1 | cem_engine.py | verify: pytest | accept: ok.\n"
        "- [ ] **P1** — final gate. | all | - | verify: verifier | accept: gates pass.\n"
    )
    g = resolver.select_task_group(_plan(text), max_size=5)
    assert [t.id for t in g.tasks] == ["B1"]


def test_group_does_not_include_task_with_unmet_dependency():
    text = (
        "- [x] **C5** — done. | none | f | verify: pytest | accept: ok. **DONE.**\n"
        "- [ ] **C6** — actionable. | C5 | cem_engine.py | verify: pytest | accept: ok.\n"
        "- [ ] **D5** — needs D4. | D4 | cem_engine.py | verify: pytest | accept: ok.\n"
        "- [ ] **D4** — needs C6. | C6 | cem_engine.py | verify: pytest | accept: ok.\n"
    )
    # From C6: D4 depends on C6 (in group) so it can join; D5 depends on D4 (also
    # now in group) so it can join too -- but only in dependency order, never a
    # task whose deps aren't satisfied by completed+group-so-far.
    g = resolver.select_task_group(_plan(text), max_size=2)
    ids = [t.id for t in g.tasks]
    assert ids == ["C6", "D4"]           # D4 added (dep C6 satisfied), capped at 2
    assert "D5" not in ids               # would need D4 first; order preserved


def test_group_mirrors_resume_decision():
    text = (
        "- [x] **A1** — done. | none | f | verify: pytest | accept: ok. **DONE.**\n"
        "- [~] **A2** — interrupted. | A1 | f | verify: pytest | accept: ok.\n"
    )
    g = resolver.select_task_group(_plan(text))
    assert g.decision == "resume"
    assert [t.id for t in g.tasks] == ["A2"]


def test_group_mirrors_done_decision():
    text = "- [x] **A1** — done. | none | f | verify: pytest | accept: ok. **DONE.**\n"
    g = resolver.select_task_group(_plan(text))
    assert g.decision == "done"
    assert g.tasks == []


def test_group_mirrors_stop_decision():
    text = (
        "- [ ] **A1** — first. | none | f | verify: pytest | accept: ok.\n"
        "- [x] **A1** — dupe. | none | f | verify: pytest | accept: ok. **DONE.**\n"
    )
    g = resolver.select_task_group(_plan(text))
    assert g.decision == "stop"
    assert "DUPLICATE_TASK_IDS" in g.stop_codes
