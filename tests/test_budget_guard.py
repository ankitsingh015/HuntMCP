import json
import os
import threading
import time

import budget_guard
import pytest


@pytest.fixture
def state_path(tmp_path):
    return str(tmp_path / "budget.json")


def test_enforce_increments_and_allows_under_cap(monkeypatch, state_path):
    monkeypatch.setattr(budget_guard, "MAX_CALLS", 10)
    status = budget_guard.enforce("nuclei", path=state_path)
    assert status["calls"] == 1
    assert status["exceeded"] is False


def test_enforce_raises_at_hard_cap(monkeypatch, state_path):
    monkeypatch.setattr(budget_guard, "MAX_CALLS", 3)
    budget_guard.enforce("nuclei", path=state_path)
    budget_guard.enforce("nuclei", path=state_path)
    # the 3rd call brings calls to 3/3 == 100%, which IS the hard stop --
    # exceeded means "at or over the cap," not "strictly past it"
    with pytest.raises(budget_guard.BudgetExceeded):
        budget_guard.enforce("nuclei", path=state_path)


def test_check_budget_is_read_only(monkeypatch, state_path):
    monkeypatch.setattr(budget_guard, "MAX_CALLS", 10)
    budget_guard.enforce("httpx", path=state_path)
    before = budget_guard.check_budget(state_path)
    after = budget_guard.check_budget(state_path)
    assert before == after == {"calls": 1, "max_calls": 10, "pct_used": 10.0,
                                "band": None, "exceeded": False, "by_tool": {"httpx": 1}}


def test_warning_bands_fire_once_each(monkeypatch, state_path, capsys):
    monkeypatch.setattr(budget_guard, "MAX_CALLS", 10)
    for _ in range(9):
        budget_guard.enforce("ffuf", path=state_path)  # crosses 70% (call 7) and 85% (call 9)
    with pytest.raises(budget_guard.BudgetExceeded):
        budget_guard.enforce("ffuf", path=state_path)  # 10/10 crosses 95% and the hard cap

    stderr = capsys.readouterr().err
    assert "7/10" in stderr and "70.0%" in stderr
    assert "9/10" in stderr and "90.0%" in stderr  # 9/10 is when the 85% band first crosses
    assert "10/10" in stderr and "100.0%" in stderr  # 10/10 is when the 95% band first crosses


def test_by_tool_breakdown(monkeypatch, state_path):
    monkeypatch.setattr(budget_guard, "MAX_CALLS", 10)
    budget_guard.enforce("nuclei", path=state_path)
    budget_guard.enforce("nuclei", path=state_path)
    budget_guard.enforce("sqlmap", path=state_path)
    status = budget_guard.check_budget(state_path)
    assert status["by_tool"] == {"nuclei": 2, "sqlmap": 1}


# ---------------------------------------------------------------------------
# F2: per-finding CEM request ceiling (HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING).
# Shares budget.json + its file lock with the engagement-wide counter; a
# separate `by_cem_finding` bucket keyed by finding id. UD-2=A: one finding's
# CEM sweep must not be able to dominate the shared engagement budget.
# ---------------------------------------------------------------------------


def test_cem_max_per_finding_default_when_env_unset(monkeypatch):
    monkeypatch.delenv("HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING", raising=False)
    assert budget_guard._cem_max_per_finding() == budget_guard.CEM_MAX_REQUESTS_PER_FINDING_DEFAULT


@pytest.mark.parametrize("raw", ["abc", "-5", "0", "  ", "3.5", "", "1e3", "None"])
def test_cem_max_per_finding_falls_back_on_malformed_or_nonpositive(monkeypatch, raw):
    monkeypatch.setenv("HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING", raw)
    assert budget_guard._cem_max_per_finding() == budget_guard.CEM_MAX_REQUESTS_PER_FINDING_DEFAULT


@pytest.mark.parametrize("raw,expected", [("1", 1), ("7", 7), ("250", 250)])
def test_cem_max_per_finding_respects_valid_positive_env(monkeypatch, raw, expected):
    monkeypatch.setenv("HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING", raw)
    assert budget_guard._cem_max_per_finding() == expected


def test_enforce_cem_finding_allows_up_to_ceiling_then_raises(monkeypatch, state_path):
    monkeypatch.setenv("HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING", "3")
    for i in (1, 2, 3):
        st = budget_guard.enforce_cem_finding(42, path=state_path)
        assert st["cem_requests"] == i
        assert st["cem_max_per_finding"] == 3
    with pytest.raises(budget_guard.BudgetExceeded) as ei:
        budget_guard.enforce_cem_finding(42, path=state_path)
    assert "per-finding" in str(ei.value) and "42" in str(ei.value)


def test_enforce_cem_finding_counts_the_denying_request_and_never_resets(monkeypatch, state_path):
    monkeypatch.setenv("HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING", "2")
    budget_guard.enforce_cem_finding(1, path=state_path)
    budget_guard.enforce_cem_finding(1, path=state_path)
    for _ in range(3):  # retry after denial -- counter keeps climbing, still denied
        with pytest.raises(budget_guard.BudgetExceeded):
            budget_guard.enforce_cem_finding(1, path=state_path)
    with open(state_path) as f:
        assert json.load(f)["by_cem_finding"]["1"] == 5  # 2 ok + 3 denied, all recorded


def test_enforce_cem_finding_isolated_per_finding(monkeypatch, state_path):
    monkeypatch.setenv("HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING", "2")
    budget_guard.enforce_cem_finding(1, path=state_path)
    budget_guard.enforce_cem_finding(1, path=state_path)
    with pytest.raises(budget_guard.BudgetExceeded):
        budget_guard.enforce_cem_finding(1, path=state_path)
    # finding 2 has its own fresh bucket -- one finding hitting its ceiling
    # cannot consume or block another's
    assert budget_guard.enforce_cem_finding(2, path=state_path)["cem_requests"] == 1


def test_enforce_cem_finding_does_not_touch_the_engagement_counter(monkeypatch, state_path):
    monkeypatch.setattr(budget_guard, "MAX_CALLS", 10)
    monkeypatch.setenv("HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING", "100")
    for _ in range(5):
        budget_guard.enforce_cem_finding(7, path=state_path)
    status = budget_guard.check_budget(state_path)
    assert status["calls"] == 0          # engagement-wide counter untouched
    assert status["by_tool"] == {}


def test_check_budget_shape_unchanged_after_cem_finding_writes(monkeypatch, state_path):
    """Regression: `by_cem_finding` lives in budget.json but must NOT leak into
    the check_budget()/_status() dict -- test_check_budget_is_read_only asserts
    that dict by exact equality."""
    monkeypatch.setattr(budget_guard, "MAX_CALLS", 10)
    budget_guard.enforce("httpx", path=state_path)
    budget_guard.enforce_cem_finding(9, path=state_path)
    assert budget_guard.check_budget(state_path) == {
        "calls": 1, "max_calls": 10, "pct_used": 10.0,
        "band": None, "exceeded": False, "by_tool": {"httpx": 1},
    }


def test_cem_requests_used_is_read_only_and_matches_the_counter(monkeypatch, state_path):
    monkeypatch.setenv("HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING", "100")
    assert budget_guard.cem_requests_used(5, path=state_path) == 0      # no file yet
    budget_guard.enforce_cem_finding(5, path=state_path)
    budget_guard.enforce_cem_finding(5, path=state_path)
    budget_guard.enforce_cem_finding(9, path=state_path)
    before = budget_guard.cem_requests_used(5, path=state_path)
    after = budget_guard.cem_requests_used(5, path=state_path)
    assert before == after == 2                                        # read does not mutate
    assert budget_guard.cem_requests_used(9, path=state_path) == 1
    assert budget_guard.cem_requests_used(404, path=state_path) == 0    # unknown finding


def test_enforce_cem_finding_reset_only_by_deleting_budget_json(monkeypatch, state_path):
    monkeypatch.setenv("HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING", "2")
    budget_guard.enforce_cem_finding(1, path=state_path)
    budget_guard.enforce_cem_finding(1, path=state_path)
    os.remove(state_path)
    assert budget_guard.enforce_cem_finding(1, path=state_path)["cem_requests"] == 1


def test_enforce_cem_finding_safe_under_concurrent_calls(monkeypatch, state_path):
    monkeypatch.setenv("HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING", "100000")
    orig_load = budget_guard._load

    def slow_load(path):
        st = orig_load(path)
        time.sleep(0.01)
        return st

    monkeypatch.setattr(budget_guard, "_load", slow_load)
    n = 20
    threads = [
        threading.Thread(target=budget_guard.enforce_cem_finding, args=(3,), kwargs={"path": state_path})
        for _ in range(n)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    with open(state_path) as f:
        assert json.load(f)["by_cem_finding"]["3"] == n  # no lost update


def test_enforce_cem_finding_concurrent_race_for_final_slot(monkeypatch, state_path):
    """N threads, ceiling M < N: exactly M must be allowed and N-M denied, and
    every attempt (allowed or denied) recorded -- no thread double-spends the
    last slot, none silently vanishes."""
    monkeypatch.setenv("HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING", "5")
    orig_load = budget_guard._load

    def slow_load(path):
        st = orig_load(path)
        time.sleep(0.005)
        return st

    monkeypatch.setattr(budget_guard, "_load", slow_load)
    n, m = 16, 5
    allowed, denied = [], []

    def worker():
        try:
            budget_guard.enforce_cem_finding(1, path=state_path)
            allowed.append(1)
        except budget_guard.BudgetExceeded:
            denied.append(1)

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(allowed) == m
    assert len(denied) == n - m
    with open(state_path) as f:
        assert json.load(f)["by_cem_finding"]["1"] == n


def test_enforce_is_safe_under_concurrent_calls(monkeypatch, state_path):
    """Regression test for the lost-update race: enforce() used to
    load-mutate-save with no locking, so two concurrent Tier-2 calls could
    both read the same starting state and one's increment would clobber
    the other's. Widen the race window artificially (sleep between the
    read and the write) so this fails reliably without file_lock, instead
    of only failing on unlucky scheduling."""
    monkeypatch.setattr(budget_guard, "MAX_CALLS", 10_000)
    orig_load = budget_guard._load

    def slow_load(path):
        state = orig_load(path)
        time.sleep(0.01)
        return state

    monkeypatch.setattr(budget_guard, "_load", slow_load)

    n = 20
    threads = [
        threading.Thread(target=budget_guard.enforce, args=("nuclei",), kwargs={"path": state_path})
        for _ in range(n)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    status = budget_guard.check_budget(state_path)
    assert status["calls"] == n
    assert status["by_tool"]["nuclei"] == n
