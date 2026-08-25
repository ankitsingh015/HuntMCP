import threading
import time

import pytest
import budget_guard


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
