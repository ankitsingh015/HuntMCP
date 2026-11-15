import os
import sys

import pytest

import browser_launch


def test_assert_dedicated_profile_dir_refuses_os_default():
    with pytest.raises(ValueError):
        browser_launch.assert_dedicated_profile_dir("~/.config/google-chrome/Default")


def test_assert_dedicated_profile_dir_allows_dedicated():
    out = browser_launch.assert_dedicated_profile_dir(
        "~/.config/huntmcp/browser-profiles/xyz"
    )
    assert out.endswith("/browser-profiles/xyz")
    assert os.path.isabs(out)


def test_persistent_context_kwargs_is_headful_with_user_data_dir():
    kwargs = browser_launch.persistent_context_kwargs("/tmp/p")
    assert kwargs["headless"] is False
    assert kwargs["user_data_dir"] == "/tmp/p"


def test_resolve_executable_honors_env_override(monkeypatch):
    monkeypatch.setenv("HUNTMCP_CHROME_PATH", sys.executable)
    assert browser_launch.resolve_executable_or_raise() == sys.executable


def test_resolve_executable_raises_actionable_when_none(monkeypatch):
    monkeypatch.delenv("HUNTMCP_CHROME_PATH", raising=False)
    monkeypatch.setattr(browser_launch, "find_browser_executable", lambda: None)
    with pytest.raises(RuntimeError) as exc:
        browser_launch.resolve_executable_or_raise()
    assert "playwright install" in str(exc.value)
