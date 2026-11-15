"""Issue #135: second-opinion-mcp must fail LOUDLY when no cross-model
provider is configured, not return a soft "unavailable" string from inside
a normal-looking tool response (which this engagement got buried in one
finding's draft notes and was found only by chance).

These tests pin:
  * cross_model_status() correctly reports (un)availability;
  * startup_warning() yields a loud banner when unavailable, None otherwise
    (what __main__ prints so the gap is visible at engagement start);
  * get_second_opinion() RAISES on the config gap instead of returning a
    verdict-shaped string, so an agent/report can never mistake "no second
    opinion available" for an actual CONFIRMED/FALSE-POSITIVE verdict.
"""

import importlib.util
import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER_PATH = os.path.join(ROOT, "mcp-servers", "second-opinion-mcp", "server.py")


@pytest.fixture
def so(monkeypatch):
    # The automatic chain (not an explicit override) is what decides
    # availability -- clear overrides so these tests exercise the chain.
    monkeypatch.delenv("HUNTMCP_MODEL", raising=False)
    monkeypatch.delenv("HUNTMCP_MODEL_EXPLOIT", raising=False)
    spec = importlib.util.spec_from_file_location("so_server_under_test", SERVER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _set_keys(monkeypatch, so, available_keys):
    """Make get_secret -- in BOTH the server module and model_gateway (each
    imported its own reference) -- report only `available_keys` env names as
    set, everything else unset."""
    import model_gateway

    def fake(key, path=None):
        return "x-secret" if key in available_keys else None

    monkeypatch.setattr(so, "get_secret", fake)
    monkeypatch.setattr(model_gateway, "get_secret", fake)


# ---- cross_model_status() ----------------------------------------------------

def test_cross_model_status_false_when_no_provider(so, monkeypatch):
    _set_keys(monkeypatch, so, set())
    available, reason = so.cross_model_status()
    assert available is False
    assert reason  # non-empty, human-readable


def test_cross_model_status_false_when_only_one_provider(so, monkeypatch):
    _set_keys(monkeypatch, so, {"ANTHROPIC_API_KEY"})
    available, reason = so.cross_model_status()
    assert available is False
    # It should name a DIFFERENT provider the operator could add.
    assert "OPENAI_API_KEY" in reason


def test_cross_model_status_true_when_two_providers(so, monkeypatch):
    _set_keys(monkeypatch, so, {"ANTHROPIC_API_KEY", "OPENAI_API_KEY"})
    available, reason = so.cross_model_status()
    assert available is True


# ---- startup_warning() (what __main__ prints loudly) -------------------------

def test_startup_warning_present_when_unavailable(so, monkeypatch):
    _set_keys(monkeypatch, so, set())
    banner = so.startup_warning()
    assert banner is not None
    assert "UNAVAILABLE" in banner.upper()


def test_startup_warning_none_when_available(so, monkeypatch):
    _set_keys(monkeypatch, so, {"ANTHROPIC_API_KEY", "OPENAI_API_KEY"})
    assert so.startup_warning() is None


# ---- get_second_opinion() raises on the config gap ---------------------------

def test_get_second_opinion_raises_when_no_provider(so, monkeypatch):
    _set_keys(monkeypatch, so, set())
    with pytest.raises(so.SecondOpinionUnavailable):
        so.get_second_opinion("some XSS finding summary")


def test_get_second_opinion_raises_when_only_one_provider(so, monkeypatch):
    _set_keys(monkeypatch, so, {"ANTHROPIC_API_KEY"})
    with pytest.raises(so.SecondOpinionUnavailable):
        so.get_second_opinion("some XSS finding summary", primary_role="exploit")


def test_get_second_opinion_returns_verdict_when_available(so, monkeypatch):
    _set_keys(monkeypatch, so, {"ANTHROPIC_API_KEY", "OPENAI_API_KEY"})
    # primary=anthropic -> second opinion goes to openai (OpenAI-compat shape).
    monkeypatch.setattr(
        so, "_post_json",
        lambda url, headers, body, timeout=60: {
            "choices": [{"message": {"content": "CONFIRMED -- evidence supports it."}}]
        },
    )
    out = so.get_second_opinion("some XSS finding summary", primary_role="exploit")
    assert "Second opinion from openai" in out
    assert "CONFIRMED" in out
