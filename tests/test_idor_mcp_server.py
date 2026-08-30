import importlib.util
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# server.py relies on its OWN "import idor_sweep" resolving via the
# automatic sys.path[0]-is-the-script's-own-directory behavior Python
# gives a directly-run script (`python3 mcp-servers/idor-mcp/server.py`)
# -- spec_from_file_location + exec_module doesn't get that for free, so
# it has to be added explicitly here, same as running the real server
# would get automatically.
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "idor-mcp"))

_spec = importlib.util.spec_from_file_location(
    "idor_mcp_server", os.path.join(ROOT, "mcp-servers", "idor-mcp", "server.py"),
)
idor_mcp_server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(idor_mcp_server)


def test_sweep_idor_falls_back_to_session_context_when_object_ids_omitted(monkeypatch):
    called_ids = []

    def fake_check_one_id(url_template, object_id, method, owner_headers, other_headers,
                           body_template, timeout_s):
        called_ids.append(object_id)
        return idor_mcp_server.idor_sweep.IdVerdict(
            object_id=object_id, owner_status=200, other_status=403, verdict="PROTECTED",
        )

    monkeypatch.setattr(idor_mcp_server.idor_sweep, "check_one_id", fake_check_one_id)
    monkeypatch.setattr(idor_mcp_server, "_enforce_budget", lambda name: None)
    monkeypatch.setattr(
        idor_mcp_server.session_context, "suggest_object_ids",
        lambda url, limit=50, db_path=None: ["4521"],
    )

    # object_ids omitted entirely -- must fall back to suggest_object_ids().
    output = idor_mcp_server.sweep_idor("https://target.com/api/orders/{id}")
    assert called_ids == ["4521"]
    assert "4521" in output


def test_sweep_idor_reports_clear_error_when_nothing_observed_and_no_ids_given(monkeypatch):
    monkeypatch.setattr(
        idor_mcp_server.session_context, "suggest_object_ids",
        lambda url, limit=50, db_path=None: [],
    )
    output = idor_mcp_server.sweep_idor("https://target.com/api/orders/{id}")
    assert "No object_ids given" in output
    assert "session_context" in output


def test_sweep_idor_explicit_object_ids_skips_session_context_lookup(monkeypatch):
    def fail_if_called(url, limit=50, db_path=None):
        raise AssertionError("suggest_object_ids should not be called when object_ids is given")

    monkeypatch.setattr(idor_mcp_server.session_context, "suggest_object_ids", fail_if_called)
    monkeypatch.setattr(idor_mcp_server, "_enforce_budget", lambda name: None)
    monkeypatch.setattr(
        idor_mcp_server.idor_sweep, "check_one_id",
        lambda *a, **k: idor_mcp_server.idor_sweep.IdVerdict(
            object_id=a[1], owner_status=200, other_status=403, verdict="PROTECTED",
        ),
    )
    output = idor_mcp_server.sweep_idor("https://target.com/api/orders/{id}", object_ids=["1"])
    assert "1" in output
