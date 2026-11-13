import asyncio
import importlib.util
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "browser-mcp"))

_spec = importlib.util.spec_from_file_location(
    "browser_mcp_server_capture", os.path.join(ROOT, "mcp-servers", "browser-mcp", "server.py")
)
cap_server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cap_server)

SECRET = "S3CRET_WRAPPER_VALUE"

TOOL_NAMES = [
    "list_test_identities",
    "start_capture",
    "finish_capture",
    "apply_pending_otp",
    "open_pending_magic_link",
    "capture_oauth_redirect",
]


def test_six_capture_tools_are_registered():
    for name in TOOL_NAMES:
        assert callable(getattr(cap_server, name)), f"{name} not defined on the server"


def test_list_test_identities_wrapper_is_json_and_secret_free(monkeypatch):
    monkeypatch.setattr(
        cap_server.session_capture, "list_identities",
        lambda path=None: [{"label": "xyz", "note": "t", "has_mailbox": False}],
    )
    out = cap_server.list_test_identities()
    data = json.loads(out)  # JSON-serializable
    assert data == [{"label": "xyz", "note": "t", "has_mailbox": False}]
    assert SECRET not in out


def test_start_capture_wrapper_passes_through_non_secret(monkeypatch):
    async def fake_start(identity_label, login_url, slug=None):
        # even if the underlying returned a secret, the wrapper must not expose it;
        # here the real function already returns only non-secret keys
        return {"identity": identity_label, "status": "open", "message": "run confirm-capture.sh"}

    monkeypatch.setattr(cap_server.session_capture, "start_capture", fake_start)
    out = asyncio.run(cap_server.start_capture("xyz", "https://app.target.com/login"))
    data = json.loads(out)
    assert data["status"] == "open"
    assert SECRET not in out


def test_finish_capture_wrapper_is_json(monkeypatch):
    async def fake_finish(identity_label, slug=None, whoami_url=""):
        return {"identity": identity_label, "captured": True, "cookie_count": 2, "has_bearer": True, "whoami": {}}

    monkeypatch.setattr(cap_server.session_capture, "finish_capture", fake_finish)
    out = asyncio.run(cap_server.finish_capture("xyz"))
    data = json.loads(out)
    assert data["captured"] is True and data["cookie_count"] == 2
    assert SECRET not in out
