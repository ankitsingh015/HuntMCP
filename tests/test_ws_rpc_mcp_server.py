"""Integration tests for ws-rpc-mcp's call_ddp_method()/
enumerate_ddp_methods() tools -- the FastMCP-decorated wiring on top of
ws_rpc.py's own unit-tested logic (tests/test_ws_rpc.py).
"""
import asyncio
import importlib.util
import json
import os
import sys
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "ws-rpc-mcp"))
_spec = importlib.util.spec_from_file_location(
    "ws_rpc_server", os.path.join(ROOT, "mcp-servers", "ws-rpc-mcp", "server.py"),
)
ws_rpc_server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ws_rpc_server)

import websockets


async def _ddp_handler(ws):
    async for raw in ws:
        msg = json.loads(raw)
        if msg.get("msg") == "connect":
            await ws.send(json.dumps({"msg": "connected", "session": "sess-abc"}))
        elif msg.get("msg") == "method":
            call_id = msg.get("id")
            if msg.get("method") == "getUserProfile":
                await ws.send(json.dumps({"msg": "result", "id": call_id,
                                           "result": {"role": "admin"}}))
            else:
                await ws.send(json.dumps({"msg": "result", "id": call_id,
                                           "error": {"error": 404, "reason": "not found"}}))


def _start_background_server():
    """Runs a synthetic DDP server on its own thread/event loop -- the
    tool under test (call_ddp_method) opens its OWN asyncio.run() loop
    internally, so the server must live outside that, same reasoning as
    test_ws_rpc.py's own sync-wrapper test."""
    port_holder: dict = {}
    ready = threading.Event()
    stop = threading.Event()

    def _serve_forever():
        async def _serve():
            async with websockets.serve(_ddp_handler, "127.0.0.1", 0) as server:
                port_holder["port"] = server.sockets[0].getsockname()[1]
                ready.set()
                while not stop.is_set():
                    await asyncio.sleep(0.05)
        asyncio.run(_serve())

    thread = threading.Thread(target=_serve_forever, daemon=True)
    thread.start()
    ready.wait(timeout=5)
    return port_holder, stop, thread


def test_call_ddp_method_reports_result(monkeypatch):
    monkeypatch.setattr(ws_rpc_server, "_enforce_budget", lambda name: None)
    port_holder, stop, thread = _start_background_server()
    try:
        url = f"ws://127.0.0.1:{port_holder['port']}"
        result = ws_rpc_server.call_ddp_method(url, "getUserProfile", params='["user_1"]')
        assert "sess-abc" in result
        assert "role" in result and "admin" in result
    finally:
        stop.set()
        thread.join(timeout=5)


def test_call_ddp_method_reports_ddp_error(monkeypatch):
    monkeypatch.setattr(ws_rpc_server, "_enforce_budget", lambda name: None)
    port_holder, stop, thread = _start_background_server()
    try:
        url = f"ws://127.0.0.1:{port_holder['port']}"
        result = ws_rpc_server.call_ddp_method(url, "unknownMethod")
        assert "DDP error" in result
        assert "404" in result
    finally:
        stop.set()
        thread.join(timeout=5)


def test_call_ddp_method_rejects_non_array_params(monkeypatch):
    monkeypatch.setattr(ws_rpc_server, "_enforce_budget", lambda name: None)
    result = ws_rpc_server.call_ddp_method("ws://127.0.0.1:1/x", "m", params='{"not": "an array"}')
    assert "Error" in result
    assert "array" in result.lower()


def test_call_ddp_method_rejects_invalid_json_params(monkeypatch):
    monkeypatch.setattr(ws_rpc_server, "_enforce_budget", lambda name: None)
    result = ws_rpc_server.call_ddp_method("ws://127.0.0.1:1/x", "m", params="not json")
    assert "Error" in result


def test_call_ddp_method_respects_budget_guard(monkeypatch):
    from budget_guard import BudgetExceeded

    def _raise(name):
        raise BudgetExceeded("500/500 calls used")

    monkeypatch.setattr(ws_rpc_server, "_enforce_budget", _raise)
    result = ws_rpc_server.call_ddp_method("ws://127.0.0.1:1/x", "m")
    assert "budget exhausted" in result.lower()


def test_enumerate_ddp_methods_reports_candidates(tmp_path):
    js_file = tmp_path / "bundle.js"
    js_file.write_text("Meteor.methods({ getUserProfile: function() {}, 'admin.deleteUser': function() {} });")
    result = ws_rpc_server.enumerate_ddp_methods(str(js_file))
    assert "getUserProfile" in result
    assert "admin.deleteUser" in result


def test_enumerate_ddp_methods_missing_file_errors():
    result = ws_rpc_server.enumerate_ddp_methods("/nonexistent/bundle.js")
    assert "Error" in result


def test_enumerate_ddp_methods_no_methods_found(tmp_path):
    js_file = tmp_path / "bundle.js"
    js_file.write_text("function unrelated() {}")
    result = ws_rpc_server.enumerate_ddp_methods(str(js_file))
    assert "No Meteor.methods" in result
