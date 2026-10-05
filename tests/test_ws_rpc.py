"""Unit/integration tests for ws-rpc-mcp's ws_rpc.py -- exercises the real
websockets client against a synthetic local DDP-style server (same
"real loopback server, not a mock" philosophy as test_http_probe.py/
test_cors_probe.py), per the issue's own suggested validation: "pilot it
on a synthetic DDP-style server before a live target."

Plain asyncio.run() wrapping rather than @pytest.mark.asyncio -- avoids a
pytest-asyncio dependency neither this repo nor this environment already
has (same "don't add a dependency the stdlib/an already-approved package
already covers" discipline as everywhere else in this repo); each test's
whole async body (start server, exercise ws_rpc, stop server) runs inside
one asyncio.run() call from an ordinary sync test function.
"""
import asyncio
import json
import os
import sys

import websockets

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                 "mcp-servers", "ws-rpc-mcp"))
import ws_rpc

# ---------------------------------------------------------------- synthetic DDP server

async def _ddp_handler(ws):
    async for raw in ws:
        msg = json.loads(raw)
        if msg.get("msg") == "connect":
            await ws.send(json.dumps({"msg": "connected", "session": "fake-session-123"}))
        elif msg.get("msg") == "method":
            method = msg.get("method")
            call_id = msg.get("id")
            if method == "getUserProfile":
                await ws.send(json.dumps({"msg": "updated", "methods": [call_id]}))
                await ws.send(json.dumps({"msg": "result", "id": call_id,
                                           "result": {"email": "admin@target.com", "role": "admin"}}))
            elif method == "raisesError":
                await ws.send(json.dumps({"msg": "result", "id": call_id,
                                           "error": {"error": 403, "reason": "Access denied"}}))
            elif method == "sendsPingFirst":
                await ws.send(json.dumps({"msg": "ping"}))
                await ws.send(json.dumps({"msg": "result", "id": call_id, "result": "ok-after-ping"}))
            elif method == "neverResponds":
                await asyncio.sleep(30)
            else:
                await ws.send(json.dumps({"msg": "result", "id": call_id,
                                           "error": {"error": 404, "reason": "Method not found"}}))
        elif msg.get("msg") == "pong":
            continue


async def _refusing_handler(ws):
    async for raw in ws:
        msg = json.loads(raw)
        if msg.get("msg") == "connect":
            await ws.send(json.dumps({"msg": "failed", "version": "1"}))


def _run(coro):
    return asyncio.run(coro)


# --------------------------------------------------------------------- connect

def test_connect_succeeds_and_returns_session():
    async def _body():
        async with websockets.serve(_ddp_handler, "127.0.0.1", 0) as server:
            port = server.sockets[0].getsockname()[1]
            ws, result = await ws_rpc.connect(f"ws://127.0.0.1:{port}")
            try:
                assert result.connected is True
                assert result.session == "fake-session-123"
                assert result.error is None
            finally:
                if ws:
                    await ws.close()
    _run(_body())


def test_connect_refused_is_reported_not_raised():
    async def _body():
        async with websockets.serve(_refusing_handler, "127.0.0.1", 0) as server:
            port = server.sockets[0].getsockname()[1]
            ws, result = await ws_rpc.connect(f"ws://127.0.0.1:{port}")
            try:
                assert result.connected is False
                assert result.error is not None
            finally:
                if ws:
                    await ws.close()
    _run(_body())


def test_connect_to_unreachable_host_returns_graceful_error():
    async def _body():
        ws, result = await ws_rpc.connect("ws://127.0.0.1:1/x", timeout_s=1)
        assert ws is None
        assert result.connected is False
        assert result.error is not None
    _run(_body())


# ----------------------------------------------------------------- call_method

def test_call_method_returns_result():
    async def _body():
        async with websockets.serve(_ddp_handler, "127.0.0.1", 0) as server:
            port = server.sockets[0].getsockname()[1]
            ws, connect_result = await ws_rpc.connect(f"ws://127.0.0.1:{port}")
            assert connect_result.connected is True
            try:
                result = await ws_rpc.call_method(ws, "getUserProfile", params=["user_42"])
                assert result.error is None
                assert result.result == {"email": "admin@target.com", "role": "admin"}
                assert result.timed_out is False
            finally:
                await ws.close()
    _run(_body())


def test_call_method_surfaces_ddp_error():
    async def _body():
        async with websockets.serve(_ddp_handler, "127.0.0.1", 0) as server:
            port = server.sockets[0].getsockname()[1]
            ws, _ = await ws_rpc.connect(f"ws://127.0.0.1:{port}")
            try:
                result = await ws_rpc.call_method(ws, "raisesError")
                assert result.result is None
                assert result.error == {"error": 403, "reason": "Access denied"}
            finally:
                await ws.close()
    _run(_body())


def test_call_method_replies_to_ping_and_still_gets_result():
    """A real DDP server can interleave a ping before the actual result --
    the client must answer it (pong) and keep waiting, not treat it as
    the response or drop the connection."""
    async def _body():
        async with websockets.serve(_ddp_handler, "127.0.0.1", 0) as server:
            port = server.sockets[0].getsockname()[1]
            ws, _ = await ws_rpc.connect(f"ws://127.0.0.1:{port}")
            try:
                result = await ws_rpc.call_method(ws, "sendsPingFirst")
                assert result.result == "ok-after-ping"
            finally:
                await ws.close()
    _run(_body())


def test_call_method_times_out_gracefully():
    async def _body():
        async with websockets.serve(_ddp_handler, "127.0.0.1", 0) as server:
            port = server.sockets[0].getsockname()[1]
            ws, _ = await ws_rpc.connect(f"ws://127.0.0.1:{port}")
            try:
                result = await ws_rpc.call_method(ws, "neverResponds", timeout_s=0.5)
                assert result.timed_out is True
                assert result.result is None
            finally:
                await ws.close()
    _run(_body())


def test_call_method_unknown_method_returns_ddp_error():
    async def _body():
        async with websockets.serve(_ddp_handler, "127.0.0.1", 0) as server:
            port = server.sockets[0].getsockname()[1]
            ws, _ = await ws_rpc.connect(f"ws://127.0.0.1:{port}")
            try:
                result = await ws_rpc.call_method(ws, "totallyMadeUpMethod")
                assert result.error["error"] == 404
            finally:
                await ws.close()
    _run(_body())


# ------------------------------------------------------------- sync wrapper

def test_run_ddp_call_sync_wrapper():
    """The synchronous entry point the MCP tool layer actually calls --
    connects, invokes one method, closes, all in one blocking call.
    run_ddp_call() itself opens its own event loop (asyncio.run()
    internally), so the server must be started/stopped OUTSIDE of any
    asyncio.run() this test drives itself -- started via a background
    thread running its own loop, not nested asyncio.run() calls sharing
    state across separately-created-and-closed event loops."""
    import threading

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
    try:
        result = ws_rpc.run_ddp_call(f"ws://127.0.0.1:{port_holder['port']}", "getUserProfile", params=["user_1"])
        assert result["connected"] is True
        assert result["result"] == {"email": "admin@target.com", "role": "admin"}
    finally:
        stop.set()
        thread.join(timeout=5)


def test_run_ddp_call_sync_wrapper_reports_connect_failure():
    result = ws_rpc.run_ddp_call("ws://127.0.0.1:1/x", "anyMethod", timeout_s=1)
    assert result["connected"] is False
    assert "error" in result


# --------------------------------------------------- enumerate_methods_from_bundle

def test_enumerate_methods_from_meteor_methods_object():
    js = """
    Meteor.methods({
      getUserProfile: function(userId) { return Users.findOne(userId); },
      'admin.deleteUser': function(userId) { ... },
      sendPasswordReset(email) { ... },
    });
    """
    methods = ws_rpc.enumerate_methods_from_bundle(js)
    assert "getUserProfile" in methods
    assert "admin.deleteUser" in methods
    assert "sendPasswordReset" in methods


def test_enumerate_methods_from_bundle_dedupes():
    js = "Meteor.methods({foo: 1}); Meteor.methods({foo: 2, bar: 3});"
    methods = ws_rpc.enumerate_methods_from_bundle(js)
    assert methods.count("foo") == 1
    assert "bar" in methods


def test_enumerate_methods_from_bundle_empty_when_no_meteor_methods_call():
    assert ws_rpc.enumerate_methods_from_bundle("function unrelated() { return 1; }") == []


def test_enumerate_methods_survives_nested_object_literal_in_method_body():
    """Regression (code-review finding, confirmed via direct reproduction):
    the original single non-greedy regex (`\\{(.*?)\\}`) stopped at the
    FIRST "}" immediately followed by ")" -- which commonly occurs
    MID-BODY (not at the real end of Meteor.methods({...})) whenever an
    earlier method's body contains a nested call whose last argument is an
    object literal, a very common real-world Meteor pattern. 'bar' used to
    be silently dropped here with no error."""
    js = """
    Meteor.methods({
      foo: function(id) { Users.update({_id: id}, {$set: {x: 1}}); },
      bar: function() { return 1; }
    });
    """
    methods = ws_rpc.enumerate_methods_from_bundle(js)
    assert "foo" in methods
    assert "bar" in methods


def test_enumerate_methods_handles_multiple_nested_object_literals():
    js = """
    Meteor.methods({
      a: function() { db.update({x: 1}, {$set: {y: 2}}); db.update({z: 3}, {$set: {w: 4}}); },
      b: function() { return 2; },
      c: function() { return 3; }
    });
    """
    methods = ws_rpc.enumerate_methods_from_bundle(js)
    assert "a" in methods
    assert "b" in methods
    assert "c" in methods
