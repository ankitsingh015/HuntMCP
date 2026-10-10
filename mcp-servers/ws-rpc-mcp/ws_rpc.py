"""Generic WebSocket-RPC client, DDP-aware (Meteor.js's Distributed Data
Protocol -- the concrete real-world protocol that motivated this tool).

Why this exists: a real engagement's highest-value surface was a custom
JavaScript RPC protocol (DDP-style) exposed over WebSocket; no MCP tool
wrapped connect/method/subscription frames, so validation required a
hand-rolled client and manual frame crafting each time -- reported live
in an engagement retrospective as a tool gap. Any future target with a
raw RPC/WebSocket protocol hits the same gap, since this repo's tool
suite (probe/crawl/scan) is otherwise entirely HTTP-oriented.

`websockets` is a genuine new project dependency (mcp-servers/ws-rpc-mcp/
requirements.txt), added deliberately after confirming Python's stdlib has
no WebSocket client and that this project has no existing one to reuse --
not a silent addition.

DDP message shapes this module speaks (per Meteor's own DDP spec):
  connect:   {"msg": "connect", "version": "1", "support": ["1"]}
  connected: {"msg": "connected", "session": "..."}
  method:    {"msg": "method", "method": "<name>", "params": [...], "id": "<id>"}
  result:    {"msg": "result", "id": "<id>", "result": ...} or {"error": {...}}
  ping/pong: server may send {"msg": "ping"} at any time; client must
             reply {"msg": "pong"} to stay connected -- call_method()
             answers these transparently while waiting for its own result.
"""

from __future__ import annotations

import asyncio
import json
import re
import uuid
from dataclasses import dataclass, field

import websockets

DEFAULT_TIMEOUT_S = 10


@dataclass
class ConnectResult:
    connected: bool
    session: str | None
    raw_message: dict | None
    error: str | None = None


@dataclass
class MethodCallResult:
    method: str
    call_id: str
    result: object = None
    error: dict | None = None
    raw_messages: list[dict] = field(default_factory=list)
    timed_out: bool = False


async def connect(url: str, headers: dict[str, str] | None = None, cookie_header: str | None = None,
                   timeout_s: float = DEFAULT_TIMEOUT_S):
    """Opens a WebSocket connection and performs the DDP connect
    handshake. Returns (connection_or_None, ConnectResult) -- the caller
    owns the connection's lifetime (pass it to call_method() as many
    times as needed, then close() it) rather than this function closing
    it itself, since a single connection is meant to be reused across
    several method calls in one session. On any failure (unreachable
    host, handshake timeout, a DDP "failed" response), returns
    (None-or-the-open-connection, ConnectResult(connected=False, ...))
    rather than raising -- callers loop over candidate hosts/methods."""
    # Bug found while auditing this file for P2-INJ (unrelated task):
    # every real connection attempt was failing with "unexpected keyword
    # argument 'extra_headers'" -- websockets v14 moved `connect()` to a
    # new asyncio-native implementation and renamed this kwarg to
    # `additional_headers` there (confirmed, not guessed: `extra_headers`
    # genuinely raises TypeError against the exact pinned version,
    # websockets==13.1, which only understands the old name -- this repo's
    # own mcp-servers/ws-rpc-mcp/requirements.txt and .github/workflows/
    # ci.yml's websockets pin were bumped to 16.0 in the same change, not
    # just this call site, specifically so the declared/CI-installed
    # version and this kwarg name stay in agreement). This made 100% of
    # real DDP connections fail silently into the graceful-error branch
    # below, which is exactly why it surfaced as a clean "Connect failed:
    # ..." message instead of a crash -- the 7 real-websocket tests in
    # tests/test_ws_rpc.py (and 2 more in test_ws_rpc_mcp_server.py) were
    # failing for this same reason throughout this session, previously
    # (incorrectly) assumed to be an unrelated, in-progress issue.
    additional_headers = dict(headers or {})
    if cookie_header:
        additional_headers["Cookie"] = cookie_header
    try:
        ws = await asyncio.wait_for(
            websockets.connect(url, additional_headers=additional_headers), timeout=timeout_s)
    except Exception as e:  # noqa: BLE001 -- any transport/handshake failure is a graceful result, not a crash
        return None, ConnectResult(connected=False, session=None, raw_message=None, error=str(e))

    try:
        await ws.send(json.dumps({"msg": "connect", "version": "1", "support": ["1"]}))
        raw = await asyncio.wait_for(ws.recv(), timeout=timeout_s)
        msg = json.loads(raw)
    except Exception as e:  # noqa: BLE001 -- same graceful-result contract as above
        return ws, ConnectResult(connected=False, session=None, raw_message=None, error=str(e))

    if msg.get("msg") == "connected":
        return ws, ConnectResult(connected=True, session=msg.get("session"), raw_message=msg)
    return ws, ConnectResult(connected=False, session=None, raw_message=msg,
                              error=f"DDP connect refused: {msg}")


async def call_method(ws, method: str, params: list | None = None,
                       timeout_s: float = DEFAULT_TIMEOUT_S) -> MethodCallResult:
    """Sends a DDP method call on an already-connected `ws` (from
    connect()) and waits for the matching "result" message (matched by
    the call's own `id`, since other unrelated messages -- "updated",
    "ping" -- can legitimately arrive first). Transparently answers a
    "ping" with "pong" while waiting, rather than treating it as an
    unexpected message or dropping the connection. Returns
    MethodCallResult(timed_out=True) rather than raising if no matching
    result arrives within timeout_s."""
    call_id = uuid.uuid4().hex[:12]
    await ws.send(json.dumps({"msg": "method", "method": method, "params": params or [], "id": call_id}))

    raw_messages: list[dict] = []
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout_s
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            return MethodCallResult(method=method, call_id=call_id, raw_messages=raw_messages, timed_out=True)
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=remaining)
        except TimeoutError:
            return MethodCallResult(method=method, call_id=call_id, raw_messages=raw_messages, timed_out=True)
        msg = json.loads(raw)
        raw_messages.append(msg)
        if msg.get("msg") == "ping":
            await ws.send(json.dumps({"msg": "pong"}))
            continue
        if msg.get("msg") == "result" and msg.get("id") == call_id:
            return MethodCallResult(method=method, call_id=call_id, result=msg.get("result"),
                                     error=msg.get("error"), raw_messages=raw_messages)


def run_ddp_call(url: str, method: str, params: list | None = None,
                  headers: dict[str, str] | None = None, cookie_header: str | None = None,
                  timeout_s: float = DEFAULT_TIMEOUT_S) -> dict:
    """Synchronous entry point for the MCP tool layer: connect, invoke one
    method, close, all in one blocking call. Returns a plain dict (not
    the dataclasses above) so it serializes directly to the tool's
    string/JSON response without the caller needing to know about
    ConnectResult/MethodCallResult."""
    async def _run():
        ws, connect_result = await connect(url, headers=headers, cookie_header=cookie_header, timeout_s=timeout_s)
        if not connect_result.connected:
            if ws:
                await ws.close()
            return {"connected": False, "error": connect_result.error}
        try:
            call_result = await call_method(ws, method, params=params, timeout_s=timeout_s)
        finally:
            await ws.close()
        return {
            "connected": True,
            "session": connect_result.session,
            "result": call_result.result,
            "error": call_result.error,
            "timed_out": call_result.timed_out,
        }
    return asyncio.run(_run())


# Meteor.methods({ name: fn, 'quoted.name': fn, shorthand(args) {...} })
# declarations in a downloaded JS bundle -- mirrors js_endpoints.py's own
# regex-based candidate-extraction philosophy (a real bundler's minified
# output is easier to regex-scan for this literal shape than to parse as
# a full AST). Matches a bare identifier or a quoted string as the key,
# immediately followed by `:` or `(` (the two real declaration shapes:
# `name: function(...)` / `name(...) {`).
_METEOR_METHODS_START_RE = re.compile(r"Meteor\.methods\s*\(\s*\{")
_METHOD_KEY_RE = re.compile(r"""(?:'([^']+)'|"([^"]+)"|\b([A-Za-z_$][A-Za-z0-9_$.]*)\b)\s*[:(]""")


def _find_meteor_methods_blocks(js_text: str) -> list[str]:
    """Finds every `Meteor.methods({...})` call and returns each one's
    balanced `{...}` block content, via a depth-counting scanner (skipping
    over string literals, so a brace inside a JS string doesn't desync the
    count).

    Replaces a SINGLE non-greedy regex (`\\{(.*?)\\}`), which stopped at
    the FIRST "}" immediately followed by ")" -- a code-review finding,
    confirmed via direct reproduction: that shape commonly occurs MID-BODY
    (not at the real end of the methods object) whenever an earlier
    method's body contains a nested call whose last argument is an object
    literal (e.g. `Users.update({_id: id}, {$set: {x: 1}});`), a very
    common real-world Meteor pattern -- every method declared after that
    point was silently dropped with no error, directly undermining this
    tool's one job."""
    blocks: list[str] = []
    for m in _METEOR_METHODS_START_RE.finditer(js_text):
        start = m.end() - 1  # index of the opening '{'
        depth = 0
        in_string: str | None = None
        i = start
        n = len(js_text)
        while i < n:
            ch = js_text[i]
            if in_string is not None:
                if ch == "\\":
                    i += 2
                    continue
                if ch == in_string:
                    in_string = None
            elif ch in ("'", '"', "`"):
                in_string = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    blocks.append(js_text[start + 1:i])
                    break
            i += 1
    return blocks


def enumerate_methods_from_bundle(js_text: str) -> list[str]:
    """Extraction of Meteor.methods({...}) declared method names from a
    downloaded JS bundle -- the "enumerate method names from a schema/
    bundle hint" half of this tool. Candidates, not verified ground truth,
    same philosophy as every other recon extraction tool in this repo
    (subfinder/httpx/katana/js_endpoints.py all return candidates).
    Deduped, insertion order preserved."""
    seen: list[str] = []
    seen_set: set[str] = set()
    for block in _find_meteor_methods_blocks(js_text):
        for key_match in _METHOD_KEY_RE.finditer(block):
            name = key_match.group(1) or key_match.group(2) or key_match.group(3)
            if name and name not in seen_set:
                seen_set.add(name)
                seen.append(name)
    return seen
