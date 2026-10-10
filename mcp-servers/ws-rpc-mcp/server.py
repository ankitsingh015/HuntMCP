"""Generic WebSocket-RPC (DDP-aware) MCP server.

See ws_rpc.py's module docstring for the full design rationale -- short
version: no MCP tool previously wrapped a raw WebSocket/RPC protocol
(DDP/Meteor-style, the concrete real-world case that motivated this),
forcing a hand-rolled client each time this surface came up.

Tier-2 (target-touching, sends real requests to the live target) --
callers MUST run scripts/check-scope.sh <host> first, exactly like every
other Tier-2 tool in this repo. Registered in scripts/hooks/
scope_gate_hook.py's TIER2_MCP_SERVERS. `url`'s key name is literally
`url` (not `ws_url`) specifically so that hook's existing HOST_ARG_KEYS-
based extraction picks it up automatically -- no new Python-side scope-
checking logic needed for this server (same convention idor-mcp already
established).

Budget/audit enforced directly here (like idor-mcp), since a direct
websockets call doesn't go through tool_resolver.run_tool()'s subprocess
chokepoint.

Logging a call's outcome to case-mcp's persistent case store (hypotheses/
experiments/findings) is the CALLING AGENT's own next step after reading
this tool's result -- e.g. `mcp__case-mcp` `log_experiment("ws-rpc-mcp",
<method+params>, <url>, result=<this tool's output>)` -- not something
this server does on the agent's behalf, matching idor-mcp/cors_probe's
same "return the evidence, let the agent's own case-mcp calls record it"
separation.
"""

import json
import os
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 2)[0])

import ws_rpc
from audit_log import log_call as _log_call
from budget_guard import BudgetExceeded
from budget_guard import enforce as _enforce_budget
from injection_boundary import quarantine as _quarantine
from mcp.server.fastmcp import FastMCP

app = FastMCP("ws-rpc-mcp")


@app.tool()
def call_ddp_method(url: str, method: str, params: str = "[]", cookie_header: str = "",
                     bearer_token: str = "", timeout_s: float = 10) -> str:
    """Connect to a DDP-style WebSocket RPC endpoint (`url`, e.g.
    "wss://target.com/websocket") and invoke one method. `params` is a
    JSON-encoded array (e.g. '["user_42", {"limit": 10}]') -- DDP methods
    take positional params, not named kwargs. cookie_header/bearer_token
    follow the same convention as idor-mcp/browser-mcp's tools, forwarded
    as connection headers (a DDP session is often authenticated the same
    way the page's own HTTP session is, via a Meteor.loginToken exchanged
    over the DDP connection itself -- if the target uses that pattern,
    call this once with no auth to get a session, then a second real
    login method call over the SAME logical flow is a separate step this
    tool doesn't automate, since the exact login method name/shape is
    target-specific). Requires scope-gate clearance first (Tier-2) -- this
    sends a real connection + method call to the live target. Returns the
    DDP session id, the method's result or DDP-level error, and whether
    the call timed out -- log the outcome to case-mcp's log_experiment()
    yourself as your own next step (see this module's own docstring)."""
    start = time.monotonic()
    try:
        _enforce_budget("ws-rpc-mcp")
    except BudgetExceeded as e:
        return f"⚠️ Tier-2 budget exhausted before this call could run: {e}"

    try:
        parsed_params = json.loads(params)
    except ValueError as e:
        return f"Error: params must be a JSON array, got invalid JSON ({e})"
    if not isinstance(parsed_params, list):
        return f"Error: params must be a JSON ARRAY (DDP methods take positional params), got {type(parsed_params).__name__}"

    headers = {}
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"

    result = ws_rpc.run_ddp_call(
        url, method, params=parsed_params, headers=headers,
        cookie_header=cookie_header or None, timeout_s=timeout_s,
    )

    duration_ms = (time.monotonic() - start) * 1000
    _log_call("ws-rpc-mcp", [url, method], returncode=None, duration_ms=duration_ms, block=None)

    if not result["connected"]:
        # P2-INJ (UU-7): result["error"] can be ws_rpc.connect()'s own
        # f"DDP connect refused: {msg}", which directly embeds the raw
        # DDP "failed" message the TARGET sent (e.g. an arbitrary
        # "reason" string) -- fully target-controlled free text reaching
        # agent-visible output, same class of surface as oob-mcp's raw-
        # request/raw-response fields. Quarantine it.
        return f"Connect failed: {_quarantine(result['error'], source_label='DDP connect error')}"
    lines = [f"Connected (session={result['session']!r})", f"Method: {method}({parsed_params})"]
    if result["timed_out"]:
        lines.append("⚠️ TIMED OUT waiting for a result message.")
    elif result["error"]:
        # P2-INJ (UU-7): a DDP-level method error is the target's own
        # {"error": ..., "reason": ...} payload -- fully target-
        # controlled, same reasoning as the result branch below.
        lines.append(f"DDP error: {_quarantine(json.dumps(result['error']), source_label='DDP method error')}")
    else:
        # P2-INJ (UU-7): a DDP method's result is whatever the target's
        # own backend decided to return -- fully target-controlled free
        # text/JSON reaching agent-visible output, found during the
        # final full-repo P2-INJ sweep. Quarantine it, same as oob-mcp's
        # raw-request/raw-response fields and browser-mcp's rendered HTML.
        lines.append(f"Result: {_quarantine(json.dumps(result['result']), source_label='DDP method result')}")
    return "\n".join(lines)


@app.tool()
def enumerate_ddp_methods(js_file_path: str) -> str:
    """Scan an already-downloaded JS bundle (e.g. from recon-agent's own
    downloaded-JS directory) for Meteor.methods({...}) declarations,
    returning candidate method names to try with call_ddp_method(). Not a
    live-target action -- reads an already-downloaded file, same contract
    as secrets-mcp's scan_directory()/extract_endpoints()."""
    if not os.path.isfile(js_file_path):
        return f"Error: {js_file_path!r} is not a file."
    with open(js_file_path, errors="replace") as f:
        text = f.read()
    methods = ws_rpc.enumerate_methods_from_bundle(text)
    if not methods:
        return f"No Meteor.methods({{...}}) declarations found in {js_file_path!r}."
    return f"{len(methods)} candidate DDP method(s) found:\n" + "\n".join(f"  {m}" for m in methods)


if __name__ == "__main__":
    print("ws-rpc-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
