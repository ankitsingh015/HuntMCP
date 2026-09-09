"""F1 (+ remediation) — CEM scope enforcement.

Core invariant under test:

  The scope decision MUST protect the URL cem_engine.run_intervention will
  ACTUALLY fetch -- meta["base_request"]["url"] -- not a caller-supplied `url`
  argument that merely claims to be that destination.

Two layers, both exercised here:

  * HOOK (scripts/hooks/scope_gate_hook.py) -- tool-level gating for MIXED MCP
    servers via TIER2_MCP_TOOLS: only case-mcp's two senders are gated; every
    local bookkeeping tool on the same server is left alone (SEC-2/ARCH-1).
    The hook also still early-filters the senders' `url` arg -- defence in
    depth, NOT the security boundary.

  * SENDER (mcp-servers/case-mcp/server.py) -- the DEFINITIVE check:
    _scope_or_error(meta["base_request"]) runs before run_intervention, reusing
    scope_guard (the same module the hook and scripts/check-scope.sh use). A
    caller cannot decouple the checked value from the fetched value because the
    checked value IS meta["base_request"]["url"] (SEC-1).

Attacker-style bypass attempts (omitted/empty/mismatched/malformed `url`,
casing, ports, userinfo, alternate host reps, missing engagement, stored
state, local-helper reroute, OpenCode tool-name translation) are all pinned
below with BLOCKED/ALLOWED + why.
"""
import importlib.util
import io
import json
import os
import sys

import engagement_paths
import pytest
import scope_gate_hook as hook

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))

_spec = importlib.util.spec_from_file_location(
    "case_mcp_server_f1", os.path.join(ROOT, "mcp-servers", "case-mcp", "server.py"),
)
srv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv)
FetchResult = srv.http_probe.FetchResult

IN_SCOPE = "in-scope-target.example"
OOS = "out-of-scope-evil.example"


@pytest.fixture(autouse=True)
def _isolate_active_engagement(monkeypatch, tmp_path):
    """Never see whatever real engagement is active in this repo -- point the
    active-engagement pointer at a path that never gets a file (mirrors
    tests/test_scope_gate_hook.py). Per-test engagement state is set explicitly
    via HUNTMCP_ENGAGEMENT_PATH below."""
    monkeypatch.setattr(engagement_paths, "ACTIVE_POINTER", str(tmp_path / ".no-active"))


def _with_engagement(tmp_path, monkeypatch, in_scope=(IN_SCOPE,)):
    p = tmp_path / "engagement.yaml"
    body = [f"target: {in_scope[0]}", "in_scope:"]
    body += [f"  - {h}" for h in in_scope]
    body += ["out_of_scope: []", ""]
    p.write_text("\n".join(body))
    monkeypatch.setenv("HUNTMCP_ENGAGEMENT_PATH", str(p))
    return p


def _without_engagement(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_ENGAGEMENT_PATH", str(tmp_path / "no-such-engagement.yaml"))


def _run_hook(monkeypatch, tool_name, tool_input):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(
        {"tool_name": tool_name, "tool_input": tool_input})))
    return hook.main()


# ======================================================================
# HOOK: tool-level gating for the mixed case-mcp server (SEC-2 / ARCH-1)
# ======================================================================

def test_case_mcp_is_not_whole_server_tier2():
    assert "case-mcp" not in hook.TIER2_MCP_SERVERS


def test_case_mcp_network_tools_are_declared_at_tool_level():
    assert hook.TIER2_MCP_TOOLS["case-mcp"] == frozenset(
        {"determinism_gate", "run_counterfactual"})


def test_mcp_tool_name_parsing():
    assert hook._mcp_tool_name("mcp__case-mcp__determinism_gate") == "determinism_gate"
    assert hook._mcp_tool_name("mcp__case-mcp__run_counterfactual") == "run_counterfactual"
    assert hook._mcp_tool_name("mcp__case-mcp__log_experiment") == "log_experiment"
    assert hook._mcp_tool_name("Bash") == ""


@pytest.mark.parametrize("tool", ["determinism_gate", "run_counterfactual"])
def test_hook_early_filters_network_sender_with_out_of_scope_url(monkeypatch, tmp_path, tool):
    _with_engagement(tmp_path, monkeypatch)
    rc = _run_hook(monkeypatch, f"mcp__case-mcp__{tool}",
                   {"finding_id": 1, "url": f"https://{OOS}/doc/1", "k": 3})
    assert rc == 2


@pytest.mark.parametrize("tool", ["determinism_gate", "run_counterfactual"])
def test_hook_allows_network_sender_with_in_scope_url(monkeypatch, tmp_path, tool):
    _with_engagement(tmp_path, monkeypatch)
    rc = _run_hook(monkeypatch, f"mcp__case-mcp__{tool}",
                   {"finding_id": 1, "url": f"https://{IN_SCOPE}/doc/1", "k": 3})
    assert rc == 0


@pytest.mark.parametrize("tool", ["log_experiment", "check_experiment_exists"])
@pytest.mark.parametrize("target", [
    f"https://{OOS}/x",            # out-of-scope-looking host
    "the internal admin panel",   # arbitrary free text
    "prod-db-01",                  # a bare token
])
def test_hook_does_not_gate_local_bookkeeping_tools(monkeypatch, tmp_path, tool, target):
    """SEC-2: log_experiment / check_experiment_exists perform NO network I/O --
    their `target` arg is a bookkeeping label. Adding case-mcp to the gate must
    not start refusing local case work."""
    _with_engagement(tmp_path, monkeypatch)
    rc = _run_hook(monkeypatch, f"mcp__case-mcp__{tool}",
                   {"tool": "curl", "input": "GET /", "target": target})
    assert rc == 0


@pytest.mark.parametrize("tool", [
    "define_conditions", "minimal_condition_sets", "minimize_poc", "evidence_bundle",
    "case_summary", "log_hypothesis", "create_finding", "add_evidence",
])
def test_hook_does_not_gate_other_local_case_tools_even_with_host_shaped_args(
        monkeypatch, tmp_path, tool):
    _with_engagement(tmp_path, monkeypatch)
    rc = _run_hook(monkeypatch, f"mcp__case-mcp__{tool}", {
        "finding_id": 1,
        "endpoint": f"https://{OOS}/x",
        "url": f"https://{OOS}/x",
        "target": f"https://{OOS}/x",
    })
    assert rc == 0


def test_hook_unknown_case_mcp_tool_defaults_to_local(monkeypatch, tmp_path):
    """A tool not in TIER2_MCP_TOOLS["case-mcp"] is treated as local -- a future
    NETWORK tool would need its own sender-side scope check (documented), same
    as the two senders have."""
    _with_engagement(tmp_path, monkeypatch)
    rc = _run_hook(monkeypatch, "mcp__case-mcp__some_future_tool",
                   {"url": f"https://{OOS}/x"})
    assert rc == 0


# ======================================================================
# HOOK: existing server-level Tier-2 behavior is UNCHANGED
# ======================================================================

def test_existing_server_level_tier2_servers_unchanged(monkeypatch, tmp_path):
    _with_engagement(tmp_path, monkeypatch)
    assert _run_hook(monkeypatch, "mcp__httpx-mcp__screenshot_hosts", {"domains": OOS}) == 2
    assert _run_hook(monkeypatch, "mcp__httpx-mcp__screenshot_hosts", {"domains": IN_SCOPE}) == 0
    assert _run_hook(monkeypatch, "mcp__obscura-mcp__browser_navigate",
                     {"url": f"https://{OOS}/"}) == 2
    assert _run_hook(monkeypatch, "mcp__writeup-mcp__fetch_cves", {"keyword": "apache"}) == 0
    assert _run_hook(monkeypatch, "mcp__memory-mcp__record_attempt",
                     {"target": OOS, "note": "x"}) == 0


def test_opencode_translated_tool_name_gates_sender_but_not_local(monkeypatch, tmp_path):
    """.opencode/plugin/scope-gate.ts turns OpenCode's `case-mcp:determinism_gate`
    into `mcp__case-mcp__determinism_gate` before invoking this hook -- verify the
    translated form hits the same tool-level decision."""
    _with_engagement(tmp_path, monkeypatch)
    assert _run_hook(monkeypatch, "mcp__case-mcp__determinism_gate",
                     {"finding_id": 1, "url": f"https://{OOS}/"}) == 2
    assert _run_hook(monkeypatch, "mcp__case-mcp__log_experiment",
                     {"target": f"https://{OOS}/"}) == 0


def test_hook_sender_with_real_target_and_no_engagement_fails_closed(monkeypatch, tmp_path):
    _without_engagement(tmp_path, monkeypatch)
    rc = _run_hook(monkeypatch, "mcp__case-mcp__determinism_gate",
                   {"finding_id": 1, "url": f"https://{OOS}/"})
    assert rc == 2


# ======================================================================
# LOOPBACK EDGE -- pre-existing hook quirk, documented, NOT fixed here
# ======================================================================

def test_KNOWN_hook_scheme_port_loopback_url_arg_without_engagement_is_blocked(
        monkeypatch, tmp_path):
    """Pre-existing quirk of _extract_hosts_from_tool_input: unlike
    _extract_hosts_from_bash it does not urlsplit a scheme+port value, so
    'http://127.0.0.1:8765/x' is treated as one opaque candidate and, with no
    engagement.yaml, fails CLOSED (rc 2). This is:
      - not CEM-specific (any Tier-2 MCP server handed http://<ip>:<port>/... hits it),
      - fail-closed (safe direction),
      - not exercised by the CEM benchmark (which drives cem_engine / the senders
        directly, and the SENDER correctly allows loopback -- see
        test_SEC1_no_engagement_loopback_base_request_is_allowed).
    F1 deliberately does not broaden into a general scope-hook refactor; tracked
    as a separate follow-up (urlsplit scheme-bearing values in
    _extract_hosts_from_tool_input, mirroring _extract_hosts_from_bash)."""
    _without_engagement(tmp_path, monkeypatch)
    rc = _run_hook(monkeypatch, "mcp__case-mcp__determinism_gate",
                   {"finding_id": 1, "url": "http://127.0.0.1:8765/doc/1"})
    assert rc == 2


def test_KNOWN_hook_scheme_port_loopback_url_arg_with_engagement_is_allowed(
        monkeypatch, tmp_path):
    _with_engagement(tmp_path, monkeypatch)
    rc = _run_hook(monkeypatch, "mcp__case-mcp__determinism_gate",
                   {"finding_id": 1, "url": "http://127.0.0.1:8765/doc/1"})
    assert rc == 0


# ======================================================================
# SENDER: SEC-1 -- scope decision protects the ACTUAL fetched URL
# ======================================================================

@pytest.fixture
def cem(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_CASE_DB_PATH", str(tmp_path / "case.db"))
    monkeypatch.setenv("HUNTMCP_BUDGET_PATH", str(tmp_path / "budget.json"))
    monkeypatch.setenv("HUNTMCP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    return tmp_path


_SIG = {"status_in": [200]}
_CONDS = [{"name": "auth_cookie", "category": "identity", "baseline_value": "p",
           "perturbation": {"drop": True}}]


def _confirmed_cem(base_url):
    """A CONFIRMED finding with CEM state whose base_request targets `base_url`.
    define_conditions is local + un-gated, so an out-of-scope base_url persists
    fine -- that is exactly the SEC-1 setup: the block must happen at the sender."""
    f = json.loads(srv.create_finding("IDOR", "/doc/{id}"))
    srv.add_evidence("request", "GET /doc/1", finding_id=f["id"])
    srv.update_finding_status(f["id"], "CONFIRMED")
    base = {"method": "GET", "url": base_url, "headers": {"Cookie": "s=1"}, "body": None}
    d = json.loads(srv.define_conditions(
        f["id"], json.dumps(base), json.dumps(_SIG), json.dumps(_CONDS), k=3))
    assert "error" not in d, d
    return f["id"], d["condition_ids"][0]


class _FetchSpy:
    def __init__(self, *, raise_on_call): self.calls = 0; self._raise = raise_on_call
    def __call__(self, *a, **k):
        self.calls += 1
        if self._raise:
            raise AssertionError("http_probe.fetch reached on a scope-blocked CEM send")
        return FetchResult(status=200, body="", error=None)


def _assert_scope_blocked(out_json, spy):
    out = json.loads(out_json)
    assert "error" in out, out
    assert "scope" in out["error"].lower(), out["error"]
    assert spy.calls == 0, "no HTTP may occur on a scope-blocked send"


# ---- the decoupling attacks: OOS base_request, various `url` args ----

def test_SEC1_determinism_gate_oos_base_request_empty_url_arg(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, _ = _confirmed_cem(f"https://{OOS}/doc/1")
    spy = _FetchSpy(raise_on_call=True)
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    _assert_scope_blocked(srv.determinism_gate(fid, "", k=3), spy)


def test_SEC1_determinism_gate_oos_base_request_in_scope_url_arg(cem, tmp_path, monkeypatch):
    """The headline bypass: caller passes an in-scope `url` while base_request
    (the fetched URL) is out of scope."""
    _with_engagement(tmp_path, monkeypatch)
    fid, _ = _confirmed_cem(f"https://{OOS}/doc/1")
    spy = _FetchSpy(raise_on_call=True)
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    _assert_scope_blocked(srv.determinism_gate(fid, f"https://{IN_SCOPE}/doc/1", k=3), spy)


def test_SEC1_determinism_gate_oos_base_request_malformed_url_arg(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, _ = _confirmed_cem(f"https://{OOS}/doc/1")
    spy = _FetchSpy(raise_on_call=True)
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    _assert_scope_blocked(srv.determinism_gate(fid, "::::not-a-url", k=3), spy)


def test_SEC1_determinism_gate_oos_base_request_unrelated_in_scope_url_arg(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch, in_scope=(IN_SCOPE, "other-allowed.example"))
    fid, _ = _confirmed_cem(f"https://{OOS}/doc/1")
    spy = _FetchSpy(raise_on_call=True)
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    _assert_scope_blocked(srv.determinism_gate(fid, "https://other-allowed.example/", k=3), spy)


def test_SEC1_run_counterfactual_oos_base_request_in_scope_url_arg(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid = _confirmed_cem(f"https://{OOS}/doc/1")
    spy = _FetchSpy(raise_on_call=True)
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    _assert_scope_blocked(srv.run_counterfactual(fid, f"https://{IN_SCOPE}/doc/1", cid, k=3), spy)


# ---- normalization: casing / port / userinfo / query|fragment ----

def test_SEC1_casing_in_base_request_host_is_normalized(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, _ = _confirmed_cem(f"HTTPS://{OOS.upper()}/DOC/1")
    spy = _FetchSpy(raise_on_call=True)
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    _assert_scope_blocked(srv.determinism_gate(fid, "", k=3), spy)


def test_SEC1_port_on_out_of_scope_base_request_is_still_blocked(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, _ = _confirmed_cem(f"https://{OOS}:8443/doc/1")
    spy = _FetchSpy(raise_on_call=True)
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    _assert_scope_blocked(srv.determinism_gate(fid, "", k=3), spy)


def test_SEC1_userinfo_at_sign_real_host_is_the_authority(cem, tmp_path, monkeypatch):
    """https://<in-scope>@<oos>/... -- the real host is <oos>."""
    _with_engagement(tmp_path, monkeypatch)
    fid, _ = _confirmed_cem(f"https://{IN_SCOPE}@{OOS}/doc/1")
    spy = _FetchSpy(raise_on_call=True)
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    _assert_scope_blocked(srv.determinism_gate(fid, "", k=3), spy)


def test_SEC1_in_scope_host_with_oos_string_in_query_is_allowed(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, _ = _confirmed_cem(f"https://{IN_SCOPE}/doc/1?next=https://{OOS}/")
    seen = []
    monkeypatch.setattr(srv.http_probe, "fetch",
                        lambda u, *a: (seen.append(u), FetchResult(200, "", None))[1])
    out = json.loads(srv.determinism_gate(fid, "", k=3))
    assert "error" not in out
    assert seen and all(IN_SCOPE in u for u in seen)


# ---- missing base_request url / missing engagement ----

def test_SEC1_base_request_without_url_key_is_refused(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    f = json.loads(srv.create_finding("IDOR", "/x"))
    srv.add_evidence("request", "r", finding_id=f["id"])
    srv.update_finding_status(f["id"], "CONFIRMED")
    srv.define_conditions(f["id"], json.dumps({"method": "GET", "headers": {}}),
                          json.dumps(_SIG), json.dumps(_CONDS), k=3)
    spy = _FetchSpy(raise_on_call=True)
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    _assert_scope_blocked(srv.determinism_gate(f["id"], "", k=3), spy)


def test_SEC1_no_engagement_real_oos_base_request_is_refused(cem, tmp_path, monkeypatch):
    _without_engagement(tmp_path, monkeypatch)
    fid, _ = _confirmed_cem(f"https://{OOS}/doc/1")
    spy = _FetchSpy(raise_on_call=True)
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    _assert_scope_blocked(srv.determinism_gate(fid, "", k=3), spy)


def test_SEC1_no_engagement_loopback_base_request_is_allowed(cem, tmp_path, monkeypatch):
    """The CEM benchmark target is 127.0.0.1:<ephemeral>. A safe test host needs
    no engagement.yaml -- same rule the hook applies to a candidate-less call."""
    _without_engagement(tmp_path, monkeypatch)
    fid, _ = _confirmed_cem("http://127.0.0.1:9/doc/1")
    seen = []
    monkeypatch.setattr(srv.http_probe, "fetch",
                        lambda *a: (seen.append(1), FetchResult(200, "", None))[1])
    out = json.loads(srv.determinism_gate(fid, "http://127.0.0.1:9/doc/1", k=3))
    assert "error" not in out
    assert out["determinism_status"] == "STABLE"
    assert len(seen) == 3


# ---- the legitimate path still works ----

def test_SEC1_in_scope_base_request_allows_the_send(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, _ = _confirmed_cem(f"https://{IN_SCOPE}/doc/1")
    seen = []
    monkeypatch.setattr(srv.http_probe, "fetch",
                        lambda u, *a: (seen.append(u), FetchResult(200, "", None))[1])
    out = json.loads(srv.determinism_gate(fid, f"https://{IN_SCOPE}/doc/1", k=3))
    assert "error" not in out
    assert out["determinism_status"] == "STABLE"
    assert seen and all(u.startswith(f"https://{IN_SCOPE}/doc/1") for u in seen)


def test_SEC1_run_counterfactual_in_scope_base_request_allows_the_send(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid = _confirmed_cem(f"https://{IN_SCOPE}/doc/1")
    it = iter([200, 200, 200, 403, 403, 403])
    seen = []
    monkeypatch.setattr(srv.http_probe, "fetch",
                        lambda u, *a: (seen.append(u), FetchResult(next(it), "", None))[1])
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN_SCOPE}/doc/1", cid, k=3))
    assert "error" not in out
    assert out["verdict"] == "necessary"
    assert len(seen) == 6 and all(IN_SCOPE in u for u in seen)


def test_SEC1_scope_block_is_upstream_of_http_and_of_budget(cem, tmp_path, monkeypatch):
    """Replaces the old near-vacuous hook-only 'before HTTP' test with a real
    assertion about the sender's execution boundary: on an out-of-scope
    base_request nothing downstream runs -- not fetch, not the budget callback,
    and nothing is persisted."""
    _with_engagement(tmp_path, monkeypatch)
    fid, _ = _confirmed_cem(f"https://{OOS}/doc/1")
    budget_hits = []
    monkeypatch.setattr(srv, "_enforce_budget", lambda name: budget_hits.append(name))
    spy = _FetchSpy(raise_on_call=True)
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.determinism_gate(fid, f"https://{IN_SCOPE}/", k=3))
    assert "error" in out and "scope" in out["error"].lower()
    assert spy.calls == 0
    assert budget_hits == []
    state = srv.case_store.cem_load_state(fid)
    assert state["trials"] == [] and state["verdicts"] == []


# ---- stored-state reroute ----

def test_SEC1_define_conditions_then_gate_blocks_at_the_send_not_the_define(cem, tmp_path, monkeypatch):
    """define_conditions (local, no I/O) persists an OOS base_request without
    complaint; the scope refusal lands at the network sender."""
    _with_engagement(tmp_path, monkeypatch)
    fid, _ = _confirmed_cem(f"https://{OOS}/doc/1")   # the define already happened, no error
    spy = _FetchSpy(raise_on_call=True)
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    _assert_scope_blocked(srv.determinism_gate(fid, "", k=3), spy)
