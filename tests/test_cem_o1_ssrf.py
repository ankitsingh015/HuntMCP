"""O1 (final security audit) -- regression tests for the CEM outbound-request
policy added under O1:

  * scheme allowlist -- CEM sends http/https only (no file:/ftp:/gopher:/data:)
  * cloud instance-metadata deny -- 169.254.0.0/16, fe80::/10, v4-mapped forms,
    and the well-known metadata hostnames, even when scope_guard.is_in_scope
    would allow them (its is_safe_test_host fast-path treats every link-local IP
    as in-scope before out_of_scope is consulted)
  * redirects are NOT followed on a CEM fetch (a scope-checked in-scope URL must
    not 3xx onto an unchecked host)

The F1-approved posture is preserved: ordinary loopback / RFC1918 still needs no
engagement.yaml and still works (the benchmark path).
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))

_spec = importlib.util.spec_from_file_location(
    "case_mcp_server_o1", os.path.join(ROOT, "mcp-servers", "case-mcp", "server.py"))
srv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv)
import case_store  # noqa: E402


@pytest.fixture()
def cem_env(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_CASE_DB_PATH", str(tmp_path / "case.db"))
    monkeypatch.setenv("HUNTMCP_BUDGET_PATH", str(tmp_path / "budget.json"))
    monkeypatch.setenv("HUNTMCP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("HUNTMCP_ENGAGEMENT_PATH", str(tmp_path / "no-engagement.yaml"))
    yield


def _confirmed(url, sig=None):
    fid = json.loads(srv.create_finding("idor", "/x"))["id"]
    srv.add_evidence("response", "confirmed", finding_id=fid)
    srv.update_finding_status(fid, "CONFIRMED")
    base = {"method": "GET", "url": url, "headers": {}, "body": None}
    conds = [{"name": "x", "category": "header", "baseline_value": "1",
              "perturbation": {"drop": True}}]
    d = json.loads(srv.define_conditions(
        fid, json.dumps(base), json.dumps(sig or {"body_contains": "x"}), json.dumps(conds), k=3))
    assert "error" not in d, d
    return fid


# --------------------------------------------------------------------------
# pure helper
# --------------------------------------------------------------------------
@pytest.mark.parametrize("url", [
    "file://localhost/etc/passwd",
    "file:///etc/passwd",
    "ftp://host/x",
    "gopher://host/_",
    "data:text/plain,hi",
])
def test_non_http_schemes_are_refused(url):
    assert srv._cem_outbound_policy_error(url) is not None


@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/",
    "https://169.254.169.254/",
    "http://[::ffff:169.254.169.254]/",
    "http://[fd00:ec2::254]/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata/",
])
def test_instance_metadata_targets_are_refused(url):
    assert srv._cem_outbound_policy_error(url) is not None


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8000/svc",
    "https://example.com/",
    "http://10.0.0.5/internal",       # F1 posture: RFC1918 still permitted by this layer
    "http://192.168.1.10:9000/x",
])
def test_ordinary_http_targets_are_permitted_by_the_policy(url):
    assert srv._cem_outbound_policy_error(url) is None


# --------------------------------------------------------------------------
# end to end through the real sender
# --------------------------------------------------------------------------
def test_sender_refuses_file_scheme_base_request(cem_env, tmp_path):
    secret = tmp_path / "s.txt"
    secret.write_text("SECRET_TOKEN_zzz\n")
    fid = _confirmed(f"file://localhost{secret}", {"body_contains": "SECRET_TOKEN"})
    out = json.loads(srv.determinism_gate(fid, "http://127.0.0.1/", k=3))
    assert "error" in out and "outbound policy" in out["error"].lower()
    assert case_store.cem_load_state(fid)["trials"] == []     # nothing sent / persisted


def test_sender_refuses_metadata_ip_base_request(cem_env):
    fid = _confirmed("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
    out = json.loads(srv.determinism_gate(fid, "http://127.0.0.1/", k=3))
    assert "error" in out and "metadata" in out["error"].lower()


def test_run_counterfactual_also_refuses_metadata_ip(cem_env):
    """run_counterfactual shares _scope_or_error + the per-trial _make_scope_cb;
    the policy must fire on that path too, before any HTTP or persistence."""
    fid = _confirmed("http://169.254.169.254/latest/meta-data/", {"body_contains": "ami-"})
    cid = case_store.cem_load_state(fid)["conditions"][0]["id"]
    out = json.loads(srv.run_counterfactual(fid, "http://127.0.0.1/", cid, k=3))
    assert "error" in out
    st = case_store.cem_load_state(fid)
    assert st["trials"] == [] and st["verdicts"] == []
    assert case_store.cem_load_state(fid)["trials"] == []


def test_cem_fetch_does_not_follow_redirects(cem_env):
    reached: list[str] = []

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            reached.append(self.path)
            if self.path.startswith("/redir"):
                self.send_response(302)
                self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
                self.end_headers()
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ORIGIN_BODY")

        def log_message(self, *a):
            pass

    s = HTTPServer(("127.0.0.1", 0), H)
    port = s.server_address[1]
    t = threading.Thread(target=s.serve_forever, daemon=True)
    t.start()
    try:
        fid = _confirmed(f"http://127.0.0.1:{port}/redir", {"body_contains": "meta-data"})
        out = json.loads(srv.determinism_gate(fid, "http://127.0.0.1/", k=3))
        # the 302 was seen but NOT followed: no second hop, oracle never matched
        assert all(p.startswith("/redir") for p in reached), reached
        assert out["hits"] == [False, False, False]
        assert out["determinism_status"] in ("NONDETERMINISTIC", "INCOMPLETE")
    finally:
        s.shutdown()
        t.join(timeout=2)


def test_benchmark_shaped_loopback_still_works(cem_env):
    reached: list[str] = []

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            reached.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"BENCH_OK")

        def log_message(self, *a):
            pass

    s = HTTPServer(("127.0.0.1", 0), H)
    port = s.server_address[1]
    t = threading.Thread(target=s.serve_forever, daemon=True)
    t.start()
    try:
        fid = _confirmed(f"http://127.0.0.1:{port}/svc", {"body_contains": "BENCH_OK"})
        out = json.loads(srv.determinism_gate(fid, "http://127.0.0.1/", k=3))
        assert out["determinism_status"] == "STABLE"
        assert out["hits"] == [True, True, True]
        assert len(reached) == 3
    finally:
        s.shutdown()
        t.join(timeout=2)
