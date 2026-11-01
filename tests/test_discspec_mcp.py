"""discspec-mcp: scope enforcement, spec-fetch wiring, and output
formatting for discover_from_openapi()/discover_from_graphql(). The
parsing logic itself (disc_spec.parse_openapi/parse_graphql_introspection)
is covered directly in tests/test_disc_spec.py -- this file is the
server-integration layer: scope gate -> http_probe.fetch -> parse ->
quarantine -> formatted text.
"""
import importlib.util
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))

import http_probe  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "discspec_mcp_server", os.path.join(ROOT, "mcp-servers", "discspec-mcp", "server.py"),
)
srv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv)


@pytest.fixture
def in_scope_engagement(tmp_path, monkeypatch):
    eng = tmp_path / "engagement.yaml"
    eng.write_text("target: t.example\nin_scope:\n  - t.example\nout_of_scope: []\n")
    monkeypatch.setenv("HUNTMCP_ENGAGEMENT_PATH", str(eng))
    return tmp_path


_OPENAPI_JSON = json.dumps({
    "paths": {
        "/users/{id}": {
            "get": {
                "parameters": [
                    {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}},
                ],
            },
        },
        "/users": {"post": {"requestBody": {"required": True}}},
    },
})

_OPENAPI_YAML = """
paths:
  /orders/{id}:
    get:
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
"""

_GRAPHQL_INTROSPECTION_JSON = json.dumps({
    "data": {
        "__schema": {
            "queryType": {"fields": [{"name": "user", "args": [
                {"name": "id", "type": {"kind": "SCALAR", "name": "ID", "ofType": None}},
            ]}]},
            "mutationType": None,
        },
    },
})


# ---------------------------------------------------------------------------
# discover_from_openapi -- scope gate
# ---------------------------------------------------------------------------

def test_discover_from_openapi_refuses_out_of_scope_url(in_scope_engagement, monkeypatch):
    def _unreachable_fetch(*a, **k):
        raise AssertionError("discover_from_openapi must refuse before ever calling http_probe.fetch")
    monkeypatch.setattr(srv.http_probe, "fetch", _unreachable_fetch)

    out = srv.discover_from_openapi("https://evil.example/openapi.json")
    assert "BLOCKED" in out
    assert "scope" in out.lower()


def test_discover_from_openapi_refuses_cloud_metadata_url(in_scope_engagement, monkeypatch):
    def _unreachable_fetch(*a, **k):
        raise AssertionError("discover_from_openapi must refuse before ever calling http_probe.fetch")
    monkeypatch.setattr(srv.http_probe, "fetch", _unreachable_fetch)

    out = srv.discover_from_openapi("http://169.254.169.254/openapi.json")
    assert "BLOCKED" in out


def test_discover_from_openapi_refuses_empty_url(in_scope_engagement):
    out = srv.discover_from_openapi("")
    assert "Error" in out or "BLOCKED" in out


# ---------------------------------------------------------------------------
# discover_from_openapi -- fetch + parse + format
# ---------------------------------------------------------------------------

def test_discover_from_openapi_formats_json_spec(in_scope_engagement, monkeypatch):
    monkeypatch.setattr(
        srv.http_probe, "fetch",
        lambda *a, **k: http_probe.FetchResult(status=200, body=_OPENAPI_JSON),
    )
    out = srv.discover_from_openapi("https://t.example/openapi.json")
    assert "GET /users/{id}" in out
    assert "POST /users" in out


def test_discover_from_openapi_formats_yaml_spec(in_scope_engagement, monkeypatch):
    monkeypatch.setattr(
        srv.http_probe, "fetch",
        lambda *a, **k: http_probe.FetchResult(status=200, body=_OPENAPI_YAML),
    )
    out = srv.discover_from_openapi("https://t.example/openapi.yaml")
    assert "GET /orders/{id}" in out


def test_discover_from_openapi_surfaces_fetch_error(in_scope_engagement, monkeypatch):
    monkeypatch.setattr(
        srv.http_probe, "fetch",
        lambda *a, **k: http_probe.FetchResult(status=None, body="", error="connection refused"),
    )
    out = srv.discover_from_openapi("https://t.example/openapi.json")
    assert "Error" in out
    assert "connection refused" in out


def test_discover_from_openapi_surfaces_http_error_status(in_scope_engagement, monkeypatch):
    monkeypatch.setattr(
        srv.http_probe, "fetch",
        lambda *a, **k: http_probe.FetchResult(status=404, body="not found"),
    )
    out = srv.discover_from_openapi("https://t.example/openapi.json")
    assert "404" in out


def test_discover_from_openapi_reports_unparseable_body(in_scope_engagement, monkeypatch):
    monkeypatch.setattr(
        srv.http_probe, "fetch",
        lambda *a, **k: http_probe.FetchResult(status=200, body="{not json or yaml: [[["),
    )
    out = srv.discover_from_openapi("https://t.example/openapi.json")
    assert "Error" in out


def test_discover_from_openapi_quarantines_the_parse_error_message(in_scope_engagement, monkeypatch):
    """Regression: a yaml.YAMLError's own message routinely echoes a
    fragment of the offending document (confirmed:
    yaml.safe_load("bad: [unterminated") raises a message containing the
    literal input text). The spec body is attacker-controlled -- a
    hostile target can craft a malformed document whose YAML error
    context contains instruction-shaped text, so this error path must be
    quarantined exactly like the success-path listing is, not returned
    as a bare f-string."""
    hostile_body = "key: [unterminated-list-with-injected-text-INSTRUCTION"
    monkeypatch.setattr(
        srv.http_probe, "fetch",
        lambda *a, **k: http_probe.FetchResult(status=200, body=hostile_body),
    )
    out = srv.discover_from_openapi("https://t.example/openapi.json")
    assert "UNTRUSTED-DATA-BEGIN" in out
    assert "UNTRUSTED-DATA-END" in out


def test_discover_from_openapi_reports_no_endpoints_found(in_scope_engagement, monkeypatch):
    monkeypatch.setattr(
        srv.http_probe, "fetch",
        lambda *a, **k: http_probe.FetchResult(status=200, body=json.dumps({"paths": {}})),
    )
    out = srv.discover_from_openapi("https://t.example/openapi.json")
    assert "No endpoints" in out


def test_discover_from_openapi_quarantines_the_endpoint_listing(in_scope_engagement, monkeypatch):
    """The formatted output is derived from attacker-controlled spec
    content (path/parameter names) -- must be wrapped in
    injection_boundary's quarantine markers, same as every other server's
    target-derived free text."""
    monkeypatch.setattr(
        srv.http_probe, "fetch",
        lambda *a, **k: http_probe.FetchResult(status=200, body=_OPENAPI_JSON),
    )
    out = srv.discover_from_openapi("https://t.example/openapi.json")
    assert "UNTRUSTED-DATA-BEGIN" in out
    assert "UNTRUSTED-DATA-END" in out


# ---------------------------------------------------------------------------
# discover_from_graphql
# ---------------------------------------------------------------------------

def test_discover_from_graphql_refuses_out_of_scope_url(in_scope_engagement, monkeypatch):
    def _unreachable_fetch(*a, **k):
        raise AssertionError("discover_from_graphql must refuse before ever calling http_probe.fetch")
    monkeypatch.setattr(srv.http_probe, "fetch", _unreachable_fetch)

    out = srv.discover_from_graphql("https://evil.example/graphql")
    assert "BLOCKED" in out


def test_discover_from_graphql_sends_introspection_query_as_post(in_scope_engagement, monkeypatch):
    captured = {}

    def _fake_fetch(url, method, headers, body, timeout_s, **kwargs):
        captured["method"] = method
        captured["body"] = body
        return http_probe.FetchResult(status=200, body=_GRAPHQL_INTROSPECTION_JSON)
    monkeypatch.setattr(srv.http_probe, "fetch", _fake_fetch)

    srv.discover_from_graphql("https://t.example/graphql")
    assert captured["method"] == "POST"
    sent = json.loads(captured["body"])
    assert sent["query"] == srv.disc_spec.GRAPHQL_INTROSPECTION_QUERY


def test_discover_from_graphql_formats_operations(in_scope_engagement, monkeypatch):
    monkeypatch.setattr(
        srv.http_probe, "fetch",
        lambda *a, **k: http_probe.FetchResult(status=200, body=_GRAPHQL_INTROSPECTION_JSON),
    )
    out = srv.discover_from_graphql("https://t.example/graphql")
    assert "query user" in out


def test_discover_from_graphql_reports_introspection_disabled(in_scope_engagement, monkeypatch):
    monkeypatch.setattr(
        srv.http_probe, "fetch",
        lambda *a, **k: http_probe.FetchResult(
            status=200, body=json.dumps({"errors": [{"message": "introspection disabled"}]}),
        ),
    )
    out = srv.discover_from_graphql("https://t.example/graphql")
    assert "introspection" in out.lower()


def test_discover_from_graphql_surfaces_fetch_error(in_scope_engagement, monkeypatch):
    monkeypatch.setattr(
        srv.http_probe, "fetch",
        lambda *a, **k: http_probe.FetchResult(status=None, body="", error="timed out"),
    )
    out = srv.discover_from_graphql("https://t.example/graphql")
    assert "Error" in out
    assert "timed out" in out


def test_discover_from_graphql_quarantines_the_parse_error_message(in_scope_engagement, monkeypatch):
    """Same quarantine requirement as the OpenAPI parse-error path -- the
    response body is attacker-controlled."""
    monkeypatch.setattr(
        srv.http_probe, "fetch",
        lambda *a, **k: http_probe.FetchResult(status=200, body="not valid json at all"),
    )
    out = srv.discover_from_graphql("https://t.example/graphql")
    assert "UNTRUSTED-DATA-BEGIN" in out
    assert "UNTRUSTED-DATA-END" in out


def test_discover_from_graphql_quarantines_the_operation_listing(in_scope_engagement, monkeypatch):
    monkeypatch.setattr(
        srv.http_probe, "fetch",
        lambda *a, **k: http_probe.FetchResult(status=200, body=_GRAPHQL_INTROSPECTION_JSON),
    )
    out = srv.discover_from_graphql("https://t.example/graphql")
    assert "UNTRUSTED-DATA-BEGIN" in out
    assert "UNTRUSTED-DATA-END" in out


# ---------------------------------------------------------------------------
# Surface-gain demonstration (tracker acceptance: "endpoints recovered
# beyond crawl") -- a fixture spec declares an endpoint that is not
# linked anywhere a crawl could reach, proving the spec-parsing path
# surfaces something a crawl-only recon pass would miss entirely.
# ---------------------------------------------------------------------------

def test_discover_from_openapi_logs_the_call_to_audit_log(in_scope_engagement, monkeypatch):
    """discspec-mcp bypasses job_runtime.start_job() entirely (a one-shot
    http_probe.fetch(), not a background job) -- the same structural
    shape as idor-mcp, which explicitly calls audit_log.log_call() for
    exactly this reason (job_runtime's own automatic audit logging never
    runs). Without this, discover_from_openapi()'s real target-touching
    request is invisible to the per-call audit trail."""
    monkeypatch.setattr(
        srv.http_probe, "fetch",
        lambda *a, **k: http_probe.FetchResult(status=200, body=_OPENAPI_JSON),
    )
    captured = []
    monkeypatch.setattr(srv, "_log_call", lambda *a, **k: captured.append((a, k)))

    srv.discover_from_openapi("https://t.example/openapi.json")

    assert len(captured) == 1
    args, kwargs = captured[0]
    assert args[0] == "discspec-mcp"
    assert "https://t.example/openapi.json" in args[1]


def test_discover_from_graphql_logs_the_call_to_audit_log(in_scope_engagement, monkeypatch):
    monkeypatch.setattr(
        srv.http_probe, "fetch",
        lambda *a, **k: http_probe.FetchResult(status=200, body=_GRAPHQL_INTROSPECTION_JSON),
    )
    captured = []
    monkeypatch.setattr(srv, "_log_call", lambda *a, **k: captured.append((a, k)))

    srv.discover_from_graphql("https://t.example/graphql")

    assert len(captured) == 1
    args, kwargs = captured[0]
    assert args[0] == "discspec-mcp"
    assert "https://t.example/graphql" in args[1]


def test_discover_from_openapi_does_not_log_a_scope_refused_call(in_scope_engagement, monkeypatch):
    """Only a real request should be audited -- a call refused before
    ever reaching http_probe.fetch() never touched the target."""
    captured = []
    monkeypatch.setattr(srv, "_log_call", lambda *a, **k: captured.append((a, k)))

    out = srv.discover_from_openapi("https://evil.example/openapi.json")

    assert "BLOCKED" in out
    assert captured == []


def test_discover_from_openapi_enforces_tier2_budget(in_scope_engagement, monkeypatch, tmp_path):
    """discspec-mcp bypasses job_runtime.start_job() (which calls
    _enforce_budget() unconditionally for every job-based scanner) --
    same gap as audit logging above, same fix shape as idor-mcp's own
    per-request _enforce_budget("idor-mcp") call."""
    monkeypatch.setenv("HUNTMCP_BUDGET_PATH", str(tmp_path / "budget.json"))

    def _exhausted(*a, **k):
        raise srv.BudgetExceeded("Tier-2 budget exhausted (test)")
    monkeypatch.setattr(srv, "_enforce_budget", _exhausted)

    def _unreachable_fetch(*a, **k):
        raise AssertionError("discover_from_openapi must refuse before ever calling http_probe.fetch")
    monkeypatch.setattr(srv.http_probe, "fetch", _unreachable_fetch)

    out = srv.discover_from_openapi("https://t.example/openapi.json")
    assert "budget" in out.lower()


def test_discover_from_graphql_enforces_tier2_budget(in_scope_engagement, monkeypatch, tmp_path):
    monkeypatch.setenv("HUNTMCP_BUDGET_PATH", str(tmp_path / "budget.json"))

    def _exhausted(*a, **k):
        raise srv.BudgetExceeded("Tier-2 budget exhausted (test)")
    monkeypatch.setattr(srv, "_enforce_budget", _exhausted)

    def _unreachable_fetch(*a, **k):
        raise AssertionError("discover_from_graphql must refuse before ever calling http_probe.fetch")
    monkeypatch.setattr(srv.http_probe, "fetch", _unreachable_fetch)

    out = srv.discover_from_graphql("https://t.example/graphql")
    assert "budget" in out.lower()


def test_discover_from_openapi_recovers_endpoint_a_crawl_would_never_find(in_scope_engagement, monkeypatch):
    unlinked_spec = json.dumps({
        "paths": {
            "/internal/admin/export": {
                "post": {"requestBody": {"required": True}},
            },
        },
    })
    monkeypatch.setattr(
        srv.http_probe, "fetch",
        lambda *a, **k: http_probe.FetchResult(status=200, body=unlinked_spec),
    )
    # A crawl (katana) only follows <a href>/<form action> links present in
    # served HTML -- an endpoint that exists ONLY in the API's own spec
    # document, never linked from any page, is exactly what a crawl-only
    # pass cannot discover. discover_from_openapi() finds it directly from
    # the spec instead.
    out = srv.discover_from_openapi("https://t.example/openapi.json")
    assert "POST /internal/admin/export" in out
