"""P3-DISCSPEC — OpenAPI/GraphQL spec-driven endpoint discovery.

Tier-2 (target-touching: fetches the spec/sends an introspection query to
the live target). Mirrors schemathesis-mcp's own in-code scope-gate
pattern (_resolve_engagement/_scope_or_error reusing scope_guard directly)
rather than relying only on scripts/hooks/scope_gate_hook.py's early
filter -- this server's own check is the real, definitive boundary (see
that hook's module docstring for why an in-code check is required
regardless of whether a server is also listed there).

The fetched spec is attacker-controlled (served by the target) -- parsing
itself is disc_spec.py's job (treats $ref/structure as untrusted); this
server additionally quarantines the formatted endpoint/operation listing
before returning it, since every path/parameter/field name in that text
originates from the target (injection_boundary.py: P2-INJ boundary every
other target-derived free text in this repo goes through).
"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import disc_spec  # noqa: E402
import http_probe  # noqa: E402
import scope_check  # noqa: E402
from audit_log import log_call as _log_call  # noqa: E402
from budget_guard import BudgetExceeded  # noqa: E402
from budget_guard import enforce as _enforce_budget  # noqa: E402
from injection_boundary import quarantine as _quarantine  # noqa: E402

try:
    import yaml
except ImportError:
    yaml = None

from mcp.server.fastmcp import FastMCP

app = FastMCP("discspec-mcp")

_FETCH_TIMEOUT_S = 15


def _resolve_engagement():
    """Mirrors schemathesis-mcp's own _resolve_engagement: NoEngagementFile
    -> an empty Engagement (a safe test host still passes via
    is_in_scope's is_safe_test_host branch; a real host does not)."""
    return scope_check.resolve_engagement()


def _scope_or_error(url, engagement) -> str | None:
    refusal = scope_check.check_url(url, engagement)
    if refusal is None:
        return None
    if refusal.kind == scope_check.EMPTY:
        return "Error: url must be a non-empty string."
    if refusal.kind == scope_check.POLICY:
        return f"BLOCKED by outbound policy: url {url!r} -- {refusal.detail}."
    if refusal.kind == scope_check.VERIFY_FAILED:
        return f"BLOCKED by scope gate: could not verify url {url!r} is in scope ({refusal.detail})."
    return f"BLOCKED by scope gate: url {url!r} is not in the active engagement's in_scope list."


def _parse_spec_body(body: str) -> dict:
    """OpenAPI documents are commonly either JSON or YAML -- try JSON
    first (the common case, and unambiguous), then YAML."""
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        pass
    if yaml is None:
        raise RuntimeError("PyYAML not installed; cannot parse a non-JSON spec")
    return yaml.safe_load(body)


def _format_endpoints(endpoints: list[dict]) -> str:
    lines = [f"Discovered {len(endpoints)} endpoint(s):", ""]
    for e in endpoints:
        params = ", ".join(
            f"{p['name']}({p['location']}{'*' if p['required'] else ''})" for p in e["parameters"]
        )
        body_note = " [has body]" if e["has_body"] else ""
        lines.append(f"  {e['method']} {e['path']}" + (f" -- params: {params}" if params else "") + body_note)
    return "\n".join(lines)


def _format_operations(operations: list[dict]) -> str:
    lines = [f"Discovered {len(operations)} GraphQL operation(s):", ""]
    for op in operations:
        args = ", ".join(f"{a['name']}: {a['type']}{'!' if a['required'] else ''}" for a in op["arguments"])
        lines.append(f"  {op['operation_type']} {op['name']}" + (f"({args})" if args else ""))
    return "\n".join(lines)


@app.tool()
def discover_from_openapi(url: str) -> str:
    """Fetches an OpenAPI 3.x or Swagger 2.0 spec from `url` (JSON or
    YAML) and parses it into a flat endpoint/parameter list -- surfaces
    endpoints beyond what a crawl (katana-mcp) can find, since API
    operations declared only in a spec document are often not linked
    from any crawlable page. The fetched spec is treated as untrusted:
    only internal ("#/...") $ref pointers are resolved, never an
    external URI (no fetch is ever made for a $ref). `url` must be in
    the active engagement's scope."""
    engagement = _resolve_engagement()
    err = _scope_or_error(url, engagement)
    if err:
        return err
    try:
        _enforce_budget("discspec-mcp")
    except BudgetExceeded as e:
        return f"BLOCKED by Tier-2 budget: {e}"

    # This server bypasses job_runtime.start_job() entirely (a one-shot
    # http_probe.fetch(), not a background job), so neither job_runtime's
    # automatic audit logging nor its automatic budget enforcement ever
    # runs for it -- both must be done explicitly here, same as idor-mcp
    # (the closest structural precedent: a one-shot http_probe.fetch()
    # caller with no job_runtime chokepoint of its own).
    start = time.monotonic()
    result = http_probe.fetch(url, "GET", {}, None, _FETCH_TIMEOUT_S)
    _log_call("discspec-mcp", [url], returncode=None,
              duration_ms=(time.monotonic() - start) * 1000, block=None)
    if result.error:
        return f"Error fetching spec: {result.error}"
    if result.status is not None and result.status >= 400:
        return f"Error: spec fetch returned HTTP {result.status}."

    try:
        spec = _parse_spec_body(result.body)
    except Exception as e:  # noqa: BLE001 - malformed/hostile body -> report, never crash
        # A yaml.YAMLError's own message routinely echoes a fragment of
        # the offending document -- quarantine it, same as the success
        # path, since the body is attacker-controlled (fetched from the
        # target).
        return f"Error: could not parse spec as JSON or YAML: {_quarantine(str(e), source_label='OpenAPI spec parse error')}"

    endpoints = disc_spec.parse_openapi(spec)
    if not endpoints:
        return "No endpoints found in the fetched spec."
    return _quarantine(_format_endpoints(endpoints), source_label="OpenAPI spec")


@app.tool()
def discover_from_graphql(url: str) -> str:
    """POSTs the standard GraphQL introspection query to `url` and parses
    the response into a flat list of query/mutation operations with
    their arguments -- confirms introspection is enabled and surfaces
    operations beyond anything a crawl would find. `url` must be in the
    active engagement's scope."""
    engagement = _resolve_engagement()
    err = _scope_or_error(url, engagement)
    if err:
        return err
    try:
        _enforce_budget("discspec-mcp")
    except BudgetExceeded as e:
        return f"BLOCKED by Tier-2 budget: {e}"

    start = time.monotonic()
    body = json.dumps({"query": disc_spec.GRAPHQL_INTROSPECTION_QUERY})
    result = http_probe.fetch(url, "POST", {"Content-Type": "application/json"}, body, _FETCH_TIMEOUT_S)
    _log_call("discspec-mcp", [url], returncode=None,
              duration_ms=(time.monotonic() - start) * 1000, block=None)
    if result.error:
        return f"Error fetching introspection result: {result.error}"
    if result.status is not None and result.status >= 400:
        return f"Error: introspection request returned HTTP {result.status}."

    try:
        data = json.loads(result.body)
    except json.JSONDecodeError as e:
        return f"Error: could not parse introspection response as JSON: {_quarantine(str(e), source_label='GraphQL introspection parse error')}"

    operations = disc_spec.parse_graphql_introspection(data)
    if not operations:
        return "No query/mutation operations found -- introspection may be disabled or unsupported."
    return _quarantine(_format_operations(operations), source_label="GraphQL introspection")


if __name__ == "__main__":
    print("discspec-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
