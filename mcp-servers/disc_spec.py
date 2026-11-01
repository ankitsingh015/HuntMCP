"""P3-DISCSPEC — OpenAPI/GraphQL -> stateful endpoint/parameter model.

Hand-rolled (no new dependency, per P3-DEP's decision: a spec-parser
dependency stays separately gated, hand-roll-first), stdlib + PyYAML only
(the caller decodes JSON/YAML text into a dict before handing it to
parse_openapi() -- see discspec-mcp/server.py). Feeds scan targeting
(endpoints beyond what a crawl finds) and, later, VAL-AUTHZ's workflow
capture (a separate GATED task; not built here).

The spec is attacker-controlled -- fetched from the target itself (e.g.
GET /openapi.json, or a GraphQL introspection POST). Every function here
treats it as untrusted data:
  - a $ref is only ever resolved if it's an INTERNAL document pointer
    ("#/..."); an external URI is never followed/fetched (SSRF guard).
  - $ref resolution is one level deep only (no recursive re-resolution of
    a resolved node's own $ref) -- avoids any possibility of an infinite
    loop from a hostile spec with cyclic references, by construction
    rather than by cycle-detection bookkeeping.
  - any malformed/unexpected shape degrades to an empty result, never an
    exception -- this is discovery-only, best-effort surface expansion,
    not a strict spec validator.
"""

from __future__ import annotations

_HTTP_METHODS = frozenset({"get", "put", "post", "delete", "options", "head", "patch", "trace"})


def _resolve_ref(doc: dict, ref) -> dict | None:
    """Resolves an internal JSON-pointer $ref ("#/a/b/c") against `doc`.
    Returns None for anything external, malformed, or that doesn't
    resolve to a dict -- never raises, never fetches."""
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return None
    node = doc
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node if isinstance(node, dict) else None


def _resolve_param(doc: dict, param) -> dict | None:
    if not isinstance(param, dict):
        return None
    if "$ref" in param:
        resolved = _resolve_ref(doc, param["$ref"])
        # One level only -- a resolved parameter object is used as-is even
        # if it itself still contains a nested $ref (see module docstring).
        return resolved
    return param


def _param_type(param: dict) -> str:
    schema = param.get("schema")
    if isinstance(schema, dict) and isinstance(schema.get("type"), str):
        return schema["type"]
    if isinstance(param.get("type"), str):  # Swagger 2.0: type is inline, not nested under schema
        return param["type"]
    return "unknown"


def _normalize_param(param: dict) -> dict | None:
    name = param.get("name")
    location = param.get("in")
    if not isinstance(name, str) or not isinstance(location, str):
        return None
    return {
        "name": name,
        "location": location,
        "required": bool(param.get("required", False)),
        "type": _param_type(param),
    }


def _has_body(doc: dict, operation: dict, resolved_params: list[dict]) -> bool:
    if isinstance(operation.get("requestBody"), dict):  # OpenAPI 3.x
        return True
    return any(p.get("in") == "body" for p in resolved_params)  # Swagger 2.0


def parse_openapi(spec: dict) -> list[dict]:
    """Flattens an already-decoded OpenAPI 3.x or Swagger 2.0 document
    into one entry per (path, method): {"method", "path", "parameters":
    [{"name","location","required","type"}, ...], "has_body"}."""
    if not isinstance(spec, dict):
        return []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []

    endpoints = []
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        path_level_params_raw = path_item.get("parameters")
        path_level_params_raw = path_level_params_raw if isinstance(path_level_params_raw, list) else []

        for key, operation in path_item.items():
            if not isinstance(key, str) or key.lower() not in _HTTP_METHODS or not isinstance(operation, dict):
                continue
            op_params_raw = operation.get("parameters")
            op_params_raw = op_params_raw if isinstance(op_params_raw, list) else []

            resolved = [p for p in (_resolve_param(spec, raw) for raw in (*path_level_params_raw, *op_params_raw))
                        if p is not None]
            normalized = [n for n in (_normalize_param(p) for p in resolved) if n is not None]
            # De-dup by (name, location); an operation-level parameter
            # overrides a path-level one of the same (name, location),
            # matching OpenAPI's own override semantics -- later wins,
            # and op-level entries are appended after path-level ones.
            by_key: dict[tuple[str, str], dict] = {}
            for n in normalized:
                by_key[(n["name"], n["location"])] = n

            endpoints.append({
                "method": key.upper(),
                "path": path,
                "parameters": list(by_key.values()),
                "has_body": _has_body(spec, operation, resolved),
            })
    return endpoints


# ---------------------------------------------------------------------------
# GraphQL
# ---------------------------------------------------------------------------

GRAPHQL_INTROSPECTION_QUERY = """
query HuntMCPDiscSpecIntrospection {
  __schema {
    queryType {
      fields {
        name
        args { name type { kind name ofType { kind name ofType { kind name ofType { kind name } } } } }
      }
    }
    mutationType {
      fields {
        name
        args { name type { kind name ofType { kind name ofType { kind name ofType { kind name } } } } }
      }
    }
  }
}
""".strip()


def _unwrap_graphql_type(type_obj) -> tuple[str, bool]:
    """Walks NON_NULL/LIST wrapper kinds down to the base named type.
    `required` is True only if the OUTERMOST kind is NON_NULL (GraphQL's
    own required-argument convention)."""
    required = isinstance(type_obj, dict) and type_obj.get("kind") == "NON_NULL"
    node = type_obj
    for _ in range(10):  # bounded -- a real type-ref chain is a handful of levels deep
        if not isinstance(node, dict):
            break
        kind = node.get("kind")
        if kind in ("NON_NULL", "LIST"):
            node = node.get("ofType")
            continue
        break
    name = node.get("name") if isinstance(node, dict) else None
    return (name if isinstance(name, str) else "unknown"), required


def parse_graphql_introspection(data) -> list[dict]:
    """Flattens a standard GraphQL introspection response (as POSTed with
    GRAPHQL_INTROSPECTION_QUERY) into one entry per root query/mutation
    field: {"operation_type", "name", "arguments": [{"name","type",
    "required"}, ...]}. Introspection disabled / malformed response ->
    []."""
    if not isinstance(data, dict):
        return []
    schema = data.get("data")
    schema = schema.get("__schema") if isinstance(schema, dict) else None
    if not isinstance(schema, dict):
        return []

    operations = []
    for type_key, op_label in (("queryType", "query"), ("mutationType", "mutation")):
        op_type = schema.get(type_key)
        if not isinstance(op_type, dict):
            continue
        fields = op_type.get("fields")
        if not isinstance(fields, list):
            continue
        for field in fields:
            if not isinstance(field, dict) or not isinstance(field.get("name"), str):
                continue
            args = []
            for arg in field.get("args") or []:
                if not isinstance(arg, dict) or not isinstance(arg.get("name"), str):
                    continue
                type_name, required = _unwrap_graphql_type(arg.get("type"))
                args.append({"name": arg["name"], "type": type_name, "required": required})
            operations.append({"operation_type": op_label, "name": field["name"], "arguments": args})
    return operations
