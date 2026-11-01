"""Unit tests for P3-DISCSPEC's hand-rolled OpenAPI/GraphQL parser
(mcp-servers/disc_spec.py).

Pure functions, no network -- given a spec_data dict (already JSON/
YAML-decoded by the caller), parse into a flat endpoint/parameter model.
The spec is treated as untrusted (fetched from the target): only internal
("#/...") $ref pointers are ever resolved, never an external URI.
"""
import disc_spec


# ---------------------------------------------------------------------------
# parse_openapi -- OpenAPI 3.x
# ---------------------------------------------------------------------------

def test_parse_openapi_extracts_method_and_path():
    spec = {
        "paths": {
            "/users": {
                "get": {"responses": {"200": {}}},
            },
        },
    }
    endpoints = disc_spec.parse_openapi(spec)
    assert len(endpoints) == 1
    assert endpoints[0]["method"] == "GET"
    assert endpoints[0]["path"] == "/users"


def test_parse_openapi_extracts_multiple_methods_on_same_path():
    spec = {
        "paths": {
            "/users": {
                "get": {},
                "post": {},
            },
        },
    }
    endpoints = disc_spec.parse_openapi(spec)
    methods = sorted(e["method"] for e in endpoints)
    assert methods == ["GET", "POST"]


def test_parse_openapi_extracts_operation_level_parameters():
    spec = {
        "paths": {
            "/users/{id}": {
                "get": {
                    "parameters": [
                        {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}},
                        {"name": "verbose", "in": "query", "required": False, "schema": {"type": "boolean"}},
                    ],
                },
            },
        },
    }
    endpoints = disc_spec.parse_openapi(spec)
    params = {p["name"]: p for p in endpoints[0]["parameters"]}
    assert params["id"] == {"name": "id", "location": "path", "required": True, "type": "string"}
    assert params["verbose"] == {"name": "verbose", "location": "query", "required": False, "type": "boolean"}


def test_parse_openapi_merges_path_level_parameters_into_every_operation():
    """A path-item-level `parameters` list applies to every operation
    under that path (OpenAPI spec semantics) -- a path parameter declared
    once at the path level, not repeated per method."""
    spec = {
        "paths": {
            "/users/{id}": {
                "parameters": [
                    {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}},
                ],
                "get": {},
                "delete": {},
            },
        },
    }
    endpoints = disc_spec.parse_openapi(spec)
    assert len(endpoints) == 2
    for e in endpoints:
        names = {p["name"] for p in e["parameters"]}
        assert "id" in names


def test_parse_openapi_resolves_internal_ref_parameter():
    spec = {
        "paths": {
            "/users/{id}": {
                "get": {
                    "parameters": [{"$ref": "#/components/parameters/UserId"}],
                },
            },
        },
        "components": {
            "parameters": {
                "UserId": {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}},
            },
        },
    }
    endpoints = disc_spec.parse_openapi(spec)
    assert endpoints[0]["parameters"] == [
        {"name": "id", "location": "path", "required": True, "type": "string"},
    ]


def test_parse_openapi_never_resolves_external_ref():
    """Security guard: a $ref pointing outside the document (anything not
    starting with "#/") must never be followed/fetched -- the spec is
    attacker-controlled (fetched from the target), so an external $ref is
    a potential SSRF vector. It's silently skipped, not resolved."""
    spec = {
        "paths": {
            "/users/{id}": {
                "get": {
                    "parameters": [{"$ref": "https://evil.example/steal#/foo"}],
                },
            },
        },
    }
    endpoints = disc_spec.parse_openapi(spec)
    assert endpoints[0]["parameters"] == []


def test_parse_openapi_flags_request_body_v3():
    spec = {
        "paths": {
            "/users": {
                "post": {
                    "requestBody": {"required": True, "content": {"application/json": {}}},
                },
            },
        },
    }
    endpoints = disc_spec.parse_openapi(spec)
    assert endpoints[0]["has_body"] is True


def test_parse_openapi_flags_body_parameter_v2_swagger():
    spec = {
        "swagger": "2.0",
        "paths": {
            "/users": {
                "post": {
                    "parameters": [
                        {"name": "body", "in": "body", "required": True, "schema": {"$ref": "#/definitions/User"}},
                    ],
                },
            },
        },
    }
    endpoints = disc_spec.parse_openapi(spec)
    assert endpoints[0]["has_body"] is True


def test_parse_openapi_no_body_when_not_declared():
    spec = {"paths": {"/users": {"get": {}}}}
    endpoints = disc_spec.parse_openapi(spec)
    assert endpoints[0]["has_body"] is False


def test_parse_openapi_matches_method_keys_case_insensitively():
    """A spec using non-lowercase method keys (plausible in a hand-edited
    or malformed real-world spec -- OpenAPI technically requires
    lowercase, but silently dropping an otherwise-valid endpoint
    understates "endpoints recovered beyond crawl," this task's own
    acceptance bar) must still be recognized as a real operation."""
    spec = {"paths": {"/users": {"POST": {}, "Get": {}}}}
    endpoints = disc_spec.parse_openapi(spec)
    methods = sorted(e["method"] for e in endpoints)
    assert methods == ["GET", "POST"]


def test_parse_openapi_ignores_non_method_keys_on_path_item():
    """A path item can carry "parameters", "summary", "description",
    "$ref" alongside the real HTTP-method keys -- only real methods
    become endpoints."""
    spec = {
        "paths": {
            "/users": {
                "summary": "User collection",
                "parameters": [],
                "get": {},
            },
        },
    }
    endpoints = disc_spec.parse_openapi(spec)
    assert len(endpoints) == 1
    assert endpoints[0]["method"] == "GET"


def test_parse_openapi_empty_spec_returns_empty_list():
    assert disc_spec.parse_openapi({}) == []


def test_parse_openapi_malformed_paths_returns_empty_list_not_raise():
    assert disc_spec.parse_openapi({"paths": "not-a-dict"}) == []


def test_parse_openapi_unresolvable_internal_ref_skipped_not_raise():
    spec = {
        "paths": {
            "/users": {
                "get": {"parameters": [{"$ref": "#/components/parameters/DoesNotExist"}]},
            },
        },
    }
    endpoints = disc_spec.parse_openapi(spec)
    assert endpoints[0]["parameters"] == []


# ---------------------------------------------------------------------------
# parse_graphql_introspection
# ---------------------------------------------------------------------------

def test_parse_graphql_extracts_query_field_with_scalar_arg():
    data = {
        "data": {
            "__schema": {
                "queryType": {
                    "fields": [
                        {
                            "name": "user",
                            "args": [
                                {"name": "id", "type": {"kind": "SCALAR", "name": "ID", "ofType": None}},
                            ],
                        },
                    ],
                },
                "mutationType": None,
            },
        },
    }
    ops = disc_spec.parse_graphql_introspection(data)
    assert ops == [
        {"operation_type": "query", "name": "user",
         "arguments": [{"name": "id", "type": "ID", "required": False}]},
    ]


def test_parse_graphql_extracts_mutation_field():
    data = {
        "data": {
            "__schema": {
                "queryType": None,
                "mutationType": {
                    "fields": [{"name": "createUser", "args": []}],
                },
            },
        },
    }
    ops = disc_spec.parse_graphql_introspection(data)
    assert ops == [{"operation_type": "mutation", "name": "createUser", "arguments": []}]


def test_parse_graphql_unwraps_non_null_and_marks_required():
    data = {
        "data": {
            "__schema": {
                "queryType": {
                    "fields": [
                        {
                            "name": "user",
                            "args": [
                                {"name": "id", "type": {
                                    "kind": "NON_NULL", "name": None,
                                    "ofType": {"kind": "SCALAR", "name": "ID", "ofType": None},
                                }},
                            ],
                        },
                    ],
                },
                "mutationType": None,
            },
        },
    }
    ops = disc_spec.parse_graphql_introspection(data)
    assert ops[0]["arguments"] == [{"name": "id", "type": "ID", "required": True}]


def test_parse_graphql_unwraps_list_of_non_null():
    data = {
        "data": {
            "__schema": {
                "queryType": {
                    "fields": [
                        {
                            "name": "usersByIds",
                            "args": [
                                {"name": "ids", "type": {
                                    "kind": "LIST", "name": None,
                                    "ofType": {"kind": "NON_NULL", "name": None,
                                               "ofType": {"kind": "SCALAR", "name": "ID", "ofType": None}},
                                }},
                            ],
                        },
                    ],
                },
                "mutationType": None,
            },
        },
    }
    ops = disc_spec.parse_graphql_introspection(data)
    assert ops[0]["arguments"] == [{"name": "ids", "type": "ID", "required": False}]


def test_parse_graphql_missing_schema_returns_empty_list():
    assert disc_spec.parse_graphql_introspection({"data": {}}) == []


def test_parse_graphql_introspection_disabled_returns_empty_list():
    """A GraphQL endpoint with introspection disabled responds with an
    errors array and no __schema -- must degrade to [], never raise."""
    data = {"errors": [{"message": "GraphQL introspection is not allowed"}]}
    assert disc_spec.parse_graphql_introspection(data) == []


def test_parse_graphql_malformed_data_returns_empty_list_not_raise():
    assert disc_spec.parse_graphql_introspection("not-a-dict") == []
    assert disc_spec.parse_graphql_introspection(None) == []


def test_graphql_introspection_query_is_a_nonempty_string():
    """discspec-mcp's discover_from_graphql() sends this as the POST
    body's `query` field -- must exist and be a real GraphQL query."""
    assert isinstance(disc_spec.GRAPHQL_INTROSPECTION_QUERY, str)
    assert "__schema" in disc_spec.GRAPHQL_INTROSPECTION_QUERY


def test_graphql_introspection_query_requests_enough_type_ref_depth_for_a_doubly_wrapped_arg():
    """Regression: a doubly-wrapped GraphQL type like `[ID!]!` (a very
    common shape for list/array arguments -- e.g. usersByIds(ids: [ID!]!))
    needs 4 type-ref levels (NON_NULL -> LIST -> NON_NULL -> SCALAR) to
    reach the base scalar name. The query previously selected only 3
    levels (`type { kind name ofType { kind name ofType { kind name } } }`),
    so the real server's JSON response simply omitted the 4th level
    (unrequested field -> absent, not null) and
    parse_graphql_introspection() silently reported type="unknown" for
    this common case. Counting "ofType {" occurrences inside one arg's
    `type { ... }` selection is a stand-in for "how many type-ref levels
    does this query actually fetch" -- must be at least 3 nested ofType
    selections (4 levels total: type itself + 3 ofType) to resolve
    [Type!]! correctly."""
    query = disc_spec.GRAPHQL_INTROSPECTION_QUERY
    # Isolate just the queryType selection (up to mutationType) so the
    # count below reflects ONE arg-type block's nesting depth, not both
    # queryType's and mutationType's combined.
    query_type_block = query.split("queryType", 1)[1].split("mutationType", 1)[0]
    type_block = query_type_block.split("type {", 1)[1]
    assert type_block.count("ofType {") >= 3


def test_parse_graphql_resolves_doubly_wrapped_type_as_the_real_server_would_respond(
):
    """End-to-end shape check: builds the response exactly as a real
    GraphQL server would answer the ACTUAL GRAPHQL_INTROSPECTION_QUERY
    (not a hand-picked shortcut) for a `[ID!]!` argument, and confirms
    the base type name survives -- not "unknown"."""
    # NON_NULL(LIST(NON_NULL(SCALAR ID))) -- exactly 4 type-ref nodes,
    # matching how many levels GRAPHQL_INTROSPECTION_QUERY selects (see
    # the test above); a real server omits any level beyond what was
    # requested, so this dict intentionally terminates with ofType: None
    # at the same depth the query itself stops at.
    type_ref = {
        "kind": "NON_NULL", "name": None,
        "ofType": {
            "kind": "LIST", "name": None,
            "ofType": {
                "kind": "NON_NULL", "name": None,
                "ofType": {"kind": "SCALAR", "name": "ID", "ofType": None},
            },
        },
    }
    data = {
        "data": {
            "__schema": {
                "queryType": {
                    "fields": [{"name": "usersByIds", "args": [{"name": "ids", "type": type_ref}]}],
                },
                "mutationType": None,
            },
        },
    }
    ops = disc_spec.parse_graphql_introspection(data)
    assert ops[0]["arguments"] == [{"name": "ids", "type": "ID", "required": True}]
