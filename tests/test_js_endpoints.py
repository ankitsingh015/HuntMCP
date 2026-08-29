import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                 "mcp-servers", "secrets-mcp"))
import js_endpoints


def test_extract_endpoints_from_text_finds_double_quoted_path():
    text = 'fetch("/api/v1/orders/{id}").then(r => r.json())'
    assert js_endpoints.extract_endpoints_from_text(text) == ["/api/v1/orders/{id}"]


def test_extract_endpoints_from_text_finds_single_and_backtick_quoted():
    text = "axios.get('/api/users/:id'); const url = `/api/webhooks/callback`;"
    result = js_endpoints.extract_endpoints_from_text(text)
    assert "/api/users/:id" in result
    assert "/api/webhooks/callback" in result


def test_extract_endpoints_from_text_dedupes():
    text = '"/api/v1/orders" "/api/v1/orders" "/api/v1/orders"'
    assert js_endpoints.extract_endpoints_from_text(text) == ["/api/v1/orders"]


def test_extract_endpoints_from_text_ignores_static_assets():
    text = '"/assets/logo.png" "/static/style.css" "/fonts/icon.woff2"'
    assert js_endpoints.extract_endpoints_from_text(text) == []


def test_extract_endpoints_from_text_ignores_single_segment_paths():
    # A bare "/login" is more often a client-side router path than a real
    # backend endpoint on its own -- require at least two segments.
    text = '"/login" "/about"'
    assert js_endpoints.extract_endpoints_from_text(text) == []


def test_extract_endpoints_from_text_keeps_multi_segment_paths():
    text = '"/api/login" "/internal/admin/users"'
    result = js_endpoints.extract_endpoints_from_text(text)
    assert "/api/login" in result
    assert "/internal/admin/users" in result


def test_extract_endpoints_from_text_captures_query_string():
    """Regression: caught live during testing -- a literal like
    "/internal/admin/export?format=csv" was silently DROPPED entirely
    (not truncated) before ?=& were added to the allowed charset, because
    the regex found no valid match once it hit the unrecognized "?" and
    never reached a closing quote on any shorter prefix either."""
    text = 'fetch("/internal/admin/export?format=csv&token=abc")'
    assert js_endpoints.extract_endpoints_from_text(text) == [
        "/internal/admin/export?format=csv&token=abc"
    ]


def test_extract_endpoints_from_text_ignores_cache_busted_static_asset():
    """Regression: adding query-string support to the path regex broke
    the static-asset filter for cache-busted references like
    "/assets/logo.png?v=123" -- "png?v=123" doesn't literally match
    "png" in the extension set unless the query string is stripped
    first."""
    text = '"/assets/logo.png?v=123"'
    assert js_endpoints.extract_endpoints_from_text(text) == []


def test_extract_params_colon_style():
    assert js_endpoints.extract_params("/api/orders/:id/items/:sku") == ["id", "sku"]


def test_extract_params_curly_brace_style():
    assert js_endpoints.extract_params("/api/orders/{orderId}") == ["orderId"]


def test_extract_params_bracket_style():
    assert js_endpoints.extract_params("/api/orders/[orderId]") == ["orderId"]


def test_extract_params_none_when_no_placeholders():
    assert js_endpoints.extract_params("/api/orders") == []


def test_scan_directory_for_endpoints_walks_js_like_files(tmp_path):
    (tmp_path / "bundle.js").write_text('fetch("/api/v1/orders/{id}")')
    (tmp_path / "app.tsx").write_text('axios.post("/api/v1/checkout")')
    (tmp_path / "readme.md").write_text('"/api/should-be-ignored"')  # not a JS-like extension

    inventory = js_endpoints.scan_directory_for_endpoints(str(tmp_path))
    assert "/api/v1/orders/{id}" in inventory
    assert "/api/v1/checkout" in inventory
    assert "/api/should-be-ignored" not in inventory


def test_scan_directory_for_endpoints_tracks_source_files(tmp_path):
    (tmp_path / "a.js").write_text('"/api/v1/orders"')
    (tmp_path / "b.js").write_text('"/api/v1/orders"')

    inventory = js_endpoints.scan_directory_for_endpoints(str(tmp_path))
    assert len(inventory["/api/v1/orders"]) == 2


def test_scan_directory_for_endpoints_respects_max_results(tmp_path):
    lines = "\n".join(f'"/api/v1/resource{i}/items"' for i in range(20))
    (tmp_path / "big.js").write_text(lines)

    inventory = js_endpoints.scan_directory_for_endpoints(str(tmp_path), max_results=5)
    assert len(inventory) <= 5


def test_scan_directory_for_endpoints_empty_directory(tmp_path):
    assert js_endpoints.scan_directory_for_endpoints(str(tmp_path)) == {}


def test_scan_directory_for_endpoints_handles_nested_directories(tmp_path):
    nested = tmp_path / "chunks" / "vendor"
    nested.mkdir(parents=True)
    (nested / "chunk.js").write_text('"/api/v1/nested/endpoint"')

    inventory = js_endpoints.scan_directory_for_endpoints(str(tmp_path))
    assert "/api/v1/nested/endpoint" in inventory
