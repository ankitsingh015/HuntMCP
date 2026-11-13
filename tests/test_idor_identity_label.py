import importlib.util
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "idor-mcp"))

_spec = importlib.util.spec_from_file_location(
    "idor_server_label", os.path.join(ROOT, "mcp-servers", "idor-mcp", "server.py")
)
idor_server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(idor_server)

import engagement_paths


def _seed(label, entry):
    p = engagement_paths.resolve("secrets/identities.json")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        json.dump({label: entry}, f)


def test_resolve_headers_by_label_reads_capture():
    _seed("xyz", {"cookies": [{"name": "s", "value": "v"}], "authorization": "Bearer tok"})
    headers, err = idor_server._resolve_headers("xyz", "", "")
    assert err is None
    assert headers["Cookie"] == "s=v"
    assert headers["Authorization"] == "Bearer tok"


def test_resolve_headers_inline_fallback_when_no_label():
    headers, err = idor_server._resolve_headers("", "a=b", "tok2")
    assert err is None
    assert headers["Cookie"] == "a=b"
    assert headers["Authorization"] == "Bearer tok2"


def test_resolve_headers_unknown_label_is_clean_error():
    headers, err = idor_server._resolve_headers("ghost", "", "")
    assert headers is None
    assert "ghost" in err


def test_resolve_headers_empty_is_empty_headers():
    headers, err = idor_server._resolve_headers("", "", "")
    assert err is None
    assert headers == {}
