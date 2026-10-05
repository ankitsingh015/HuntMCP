import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                 "mcp-servers", "secrets-mcp"))
import source_map

# ---------------------------------------------------------------- discovery

def test_find_source_mapping_url_standard_comment():
    text = "console.log('hi');\n//# sourceMappingURL=app.min.js.map\n"
    assert source_map.find_source_mapping_url(text) == "app.min.js.map"


def test_find_source_mapping_url_legacy_at_comment():
    # Older/legacy tooling used //@ instead of //# -- still real, still seen.
    text = "console.log('hi');\n//@ sourceMappingURL=app.min.js.map"
    assert source_map.find_source_mapping_url(text) == "app.min.js.map"


def test_find_source_mapping_url_absolute_url():
    text = "//# sourceMappingURL=https://cdn.example.com/static/app.js.map"
    assert source_map.find_source_mapping_url(text) == "https://cdn.example.com/static/app.js.map"


def test_find_source_mapping_url_absent_returns_none():
    assert source_map.find_source_mapping_url("console.log('no map here');") is None


def test_find_source_mapping_url_ignores_data_uri_inline_maps():
    """A data: URI carries the ENTIRE map inline in the JS response itself
    (no second network fetch needed) -- a genuinely different, rarer case
    than a normal filename/URL. Detected as present but distinguished from
    a fetchable URL, so a caller doesn't try to curl a data: URI as if it
    were a real destination."""
    text = "//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjoz"
    assert source_map.find_source_mapping_url(text) is None
    assert source_map.find_inline_data_uri_map(text) is not None


def test_find_source_mapping_url_guess_when_absent():
    """Per the issue's own suggested implementation: "discover via
    sourceMappingURL comment OR .map guess" -- when no comment is present,
    the conventional guess is the same URL with .map appended."""
    assert source_map.guess_source_map_url("https://target.com/static/app.min.js") == \
        "https://target.com/static/app.min.js.map"


# ------------------------------------------------------------------ parsing

def test_parse_source_map_valid():
    raw = json.dumps({
        "version": 3,
        "sources": ["webpack:///./src/App.js", "webpack:///./src/utils/auth.js"],
        "sourcesContent": ["const App = () => {};", "export function login() {}"],
    })
    result = source_map.parse_source_map(raw)
    assert "error" not in result
    assert len(result["recovered"]) == 2
    assert result["recovered"][0]["source"] == "webpack:///./src/App.js"
    assert result["recovered"][0]["content"] == "const App = () => {};"


def test_parse_source_map_invalid_json_returns_error():
    result = source_map.parse_source_map("{not valid json")
    assert "error" in result


def test_parse_source_map_missing_sources_content_returns_error():
    """sourcesContent is what actually makes a source map worth recovering
    (full unminified source) -- a map with sources but no sourcesContent
    only names filenames, nothing to write out."""
    raw = json.dumps({"version": 3, "sources": ["app.js"]})
    result = source_map.parse_source_map(raw)
    assert "error" in result


def test_parse_source_map_mismatched_array_lengths_skips_unpaired_entries():
    """A malformed/truncated map could have more sources than
    sourcesContent entries (or vice versa) -- pair only what genuinely
    lines up, don't crash or fabricate content for the rest."""
    raw = json.dumps({
        "version": 3,
        "sources": ["a.js", "b.js", "c.js"],
        "sourcesContent": ["content-a", "content-b"],
    })
    result = source_map.parse_source_map(raw)
    assert "error" not in result
    assert len(result["recovered"]) == 2


def test_parse_source_map_null_content_entry_is_skipped():
    """A real source map can have a null sourcesContent entry for a source
    it doesn't actually embed (e.g. a third-party vendored file) -- skip
    it, don't write literal "null" as recovered source content."""
    raw = json.dumps({
        "version": 3,
        "sources": ["a.js", "vendor.js"],
        "sourcesContent": ["real content", None],
    })
    result = source_map.parse_source_map(raw)
    assert len(result["recovered"]) == 1
    assert result["recovered"][0]["source"] == "a.js"


# ------------------------------------------------------------- writing out

def test_write_recovered_sources_writes_files(tmp_path):
    parsed = {"recovered": [
        {"source": "webpack:///./src/App.js", "content": "const App = () => {};"},
        {"source": "webpack:///./src/utils/auth.js", "content": "export function login() {}"},
    ]}
    written = source_map.write_recovered_sources(parsed, str(tmp_path))
    assert len(written) == 2
    for path in written:
        assert os.path.isfile(path)
        assert str(tmp_path) in path


def test_write_recovered_sources_strips_webpack_scheme_prefix(tmp_path):
    """webpack:///./src/App.js is the overwhelmingly common real-world
    source path shape -- strip the scheme so the written file lands at a
    sane relative path, not a literal directory named "webpack:"."""
    parsed = {"recovered": [{"source": "webpack:///./src/App.js", "content": "x"}]}
    written = source_map.write_recovered_sources(parsed, str(tmp_path))
    assert "webpack:" not in written[0]
    assert written[0].endswith("src/App.js") or written[0].endswith("src" + os.sep + "App.js")


def test_write_recovered_sources_rejects_path_traversal(tmp_path):
    """SECURITY: a malicious/crafted source map's own "sources" array is
    attacker-influenced content (the target served it) -- a "../../../../
    etc/passwd"-shaped source path must NEVER be allowed to write outside
    output_dir. This is the same path-confinement discipline this repo
    already applies elsewhere (e.g. scope_gate_hook.py's own protected-
    path ancestry check)."""
    parsed = {"recovered": [
        {"source": "../../../../../../etc/passwd", "content": "attacker-controlled content"},
        {"source": "webpack:///../../../../tmp/evil.js", "content": "also attacker-controlled"},
    ]}
    written = source_map.write_recovered_sources(parsed, str(tmp_path))
    real_output_dir = os.path.realpath(str(tmp_path))
    for path in written:
        assert os.path.realpath(path).startswith(real_output_dir + os.sep)
    # Neither malicious entry escaped -- confirm no file landed at the
    # literal attacker-intended absolute path.
    assert not os.path.isfile("/tmp/evil.js")


def test_write_recovered_sources_rejects_absolute_path_source(tmp_path):
    parsed = {"recovered": [{"source": "/etc/passwd", "content": "x"}]}
    written = source_map.write_recovered_sources(parsed, str(tmp_path))
    real_output_dir = os.path.realpath(str(tmp_path))
    for path in written:
        assert os.path.realpath(path).startswith(real_output_dir + os.sep)


def test_write_recovered_sources_empty_list_writes_nothing(tmp_path):
    written = source_map.write_recovered_sources({"recovered": []}, str(tmp_path))
    assert written == []
