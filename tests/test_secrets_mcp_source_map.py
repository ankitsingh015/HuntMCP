"""Integration tests for secrets-mcp's find_source_map_reference()/
recover_source_map() tools -- the FastMCP-decorated wiring on top of
source_map.py's own unit-tested logic (tests/test_source_map.py).
"""
import base64
import importlib.util
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "secrets-mcp"))
_spec = importlib.util.spec_from_file_location(
    "secrets_server", os.path.join(ROOT, "mcp-servers", "secrets-mcp", "server.py"),
)
secrets_server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(secrets_server)


def test_find_source_map_reference_reports_the_url(tmp_path):
    js_file = tmp_path / "app.min.js"
    js_file.write_text("console.log(1);\n//# sourceMappingURL=app.min.js.map\n")
    result = secrets_server.find_source_map_reference(str(js_file))
    assert "app.min.js.map" in result


def test_find_source_map_reference_guesses_when_absent(tmp_path):
    js_file = tmp_path / "app.min.js"
    js_file.write_text("console.log(1);")
    result = secrets_server.find_source_map_reference(str(js_file))
    assert "app.min.js.map" in result
    assert "guess" in result.lower()


def test_find_source_map_reference_notes_inline_data_uri(tmp_path):
    inline_map = base64.b64encode(b'{"version":3}').decode()
    js_file = tmp_path / "app.js"
    js_file.write_text(f"console.log(1);\n//# sourceMappingURL=data:application/json;base64,{inline_map}\n")
    result = secrets_server.find_source_map_reference(str(js_file))
    assert "inline" in result.lower()


def test_find_source_map_reference_missing_file_errors():
    result = secrets_server.find_source_map_reference("/nonexistent/path.js")
    assert "Error" in result


def test_recover_source_map_writes_files_and_names_next_steps(tmp_path):
    map_file = tmp_path / "app.min.js.map"
    map_file.write_text(json.dumps({
        "version": 3,
        "sources": ["webpack:///./src/App.js"],
        "sourcesContent": ["const secretApiKey = 'sk_live_abc123';"],
    }))
    output_dir = tmp_path / "recovered"
    result = secrets_server.recover_source_map(str(map_file), str(output_dir))
    assert "Recovered 1" in result
    assert "scan_directory" in result
    assert "extract_endpoints" in result
    written_file = output_dir / "src" / "App.js"
    assert written_file.is_file()
    assert "secretApiKey" in written_file.read_text()


def test_recover_source_map_decodes_inline_data_uri(tmp_path):
    inline_json = json.dumps({
        "version": 3, "sources": ["a.js"], "sourcesContent": ["const x = 1;"],
    }).encode()
    encoded = base64.b64encode(inline_json).decode()
    js_file = tmp_path / "app.js"
    js_file.write_text(f"//# sourceMappingURL=data:application/json;base64,{encoded}")
    output_dir = tmp_path / "recovered"
    result = secrets_server.recover_source_map(str(js_file), str(output_dir))
    assert "Recovered 1" in result
    assert (output_dir / "a.js").is_file()


def test_recover_source_map_decodes_non_base64_percent_encoded_inline_data_uri(tmp_path):
    """Code-review finding #8: a data: URI's non-base64 form (no
    `;base64` token in the header, per RFC 2397) is PERCENT-encoded, not
    raw JSON -- e.g. `data:application/json,%7B%22version%22...`. The
    original code only handled the `;base64` branch and otherwise used
    the still-percent-encoded text directly as `raw`, which
    parse_source_map() could never parse as JSON (literal "%7B" isn't
    "{"), silently losing every non-base64-encoded inline source map."""
    import urllib.parse
    inline_json = json.dumps({
        "version": 3, "sources": ["b.js"], "sourcesContent": ["const y = 2;"],
    })
    encoded = urllib.parse.quote(inline_json)
    js_file = tmp_path / "app.js"
    js_file.write_text(f"//# sourceMappingURL=data:application/json,{encoded}")
    output_dir = tmp_path / "recovered"
    result = secrets_server.recover_source_map(str(js_file), str(output_dir))
    assert "Recovered 1" in result
    assert (output_dir / "b.js").is_file()


def test_recover_source_map_invalid_json_errors(tmp_path):
    map_file = tmp_path / "broken.map"
    map_file.write_text("{not valid")
    result = secrets_server.recover_source_map(str(map_file), str(tmp_path / "out"))
    assert "Error" in result


def test_recover_source_map_missing_file_errors():
    result = secrets_server.recover_source_map("/nonexistent/x.map", "/tmp/out")
    assert "Error" in result


def test_recover_source_map_then_scan_directory_finds_the_secret(tmp_path, monkeypatch):
    """End-to-end: recovering a source map, then running the EXISTING
    scan_directory() secret scanner over the recovered output -- exactly
    the "run the existing secret and endpoint scanners over the recovered
    source" reuse the issue this closes asked for, not a parallel
    analysis path."""
    map_file = tmp_path / "app.min.js.map"
    map_file.write_text(json.dumps({
        "version": 3,
        "sources": ["config.js"],
        "sourcesContent": ["const AWS_SECRET = 'AKIAIOSFODNN7EXAMPLE';"],
    }))
    output_dir = tmp_path / "recovered"
    secrets_server.recover_source_map(str(map_file), str(output_dir))
    assert (output_dir / "config.js").is_file()

    def _fake_run_tool(binary, args, **kwargs):
        report_path = args[args.index("--report-path") + 1]
        findings = [{
            "RuleID": "aws-access-token", "File": str(output_dir / "config.js"),
            "StartLine": 1, "Match": "AKIAIOSFODNN7EXAMPLE",
        }]
        with open(report_path, "w") as f:
            json.dump(findings, f)

        class _Result:
            returncode = 0
        return _Result()

    monkeypatch.setattr(secrets_server, "run_tool", _fake_run_tool)
    scan_result = secrets_server.scan_directory(str(output_dir), redact=False)
    assert "aws-access-token" in scan_result
