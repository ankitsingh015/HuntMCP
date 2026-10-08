"""C1b: research-run manifest capture -- tool/model/policy versions plus a
target-snapshot hash, captured once per research run.

Fixtures below are REAL `--version`/`-version` output captured from the
actual installed binaries in this dev environment (subfinder v2.14.0,
httpx v1.9.0, katana v1.6.1, nuclei v3.11.0, nmap 7.94SVN, sqlmap 1.8.4,
dalfox v2.13.0, ffuf 2.1.0-dev) -- not invented strings -- so the
version-extraction heuristic is verified against real banner noise (ANSI
color codes, ASCII-art logos) rather than an idealized clean string.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "mcp-servers"))

import pytest
import research_manifest
import tool_resolver


def _all_scanners_installed() -> bool:
    for name in research_manifest.TOOL_VERSION_FLAGS:
        path = tool_resolver.resolve_tool(name)
        if not (os.path.isfile(path) and os.access(path, os.X_OK)):
            return False
    return True


requires_all_scanner_binaries = pytest.mark.skipif(
    not _all_scanners_installed(),
    reason="not all 8 scanner binaries (subfinder/httpx/katana/nuclei/nmap/sqlmap/dalfox/ffuf) "
           "are installed -- CI's unit-test job doesn't install them (see .github/workflows/ci.yml); "
           "this test is a dev-environment sanity check against the real binaries, same convention "
           "as test_p2_bench_fixture.py's requires_sqlmap",
)

# --- real captured banners (ANSI codes kept, exactly as the tools print them) ---

SUBFINDER_OUT = "\x1b[34m[\x1b[0m\x1b[1;34mINF\x1b[0m\x1b[34m]\x1b[0m Current Version: v2.14.0\n[INF] Subfinder Config Directory: /home/x/.config/subfinder\n"
HTTPX_OUT = "\n    __    __  __       _  __\n   / /_  / /_/ /_____ | |/ /\n\n\t\tprojectdiscovery.io\n\n[INF] Current Version: v1.9.0\n"
KATANA_OUT = "\n   __        __\n  / /_____ _/ /____ ____  ___ _\n\n\t\tprojectdiscovery.io\n\n[INF] Current version: v1.6.1\n"
NUCLEI_OUT = "[INF] Nuclei Engine Version: v3.11.0\n[INF] Nuclei Config Directory: /home/x/.config/nuclei\n"
NMAP_OUT = "Nmap version 7.94SVN ( https://nmap.org )\nPlatform: x86_64-pc-linux-gnu\n"
SQLMAP_OUT = "1.8.4#stable\n[12:31:17] [WARNING] your sqlmap version is outdated\n"
DALFOX_OUT = "                 Dalfox v2.13.0\n Powerful open-source XSS scanner\n\n\x1b[93mv2.13.0\x1b[0m\n"
FFUF_OUT = "ffuf version: 2.1.0-dev\n"

NO_VERSION_HINT_OUT = "some unrelated banner with no version info at all\n"


def test_strips_ansi_and_extracts_versioned_line():
    assert research_manifest.parse_tool_version(SUBFINDER_OUT) == "2.14.0"


def test_extracts_version_from_projectdiscovery_httpx_banner():
    assert research_manifest.parse_tool_version(HTTPX_OUT) == "1.9.0"


def test_extracts_version_from_katana_banner():
    assert research_manifest.parse_tool_version(KATANA_OUT) == "1.6.1"


def test_extracts_version_from_nuclei_banner():
    assert research_manifest.parse_tool_version(NUCLEI_OUT) == "3.11.0"


def test_extracts_version_with_trailing_letters_from_nmap():
    assert research_manifest.parse_tool_version(NMAP_OUT) == "7.94SVN"


def test_extracts_bare_version_line_from_sqlmap():
    assert research_manifest.parse_tool_version(SQLMAP_OUT) == "1.8.4#stable"


def test_extracts_trailing_bare_version_line_from_dalfox_ignoring_ansi():
    assert research_manifest.parse_tool_version(DALFOX_OUT) == "2.13.0"


def test_extracts_version_with_dev_suffix_from_ffuf():
    assert research_manifest.parse_tool_version(FFUF_OUT) == "2.1.0-dev"


def test_returns_none_rather_than_fabricating_a_version():
    assert research_manifest.parse_tool_version(NO_VERSION_HINT_OUT) is None


def test_returns_none_on_empty_output():
    assert research_manifest.parse_tool_version("") is None


# Regressions found by an independent correctness review of the first
# draft's looser "line contains the word 'version'" + "first number
# anywhere on that line" heuristic.

def test_does_not_match_version_as_a_substring_of_another_word():
    assert research_manifest.parse_tool_version("conversion 1.2.3") is None


def test_does_not_grab_an_unrelated_ip_port_sharing_a_line_with_version():
    assert research_manifest.parse_tool_version("127.0.0.1:8080 version check disabled") is None


def test_does_not_grab_an_unrelated_runtime_version_on_a_later_line():
    """A hypothetical sqlmap-like tool that also prints a Python-runtime
    version warning must not have that warning's digits mistaken for the
    tool's own bare first-line version."""
    out = "1.8.4#stable\n[WARNING] Python version 3.12.3 detected\n"
    assert research_manifest.parse_tool_version(out) == "1.8.4#stable"


def test_extracts_a_labeled_version_with_four_components():
    assert research_manifest.parse_tool_version("Version: 1.2.3.4") == "1.2.3.4"


def test_extracts_a_bare_prerelease_style_version():
    assert research_manifest.parse_tool_version("v3.0.0-rc.1") == "3.0.0-rc.1"


def test_strips_charset_select_ansi_sequences_not_just_csi_codes():
    assert research_manifest.parse_tool_version("\x1b(B\x1b[mv2.13.0\x1b(B\x1b[m") == "2.13.0"


@requires_all_scanner_binaries
def test_capture_tool_versions_against_real_installed_binaries():
    """Black-box: actually spawn each real resolved binary (no mocks) and
    confirm every one of the 8 known scanners is both resolved AND
    produces a non-None parsed version in this dev environment -- proof
    the per-tool version-flag map (`TOOL_VERSION_FLAGS`) is correct, not
    just that the regex heuristic parses a canned fixture."""
    versions = research_manifest.capture_tool_versions()
    assert set(versions) == set(research_manifest.TOOL_VERSION_FLAGS)
    for name, info in versions.items():
        assert info["resolved"] is True, f"{name} did not resolve to a real binary: {info}"
        assert info["version"] is not None, f"{name} resolved but version parsing failed: {info}"


def test_capture_tool_versions_degrades_gracefully_for_unknown_binary(monkeypatch):
    import tool_resolver

    monkeypatch.setattr(tool_resolver, "resolve_tool", lambda name: "/nonexistent/path/" + name)
    versions = research_manifest.capture_tool_versions()
    for info in versions.values():
        assert info["resolved"] is False
        assert info["version"] is None


def test_capture_model_info_reflects_explicit_override(monkeypatch):
    monkeypatch.setenv("HUNTMCP_MODEL", "deepseek")
    info = research_manifest.capture_model_info()
    assert info["provider"] == "deepseek"
    assert info["model"] is not None
    assert info["source"] == "explicit_override"


def test_capture_model_info_degrades_gracefully_when_no_provider_available(monkeypatch):
    monkeypatch.delenv("HUNTMCP_MODEL", raising=False)
    monkeypatch.setattr(
        "model_gateway.PROVIDER_CHAIN", [("anthropic", "ANTHROPIC_API_KEY_NOT_SET_XYZ", "x", None)]
    )
    info = research_manifest.capture_model_info()
    assert info["provider"] is None
    assert info["model"] is None
    assert "error" in info


def test_capture_policy_version_hashes_the_real_hook_file():
    policy = research_manifest.capture_policy_version()
    assert policy["available"] is True
    assert len(policy["hash"]) == 64  # sha256 hex digest
    # same file, called twice -> same hash (deterministic, not time-based)
    assert research_manifest.capture_policy_version()["hash"] == policy["hash"]


def test_capture_policy_version_degrades_gracefully_if_hook_file_missing(monkeypatch):
    monkeypatch.setattr(research_manifest, "_SCOPE_GATE_HOOK_PATH", "/nonexistent/scope_gate_hook.py")
    policy = research_manifest.capture_policy_version()
    assert policy["available"] is False
    assert policy["hash"] is None


def test_hash_target_snapshot_reflects_case_db_contents(tmp_path, monkeypatch):
    import case_store

    db_path = str(tmp_path / "case.db")
    empty = research_manifest.hash_target_snapshot(db_path)
    assert empty["available"] is True
    assert len(empty["hash"]) == 64

    case_store.create_finding("IDOR", "/doc/{id}", db_path=db_path)
    changed = research_manifest.hash_target_snapshot(db_path)
    assert changed["hash"] != empty["hash"]


def test_capture_manifest_shape(tmp_path):
    db_path = str(tmp_path / "case.db")
    manifest = research_manifest.capture_manifest("example.com", db_path=db_path)
    assert manifest["target"] == "example.com"
    assert "captured_at" in manifest
    assert set(manifest["tool_versions"]) == set(research_manifest.TOOL_VERSION_FLAGS)
    assert "model" in manifest
    assert "policy_version" in manifest
    assert "target_snapshot_hash" in manifest


def test_capture_manifest_never_raises_even_if_everything_fails(tmp_path, monkeypatch):
    """A manifest-capture failure must never abort the research run it's
    attached to -- every sub-capture degrades to a null/False result
    instead of propagating. Checks all 4 sub-captures (a prior draft of
    this test only checked 2, found by review). `case_store.case_export`
    is monkeypatched to actually raise -- case_store's own `_get_conn`
    auto-creates any missing directory (`os.makedirs(..., exist_ok=True)`,
    by design elsewhere in this codebase), so merely pointing db_path at a
    nonexistent subdirectory does NOT make the snapshot capture fail; it
    just makes it succeed against a freshly-created empty db."""
    monkeypatch.setattr(tool_resolver, "resolve_tool", lambda name: "/nonexistent/" + name)
    monkeypatch.setattr(research_manifest, "_SCOPE_GATE_HOOK_PATH", "/nonexistent/hook.py")
    monkeypatch.setattr("model_gateway.PROVIDER_CHAIN", [])

    import case_store

    def _boom(db_path=None):
        raise RuntimeError("simulated case_export failure")

    monkeypatch.setattr(case_store, "case_export", _boom)

    manifest = research_manifest.capture_manifest("example.com", db_path=str(tmp_path / "case.db"))

    assert manifest["target"] == "example.com"
    assert manifest["model"]["provider"] is None
    assert manifest["policy_version"]["available"] is False
    assert manifest["target_snapshot_hash"]["available"] is False
    for info in manifest["tool_versions"].values():
        assert info["resolved"] is False
        assert info["version"] is None
