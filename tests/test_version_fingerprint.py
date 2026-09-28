import version_fingerprint


def _sig(**overrides):
    base = dict(
        id="sig-1",
        package="example-multipart-parser",
        pattern=r"at ExampleMultipartParser\.parse \(lib/multipart\.js:(\d+):\d+\)",
        version_range="4.4.24 - 4.4.26",
        source="synthetic test fixture, not a real advisory",
    )
    base.update(overrides)
    return version_fingerprint.VersionSignature(**base)


def test_fingerprint_matches_a_known_signature():
    stack = "TypeError: boundary not found\n    at ExampleMultipartParser.parse (lib/multipart.js:142:19)\n"
    matches = version_fingerprint.fingerprint(stack, signatures=[_sig()])
    assert len(matches) == 1
    assert matches[0].package == "example-multipart-parser"
    assert matches[0].version_range == "4.4.24 - 4.4.26"
    assert "lib/multipart.js:142:19" in matches[0].matched_text


def test_fingerprint_no_match_returns_empty_list():
    stack = "completely unrelated stack trace text"
    matches = version_fingerprint.fingerprint(stack, signatures=[_sig()])
    assert matches == []


def test_fingerprint_matches_multiple_signatures_independently():
    stack = (
        "at ExampleMultipartParser.parse (lib/multipart.js:142:19)\n"
        "at ExampleWebFramework.handle (lib/framework.js:88:4)\n"
    )
    sig2 = _sig(
        id="sig-2", package="example-web-framework",
        pattern=r"at ExampleWebFramework\.handle \(lib/framework\.js:(\d+):\d+\)",
        version_range="2.1.x",
    )
    matches = version_fingerprint.fingerprint(stack, signatures=[_sig(), sig2])
    assert {m.package for m in matches} == {"example-multipart-parser", "example-web-framework"}


def test_fingerprint_against_empty_signature_set_returns_empty():
    """The starter database ships empty by design -- fabricating unverified
    version/CVE fingerprints would be actively harmful (a wrong version
    attribution in a security report), so real signatures are added one at
    a time as they're individually verified, not pre-populated here. This
    just confirms the mechanism degrades safely (empty result, not an
    error) when nothing is loaded yet."""
    assert version_fingerprint.fingerprint("any stack trace", signatures=[]) == []


def test_add_and_load_signature_round_trips(tmp_path):
    p = str(tmp_path / "version-signatures.json")
    version_fingerprint.add_signature(
        package="example-multipart-parser",
        pattern=r"at ExampleMultipartParser\.parse \(lib/multipart\.js:(\d+):\d+\)",
        version_range="4.4.24 - 4.4.26",
        source="synthetic test fixture",
        path=p,
    )
    loaded = version_fingerprint.load_signatures(path=p)
    assert len(loaded) == 1
    assert loaded[0].package == "example-multipart-parser"

    stack = "at ExampleMultipartParser.parse (lib/multipart.js:142:19)"
    matches = version_fingerprint.fingerprint(stack, signatures=loaded)
    assert len(matches) == 1


def test_add_signature_rejects_invalid_regex(tmp_path):
    p = str(tmp_path / "version-signatures.json")
    result = version_fingerprint.add_signature(
        package="x", pattern="(unclosed", version_range="1.0", source="test", path=p,
    )
    assert "error" in result
    assert version_fingerprint.load_signatures(path=p) == []


def test_load_signatures_from_missing_file_returns_empty_list(tmp_path):
    p = str(tmp_path / "does-not-exist.json")
    assert version_fingerprint.load_signatures(path=p) == []


# ---- position-pinning (code-review finding, empirically reproduced) --------
#
# The module's entire premise is "matching frame LINE/COLUMN coordinates"
# (see its own docstring), but the original fingerprint() never compared any
# digits a pattern happened to capture against anything -- a pattern written
# with `(\d+)` for the line number (the "obvious" way to write one, and
# exactly what every signature above this comment uses) matched that call
# site at ANY line, not just the one a human verified against the changelog.

def _pinned_sig(expected_line=142, expected_column=19, **overrides):
    base = dict(
        id="sig-pinned",
        package="example-multipart-parser",
        pattern=r"at ExampleMultipartParser\.parse \(lib/multipart\.js:(?P<line>\d+):(?P<col>\d+)\)",
        version_range="4.4.24 - 4.4.26",
        source="synthetic test fixture, not a real advisory",
        expected_line=expected_line,
        expected_column=expected_column,
    )
    base.update(overrides)
    return version_fingerprint.VersionSignature(**base)


def test_fingerprint_matches_when_line_and_column_agree():
    stack = "at ExampleMultipartParser.parse (lib/multipart.js:142:19)"
    matches = version_fingerprint.fingerprint(stack, signatures=[_pinned_sig()])
    assert len(matches) == 1


def test_fingerprint_rejects_match_at_a_different_line():
    """The confirmed bug, reproduced directly: same call site, but at a
    DIFFERENT line number than the one the signature was verified against
    -- must NOT match, since this is exactly the false-version-attribution
    scenario the module's own docstring calls "actively harmful"."""
    stack = "at ExampleMultipartParser.parse (lib/multipart.js:9999:1)"
    matches = version_fingerprint.fingerprint(stack, signatures=[_pinned_sig()])
    assert matches == []


def test_fingerprint_rejects_match_at_a_different_column(tmp_path):
    stack = "at ExampleMultipartParser.parse (lib/multipart.js:142:1)"
    matches = version_fingerprint.fingerprint(stack, signatures=[_pinned_sig()])
    assert matches == []


def test_fingerprint_unpinned_signature_still_matches_anywhere():
    """Backward-compatible default: expected_line/expected_column both
    None (unset) preserves the original "just needs to match somewhere"
    behavior -- e.g. for a version string literal with no meaningful
    position. Every signature in this file ABOVE this section already
    relies on this."""
    stack = "at ExampleMultipartParser.parse (lib/multipart.js:9999:1)"
    matches = version_fingerprint.fingerprint(stack, signatures=[_sig()])
    assert len(matches) == 1


def test_add_signature_rejects_expected_line_without_a_named_group(tmp_path):
    """Fail closed at signature-creation time, not silently-never-checked
    later: requesting position-pinning for a pattern that can't actually
    honor it (no `(?P<line>...)` group) must be refused, not saved."""
    p = str(tmp_path / "version-signatures.json")
    result = version_fingerprint.add_signature(
        package="x", pattern=r"at Foo\.bar \((\d+):(\d+)\)", version_range="1.0",
        source="test", expected_line=142, path=p,
    )
    assert "error" in result
    assert version_fingerprint.load_signatures(path=p) == []


def test_add_signature_accepts_expected_line_with_a_named_group(tmp_path):
    p = str(tmp_path / "version-signatures.json")
    result = version_fingerprint.add_signature(
        package="x", pattern=r"at Foo\.bar \(x:(?P<line>\d+):(?P<col>\d+)\)", version_range="1.0",
        source="test", expected_line=142, expected_column=19, path=p,
    )
    assert "id" in result
    loaded = version_fingerprint.load_signatures(path=p)
    assert loaded[0].expected_line == 142
    assert loaded[0].expected_column == 19
