"""Error-page/stack-trace dependency version-fingerprint helper.

Why this exists: pinning a dependency's version from an error-page stack
trace (matching frame line/column coordinates against a published
package's source) previously had to be done manually by the model --
worked, but was model-dependent, not reproducible by a less capable agent,
and was recorded as a tool gap during a real engagement (a multipart-
parsing middleware pinned to its exact final release, and a web framework
to a minor-version range, purely from stack-frame coordinates matched by
hand).

This module is deliberately just the MATCHING MECHANISM, shipped with an
EMPTY starter signature database -- not a pre-populated fingerprint
database. Fabricating unverified version/CVE signatures here would be
actively harmful (a wrong version attribution ends up in a security
report as a false claim), so real signatures must be added one at a time
via add_signature(), each individually verified against the package's own
published source/changelog before being trusted -- the same "evidence
before claims" principle this repo applies everywhere else. Mirrors
tool_gaps.py's own philosophy: build the reusable capability, let real
signatures accumulate over time as they're found and verified, rather
than guessing at a comprehensive set up front.

Global, not per-engagement (same reasoning as tool_gaps.py): a verified
signature ("this exact stack-frame shape means this exact package
version") is a cross-engagement fact about a piece of software, not
something scoped to one target.

CLI usage:
    python3 mcp-servers/version_fingerprint.py add <package> <pattern> <version_range> <source>
        -> prints the signature id, or BLOCKED + reason for an invalid regex
    python3 mcp-servers/version_fingerprint.py match <stack_trace_file>
        -> JSON list of matches against every loaded signature
    python3 mcp-servers/version_fingerprint.py list
"""

from __future__ import annotations

import json
import os
import re
import sys
import uuid
from dataclasses import asdict, dataclass

DEFAULT_PATH = os.getenv(
    "HUNTMCP_VERSION_SIGNATURES_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "version-signatures.json"),
)


@dataclass
class VersionSignature:
    id: str
    package: str
    pattern: str  # a regex matched against raw stack-trace/error-page text
    version_range: str  # human-readable, e.g. "4.4.24 - 4.4.26" or "2.1.x"
    source: str  # citation: changelog URL, commit, advisory -- how this was verified
    # Code-review finding (CONFIRMED, empirically reproduced): this module's
    # entire premise is "matching frame LINE/COLUMN coordinates" (see module
    # docstring), but a bare `.search()` never compares any digits the
    # pattern happens to capture against anything -- a pattern written with
    # `(\d+)` for the line number (exactly what the "obvious" way to write
    # one looks like) matches that call site at ANY line, not just the one
    # a human verified against the changelog. expected_line/expected_column
    # make position-pinning an explicit, opt-in, VERIFIED comparison instead
    # of an illusion created by the capture group's mere presence -- None
    # (the default) preserves the old "just needs to match somewhere"
    # behavior for a signature that genuinely has no meaningful position
    # (e.g. a version string literal embedded directly in the trace).
    expected_line: int | None = None
    expected_column: int | None = None


@dataclass
class FingerprintMatch:
    signature_id: str
    package: str
    version_range: str
    matched_text: str
    source: str


def load_signatures(path: str = DEFAULT_PATH) -> list[VersionSignature]:
    if not os.path.isfile(path):
        return []
    with open(path) as f:
        raw = json.load(f)
    return [VersionSignature(**entry) for entry in raw]


def _save(signatures: list[VersionSignature], path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump([asdict(s) for s in signatures], f, indent=2)


def add_signature(package: str, pattern: str, version_range: str, source: str,
                   expected_line: int | None = None, expected_column: int | None = None,
                   path: str = DEFAULT_PATH) -> dict:
    """Returns {"id": ...} on success, or {"error": ...} for an invalid
    regex or a position-pinning request the pattern can't actually honor
    (nothing is saved in that case). If expected_line/expected_column are
    given, the pattern MUST use the correspondingly-named capture group
    (`(?P<line>...)` / `(?P<col>...)`) -- fail closed here, at signature-
    creation time, rather than silently never checking the position later
    (the exact bug this field pair exists to close)."""
    try:
        compiled = re.compile(pattern)
    except re.error as e:
        return {"error": f"invalid regex pattern: {e}"}
    if expected_line is not None and "line" not in compiled.groupindex:
        return {"error": "expected_line given but pattern has no (?P<line>...) named group"}
    if expected_column is not None and "col" not in compiled.groupindex:
        return {"error": "expected_column given but pattern has no (?P<col>...) named group"}
    signatures = load_signatures(path)
    sig = VersionSignature(id=uuid.uuid4().hex[:8], package=package, pattern=pattern,
                            version_range=version_range, source=source,
                            expected_line=expected_line, expected_column=expected_column)
    signatures.append(sig)
    _save(signatures, path)
    return {"id": sig.id}


def fingerprint(stack_trace: str, signatures: list[VersionSignature] | None = None,
                 path: str = DEFAULT_PATH) -> list[FingerprintMatch]:
    """Match `stack_trace` against every signature (loaded from `path` if
    `signatures` isn't given explicitly). A signature whose pattern doesn't
    compile (shouldn't happen via add_signature's own validation, but a
    hand-edited signatures file could) is skipped rather than raising, so
    one bad entry can't break matching against every other signature."""
    if signatures is None:
        signatures = load_signatures(path)
    matches: list[FingerprintMatch] = []
    for sig in signatures:
        try:
            compiled = re.compile(sig.pattern)
        except re.error:
            continue
        m = compiled.search(stack_trace)
        if not m:
            continue
        if not _position_matches(m, sig):
            continue
        matches.append(FingerprintMatch(
            signature_id=sig.id, package=sig.package, version_range=sig.version_range,
            matched_text=m.group(0), source=sig.source,
        ))
    return matches


def _position_matches(m: re.Match, sig: VersionSignature) -> bool:
    """True unless the signature pinned a line/column and the ACTUAL
    captured value disagrees -- the fix for the confirmed bug where a
    pattern capturing the line number was never actually checked against
    anything. A hand-edited signatures file with expected_line/
    expected_column set but no matching named group (add_signature() would
    refuse to create one, but a hand-edited file could) fails this check
    (KeyError/IndexError -> False) rather than crashing fingerprint() for
    every other signature."""
    for expected, group_name in ((sig.expected_line, "line"), (sig.expected_column, "col")):
        if expected is None:
            continue
        try:
            if int(m.group(group_name)) != expected:
                return False
        except (IndexError, ValueError):
            return False
    return True


def _cli() -> None:
    if len(sys.argv) < 2:
        print("usage: version_fingerprint.py <add|match|list> ...", file=sys.stderr)
        sys.exit(2)
    cmd = sys.argv[1]
    if cmd == "add":
        if len(sys.argv) < 6:
            print("usage: version_fingerprint.py add <package> <pattern> <version_range> <source> "
                  "[expected_line] [expected_column]", file=sys.stderr)
            sys.exit(2)
        expected_line = int(sys.argv[6]) if len(sys.argv) > 6 else None
        expected_column = int(sys.argv[7]) if len(sys.argv) > 7 else None
        result = add_signature(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5],
                                expected_line=expected_line, expected_column=expected_column)
        if "error" in result:
            print(f"BLOCKED: {result['error']}", file=sys.stderr)
            sys.exit(1)
        print(result["id"])
    elif cmd == "match":
        if len(sys.argv) < 3:
            print("usage: version_fingerprint.py match <stack_trace_file>", file=sys.stderr)
            sys.exit(2)
        with open(sys.argv[2]) as f:
            stack_trace = f.read()
        matches = fingerprint(stack_trace)
        print(json.dumps([asdict(m) for m in matches], indent=2))
    elif cmd == "list":
        signatures = load_signatures()
        print(json.dumps([asdict(s) for s in signatures], indent=2))
    else:
        print(f"unknown command {cmd!r}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    _cli()
