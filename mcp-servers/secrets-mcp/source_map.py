"""Source-map recovery and static analysis -- the highest-value recon
artifact on any engagement that has one: an exposed `.js.map` with
`sourcesContent` is a strictly richer artifact than a minified bundle
alone (full unminified source, comments, authorization-design intent,
feature flags, and secrets `js_endpoints.py`'s minified-JS extraction
can't recover from a minified file, since the identifiers/structure a
regex or even an AST walk relies on are already gone).

Deliberately LOCAL-FILE-ONLY, same contract as this module's siblings in
this file's own directory (scan_directory()/extract_endpoints() in
server.py): fetching the JS bundle and its `.map` file from the live
target is NOT done here -- that's an ordinary `curl` call, already
Tier-2 scope-gated by scripts/hooks/scope_gate_hook.py's existing
TIER2_BASH_TOOLS set, exactly like every other live request an agent
makes. Adding a live-fetch capability directly to this module would mean
either bypassing that existing gate or re-registering this whole
directory as a Tier-2 MCP server (a protected-file change to the scope
gate's own TIER2_MCP_SERVERS set) -- deliberately avoided: recon-agent's
own workflow is curl the bundle -> curl the map -> hand both files to
this module, reusing the scope-gate boundary that already exists rather
than duplicating or widening it.

Once files are local, the recovered sources land in an ordinary directory
that scan_directory()/extract_endpoints() (this same server) can then run
over unmodified -- reuse, not a parallel analysis path.
"""

from __future__ import annotations

import json
import os
import re

# Matches the sourceMappingURL comment, either modern (`//#`) or legacy
# (`//@`, older tooling) form, JS or CSS-comment style. Deliberately does
# NOT match a data: URI value here -- see find_inline_data_uri_map()'s own
# docstring for why that's a distinct case with a different caller
# contract (no second fetch needed).
_SOURCE_MAPPING_URL_RE = re.compile(
    r"//[#@]\s*sourceMappingURL\s*=\s*(?!data:)(\S+)", re.MULTILINE,
)

_DATA_URI_MAP_RE = re.compile(
    r"//[#@]\s*sourceMappingURL\s*=\s*(data:application/json[^\s]*)", re.MULTILINE,
)


def find_source_mapping_url(js_text: str) -> str | None:
    """A fetchable URL/filename from the sourceMappingURL comment, or None
    if absent OR if the comment holds an inline data: URI instead (use
    find_inline_data_uri_map() for that case)."""
    m = _SOURCE_MAPPING_URL_RE.search(js_text)
    return m.group(1) if m else None


def find_inline_data_uri_map(js_text: str) -> str | None:
    """The raw `data:application/json...` URI value, when the map is
    embedded inline in the JS response itself rather than a separate
    fetchable file. Caller decodes it directly (base64 or percent-encoded
    per the URI's own declared encoding) -- no second network request."""
    m = _DATA_URI_MAP_RE.search(js_text)
    return m.group(1) if m else None


def guess_source_map_url(js_url: str) -> str:
    """The conventional fallback when no sourceMappingURL comment is
    present at all: the same URL with `.map` appended. A guess, not a
    confirmed map -- the caller's own fetch will 404 if it's wrong, same
    "candidate, verify by trying" philosophy as every other recon tool in
    this repo."""
    return js_url + ".map"


def parse_source_map(map_json_text: str) -> dict:
    """Validates the map is real JSON and pairs each `sources[i]` with
    `sourcesContent[i]`. Returns {"recovered": [{"source": ..., "content":
    ...}, ...]} on success, or {"error": ...} for invalid JSON or a map
    with no sourcesContent at all (nothing to recover). A source with a
    null/missing content entry, or an index beyond the shorter of the two
    arrays, is silently skipped rather than fabricated -- never invent
    content for a source the map didn't actually embed."""
    try:
        data = json.loads(map_json_text)
    except ValueError as e:
        return {"error": f"invalid JSON: {e}"}
    if not isinstance(data, dict):
        return {"error": "source map JSON is not an object"}

    sources = data.get("sources")
    sources_content = data.get("sourcesContent")
    if not isinstance(sources, list) or not isinstance(sources_content, list) or not sources_content:
        return {"error": "no sourcesContent in this map -- nothing to recover (filenames only)"}

    recovered = []
    for source, content in zip(sources, sources_content):
        if not isinstance(content, str):
            continue  # null/missing entry for a source this map doesn't actually embed
        recovered.append({"source": source, "content": content})
    return {"recovered": recovered}


# webpack's own source-path convention: "webpack:///./src/App.js" or
# "webpack:///../node_modules/x/index.js" -- the scheme itself carries no
# real filesystem meaning, strip it before treating the rest as a
# relative path. Other bundlers (Rollup/esbuild/Vite) typically emit
# plain relative paths already, so this is a no-op for those.
_WEBPACK_SCHEME_RE = re.compile(r"^webpack://[^/]*/")


def _safe_relative_path(source: str) -> str:
    """Turns an arbitrary, attacker-influenced `sources[i]` string (the
    target served this map -- never trust it) into a path GUARANTEED to
    stay inside whatever output_dir the caller joins it with. Strips the
    webpack:// scheme, then strips every leading "/" and every ".."
    path segment -- not just a single realpath-after-join check, since
    the goal is a clean, readable recovered-source tree, not merely
    "didn't escape" (a path with embedded ".." components left in place
    would still resolve safely after the realpath confinement check
    below, but would look confusing on disk)."""
    path = _WEBPACK_SCHEME_RE.sub("", source)
    path = path.lstrip("/")
    parts = [p for p in path.split("/") if p not in ("", ".", "..")]
    return os.path.join(*parts) if parts else "unnamed-source"


def write_recovered_sources(parsed: dict, output_dir: str) -> list[str]:
    """Writes each parse_source_map() "recovered" entry to a file under
    output_dir, returns the list of written paths. SECURITY: every
    destination is confirmed (via os.path.realpath) to actually resolve
    inside output_dir before writing -- a source map's own "sources"
    array is attacker-influenced (the target served it), so a crafted
    "../../../../etc/passwd"-shaped entry must never be allowed to write
    outside output_dir. Belt-and-suspenders with _safe_relative_path()'s
    own "..\"/leading-slash stripping, not a substitute for it."""
    output_dir_real = os.path.realpath(output_dir)
    written: list[str] = []
    for entry in parsed.get("recovered", []):
        rel = _safe_relative_path(entry["source"])
        dest = os.path.join(output_dir, rel)
        dest_real = os.path.realpath(dest)
        if not (dest_real == output_dir_real or dest_real.startswith(output_dir_real + os.sep)):
            continue  # would escape output_dir -- refuse, don't write anywhere else either
        os.makedirs(os.path.dirname(dest_real) or output_dir_real, exist_ok=True)
        with open(dest_real, "w") as f:
            f.write(entry["content"])
        written.append(dest_real)
    return written
