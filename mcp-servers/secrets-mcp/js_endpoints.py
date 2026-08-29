"""JS-bundle endpoint inventory -- automates the second half of the manual
grind recon usually does by hand: grepping every downloaded JS bundle for
`/api/...`-shaped path literals one file at a time. Complements
server.py's existing scan_directory() (gitleaks, secrets) rather than
duplicating it -- this tool finds ROUTES, that one finds CREDENTIALS,
both operate on the exact same local directory of already-downloaded JS
(recon-agent's own Phase 3 already documents the download step; neither
tool does any live-network fetching of its own).

Regex-based, not a JS parser/AST walk -- deliberately: a real bundler
output is minified/obfuscated enough that a regex over the raw text
catches string literals a full parser would need a source map to make
sense of anyway, and "candidate paths for a human/agent to review" is
the same philosophy every other recon tool in this repo already uses
(subfinder/httpx/katana all return candidates, not verified ground
truth) -- false positives here cost a quick glance, false negatives from
an over-engineered parser that chokes on a webpack bundle would cost the
actual finding.
"""

from __future__ import annotations

import os
import re

# Extensions that commonly appear at the end of a string literal starting
# with "/" but are static assets, not API routes -- filtering these out is
# the single highest-value noise reduction, since a JS bundle references
# far more images/fonts/stylesheets than actual API endpoints.
_STATIC_ASSET_EXTENSIONS = {
    "png", "jpg", "jpeg", "gif", "svg", "ico", "css", "woff", "woff2",
    "ttf", "eot", "otf", "map", "webp", "mp4", "webm", "wasm", "json",
}

# Matches a quoted string literal (single/double/backtick) starting with
# "/" -- deliberately permissive on what characters can follow (real
# paths contain {param}/:param placeholders, dots, dashes, colons for
# port-like segments, and query strings with ?=&%) since
# over-constraining the charset just produces silent false negatives on a
# route shape not anticipated in advance. Caught live during testing: a
# literal like "/internal/admin/export?format=csv" was silently dropped
# entirely (not truncated -- dropped) before ?=& were added, because the
# regex engine found no valid match once it hit the unrecognized "?" and
# never reached a closing quote on any shorter prefix either.
_PATH_LITERAL_RE = re.compile(r'''["'`](/[a-zA-Z0-9_][a-zA-Z0-9_\-./{}:?=&%]{1,160})["'`]''')

# Route-parameter placeholders inside a path: /orders/{id}, /orders/:id,
# /orders/[id] (Next.js), each style used by a different framework.
_PARAM_RE = re.compile(r"[:{\[]([a-zA-Z_][a-zA-Z0-9_]*)[}\]]?")

_JS_LIKE_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".map"}


def _looks_like_endpoint(path: str) -> bool:
    """Filters _PATH_LITERAL_RE's raw matches down to plausible API
    routes: at least two path segments (a single-segment path like
    "/login" as a bare string is more often a client-side router path
    than a real backend endpoint, though it's a judgment call, not a
    guarantee either way), and not ending in a known static-asset
    extension. Strips a trailing query string before the extension check
    -- a cache-busted asset reference like "/assets/logo.png?v=123" must
    still be recognized as a .png, not miscounted as a real endpoint just
    because "png?v=123" doesn't literally match "png"."""
    path_only = path.split("?", 1)[0]
    last_segment = path_only.rsplit("/", 1)[-1]
    if "." in last_segment:
        ext = last_segment.rsplit(".", 1)[-1].lower()
        if ext in _STATIC_ASSET_EXTENSIONS:
            return False
    return path_only.count("/") >= 2


def extract_endpoints_from_text(text: str) -> list[str]:
    """Pure-logic extraction from one file's already-read text content --
    factored out from the directory walk so it's unit-testable without
    touching the filesystem."""
    candidates = {m.group(1) for m in _PATH_LITERAL_RE.finditer(text)}
    return sorted(p for p in candidates if _looks_like_endpoint(p))


def extract_params(path: str) -> list[str]:
    """Route-parameter names found in a path, e.g. "/orders/{id}/items/:sku"
    -> ["id", "sku"]. Only looks at segments that actually use a
    parameter-placeholder syntax -- a bare numeric-looking segment
    ("/orders/12345") is a specific object id from real app data, not a
    route parameter name, and reporting it as one would be misleading."""
    return _PARAM_RE.findall(path)


def scan_directory_for_endpoints(path: str, max_results: int = 500) -> dict[str, list[str]]:
    """Walk path recursively, extract endpoint candidates from every
    JS-like file, and return {endpoint: [source files it was found in]}
    -- the source-file mapping is what makes a candidate actually
    actionable (go look at THIS file for how it's called, what payload
    it sends) rather than just a bare list of strings with no context.
    Caps at max_results distinct endpoints so a huge bundle directory
    can't blow out the tool's return size -- stops the walk entirely once
    the cap is hit, rather than finishing every file and truncating the
    result afterward, so a directory much larger than the cap doesn't
    cost a full scan for output that gets thrown away anyway."""
    inventory: dict[str, list[str]] = {}
    for root, _dirs, files in os.walk(path):
        for filename in files:
            if os.path.splitext(filename)[1].lower() not in _JS_LIKE_EXTENSIONS:
                continue
            filepath = os.path.join(root, filename)
            try:
                with open(filepath, encoding="utf-8", errors="replace") as f:
                    text = f.read()
            except OSError:
                continue
            for endpoint in extract_endpoints_from_text(text):
                sources = inventory.setdefault(endpoint, [])
                if filepath not in sources:
                    sources.append(filepath)
                if len(inventory) >= max_results:
                    return inventory
    return inventory
