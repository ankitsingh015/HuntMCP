"""Finding-level dedup check (Phase 2.10, `google/mantis`'s `mantis-dedupe`
pattern).

Complements `work_registry.py` (which dedupes agent SPAWNS on a host) with
a check at the FINDING level: has this exact vuln_class+endpoint+parameter
combination already been confirmed this engagement? Two scan passes (or a
scan-agent retry after a fix) can independently surface the same
underlying bug -- this catches it before exploit-agent writes up a
duplicate, rather than relying on the human reviewer to notice at
report-review time.

State is per-engagement, reset alongside engagement.yaml/budget.json/
work-registry.json.

CLI usage (what exploit-agent runs via Bash right before finalizing a
CONFIRMED verdict):
    python3 mcp-servers/dedupe_check.py <vuln_class> <endpoint> [parameter]
    exit 0 -> new finding, recorded
    exit 1 -> duplicate of an already-confirmed finding this engagement
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time

try:
    import engagement_paths
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import engagement_paths

DEFAULT_PATH = engagement_paths.resolve("findings-seen.json", override_env="HUNTMCP_FINDINGS_SEEN_PATH")


def _fingerprint(vuln_class: str, endpoint: str, parameter: str = "") -> str:
    key = f"{vuln_class.strip().lower()}|{endpoint.strip().lower()}|{parameter.strip().lower()}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _load(path: str = DEFAULT_PATH) -> dict:
    if not os.path.isfile(path):
        return {}
    with open(path) as f:
        return json.load(f)


def _save(state: dict, path: str = DEFAULT_PATH) -> None:
    with open(path, "w") as f:
        json.dump(state, f, indent=2)


def check_and_record(vuln_class: str, endpoint: str, parameter: str = "",
                      path: str = DEFAULT_PATH) -> dict:
    """Check whether this vuln_class+endpoint+parameter was already
    confirmed this engagement. If new, records it (so the NEXT call with
    the same fingerprint IS flagged as a duplicate) and returns
    duplicate=False. Call this once per finding, right before finalizing a
    CONFIRMED verdict -- not on every candidate, since a candidate that
    turns out to be a false positive shouldn't occupy a fingerprint slot."""
    fp = _fingerprint(vuln_class, endpoint, parameter)
    state = _load(path)
    if fp in state:
        return {
            "duplicate": True,
            "fingerprint": fp,
            "first_seen_at": state[fp]["seen_at"],
            "first_seen_as": state[fp]["label"],
        }
    label = f"{vuln_class} @ {endpoint}" + (f" ({parameter})" if parameter else "")
    state[fp] = {"seen_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "label": label}
    _save(state, path)
    return {"duplicate": False, "fingerprint": fp}


def _cli() -> None:
    if len(sys.argv) < 3:
        print("usage: dedupe_check.py <vuln_class> <endpoint> [parameter]", file=sys.stderr)
        sys.exit(2)
    vuln_class, endpoint = sys.argv[1], sys.argv[2]
    parameter = sys.argv[3] if len(sys.argv) > 3 else ""
    result = check_and_record(vuln_class, endpoint, parameter)
    print(json.dumps(result, indent=2))
    sys.exit(1 if result["duplicate"] else 0)


if __name__ == "__main__":
    _cli()
