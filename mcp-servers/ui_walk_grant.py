"""#164: the human-owned grant that enables the UI-walk's Pass 2 (real canary
submits + create->destroy->verify on walker-owned objects).

User decision (spec decision 3, option B): the human grants canary mode ONCE
per engagement, with no terminal keystroke per walk. The grant lives in its
own file, data/engagements/<slug>/ui-walk-authorized.yaml, NOT in
engagement.yaml: huntbrain itself writes engagement.yaml at engagement start,
so a grant there could be self-issued by an agent (or by prompt-injected target
text steering one). This file -- and this module, which decides how it is
parsed -- are on scripts/hooks/scope_gate_hook.py's protected-path list, so an
agent's Write/Edit/Bash to either is blocked; the human creates the file by
hand in their own terminal, e.g.

    printf 'canary_submit: true\\n' > data/engagements/<slug>/ui-walk-authorized.yaml

Fields:
  canary_submit: true            # must be the YAML boolean true, nothing else
  hosts: [app.example.com]       # optional subset of scope; empty = any in-scope host
  real_submit_cap_per_walk: 200  # optional, positive int

Absent / unparsable / not literally true -> no grant (Pass 1 still allowed).

HONEST LIMIT (same class as state_change_confirm): an agent that escapes the
hook entirely (its own pty, a write the hook cannot see) is outside this
module's reach.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

import engagement_paths

try:
    import yaml
except ImportError:  # pragma: no cover - PyYAML is a repo dependency
    yaml = None

GRANT_FILENAME = "ui-walk-authorized.yaml"
DEFAULT_REAL_SUBMIT_CAP = 200


@dataclass
class Grant:
    canary_submit: bool
    hosts: list[str] = field(default_factory=list)
    real_submit_cap_per_walk: int = DEFAULT_REAL_SUBMIT_CAP


def grant_path(slug: str | None = None) -> str:
    slug = slug or engagement_paths.get_active_target()
    if not slug:
        raise RuntimeError("no active engagement -- the UI-walk grant is per engagement")
    return os.path.join(engagement_paths.ENGAGEMENTS_ROOT, slug, GRANT_FILENAME)


def load_grant(slug: str | None = None) -> Grant | None:
    try:
        path = grant_path(slug)
    except RuntimeError:
        return None
    if yaml is None or not os.path.isfile(path):
        return None
    try:
        with open(path) as fh:
            data = yaml.safe_load(fh)
    except (OSError, yaml.YAMLError):
        return None
    if not isinstance(data, dict) or data.get("canary_submit") is not True:
        return None
    hosts = data.get("hosts") or []
    if not isinstance(hosts, list):
        return None
    cap = data.get("real_submit_cap_per_walk", DEFAULT_REAL_SUBMIT_CAP)
    if not isinstance(cap, int) or isinstance(cap, bool) or cap <= 0:
        cap = DEFAULT_REAL_SUBMIT_CAP
    return Grant(canary_submit=True, hosts=[str(h).lower() for h in hosts], real_submit_cap_per_walk=cap)


def grant_allows(grant: Grant | None, host: str) -> bool:
    if grant is None or grant.canary_submit is not True:
        return False
    return not grant.hosts or (host or "").lower() in grant.hosts
