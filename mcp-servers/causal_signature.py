"""P4-SIG -- canonical causal signatures derived from CEM minimal condition sets.

MASTER-ROADMAP-FINAL-v3.md section 7 ("CEM Position"): *the CEM engine is
frozen/accepted; later work only consumes/extends AROUND it*, and *Phase-5 uses
causal signatures for variants/transfer (gated)*. This module is the
signature-PRODUCER that P5 (P5-T1 transfer, P5-VARIANT discovery) will later
consume. P5 itself is deliberately NOT in scope here.

What a causal signature is
--------------------------
A deterministic, canonical fingerprint of the *necessary-condition pattern* CEM
already recovered for a confirmed finding -- the sorted/normalized minimal
condition set(s) that CEM's own `minimal_condition_sets` produced, carried
together with the finding's vuln-class and each condition's category (invariant
metadata). The core property, the whole point of the task, is:

  * SAME underlying causal structure  -> SAME signature (canonicality), and
  * DIFFERENT structure               -> DIFFERENT signature (discrimination),

so that P5 can recognise "the same root cause elsewhere" (transfer) and generate
variants. The signature is a content hash over a canonical form, so two CEM
results with the same minimal necessary conditions compare equal regardless of
incidental element order, the order the alternate minimal sets are listed in, or
case/whitespace "labeling" of the names.

Normalization scheme (documented, deterministic)
------------------------------------------------
  * vuln_class  -> strip, collapse internal whitespace to single spaces, UPPER.
  * condition name / category -> strip, collapse internal whitespace, lower.
    Only case and whitespace are treated as incidental "labeling". Structural
    separators ('_', '-', ':', '.', '/') are PRESERVED, so "role_admin" and
    "role-admin" stay distinct -- normalization is deliberately conservative so
    it never collapses two genuinely different conditions (which would silently
    destroy discrimination).
  * a condition token is "<category>:<name>" when a category is known for that
    name, else just "<name>". Categories are matched by normalized name, so a
    category supplied with different case/whitespace still attaches.
  * within a minimal set: tokens are sorted and de-duplicated (normalization
    could map two labels to one token -- that must not invent a 2-element set).
  * the collection of minimal sets is sorted and de-duplicated, so the order CEM
    happened to list alternates in is irrelevant.
  * the canonical form is a dict with sorted keys; the signature is
    "sha256:" + sha256 of its compact, sorted-key JSON encoding -- stable across
    processes and runs.

No fabrication
--------------
`causal_signature()` returns None when there is no non-empty minimal
necessary-condition set to describe (empty/None input, or input whose names all
normalize away). `signature_for_finding()` returns None when the finding does
not exist, has no CEM state, or recorded no `necessary` verdict -- CEM's own
`minimal_condition_sets` likewise refuses to produce a set in that case. A
signature therefore only ever reflects CEM's ACTUAL minimal-set output; it never
invents necessity.

Read-only / offline
-------------------
This is an offline, read-only CONSUMER, matching the P2-TEL/P2-E1/P4-COVMATRIX
pattern for analysis modules. It reads finding + CEM state through case_store's
existing read APIs (`get_finding`, `cem_load_state`) and, for the multi-set
reconstruction, reuses the FROZEN `cem_engine.find_alternate_condition_sets`
VERBATIM (a direct call -- ddmin is never reimplemented here). It never calls a
case_store WRITE function, never imports tool_resolver/job_runtime/scope_guard/
budget_guard, defines no new table/column/migration, and holds no write path
into CEM. `test_causal_signature.test_module_has_no_write_or_tool_calls` asserts
this structurally, and `..._never_mutates_the_case_store` at runtime.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from collections.abc import Iterable, Mapping

try:
    import case_store
except ImportError:  # pragma: no cover - import shim mirrors sibling modules
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import case_store

SIGNATURE_VERSION = 1

_WS_RE = re.compile(r"\s+")


def _norm_class(value: str) -> str:
    """Canonicalize a vuln-class label: strip, collapse whitespace, upper-case."""
    return _WS_RE.sub(" ", (value or "").strip()).upper()


def _norm_token(value: str) -> str:
    """Canonicalize a condition name / category: strip, collapse whitespace,
    lower-case. Structural separators are preserved (see module docstring)."""
    return _WS_RE.sub(" ", (value or "").strip()).lower()


def _condition_token(name: str, categories: Mapping[str, str] | None) -> str:
    """Build the canonical "<category>:<name>" (or bare "<name>") token for one
    condition. Returns "" when the name normalizes to empty (dropped by caller)."""
    norm_name = _norm_token(name)
    if not norm_name:
        return ""
    if categories:
        cat = categories.get(norm_name)
        if cat:
            return f"{_norm_token(cat)}:{norm_name}"
    return norm_name


def _normalize_categories(categories: Mapping[str, str] | None) -> dict[str, str] | None:
    """Re-key a caller-supplied {name: category} map by NORMALIZED name so the
    lookup is itself label-insensitive. Last writer wins on a normalization
    collision (deterministic for a given dict iteration)."""
    if not categories:
        return None
    return {_norm_token(k): v for k, v in categories.items()}


def causal_signature(
    vuln_class: str,
    minimal_sets: Iterable[Iterable[str]] | None,
    interacting: Iterable[str] | None = None,
    condition_categories: Mapping[str, str] | None = None,
) -> dict | None:
    """Derive a canonical causal signature from a CEM minimal-set result.

    Pure function: no I/O, no CEM call, no DB. Inputs are exactly what CEM's own
    `minimal_condition_sets` tool emits, plus the finding's vuln-class and an
    optional {condition_name: category} map (CEM's `cem_conditions.category`).

    Args:
        vuln_class: the finding's vulnerability class (e.g. "SQLi", "IDOR").
        minimal_sets: CEM's `minimal_sets` -- a list of condition-name lists,
            each an independently-sufficient 1-minimal necessary-condition set.
        interacting: CEM's `interacting` list (C6), if any.
        condition_categories: optional {name: category} invariant metadata.

    Returns:
        A JSON-serializable signature dict, or None when there is no non-empty
        minimal necessary-condition set to describe (NO fabrication).
    """
    cats = _normalize_categories(condition_categories)

    canon_sets: set[tuple[str, ...]] = set()
    for s in (minimal_sets or ()):
        tokens = {t for t in (_condition_token(n, cats) for n in (s or ())) if t}
        if tokens:
            canon_sets.add(tuple(sorted(tokens)))

    if not canon_sets:
        # CEM produced no minimal necessary-condition set -> no signature.
        return None

    sorted_sets = [list(t) for t in sorted(canon_sets)]
    canon_interacting = sorted(
        {t for t in (_condition_token(n, cats) for n in (interacting or ())) if t}
    )

    canonical = {
        "version": SIGNATURE_VERSION,
        "vuln_class": _norm_class(vuln_class),
        "minimal_sets": sorted_sets,
        "interacting": canon_interacting,
    }
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    result = dict(canonical)
    result["signature"] = f"sha256:{digest}"
    return result


def _stored_verdict_map(state: dict) -> dict:
    """condition name -> most-recent stored per-condition verdict string.

    A verbatim mirror of case-mcp/server.py's own `_stored_verdict_map`, so this
    consumer reconstructs the same E1 stored-verdict predicate CEM's
    `minimal_condition_sets` tool uses -- not a second, divergent source of
    truth."""
    by_id = {c["id"]: c["name"] for c in state["conditions"]}
    out: dict[str, str] = {}
    for v in state["verdicts"]:
        name = by_id.get(v["condition_id"])
        if name is not None:
            out[name] = v["verdict"]
    return out


def signature_for_finding(finding_id: int, db_path: str | None = None) -> dict | None:
    """Read-only end-to-end path: reconstruct a finding's CEM minimal set(s)
    from persisted CEM state and derive its causal signature.

    Mirrors case-mcp's `minimal_condition_sets` tool exactly (same stored-verdict
    E1 predicate; the single-necessary-condition degenerate branch; the frozen
    `cem_engine.find_alternate_condition_sets` for the multi-condition case),
    then hands the result to `causal_signature`. Returns None -- never an
    invented signature -- when the finding does not exist, has no CEM state, or
    recorded no `necessary` verdict.
    """
    finding = case_store.get_finding(finding_id, db_path=db_path)
    if finding is None:
        return None

    state = case_store.cem_load_state(finding_id, db_path=db_path)
    if "error" in state:
        return None

    # Deferred import: cem_engine is only pulled into sys.modules when a caller
    # actually reconstructs a multi-condition minimal set, matching case_store's
    # own documented reason for deferring its cem_engine import (keeps the "CEM
    # not yet installed" cost baseline that test honest).
    import cem_engine

    vmap = _stored_verdict_map(state)
    present = sorted(n for n, v in vmap.items() if v == cem_engine.VERDICT_NECESSARY)
    if not present:
        # No condition classified `necessary` -> CEM has no minimal set here.
        return None

    if len(present) == 1:
        minimal_sets = [present]
        interacting: list[str] = []
    else:
        def is_interesting(subset) -> bool:
            # every condition NOT in `subset` must be individually droppable --
            # identical to the tool's E1 predicate.
            return bool(subset) and all(
                vmap.get(n) == cem_engine.VERDICT_APPARENTLY_NOT_NECESSARY
                for n in present if n not in subset
            )

        result = cem_engine.find_alternate_condition_sets(present, is_interesting, max_trials=64)
        minimal_sets = [sorted(s) for s in result.minimal_sets]
        interacting = sorted(result.interacting)

    categories = {c["name"]: c["category"] for c in state["conditions"]}
    return causal_signature(
        finding["vuln_class"], minimal_sets, interacting=interacting,
        condition_categories=categories,
    )
