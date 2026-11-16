"""P4-SIG -- causal signatures from CEM minimal-sets (feeds P5 transfer/variants).

These tests pin the THREE acceptance properties the tracker row requires of a
causal signature, plus the read-only/no-fabrication guarantees every P4 analysis
module in this repo must satisfy:

  (a) canonicality   -- the SAME minimal necessary-condition structure always
                        produces the SAME signature, regardless of incidental
                        element order, order of multiple minimal sets, or
                        case/whitespace "labeling" of the names;
  (b) discrimination -- a genuinely different structure (different condition
                        present/absent, different vuln-class, different category)
                        produces a DIFFERENT signature;
  (c) no fabrication -- a finding with no CEM minimal necessary-condition set
                        yields NO signature (None), never an invented one.

Isolation: every DB test seeds an isolated temp case.db purely through
case_store's own CEM write APIs (create_finding / cem_define / cem_record_verdict).
The protected cem_target fixture and tests/test_cem_benchmark.py are NOT touched;
causal_signature is a read-only CONSUMER of CEM's minimal-set output and reuses
the FROZEN cem_engine verbatim (never reimplements ddmin).
"""

import json

import case_store
import causal_signature

# --------------------------------------------------------------------------- #
# Pure canonicalizer: causal_signature(vuln_class, minimal_sets, ...)          #
# --------------------------------------------------------------------------- #

def test_signature_is_deterministic_across_calls():
    a = causal_signature.causal_signature("SQLi", [["role_admin", "flag_on"]])
    b = causal_signature.causal_signature("SQLi", [["role_admin", "flag_on"]])
    assert a == b
    assert a["signature"] == b["signature"]
    assert a["signature"].startswith("sha256:")


def test_signature_shape():
    sig = causal_signature.causal_signature("SQLi", [["b", "a"]], interacting=["a"])
    assert set(sig) == {"version", "vuln_class", "minimal_sets", "interacting", "signature"}
    assert sig["vuln_class"] == "SQLI"
    # minimal_sets are canonical: each a sorted list, the collection sorted.
    assert sig["minimal_sets"] == [["a", "b"]]
    assert sig["interacting"] == ["a"]
    assert sig["signature"].startswith("sha256:")


def test_canonical_regardless_of_element_order_and_labeling():
    # property (a): same underlying conditions, but different element order and
    # different case / surrounding whitespace -> identical signature.
    base = causal_signature.causal_signature("SQLi", [["role_admin", "flag_on"]])
    reordered = causal_signature.causal_signature("SQLi", [["flag_on", "role_admin"]])
    relabelled = causal_signature.causal_signature("  sqli ", [["  FLAG_ON ", "Role_Admin"]])
    assert base["signature"] == reordered["signature"] == relabelled["signature"]


def test_canonical_regardless_of_minimal_set_order():
    # property (a): the order the alternate minimal sets are listed in is
    # incidental -- two results listing the same sets in different order match.
    x = causal_signature.causal_signature("IDOR", [["a", "b"], ["c"]])
    y = causal_signature.causal_signature("IDOR", [["c"], ["b", "a"]])
    assert x["signature"] == y["signature"]
    assert x["minimal_sets"] == [["a", "b"], ["c"]]


def test_duplicate_sets_and_names_are_collapsed():
    # normalization that collapses two labels to the same token must not create
    # a spurious 2-element set, and a repeated minimal set is deduplicated.
    sig = causal_signature.causal_signature("XSS", [["Role_Admin", "role_admin"], ["role_admin"]])
    assert sig["minimal_sets"] == [["role_admin"]]


def test_different_minimal_set_yields_different_signature():
    # property (b): dropping / changing a necessary condition changes the signature.
    full = causal_signature.causal_signature("SQLi", [["role_admin", "flag_on"]])
    fewer = causal_signature.causal_signature("SQLi", [["role_admin"]])
    other = causal_signature.causal_signature("SQLi", [["role_user", "flag_on"]])
    assert full["signature"] != fewer["signature"]
    assert full["signature"] != other["signature"]


def test_different_vuln_class_yields_different_signature():
    # property (b): same necessary structure under a different class is a
    # different causal signature.
    sqli = causal_signature.causal_signature("SQLi", [["role_admin"]])
    xss = causal_signature.causal_signature("XSS", [["role_admin"]])
    assert sqli["signature"] != xss["signature"]


def test_condition_category_is_part_of_structure():
    # property (b): category is invariant metadata -- the same name under a
    # different category is a different structure.
    identity = causal_signature.causal_signature(
        "IDOR", [["carried_id"]], condition_categories={"carried_id": "identity"})
    header = causal_signature.causal_signature(
        "IDOR", [["carried_id"]], condition_categories={"carried_id": "header"})
    assert identity["signature"] != header["signature"]


def test_condition_category_lookup_is_label_normalized():
    # property (a): categories supplied with different case/whitespace still
    # match the same condition and produce the same signature.
    a = causal_signature.causal_signature(
        "IDOR", [["carried_id"]], condition_categories={"carried_id": "identity"})
    b = causal_signature.causal_signature(
        "IDOR", [["Carried_Id"]], condition_categories={"CARRIED_ID": "  Identity "})
    assert a["signature"] == b["signature"]


def test_interacting_conditions_are_canonical_and_discriminating():
    none = causal_signature.causal_signature("SQLi", [["a", "b"]])
    inter = causal_signature.causal_signature("SQLi", [["a", "b"]], interacting=["a", "b"])
    inter_reordered = causal_signature.causal_signature("SQLi", [["a", "b"]], interacting=["B", "A"])
    assert none["signature"] != inter["signature"]            # discrimination
    assert inter["signature"] == inter_reordered["signature"]  # canonicality


def test_no_minimal_set_yields_no_signature():
    # property (c): no fabrication. Empty / None / all-empty-after-normalization
    # means "CEM found no minimal necessary-condition set" -> None, not a sig.
    assert causal_signature.causal_signature("XSS", None) is None
    assert causal_signature.causal_signature("XSS", []) is None
    assert causal_signature.causal_signature("XSS", [[]]) is None
    assert causal_signature.causal_signature("XSS", [["", "   "]]) is None


# --------------------------------------------------------------------------- #
# DB consumer: signature_for_finding(finding_id, db_path) over real CEM state  #
# --------------------------------------------------------------------------- #

def _db(tmp_path):
    return str(tmp_path / "case.db")


def _cond(name, category):
    return {"name": name, "category": category, "perturbation": {"op": "drop"}}


def _seed_cem_finding(db, vuln_class, endpoint, cond_verdicts):
    """Create a finding + CEM state and record one verdict per condition.

    cond_verdicts: list of (name, category, verdict) tuples. verdict is a valid
    case_store.CEM_VERDICTS string ('necessary' / 'apparently_not_necessary' / ...).
    Returns the finding id.
    """
    fid = case_store.create_finding(vuln_class, endpoint, db_path=db)["id"]
    conds = [_cond(n, c) for (n, c, _v) in cond_verdicts]
    res = case_store.cem_define(
        fid,
        base_request={"method": "GET", "url": "http://localhost/x"},
        success_signature={"status": 200},
        conditions=conds,
        k=5,
        db_path=db,
    )
    cond_ids = res["condition_ids"]
    for (name, _cat, verdict), cid in zip(cond_verdicts, cond_ids):
        case_store.cem_record_verdict(
            fid, verdict, k=5, controls={}, condition_id=cid, db_path=db)
    return fid


def test_signature_for_finding_reflects_only_necessary_conditions(tmp_path):
    db = _db(tmp_path)
    fid = _seed_cem_finding(db, "SQLi", "/api/order", [
        ("role_admin", "identity", "necessary"),
        ("flag_on", "state", "necessary"),
        ("noise_header", "header", "apparently_not_necessary"),
    ])
    sig = causal_signature.signature_for_finding(fid, db_path=db)
    assert sig is not None
    tokens = {t for s in sig["minimal_sets"] for t in s}
    assert tokens == {"identity:role_admin", "state:flag_on"}
    assert "header:noise_header" not in tokens


def test_single_necessary_condition_degenerate_branch(tmp_path):
    db = _db(tmp_path)
    fid = _seed_cem_finding(db, "IDOR", "/api/user", [
        ("carried_id", "identity", "necessary"),
        ("other", "param", "apparently_not_necessary"),
    ])
    sig = causal_signature.signature_for_finding(fid, db_path=db)
    assert sig is not None
    assert sig["minimal_sets"] == [["identity:carried_id"]]


def test_finding_with_no_necessary_condition_has_no_signature(tmp_path):
    # property (c): CEM ran but found nothing necessary -> no minimal set -> None.
    db = _db(tmp_path)
    fid = _seed_cem_finding(db, "XSS", "/search", [
        ("a", "param", "apparently_not_necessary"),
        ("b", "param", "apparently_not_necessary"),
    ])
    assert causal_signature.signature_for_finding(fid, db_path=db) is None


def test_finding_with_no_cem_state_has_no_signature(tmp_path):
    # property (c): a finding with no CEM run at all yields no signature.
    db = _db(tmp_path)
    fid = case_store.create_finding("SQLi", "/api/x", db_path=db)["id"]
    assert causal_signature.signature_for_finding(fid, db_path=db) is None


def test_nonexistent_finding_has_no_signature(tmp_path):
    db = _db(tmp_path)
    case_store.create_finding("SQLi", "/api/x", db_path=db)  # make the db exist
    assert causal_signature.signature_for_finding(9999, db_path=db) is None


def test_same_causal_structure_across_findings_yields_same_signature(tmp_path):
    # The transfer property P5 relies on: two DISTINCT findings (different ids /
    # endpoints) with the same vuln-class + same necessary conditions + same
    # categories must hash to the SAME signature so "the same root cause
    # elsewhere" is recognizable.
    db = _db(tmp_path)
    f1 = _seed_cem_finding(db, "IDOR", "/api/a", [
        ("carried_id", "identity", "necessary"),
        ("junk", "header", "apparently_not_necessary"),
    ])
    f2 = _seed_cem_finding(db, "idor", "/api/b/different/endpoint", [
        ("carried_id", "identity", "necessary"),
        ("unrelated", "param", "apparently_not_necessary"),
    ])
    s1 = causal_signature.signature_for_finding(f1, db_path=db)
    s2 = causal_signature.signature_for_finding(f2, db_path=db)
    assert s1 is not None and s2 is not None
    assert s1["signature"] == s2["signature"]


def test_different_structure_across_findings_yields_different_signature(tmp_path):
    db = _db(tmp_path)
    f1 = _seed_cem_finding(db, "IDOR", "/api/a", [
        ("carried_id", "identity", "necessary"),
    ])
    f2 = _seed_cem_finding(db, "IDOR", "/api/b", [
        ("carried_id", "identity", "necessary"),
        ("role_admin", "identity", "necessary"),
    ])
    s1 = causal_signature.signature_for_finding(f1, db_path=db)
    s2 = causal_signature.signature_for_finding(f2, db_path=db)
    assert s1["signature"] != s2["signature"]


def test_signature_for_finding_never_mutates_the_case_store(tmp_path):
    db = _db(tmp_path)
    fid = _seed_cem_finding(db, "SQLi", "/api/x", [
        ("role_admin", "identity", "necessary"),
    ])
    before = case_store.case_export(db_path=db)
    causal_signature.signature_for_finding(fid, db_path=db)
    after = case_store.case_export(db_path=db)
    assert before == after


def test_module_has_no_write_or_tool_calls():
    # Structural guarantee (same bar as coverage_signal/postmortem): the module
    # calls no case_store WRITE function and imports no tool/scope/budget/job
    # surface. Docstrings are stripped so the prose above doesn't false-trigger.
    import ast
    import inspect

    src = inspect.getsource(causal_signature)
    tree = ast.parse(src)
    # strip docstrings
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(
                    getattr(body[0], "value", None), ast.Constant) and isinstance(body[0].value.value, str):
                body[0].value.value = ""
    stripped = ast.unparse(tree)

    forbidden = [
        "create_finding", "add_evidence", "cem_define", "cem_record_trial",
        "cem_record_verdict", "update_finding", "log_hypothesis", "update_hypothesis",
        "log_experiment", "tool_resolver", "job_runtime", "scope_guard",
        "budget_guard", "subprocess", "requests", "urllib", "socket",
    ]
    hits = [tok for tok in forbidden if tok in stripped]
    assert hits == [], f"module must stay read-only/offline, found: {hits}"


def test_signature_json_serializable(tmp_path):
    db = _db(tmp_path)
    fid = _seed_cem_finding(db, "SQLi", "/api/x", [
        ("role_admin", "identity", "necessary"),
    ])
    sig = causal_signature.signature_for_finding(fid, db_path=db)
    # must round-trip as JSON (P5 will store/transfer it)
    assert json.loads(json.dumps(sig)) == sig


def test_signature_for_finding_agrees_with_the_real_minimal_condition_sets_tool(tmp_path, monkeypatch):
    """Drift guard (P4-SIG review finding): signature_for_finding() copies
    case-mcp's minimal_condition_sets reconstruction (the stored-verdict E1
    predicate + degenerate branch) rather than sharing it. Feeding the REAL
    tool's output into causal_signature() must yield the IDENTICAL signature
    that signature_for_finding() derives from its own copy. If the canonical
    tool's predicate ever changes and this module's copy is not updated in
    lockstep, this fails loudly instead of silently desyncing signatures from
    CEM's actual minimal-set output."""
    import importlib.util
    import os

    db = _db(tmp_path)
    fid = _seed_cem_finding(db, "SQLi", "/api/order", [
        ("role_admin", "identity", "necessary"),
        ("flag_on", "state", "necessary"),
        ("noise_header", "header", "apparently_not_necessary"),
    ])
    # the MCP tool resolves the ACTIVE engagement db -- point it at this temp db
    monkeypatch.setenv("HUNTMCP_CASE_DB_PATH", db)
    server_path = os.path.join(os.path.dirname(case_store.__file__), "case-mcp", "server.py")
    spec = importlib.util.spec_from_file_location("case_mcp_drift_guard", server_path)
    srv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(srv)

    tool_out = json.loads(srv.minimal_condition_sets(fid))
    cats = {"role_admin": "identity", "flag_on": "state", "noise_header": "header"}
    sig_from_tool = causal_signature.causal_signature(
        "SQLi", tool_out["minimal_sets"], interacting=tool_out["interacting"],
        condition_categories=cats)
    sig_direct = causal_signature.signature_for_finding(fid, db_path=db)
    assert sig_direct is not None
    assert sig_from_tool["signature"] == sig_direct["signature"]
