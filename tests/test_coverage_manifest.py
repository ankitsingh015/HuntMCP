import os

import case_store
import coverage_manifest
import surface_map


def _node(kind, label="x", signature="sig", precedent=None, findings=None, na=None, nid=1, meta=None):
    return {
        "id": nid, "kind": kind, "label": label, "signature": signature,
        "parent_id": None, "state": "discovered", "precedent": precedent,
        "findings": findings or [], "meta": meta or {}, "na": na or {},
    }


# ---- required_classes: floor by kind, UNION precedent ---------------------

def test_required_classes_floor_by_kind():
    got = coverage_manifest.required_classes(_node("endpoint"))
    assert got == coverage_manifest.BATTERY_BY_KIND["endpoint"]
    assert "xss" in got and "sqli" in got and "access-control" in got


def test_required_classes_unknown_kind_is_empty():
    assert coverage_manifest.required_classes(_node("whatever-kind")) == set()


def test_required_classes_unions_precedent():
    # precedent text that surfaces a class NOT in the endpoint floor widens it.
    node = _node("endpoint", precedent="Prior report: a prototype pollution gadget chain...")
    got = coverage_manifest.required_classes(node)
    assert coverage_manifest.BATTERY_BY_KIND["endpoint"] <= got   # floor preserved
    assert "prototype-pollution" in got                            # precedent widened


# ---- endpoint normalization ----------------------------------------------

def test_normalize_endpoint_equates_trivially_different_forms():
    n = coverage_manifest._normalize_endpoint
    assert n("https://API.Example.com:443/users/5/") == n("https://api.example.com/users/5")
    assert n("http://a.com:80/x?q=1#f") == n("http://a.com/x")


# ---- conservative class matcher ------------------------------------------

def test_class_matches_aliases():
    m = coverage_manifest._class_matches
    assert m("xss-js-confirmation", "xss") is True
    assert m("sql-injection", "sqli") is True
    assert m("idor-bola", "idor") is True
    assert m("Cross-Site Scripting", "xss") is True


def test_class_matches_does_not_over_match():
    m = coverage_manifest._class_matches
    assert m("csrf", "sqli") is False
    assert m("open-redirect", "ssrf") is False   # different class, no loose substring match


# ---- compute_manifest: the join + exhaustion verdict ----------------------

def _mp(tmp_path):
    return str(tmp_path / "surface-map.json")


def _db(tmp_path):
    return str(tmp_path / "case.db")


def test_exhausted_true_when_empty_map(tmp_path):
    out = coverage_manifest.compute_manifest(db_path=_db(tmp_path), map_path=_mp(tmp_path))
    assert out["exhausted"] is True
    assert out["open_cells"] == []
    assert out["counts"] == {"covered": 0, "na": 0, "open": 0}


def test_cell_covered_via_attached_finding(tmp_path):
    mp, db = _mp(tmp_path), _db(tmp_path)
    nid = surface_map.add_node("endpoint", "/api/users/5", "idor:user", path=mp)
    f = case_store.create_finding("idor-bola", "/api/users/5", db_path=db)
    case_store.add_evidence("response", "leaked other user", finding_id=f["id"], db_path=db)
    surface_map.attach_finding(nid, f["id"], path=mp)
    out = coverage_manifest.compute_manifest(db_path=db, map_path=mp)
    node = next(n for n in out["nodes"] if n["node_id"] == nid)
    idor = next(c for c in node["cells"] if c["vuln_class"] == "idor")
    assert idor["state"] == "covered"


def test_cell_covered_via_endpoint_match(tmp_path):
    mp, db = _mp(tmp_path), _db(tmp_path)
    # node label IS the endpoint; no attach link -- join falls back to endpoint.
    nid = surface_map.add_node("endpoint", "https://API.example.com/search", "xss:q", path=mp)
    f = case_store.create_finding("xss-js-confirmation", "https://api.example.com/search/", db_path=db)
    case_store.add_evidence("response", "alert fired", finding_id=f["id"], db_path=db)
    out = coverage_manifest.compute_manifest(db_path=db, map_path=mp)
    node = next(n for n in out["nodes"] if n["node_id"] == nid)
    xss = next(c for c in node["cells"] if c["vuln_class"] == "xss")
    assert xss["state"] == "covered"


def test_cell_open_when_finding_has_no_evidence(tmp_path):
    mp, db = _mp(tmp_path), _db(tmp_path)
    nid = surface_map.add_node("endpoint", "/api/x", "sqli:id", path=mp)
    f = case_store.create_finding("sql-injection", "/api/x", db_path=db)  # no evidence
    surface_map.attach_finding(nid, f["id"], path=mp)
    out = coverage_manifest.compute_manifest(db_path=db, map_path=mp)
    node = next(n for n in out["nodes"] if n["node_id"] == nid)
    sqli = next(c for c in node["cells"] if c["vuln_class"] == "sqli")
    assert sqli["state"] == "open"


def test_na_cell_closes_without_evidence(tmp_path):
    mp, db = _mp(tmp_path), _db(tmp_path)
    nid = surface_map.add_node("endpoint", "/static/logo.png", "asset:image", path=mp)
    surface_map.mark_na(nid, "sqli", "static image asset, no query path", path=mp)
    out = coverage_manifest.compute_manifest(db_path=db, map_path=mp)
    node = next(n for n in out["nodes"] if n["node_id"] == nid)
    sqli = next(c for c in node["cells"] if c["vuln_class"] == "sqli")
    assert sqli["state"] == "na"
    assert "static image" in sqli["reason"]


def test_exhausted_false_lists_open_cells(tmp_path):
    mp, db = _mp(tmp_path), _db(tmp_path)
    nid = surface_map.add_node("endpoint", "/api/y", "ep:y", path=mp)
    out = coverage_manifest.compute_manifest(db_path=db, map_path=mp)
    assert out["exhausted"] is False
    assert out["counts"]["open"] == len(coverage_manifest.BATTERY_BY_KIND["endpoint"])
    assert all(c["node_id"] == nid for c in out["open_cells"])
    assert {"node_id": nid, "vuln_class": "sqli"} in out["open_cells"]
