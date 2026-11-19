import os

import coverage_manifest


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
