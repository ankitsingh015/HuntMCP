import importlib.util
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_spec = importlib.util.spec_from_file_location(
    "chainer_mcp_server_new_templates", os.path.join(ROOT, "mcp-servers", "chainer-mcp", "server.py")
)
chainer = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(chainer)


def test_mass_assignment_template_registered():
    assert "massassignment_pollution_privesc" in chainer.CHAIN_TEMPLATES
    t = chainer.CHAIN_TEMPLATES["massassignment_pollution_privesc"]
    assert t["required_findings"] == ["MASS ASSIGNMENT", "PARAMETER POLLUTION"]
    assert len(t["chain_steps"]) >= 3


def test_cors_xss_template_registered():
    assert "cors_xss_credential_theft" in chainer.CHAIN_TEMPLATES
    t = chainer.CHAIN_TEMPLATES["cors_xss_credential_theft"]
    assert t["required_findings"] == ["CORS MISCONFIGURATION", "XSS"]
    assert len(t["chain_steps"]) >= 3


def test_analyze_chains_matches_mass_assignment_pollution():
    findings = (
        '[{"class": "Mass Assignment", "endpoint": "/api/users", "confidence": "HIGH"},'
        '{"class": "Parameter Pollution", "endpoint": "/api/users", "confidence": "HIGH"}]'
    )
    out = chainer.analyze_chains(findings)
    assert "massassignment_pollution_privesc" in out
    assert "Mass Assignment + Parameter Pollution" in out


def test_analyze_chains_matches_cors_xss():
    findings = (
        '[{"class": "CORS Misconfiguration", "endpoint": "/api/profile", "confidence": "HIGH"},'
        '{"class": "XSS", "endpoint": "/search", "confidence": "HIGH"}]'
    )
    out = chainer.analyze_chains(findings)
    assert "cors_xss_credential_theft" in out
    assert "CORS Misconfiguration + XSS" in out


def test_analyze_chains_does_not_match_with_only_one_half():
    # Mass Assignment alone (no Parameter Pollution) should not claim the
    # chain is available.
    findings = '[{"class": "Mass Assignment", "endpoint": "/api/users", "confidence": "HIGH"}]'
    out = chainer.analyze_chains(findings)
    assert "massassignment_pollution_privesc" not in out


def test_plan_chain_mass_assignment_full_output():
    findings = (
        '[{"class": "Mass Assignment", "endpoint": "/api/signup"},'
        '{"class": "Parameter Pollution", "endpoint": "/api/signup"}]'
    )
    out = chainer.plan_chain("massassignment_pollution_privesc", findings)
    assert "All required findings present" in out
    assert "role" in out.lower() or "isAdmin" in out or "privilege" in out.lower()


def test_plan_chain_cors_xss_reports_missing_when_only_one_present():
    findings = '[{"class": "XSS", "endpoint": "/search"}]'
    out = chainer.plan_chain("cors_xss_credential_theft", findings)
    assert "Missing required finding" in out
    assert "CORS MISCONFIGURATION" in out
