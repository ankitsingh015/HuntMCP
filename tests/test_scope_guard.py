import pytest
from scope_guard import Engagement, NoEngagementFile, is_in_scope, load_engagement


def _engagement(**kw):
    defaults = dict(target="example.com", in_scope=["*.example.com", "example.com"], out_of_scope=[])
    defaults.update(kw)
    return Engagement(**defaults)


def test_in_scope_exact_match():
    e = _engagement()
    assert is_in_scope("example.com", e) is True


def test_in_scope_wildcard_subdomain():
    e = _engagement()
    assert is_in_scope("api.example.com", e) is True


def test_not_in_scope_unrelated_host():
    e = _engagement()
    assert is_in_scope("evil.com", e) is False


def test_out_of_scope_wins_over_in_scope():
    e = _engagement(out_of_scope=["internal.example.com"])
    assert is_in_scope("internal.example.com", e) is False


def test_accepts_full_url_not_just_bare_host():
    e = _engagement()
    assert is_in_scope("https://api.example.com/path?x=1", e) is True


def test_load_engagement_missing_file_raises(tmp_path):
    with pytest.raises(NoEngagementFile):
        load_engagement(str(tmp_path / "nope.yaml"))


def test_load_engagement_roundtrip(tmp_path):
    p = tmp_path / "engagement.yaml"
    p.write_text(
        "target: example.com\n"
        "in_scope:\n  - example.com\n  - '*.example.com'\n"
        "out_of_scope:\n  - internal.example.com\n"
        "program_url: https://hackerone.com/example\n"
        "authorized_on: '2026-08-24'\n"
    )
    e = load_engagement(str(p))
    assert e.target == "example.com"
    assert is_in_scope("api.example.com", e) is True
    assert is_in_scope("internal.example.com", e) is False
