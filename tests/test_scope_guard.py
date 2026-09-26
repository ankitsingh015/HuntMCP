import pytest
from scope_guard import (
    Engagement,
    NoEngagementFile,
    detect_scope_conflicts,
    is_in_scope,
    is_safe_test_host,
    load_engagement,
)


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


def test_exact_in_scope_literal_overrides_broader_out_of_scope_wildcard():
    """Regression test reported live, independently, in two engagement
    retrospectives: an out_of_scope wildcard meant to express "no sibling
    hosts of the same root domain" silently shadowed specific, explicitly
    authorized in_scope hosts, blocking legitimate work on a correctly
    scoped target."""
    e = Engagement(
        target="example.com",
        in_scope=["app.example.com", "api.example.com"],
        out_of_scope=["*.example.com"],
    )
    assert is_in_scope("app.example.com", e) is True
    assert is_in_scope("api.example.com", e) is True
    # A host NOT explicitly named in in_scope is still correctly excluded --
    # the fix only rescues an exact, specific in_scope literal, not every
    # subdomain the wildcard would otherwise have blocked.
    assert is_in_scope("other.example.com", e) is False


def test_exact_out_of_scope_literal_still_wins_over_exact_in_scope_literal():
    """A genuine, deliberate exact exclusion of a specific host must still
    win -- the fix only rescues the case where the ONLY reason a host was
    excluded is a broader wildcard, not a real, specific exclusion."""
    e = Engagement(
        target="example.com",
        in_scope=["internal.example.com"],
        out_of_scope=["internal.example.com"],
    )
    assert is_in_scope("internal.example.com", e) is False


def test_load_engagement_missing_file_raises(tmp_path):
    with pytest.raises(NoEngagementFile):
        load_engagement(str(tmp_path / "nope.yaml"))


def test_detect_scope_conflicts_flags_wildcard_shadowing_exact_in_scope():
    """Load-time diagnostic for the same file shape
    test_exact_in_scope_literal_overrides_broader_out_of_scope_wildcard
    already proves is_in_scope() resolves correctly at runtime -- this
    surfaces a warning so the operator isn't left guessing why an
    engagement.yaml that reads as self-contradictory actually worked."""
    e = Engagement(
        target="example.com",
        in_scope=["app.example.com", "api.example.com"],
        out_of_scope=["*.example.com"],
    )
    warnings = detect_scope_conflicts(e)
    assert len(warnings) == 2
    assert any("app.example.com" in w and "IS authorized" in w for w in warnings)
    assert any("api.example.com" in w and "IS authorized" in w for w in warnings)


def test_detect_scope_conflicts_flags_exact_literal_in_both_lists():
    e = Engagement(
        target="example.com",
        in_scope=["internal.example.com"],
        out_of_scope=["internal.example.com"],
    )
    warnings = detect_scope_conflicts(e)
    assert len(warnings) == 1
    assert "internal.example.com" in warnings[0]
    assert "NOT authorized" in warnings[0]


def test_detect_scope_conflicts_empty_for_a_clean_engagement_file():
    e = _engagement()  # in_scope=["*.example.com", "example.com"], out_of_scope=[]
    assert detect_scope_conflicts(e) == []


def test_detect_scope_conflicts_no_warning_when_out_of_scope_is_unrelated():
    e = Engagement(
        target="example.com",
        in_scope=["app.example.com"],
        out_of_scope=["staging.otherdomain.com"],
    )
    assert detect_scope_conflicts(e) == []


@pytest.mark.parametrize(
    "host",
    ["example.com", "example.org", "localhost", "0.0.0.0",
     "github.com", "raw.githubusercontent.com", "pypi.org",
     "192.168.1.1", "127.0.0.1", "10.0.0.5",
     "results.json", "payload.txt"],
)
def test_is_safe_test_host_true(host):
    assert is_safe_test_host(host) is True


@pytest.mark.parametrize("host", ["realtarget-corp.com", "evil.com", "attacker.com", "8.8.8.8"])
def test_is_safe_test_host_false(host):
    # evil.com/attacker.com are deliberately NOT exempt here -- see
    # scope_guard.py's comment on SAFE_TEST_HOSTS: someone could genuinely
    # own one, and this function answers "is this authorized," not
    # "is this incidentally present in a command's header value" (that
    # narrower concern is scope_gate_hook.py's own
    # _ATTACKER_PLACEHOLDER_HOSTS, kept deliberately separate).
    assert is_safe_test_host(host) is False


def test_is_in_scope_exempts_safe_host_under_an_unrelated_engagement():
    """Regression: scripts/check-scope.sh used to require the exact host to
    be in THIS engagement's in_scope list even for example.com/github.com --
    an agent following its own "check scope before touching any host"
    instruction would self-block on a totally safe host the moment ANY
    engagement existed for a different target. A safe/dev-infra host must
    pass regardless of which engagement (if any) is currently active."""
    e = _engagement(target="unrelated-target.com", in_scope=["unrelated-target.com"])
    assert is_in_scope("example.com", e) is True
    assert is_in_scope("github.com", e) is True


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
