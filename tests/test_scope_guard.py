import socket

import pytest
from scope_guard import (
    Engagement,
    NoEngagementFile,
    detect_scope_conflicts,
    is_in_scope,
    is_safe_test_host,
    load_engagement,
    outbound_policy_error,
    pin_hosts_or_error,
    resolve_and_pin,
    resolved_ip_policy_error,
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
    ["example.com", "example.org", "localhost", "0.0.0.0", "127.0.0.1"],
)
def test_is_safe_test_host_true(host):
    assert is_safe_test_host(host) is True


@pytest.mark.parametrize("host", ["realtarget-corp.com", "evil.com", "attacker.com", "8.8.8.8",
                                  # 2026-11-22 scope-bypass fix: no longer exempt
                                  "github.com", "192.168.1.1", "10.0.0.5", "results.json"])
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
    be in THIS engagement's in_scope list even for example.com -- an agent
    following its own "check scope before touching any host" instruction
    would self-block on a totally safe host the moment ANY engagement existed
    for a different target. A safe test host must pass regardless of which
    engagement (if any) is currently active. Dev infra (github.com) is no
    longer in scope (2026-11-22 bypass fix): it is only exempt for the hook's
    plain curl/wget downloads -- see scope_guard.is_dev_infra_host()."""
    e = _engagement(target="unrelated-target.com", in_scope=["unrelated-target.com"])
    assert is_in_scope("example.com", e) is True
    assert is_in_scope("github.com", e) is False


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


def test_outbound_policy_error_rejects_cloud_metadata_ip():
    assert outbound_policy_error("http://169.254.169.254/latest/meta-data/") is not None


def test_outbound_policy_error_rejects_non_http_scheme():
    assert outbound_policy_error("file:///etc/passwd") is not None


def test_outbound_policy_error_allows_ordinary_http_url():
    assert outbound_policy_error("http://example.com/openapi.json") is None


# resolved_ip_policy_error() -- the real SSRF enforcement boundary added
# after a security review found outbound_policy_error() alone cannot catch
# DNS-rebinding or alternate numeric IP encodings (see its own docstring).


def _fake_getaddrinfo(answer: str):
    """Returns a function matching socket.getaddrinfo's signature, which
    reports `answer` as the ONLY resolved address for any host -- same
    technique a real DNS-rebinding attack uses (the hostname's own records
    point wherever the attacker wants), without this test depending on real
    DNS infrastructure."""
    def _fn(host, port, *a, **k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (answer, 0))]
    return _fn


def test_resolved_ip_policy_error_catches_dns_rebinding_to_metadata_ip(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("169.254.169.254"))
    assert resolved_ip_policy_error("sub.target.example") is not None


def test_resolved_ip_policy_error_permits_ordinary_resolution(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("93.184.216.34"))
    assert resolved_ip_policy_error("target.example") is None


def test_resolved_ip_policy_error_permits_loopback(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("127.0.0.1"))
    assert resolved_ip_policy_error("localhost") is None


def test_resolved_ip_policy_error_does_not_block_on_resolution_failure():
    # ".invalid" is RFC 2606 reserved -- guaranteed to never resolve, no
    # mocking needed, and a resolution FAILURE must never be treated as a
    # refusal (the caller's own real connection attempt surfaces it).
    assert resolved_ip_policy_error("this-does-not-exist.invalid") is None


def test_resolved_ip_policy_error_catches_real_decimal_ip_encoding():
    # No mocking -- this is real OS-resolver behavior (glibc getaddrinfo
    # accepts legacy decimal/octal numeric-host notation that Python's own
    # strict ipaddress.ip_address() rejects), verified live during this
    # task's own security review. Self-adapting rather than a blind
    # assertion: skips rather than fails if this specific machine's
    # resolver doesn't exhibit that behavior, since this is resolver/libc
    # behavior this test deliberately does not control.
    try:
        infos = socket.getaddrinfo("2852039166", None)
    except OSError:
        pytest.skip("this resolver doesn't resolve decimal-notation hosts at all")
    if infos[0][4][0] != "169.254.169.254":
        pytest.skip("this resolver's decimal-notation parsing doesn't match glibc's")
    assert resolved_ip_policy_error("2852039166") is not None


# resolve_and_pin() -- for a caller (schemathesis-mcp) whose real requests
# are made by an external process that never goes through
# resolved_ip_policy_error()'s own per-connection check.


def test_resolve_and_pin_returns_ip_for_ordinary_host(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("93.184.216.34"))
    ip, error = resolve_and_pin("target.example")
    assert ip == "93.184.216.34"
    assert error is None


def test_resolve_and_pin_refuses_metadata_ip(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("169.254.169.254"))
    ip, error = resolve_and_pin("sub.target.example")
    assert ip is None
    assert error is not None


def test_resolve_and_pin_refuses_on_resolution_failure():
    # Unlike resolved_ip_policy_error(), resolve_and_pin()'s whole caller
    # (schemathesis-mcp) never makes its own connection right after this
    # check -- an EXTERNAL process does, later. A transient resolution
    # failure here must therefore be a refusal, not silently-proceed-
    # unpinned, or the later unprotected resolution gets zero protection.
    ip, error = resolve_and_pin("this-does-not-exist.invalid")
    assert ip is None
    assert error is not None


def test_resolve_and_pin_pins_a_literal_ip_to_itself():
    # A caller-supplied literal IP (no DNS involved at all) resolves to
    # itself -- same contract, no special-casing needed by the caller.
    ip, error = resolve_and_pin("127.0.0.1")
    assert ip == "127.0.0.1"
    assert error is None


# pin_hosts_or_error() -- the shared convention every job_runtime-based
# scanner server (sqlmap/nuclei/dalfox/ffuf/schemathesis) should use.


def test_pin_hosts_or_error_dedupes_shared_host(monkeypatch):
    calls = []

    def fake_resolve_and_pin(host):
        calls.append(host)
        return "93.184.216.34", None

    monkeypatch.setattr("scope_guard.resolve_and_pin", fake_resolve_and_pin)
    extra_hosts, error = pin_hosts_or_error("https://t.example/a", "https://t.example/b")

    assert error is None
    assert extra_hosts == {"t.example": "93.184.216.34"}
    assert calls == ["t.example"]  # resolved once, not twice


def test_pin_hosts_or_error_pins_each_distinct_host(monkeypatch):
    def fake_resolve_and_pin(host):
        return {"a.example": "10.0.0.1", "b.example": "10.0.0.2"}[host], None

    monkeypatch.setattr("scope_guard.resolve_and_pin", fake_resolve_and_pin)
    extra_hosts, error = pin_hosts_or_error("https://a.example/", "https://b.example/")

    assert error is None
    assert extra_hosts == {"a.example": "10.0.0.1", "b.example": "10.0.0.2"}


def test_pin_hosts_or_error_refuses_on_any_blocked_host(monkeypatch):
    def fake_resolve_and_pin(host):
        if host == "bad.example":
            return None, "blocked"
        return "10.0.0.1", None

    monkeypatch.setattr("scope_guard.resolve_and_pin", fake_resolve_and_pin)
    extra_hosts, error = pin_hosts_or_error("https://ok.example/", "https://bad.example/")

    assert extra_hosts == {}
    assert error == "blocked"


def test_pin_hosts_or_error_returns_empty_dict_for_no_extractable_host():
    # "" and a path-only string genuinely produce no host via _host_of()
    # (unlike "not-a-url", which _host_of() DOES treat as a bare hostname
    # -- see the dedicated test below for exactly why that distinction
    # matters).
    extra_hosts, error = pin_hosts_or_error("", "/just/a/path")
    assert extra_hosts == {}
    assert error is None


def test_pin_hosts_or_error_handles_a_bare_hostname_with_no_scheme(monkeypatch):
    # Regression: urlsplit("target.com").hostname is None (no "//" means
    # the whole string parses as a path, not a netloc) -- a bare
    # urlsplit-based extraction would have made this function a silent
    # no-op for nuclei-mcp's own real call shape (scan_target("target.com"),
    # confirmed against tests/test_nuclei_mcp.py). _host_of() handles it.
    def fake_resolve_and_pin(host):
        assert host == "target.com"
        return "93.184.216.34", None

    monkeypatch.setattr("scope_guard.resolve_and_pin", fake_resolve_and_pin)
    extra_hosts, error = pin_hosts_or_error("target.com")

    assert error is None
    assert extra_hosts == {"target.com": "93.184.216.34"}


def test_pin_hosts_or_error_skips_pinning_entirely_under_bench_network(monkeypatch):
    # Regression: "bench-target" (P2-BENCH's own real-tool fixture-proof
    # tests) is resolvable ONLY from inside a container joined to the
    # throwaway --internal podman network those tests set up -- never
    # from this host-side process. Without this escape hatch (the same
    # one sandbox_runner.build_argv() itself already documents for this
    # exact env var), resolve_and_pin() would always fail to resolve it
    # here and refuse every real-tool benchmark run.
    def _unreachable_resolve_and_pin(host):
        raise AssertionError("must not even attempt resolution under HUNTMCP_BENCH_NETWORK")

    monkeypatch.setattr("scope_guard.resolve_and_pin", _unreachable_resolve_and_pin)
    monkeypatch.setenv("HUNTMCP_BENCH_NETWORK", "huntmcp-bench-net-deadbeef")

    extra_hosts, error = pin_hosts_or_error("http://bench-target:8000/")

    assert extra_hosts == {}
    assert error is None


# ---------------------------------------------------------------------------
# Scope-bypass fix (2026-11-22): is_safe_test_host() used to treat real,
# registrable TLDs that look like file extensions (.sh/.py/.md/.zip), every
# RFC1918/link-local/metadata IP, and DEV_INFRA_HOSTS as "needs no
# authorization", so is_in_scope() short-circuited to True for them under ANY
# engagement. Contactable-without-engagement is now only the RFC 2606 example
# domains, localhost/0.0.0.0 and loopback IPs.
# ---------------------------------------------------------------------------
from scope_guard import (
    NON_TLD_FILE_EXTENSIONS,
    is_dev_infra_host,
    looks_like_filename,
)

# Real IANA TLDs (checked against data.iana.org/TLD/tlds-alpha-by-domain.txt
# on 2026-11-22) that were wrongly listed as "file extensions". Pinned so a
# future edit can't quietly put one back.
_REAL_TLDS_THAT_LOOK_LIKE_EXTENSIONS = {"sh", "py", "md", "zip"}


def _target_only():
    return Engagement(target="target.com", in_scope=["*.target.com"], out_of_scope=[])


def _as_url(host):
    return f"http://[{host}]/" if ":" in host else f"http://{host}/"


@pytest.mark.parametrize(
    "host",
    ["evil.sh", "attacker.zip", "x.py", "evil.md",
     "github.com", "raw.githubusercontent.com", "pypi.org",
     "10.0.0.5", "192.168.1.1", "172.16.0.1",
     "169.254.169.254", "169.254.1.1", "fe80::1", "fd00:ec2::254"],
)
def test_bypass_hosts_are_not_in_scope_for_unrelated_engagement(host):
    e = _target_only()
    assert is_in_scope(host, e) is False
    assert is_in_scope(_as_url(host), e) is False


@pytest.mark.parametrize(
    "host", ["evil.sh", "x.py", "github.com", "10.0.0.5", "192.168.1.1", "169.254.169.254", "fe80::1"],
)
def test_bypass_hosts_are_not_safe_test_hosts(host):
    assert is_safe_test_host(host) is False


@pytest.mark.parametrize(
    "host", ["example.com", "example.org", "example.net", "localhost", "0.0.0.0",
             "127.0.0.1", "127.5.6.7", "::1", "EXAMPLE.COM."],
)
def test_local_dev_hosts_stay_safe(host):
    assert is_safe_test_host(host) is True
    # Bare IPv6 ("::1") isn't a form _host_of() parses (it splits on ':' and
    # fails closed) -- that's pre-existing and unchanged; use the URL form.
    assert is_in_scope(_as_url(host.strip(".")) if ":" in host else host, _target_only()) is True


def test_private_ip_passes_only_when_explicitly_in_scope():
    e = Engagement(target="lab", in_scope=["10.88.0.*", "192.168.56.10"], out_of_scope=[])
    assert is_in_scope("10.88.0.7", e) is True
    assert is_in_scope("http://192.168.56.10:8080/", e) is True
    assert is_in_scope("10.0.0.5", e) is False


def test_out_of_scope_private_ip_is_respected():
    e = Engagement(target="lab", in_scope=["10.88.0.*"], out_of_scope=["10.88.0.1"])
    assert is_in_scope("10.88.0.1", e) is False


def test_no_real_tld_is_treated_as_file_extension():
    assert not (NON_TLD_FILE_EXTENSIONS & _REAL_TLDS_THAT_LOOK_LIKE_EXTENSIONS)


@pytest.mark.parametrize("token", ["results.json", "payload.txt", "wordlist.TXT", "a.tar", "notes.log"])
def test_looks_like_filename_true(token):
    assert looks_like_filename(token) is True


@pytest.mark.parametrize("token", ["evil.sh", "x.py", "evil.md", "a.zip", "target.com", "10.0.0.5", "json"])
def test_looks_like_filename_false(token):
    assert looks_like_filename(token) is False


def test_dev_infra_is_separate_from_safe():
    assert is_dev_infra_host("github.com") is True
    assert is_dev_infra_host("RAW.githubusercontent.com.") is True
    assert is_dev_infra_host("evil-github.com") is False
    assert is_safe_test_host("github.com") is False
