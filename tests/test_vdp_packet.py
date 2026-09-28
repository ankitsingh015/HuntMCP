import vdp_packet


def test_short_summary_under_limit_is_unchanged():
    packet = vdp_packet.build_vdp_packet(
        finding_id="7", vuln_class="IDOR", title="IDOR on /api/orders/{id}",
        description="Any authenticated user can read another user's order by ID.",
        impact="Full read access to any user's order history.",
    )
    assert packet.truncated is False
    assert len(packet.short_summary) <= 1000
    assert "IDOR on /api/orders/{id}" in packet.short_summary
    assert "another user's order" in packet.short_summary


def test_long_description_is_truncated_at_word_boundary_within_limit():
    long_desc = "word " * 500  # way over any reasonable char_limit
    packet = vdp_packet.build_vdp_packet(
        finding_id="3", vuln_class="SSRF", title="SSRF via webhook URL",
        description=long_desc, impact="Cloud metadata reachable.", char_limit=200,
    )
    assert packet.truncated is True
    assert len(packet.short_summary) <= 200
    # Must not cut mid-word -- the text right before any trailing marker
    # should end on a word boundary, not a chopped fragment.
    assert not packet.short_summary.rstrip("[...truncated, full report attached separately]").endswith(" wor")
    assert "truncated" in packet.short_summary.lower()


def test_filename_stub_is_unambiguous_and_deterministic():
    """Regression: a submission mix-up occurred live when an operator
    manually pasted the wrong finding's text into a per-finding form field
    -- the fix is that every artifact's OWN filename/label carries its
    finding id + vuln class, so a mismatch is detectable at a glance."""
    packet = vdp_packet.build_vdp_packet(
        finding_id="12", vuln_class="Broken Access Control", title="x", description="y", impact="z",
    )
    assert packet.filename_stub == "finding-12-broken-access-control"
    # Same inputs -> same stub, every time (no randomness/timestamp).
    packet2 = vdp_packet.build_vdp_packet(
        finding_id="12", vuln_class="Broken Access Control", title="x", description="y", impact="z",
    )
    assert packet2.filename_stub == packet.filename_stub


def test_short_summary_always_labeled_with_finding_id_and_vuln_class():
    """Every packet's own summary text -- not just the filename -- carries
    the finding id and vuln class, so a mix-up is detectable even if the
    filename gets renamed/lost in transit (e.g. pasted into a web form)."""
    packet = vdp_packet.build_vdp_packet(
        finding_id="9", vuln_class="XSS", title="Reflected XSS on /search",
        description="d", impact="i",
    )
    assert "[#9" in packet.short_summary or "#9" in packet.short_summary
    assert "XSS" in packet.short_summary


def test_char_limit_is_respected_even_with_short_content():
    packet = vdp_packet.build_vdp_packet(
        finding_id="1", vuln_class="Open Redirect", title="t", description="d", impact="i", char_limit=50,
    )
    assert len(packet.short_summary) <= 50


def test_label_survives_intact_even_with_a_tiny_char_limit_and_long_content():
    """Code-review finding, reproduced directly: with a small-but-nonzero
    char_limit and content that actually needs truncating, the original
    implementation handed the WHOLE labeled string to textwrap.shorten(),
    whose break_long_words behavior chopped the leading "[#1" token itself
    down to an unrecognizable fragment -- destroying the exact disambiguation
    mechanism this module exists to guarantee, for precisely the tight-limit
    inputs it was built for."""
    packet = vdp_packet.build_vdp_packet(
        finding_id="1", vuln_class="Open Redirect", title="Some title here",
        description="word " * 50, impact="some impact text", char_limit=50,
    )
    assert packet.truncated is True
    assert len(packet.short_summary) <= 50
    assert "[#1 Open Redirect]" in packet.short_summary


def test_redacts_a_secret_embedded_in_description_before_building_the_summary():
    """Code-review finding: this content is destined to leave the toolchain
    entirely (pasted into a public, self-run VDP web form) and previously
    was never redacted, unlike every other report-shaped output in this
    repo (e.g. postmortem.py)."""
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    packet = vdp_packet.build_vdp_packet(
        finding_id="4", vuln_class="SSRF", title="t",
        description=f"session token observed: {jwt}", impact="i",
    )
    assert jwt not in packet.short_summary


def test_build_packet_set_for_multiple_findings_never_collides():
    findings = [
        {"finding_id": "1", "vuln_class": "XSS", "title": "a", "description": "b", "impact": "c"},
        {"finding_id": "2", "vuln_class": "XSS", "title": "d", "description": "e", "impact": "f"},
    ]
    packets = vdp_packet.build_vdp_packet_set(findings)
    stubs = [p.filename_stub for p in packets]
    assert len(stubs) == len(set(stubs))
