import side_effect_probe_log


def test_record_probe_returns_id(tmp_path):
    p = str(tmp_path / "side-effect-probes.jsonl")
    probe_id = side_effect_probe_log.record_probe(
        "https://target.com/api/contact-form", "email", 422, True,
        note="malformed email rejected as expected", path=p,
    )
    assert len(probe_id) == 8


def test_list_probes_filters_uncertain_ones(tmp_path):
    """The exact scenario reported live: a probe the backend treated as
    acceptable (timed out instead of returning a validation error) may
    have created a real artifact -- this is the post-engagement check a
    human reviews to answer "did any side-effecting probe possibly
    succeed?" rather than that signal being lost in narrative."""
    p = str(tmp_path / "side-effect-probes.jsonl")
    side_effect_probe_log.record_probe(
        "https://target.com/api/contact-form", "email", 422, True,
        note="rejected cleanly", path=p,
    )
    side_effect_probe_log.record_probe(
        "https://target.com/api/contact-form", "phone", None, False,
        note="request timed out instead of returning a validation error", path=p,
    )
    uncertain = side_effect_probe_log.list_probes(status="uncertain", path=p)
    rejected = side_effect_probe_log.list_probes(status="rejected", path=p)
    all_probes = side_effect_probe_log.list_probes(status="all", path=p)

    assert len(uncertain) == 1
    assert "timed out" in uncertain[0]["note"]
    assert len(rejected) == 1
    assert len(all_probes) == 2


def test_uncertain_probes_carry_the_endpoint_and_field_used(tmp_path):
    p = str(tmp_path / "side-effect-probes.jsonl")
    side_effect_probe_log.record_probe(
        "https://target.com/api/signup", "confirm_token", 500, False,
        note="unexpected 500, response body unclear", path=p,
    )
    uncertain = side_effect_probe_log.list_probes(status="uncertain", path=p)
    assert uncertain[0]["endpoint"] == "https://target.com/api/signup"
    assert uncertain[0]["provably_invalid_field"] == "confirm_token"
    assert uncertain[0]["response_status"] == 500


def test_no_probes_recorded_returns_empty(tmp_path):
    p = str(tmp_path / "side-effect-probes.jsonl")
    assert side_effect_probe_log.list_probes(status="all", path=p) == []
