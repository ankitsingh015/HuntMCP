"""Session keep-alive scheduler + session_health (no browser: refresh is faked)."""

import json

import pytest
import session_keepalive as K
import session_refresh as R

SENTINEL = "S3NTINEL_TOKEN_VALUE"


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture
def clock():
    return Clock()


def _ka(clock, refreshed, labels=("xyz",), interval_s=7200, rand=0.5):
    async def fake_refresh(label, slug=None):
        refreshed.append(label)
        return {"identity": label, "refreshed": True}

    return K.KeepAlive(list(labels), None, fake_refresh, interval_s=interval_s, now_fn=clock, rand_fn=lambda: rand)


def _state(label, **kw):
    st = R._load_refresh_state(label)
    st.update(kw)
    R._save_refresh_state(label, st)


def test_next_due_prefers_access_exp_minus_300(clock):
    _state("xyz", last_refresh=clock.t, access_exp=clock.t + 1000)
    ka = _ka(clock, [])
    assert ka.next_due("xyz") == clock.t + 700


def test_next_due_uses_jittered_interval_without_exp(clock):
    _state("xyz", last_refresh=clock.t)
    assert _ka(clock, [], rand=0.0).next_due("xyz") == pytest.approx(clock.t + 7200 * 0.9)
    assert _ka(clock, [], rand=1.0).next_due("xyz") == pytest.approx(clock.t + 7200 * 1.1)


def test_never_refreshed_is_due_now(clock):
    assert _ka(clock, []).next_due("xyz") <= clock.t


def test_interval_clamped_to_1800(clock):
    assert _ka(clock, [], interval_s=60).interval_s == 1800


def test_tick_refreshes_only_due_labels(clock):
    _state("aaa", last_refresh=clock.t, access_exp=clock.t + 5000)
    refreshed = []
    ka = _ka(clock, refreshed, labels=("aaa", "bbb"))
    assert ka.tick() == ["bbb"] and refreshed == ["bbb"]


def test_tick_skips_running_label(clock):
    refreshed = []
    ka = _ka(clock, refreshed)
    ka._running.add("xyz")
    assert ka.tick() == [] and refreshed == []


def test_tick_skips_label_needing_human(clock):
    _state("xyz", needs_human_login=True, last_attempt=clock.t - 60)
    refreshed = []
    assert _ka(clock, refreshed).tick() == []


def test_start_keepalive_validates_and_replaces(monkeypatch, tmp_path):
    roster = tmp_path / "roster.yaml"
    roster.write_text("identities:\n  xyz: {profile_dir: /tmp/p1}\n  abc: {profile_dir: /tmp/p2}\n")
    monkeypatch.setenv("HUNTMCP_TEST_IDENTITIES", str(roster))
    started = []
    monkeypatch.setattr(K.KeepAlive, "start", lambda self: started.append(self))
    monkeypatch.setattr(K.KeepAlive, "stop", lambda self: None)
    out = K.start_keepalive(["xyz", "../x"])
    assert "error" in out and not started
    out = K.start_keepalive(["xyz"], interval_s=10)
    assert out["status"] == "running" and started[-1].interval_s == 1800
    assert "error" in K.start_keepalive(["nobody"])
    K.start_keepalive(["abc"])
    assert len(started) == 2 and K.stop_keepalive()["status"] == "stopped"
    assert K.stop_keepalive()["status"] == "not_running"


def test_health_warns_under_48h_and_notifies_once(monkeypatch, clock):
    monkeypatch.setattr(K, "_now", clock)
    calls = []
    monkeypatch.setattr(R, "notify", lambda t, b: calls.append((t, b)))
    _state("xyz", last_refresh=clock.t - 100, last_layer="app", access_exp=clock.t + 900,
           sso_expiry=clock.t + 24 * 3600)
    out = K.session_health(["xyz"])
    row = out["identities"][0]
    assert row["warning"] and row["access_expires_in_s"] == 900 and row["layer"] == "app"
    assert row["estimated_next_human_login"]
    K.session_health(["xyz"])
    assert len(calls) == 1


def test_health_estimate_is_max_of_sso_and_rt(monkeypatch, clock):
    monkeypatch.setattr(K, "_now", clock)
    _state("xyz", sso_expiry=clock.t + 3 * 86400, rt_expiry=clock.t + 10 * 86400)
    row = K.session_health(["xyz"])["identities"][0]
    assert row["warning"] is None
    assert row["estimated_next_human_login"].startswith(
        __import__("time").strftime("%Y-%m-%d", __import__("time").gmtime(clock.t + 10 * 86400)))


def test_health_no_secret(monkeypatch, clock):
    monkeypatch.setattr(K, "_now", clock)
    _state("xyz", last_refresh=clock.t, secret_should_not_leak=SENTINEL)
    out = K.session_health(["xyz"])
    assert SENTINEL not in json.dumps(out)
    for row in out["identities"]:
        assert set(row) <= R.ALLOWED_SUMMARY_KEYS


def test_tick_resumes_after_human_recaptures(clock):
    import os

    import engagement_paths

    _state("xyz", needs_human_login=True, last_attempt=clock.t - 60)
    ipath = engagement_paths.resolve("secrets/identities.json")
    os.makedirs(os.path.dirname(ipath), exist_ok=True)
    with open(ipath, "w") as fh:
        json.dump({"xyz": {"captured_at": clock.t - 10}}, fh)
    refreshed = []
    assert _ka(clock, refreshed).tick() == ["xyz"]


def test_no_refresh_storm_inside_pre_expiry_window(clock):
    # a refresh at exp-300 that leaves the (still valid) token in place must not
    # make the next one due immediately again
    _state("xyz", last_refresh=clock.t, access_exp=clock.t + 200)
    assert _ka(clock, []).next_due("xyz") == clock.t + 205
