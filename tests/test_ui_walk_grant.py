"""#164: the human-owned, hook-protected Pass-2 grant file."""

import os

import engagement_paths
import pytest
import ui_walk_grant as G


def _write(text):
    path = G.grant_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(text)
    return path


def test_grant_path_is_under_active_engagement():
    slug = engagement_paths.get_active_target()
    assert G.grant_path().endswith(os.path.join(slug, "ui-walk-authorized.yaml"))


def test_grant_path_without_active_engagement_raises(monkeypatch, tmp_path):
    monkeypatch.setattr(engagement_paths, "ACTIVE_POINTER", str(tmp_path / "none"))
    with pytest.raises(RuntimeError):
        G.grant_path()


def test_absent_grant_is_none():
    assert G.load_grant() is None


def test_true_grant_loads_with_default_cap():
    _write("canary_submit: true\n")
    g = G.load_grant()
    assert g == G.Grant(canary_submit=True, hosts=[], real_submit_cap_per_walk=200)


def test_non_literal_true_is_refused():
    _write('canary_submit: "yes"\n')
    assert G.load_grant() is None


def test_malformed_yaml_is_none():
    _write("canary_submit: [unclosed\n")
    assert G.load_grant() is None


def test_hosts_restriction():
    _write("canary_submit: true\nhosts: [app.example.org]\nreal_submit_cap_per_walk: 5\n")
    g = G.load_grant()
    assert g.real_submit_cap_per_walk == 5
    assert G.grant_allows(g, "app.example.org")
    assert not G.grant_allows(g, "other.example.org")


def test_no_hosts_means_any_in_scope_host():
    _write("canary_submit: true\n")
    assert G.grant_allows(G.load_grant(), "anything.test")


def test_none_grant_allows_nothing():
    assert not G.grant_allows(None, "a.test")


def test_bad_cap_falls_back_to_default():
    _write("canary_submit: true\nreal_submit_cap_per_walk: -3\n")
    assert G.load_grant().real_submit_cap_per_walk == 200
