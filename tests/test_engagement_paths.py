import json
import os

import engagement_paths


def test_slugify_normalizes_target():
    assert engagement_paths.slugify("Example.com") == "example-com"
    assert engagement_paths.slugify("  api.Target.io  ") == "api-target-io"
    assert engagement_paths.slugify("***") == "unnamed-target"


def test_get_active_target_none_when_no_pointer(tmp_path):
    pointer = str(tmp_path / ".active-engagement")
    assert engagement_paths.get_active_target(pointer) is None


def test_set_active_target_creates_dir_and_pointer(tmp_path):
    pointer = str(tmp_path / ".active-engagement")
    root = str(tmp_path / "engagements")
    slug = engagement_paths.set_active_target("example.com", pointer, root)
    assert slug == "example-com"
    assert os.path.isfile(pointer)
    assert os.path.isdir(os.path.join(root, "example-com"))
    assert engagement_paths.get_active_target(pointer) == "example-com"


def test_switching_target_does_not_touch_other_targets_files(tmp_path):
    pointer = str(tmp_path / ".active-engagement")
    root = str(tmp_path / "engagements")

    engagement_paths.set_active_target("target-a.com", pointer, root)
    a_budget = engagement_paths.resolve("budget.json", pointer_path=pointer, engagements_root=root)
    os.makedirs(os.path.dirname(a_budget), exist_ok=True)
    with open(a_budget, "w") as f:
        json.dump({"calls": 42}, f)

    engagement_paths.set_active_target("target-b.com", pointer, root)
    b_budget = engagement_paths.resolve("budget.json", pointer_path=pointer, engagements_root=root)
    assert b_budget != a_budget
    assert not os.path.isfile(b_budget)

    # resuming target-a later is just switching the pointer back --
    # its budget.json is untouched by anything that happened on target-b
    engagement_paths.set_active_target("target-a.com", pointer, root)
    resumed_budget = engagement_paths.resolve("budget.json", pointer_path=pointer, engagements_root=root)
    assert resumed_budget == a_budget
    with open(resumed_budget) as f:
        assert json.load(f)["calls"] == 42


def test_resolve_falls_back_to_legacy_when_no_active_target(tmp_path):
    pointer = str(tmp_path / ".active-engagement")
    assert engagement_paths.resolve("budget.json", pointer_path=pointer) == "budget.json"
    assert engagement_paths.resolve(
        "budget.json", pointer_path=pointer, legacy_default="/some/legacy/path.json"
    ) == "/some/legacy/path.json"


def test_resolve_env_override_wins_over_active_target(tmp_path, monkeypatch):
    pointer = str(tmp_path / ".active-engagement")
    root = str(tmp_path / "engagements")
    engagement_paths.set_active_target("example.com", pointer, root)
    monkeypatch.setenv("HUNTMCP_TEST_OVERRIDE", "/explicit/override.json")
    resolved = engagement_paths.resolve(
        "budget.json", override_env="HUNTMCP_TEST_OVERRIDE",
        pointer_path=pointer, engagements_root=root,
    )
    assert resolved == "/explicit/override.json"


def test_list_engagements_empty_when_no_root(tmp_path):
    root = str(tmp_path / "nope")
    assert engagement_paths.list_engagements(root) == []


def test_check_conflict_none_when_nothing_active(tmp_path):
    pointer = str(tmp_path / ".active-engagement")
    assert engagement_paths.check_conflict("example.com", pointer_path=pointer) is None


def test_check_conflict_none_when_same_target(tmp_path):
    pointer = str(tmp_path / ".active-engagement")
    root = str(tmp_path / "engagements")
    engagement_paths.set_active_target("example.com", pointer, root)
    assert engagement_paths.check_conflict(
        "example.com", pointer_path=pointer, engagements_root=root
    ) is None


def test_check_conflict_warns_on_different_incomplete_target(tmp_path):
    pointer = str(tmp_path / ".active-engagement")
    root = str(tmp_path / "engagements")
    engagement_paths.set_active_target("target-a.com", pointer, root)
    warning = engagement_paths.check_conflict(
        "target-b.com", pointer_path=pointer, engagements_root=root
    )
    assert warning is not None
    assert "target-a-com" in warning
    assert "target-b-com" in warning


def test_check_conflict_none_when_active_target_marked_complete(tmp_path):
    pointer = str(tmp_path / ".active-engagement")
    root = str(tmp_path / "engagements")
    engagement_paths.set_active_target("target-a.com", pointer, root)
    engagement_paths.mark_complete(pointer, root)
    warning = engagement_paths.check_conflict(
        "target-b.com", pointer_path=pointer, engagements_root=root
    )
    assert warning is None


def test_mark_complete_returns_none_when_nothing_active(tmp_path):
    pointer = str(tmp_path / ".active-engagement")
    root = str(tmp_path / "engagements")
    assert engagement_paths.mark_complete(pointer, root) is None


def test_is_complete_false_until_marked(tmp_path):
    pointer = str(tmp_path / ".active-engagement")
    root = str(tmp_path / "engagements")
    engagement_paths.set_active_target("example.com", pointer, root)
    assert engagement_paths.is_complete("example-com", root) is False
    engagement_paths.mark_complete(pointer, root)
    assert engagement_paths.is_complete("example-com", root) is True


def test_list_engagements_includes_complete_flag(tmp_path):
    root = str(tmp_path / "engagements")
    pointer = str(tmp_path / ".active-engagement")
    engagement_paths.set_active_target("example.com", pointer, root)
    result = engagement_paths.list_engagements(root)
    assert result[0]["complete"] is False
    engagement_paths.mark_complete(pointer, root)
    result = engagement_paths.list_engagements(root)
    assert result[0]["complete"] is True


def test_list_engagements_reports_target_and_calls(tmp_path):
    root = str(tmp_path / "engagements")
    slug_dir = os.path.join(root, "example-com")
    os.makedirs(slug_dir)
    with open(os.path.join(slug_dir, "engagement.yaml"), "w") as f:
        f.write("target: example.com\nin_scope:\n  - example.com\n")
    with open(os.path.join(slug_dir, "budget.json"), "w") as f:
        json.dump({"calls": 7}, f)

    result = engagement_paths.list_engagements(root)
    assert len(result) == 1
    assert result[0]["slug"] == "example-com"
    assert result[0]["target"] == "example.com"
    assert result[0]["tier2_calls"] == 7
