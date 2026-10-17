from __future__ import annotations

import pytest

from workspace.cgroup_v2 import CgroupV2Error, CgroupV2Scope


def _scope(tmp_path):
    path = tmp_path / "scope"
    path.mkdir()
    (path / "memory.events.local").write_text(
        "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n",
        encoding="ascii",
    )
    (path / "pids.events").write_text("max 0\n", encoding="ascii")
    return CgroupV2Scope(
        path,
        {"oom": 0, "oom_kill": 0},
        {"max": 0},
    )


def test_oom_event_delta_is_attributed_to_cgroup_memory_limit(tmp_path):
    scope = _scope(tmp_path)
    (scope.path / "memory.events.local").write_text(
        "low 0\nhigh 0\nmax 1\noom 1\noom_kill 1\noom_group_kill 0\n",
        encoding="ascii",
    )

    assert scope.resource_limit_reason() == "cgroup_memory_limit"


def test_pids_event_delta_is_attributed_without_inventing_memory_oom(tmp_path):
    scope = _scope(tmp_path)
    (scope.path / "pids.events").write_text("max 1\n", encoding="ascii")

    assert scope.resource_limit_reason() == "cgroup_process_count_limit"


def test_unchanged_resource_counters_do_not_misclassify_external_sigkill(tmp_path):
    scope = _scope(tmp_path)

    # An unrelated SIGKILL has no cgroup resource attribution without a counter delta.
    assert scope.resource_limit_reason() is None


def test_missing_memory_event_counters_fail_closed(tmp_path):
    scope = _scope(tmp_path)
    (scope.path / "memory.events.local").unlink()
    (scope.path / "memory.events").write_text("oom 0\n", encoding="ascii")

    with pytest.raises(CgroupV2Error, match="required cgroup resource event counters"):
        scope.resource_limit_reason()


def test_malformed_event_file_fails_closed(tmp_path):
    scope = _scope(tmp_path)
    (scope.path / "memory.events.local").write_text("oom not-a-counter\n", encoding="ascii")

    with pytest.raises(CgroupV2Error, match="cgroup resource event counters are malformed"):
        scope.resource_limit_reason()


def test_missing_baseline_counter_fails_closed(tmp_path):
    scope = _scope(tmp_path)
    scope.memory_events_before = {"oom": 0}

    with pytest.raises(CgroupV2Error, match="baseline cgroup memory event counters are incomplete"):
        scope.resource_limit_reason()
