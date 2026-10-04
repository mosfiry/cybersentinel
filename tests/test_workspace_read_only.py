from __future__ import annotations

import os
import shlex
import subprocess
from pathlib import Path

import pytest

from security.mission_authorization import MissionAuthorizationSnapshot
from workspace.environment import Workspace, WorkspaceBoundaryError


def _authorized_workspace(
    root: Path,
    *,
    actions: tuple[str, ...] = ("workspace_read",),
    tool_id: str = "workspace_read",
) -> Workspace:
    snapshot = MissionAuthorizationSnapshot.create(
        owner_identity="owner:7",
        mission_id="mission-1",
        target_identity="test-target",
        scope=("workspace",),
        allowed_actions=actions,
        forbidden_actions=(),
        allowed_tools=actions,
        time_window={"timezone": "UTC"},
        max_duration=3600,
        rate_limits={action: 10 for action in actions},
        network_boundary={"allowed": ()},
        data_boundary={"allowed": ("test-target",)},
        credential_boundary={"allowed": ()},
        workspace_boundary={"root": str(root)},
        policy_version="test-workspace-read",
        owner_approval="owner:7",
    )
    return Workspace(
        root,
        mission_id="mission-1",
        request_id="request-1",
        tool_id=tool_id,
        authorization_snapshot=snapshot,
    )


def test_list_entries_is_bounded_sorted_and_excludes_symlinks(tmp_path: Path) -> None:
    (tmp_path / "z-file.txt").write_text("z", encoding="utf-8")
    (tmp_path / "a-folder").mkdir()
    (tmp_path / "b-file.txt").write_text("b", encoding="utf-8")
    outside = tmp_path.parent / f"{tmp_path.name}-outside.txt"
    outside.write_text("outside", encoding="utf-8")
    try:
        (tmp_path / "linked.txt").symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is not available on this platform")

    workspace = _authorized_workspace(tmp_path)
    try:
        entries = workspace.list_entries(".", limit=2)
        assert [entry["name"] for entry in entries] == ["a-folder", "b-file.txt"]
        assert entries[0]["directory"] is True
        assert entries[1]["size"] == 1
        assert "linked.txt" not in {entry["name"] for entry in workspace.list_entries(".", limit=20)}
        with pytest.raises(ValueError, match="limit"):
            workspace.list_entries(".", limit=0)
    finally:
        workspace.close()
        outside.unlink(missing_ok=True)


def test_read_bounded_enforces_regular_file_and_size(tmp_path: Path) -> None:
    (tmp_path / "small.txt").write_bytes(b"hello")
    (tmp_path / "large.txt").write_bytes(b"0123456789")
    (tmp_path / "nested").mkdir()
    workspace = _authorized_workspace(tmp_path)
    try:
        assert workspace.read_bounded("small.txt", max_bytes=5) == "hello"
        with pytest.raises(ValueError, match="too_large"):
            workspace.read_bounded("large.txt", max_bytes=5)
        with pytest.raises((ValueError, OSError, WorkspaceBoundaryError)):
            workspace.read_bounded("nested", max_bytes=20)
        with pytest.raises(ValueError, match="positive"):
            workspace.read_bounded("small.txt", max_bytes=0)
    finally:
        workspace.close()


def test_read_bounded_does_not_follow_symlink(tmp_path: Path) -> None:
    target = tmp_path.parent / f"{tmp_path.name}-target.txt"
    target.write_text("outside", encoding="utf-8")
    try:
        (tmp_path / "linked.txt").symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is not available on this platform")
    workspace = _authorized_workspace(tmp_path)
    try:
        with pytest.raises((OSError, WorkspaceBoundaryError, PermissionError)):
            workspace.read_bounded("linked.txt", max_bytes=20)
    finally:
        workspace.close()
        target.unlink(missing_ok=True)


@pytest.mark.skipif(os.name != "posix", reason="fsmonitor script test requires POSIX")
def test_git_readonly_disables_repository_fsmonitor_and_optional_writes(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "--quiet"], cwd=repo, check=True)
    marker = tmp_path / "fsmonitor-was-executed"
    hook = tmp_path / "malicious-fsmonitor.sh"
    hook.write_text(f"#!/bin/sh\nprintf reached > {shlex.quote(str(marker))}\nprintf 'token\\n'\n", encoding="utf-8")
    hook.chmod(0o700)
    subprocess.run(["git", "config", "core.fsmonitor", str(hook)], cwd=repo, check=True)

    workspace = _authorized_workspace(repo, actions=("git_read",), tool_id="git_read")
    try:
        result = workspace.git_readonly("status")
        assert result.exit_code == 0, result.stderr
        assert not marker.exists()
        assert "--no-optional-locks" in result.command
        assert "core.fsmonitor=false" in result.command
        assert "core.untrackedCache=false" in result.command
    finally:
        workspace.close()
