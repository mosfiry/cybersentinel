from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from tools.registry import MAX_SANDBOX_PROCESS_SECONDS, _run_project_tests


class _EvidenceStore:
    def __init__(self):
        self.payload = None
        self.fence = None

    def append(self, payload, *, execution_fence):
        self.payload = payload
        self.fence = execution_fence
        return {"evidence_id": "evidence-test", "sequence": 1, "current_hash": "hash-test"}


@pytest.mark.parametrize(
    ("mission_timeout", "workspace_timeout", "expected_timeout"),
    [
        (900, 300, 300),
        (120, 300, 120),
        (900, 90, 90),
        (900, 900, 300),
    ],
)
def test_project_tests_use_finite_effective_cap_and_preserve_cancellation(
    tmp_path: Path, mission_timeout: float, workspace_timeout: float, expected_timeout: float
):
    root = tmp_path.resolve()
    authorization = SimpleNamespace(
        workspace_boundary={"root": str(root)},
        max_duration=mission_timeout,
        authorization_hash="authorization-hash",
    )
    snapshot = SimpleNamespace(authorization_hash="authorization-hash")
    cancellation_event = object()
    execution_fence = SimpleNamespace(task_id="task-test")
    evidence_store = _EvidenceStore()
    captured = {}

    class Workspace:
        def __init__(self):
            self.root = root
            self.authorization_snapshot = snapshot
            self.mission_id = "mission-test"
            self.request_id = "request-test"
            self.tool_id = "run_project_tests"
            self.policy = SimpleNamespace(max_timeout_seconds=workspace_timeout)

        def resolve(self, _target):
            return root

        def develop(self, command, *, cwd, timeout, cancellation_event):
            captured.update(
                command=tuple(command),
                cwd=cwd,
                timeout=timeout,
                cancellation_event=cancellation_event,
            )
            return SimpleNamespace(
                command=tuple(command),
                artifacts=(),
                stdout="7 passed in 0.20s\n",
                stderr="",
                ok=True,
                exit_code=0,
                timed_out=False,
                cancelled=False,
                duration_seconds=0.20,
                sandbox_backend="bubblewrap+prlimit",
                artifact_capture_truncated=False,
            )

    workspace = Workspace()
    context = SimpleNamespace(
        assert_active=lambda: None,
        mission_authorization=authorization,
        mission_id="mission-test",
        request_id="request-test",
        tool_id="run_project_tests",
        cancellation_event=cancellation_event,
        artifact_store=object(),
        evidence_store=evidence_store,
        execution_fence=execution_fence,
        scope_snapshot={"scope_snapshot_id": "scope-test", "target_id": "target-test"},
        owner_identity="owner-test",
    )

    result = _run_project_tests(".", workspace=workspace, execution_context=context)

    assert MAX_SANDBOX_PROCESS_SECONDS == 300
    assert captured["timeout"] == expected_timeout
    assert captured["cancellation_event"] is cancellation_event
    assert captured["command"] == (
        "python3", "-m", "pytest", "-q", "--junitxml=/artifacts/pytest.xml"
    )
    assert result["ok"] is True
    assert result["timed_out"] is False
    assert result["cancelled"] is False
    assert result["returncode"] == 0
    assert "7 passed" in result["output"]
    assert result["evidence_ref"]["evidence_id"] == "evidence-test"
    assert evidence_store.payload["evidence"]["exit_code"] == 0
    assert evidence_store.fence is execution_fence
