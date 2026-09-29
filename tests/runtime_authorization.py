from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from security.mission_authorization import MissionAuthorizationSnapshot


def make_test_snapshot(mission: Any, *, root: str = "/workspace/test") -> MissionAuthorizationSnapshot:
    owner = str(mission.owner_identity_ref or "test-owner")
    owner_approval = "test-owner-approval"
    if isinstance(mission.authorization_context, dict):
        from security.authorization_context import AuthorizationContext
        context = AuthorizationContext.from_dict(mission.authorization_context)
        owner = str(context.owner_evidence.owner_id or owner or "test-owner")
        owner_approval = context.owner_evidence.proof_fingerprint
        mission.owner_identity_ref = owner
    if not mission.owner_identity_ref:
        mission.owner_identity_ref = owner
    actions = tuple(dict.fromkeys(tuple(step.action for step in mission.plan.steps if step.action != "__planning_failure__") + ("status", "search", "latest_intel", "run_project_tests")))
    now = datetime.now(timezone.utc)
    return MissionAuthorizationSnapshot.create(
        owner_identity=owner,
        mission_id=mission.mission_id,
        target_identity="test-target",
        scope=("workspace",),
        allowed_actions=actions,
        forbidden_actions=(),
        allowed_tools=actions,
        time_window={"timezone": "UTC"},
        max_duration=max(300, mission.max_iterations * 60),
        rate_limits={action: max(1, mission.max_iterations) for action in actions},
        network_boundary={"allowed": ()},
        data_boundary={"allowed": ("test-target",)},
        credential_boundary={"allowed": ()},
        workspace_boundary={"root": str(Path(root).resolve())},
        policy_version="test-policy-v1",
        owner_approval=owner_approval,
        created_at=now.isoformat(),
        expires_at=(now + timedelta(hours=1)).isoformat(),
    )


def signed_test_owner_kwargs(monkeypatch: Any, tmp_path: str | Path, *, request_id: str, token: str = "valid-owner") -> dict[str, Any]:
    """Return real, signed Owner evidence bound to an isolated test DB."""
    from owner_session_testutils import allow_owner_sessions
    from security import owner_policy
    from security.authorization_context import AuthorizationContext
    from security.owner_policy import authenticate_owner, capture_policy_snapshot

    allow_owner_sessions(monkeypatch, token)
    monkeypatch.setattr(owner_policy, "STATE_PATH", Path(tmp_path) / "owner-policy-state.json")
    evidence = authenticate_owner(token, request_id)
    snapshot = capture_policy_snapshot(request_id, evidence)
    context = AuthorizationContext(request_id, evidence, snapshot)
    return {
        "request_id": request_id,
        "owner_identity_ref": str(evidence.owner_id),
        "authorization_context": context.to_dict(),
        "policy_snapshot": snapshot.to_dict(),
    }
