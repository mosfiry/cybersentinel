from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from security.mission_authorization import MissionAuthorizationSnapshot


def make_test_snapshot(mission: Any, *, root: str = "/workspace/test") -> MissionAuthorizationSnapshot:
    owner = str(mission.owner_identity_ref or "test-owner")
    if not mission.owner_identity_ref:
        mission.owner_identity_ref = owner
    actions = tuple(dict.fromkeys(tuple(step.action for step in mission.plan.steps if step.action != "__planning_failure__") + ("status", "search", "run_project_tests")))
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
        rate_limits={action: 10 for action in actions},
        network_boundary={"allowed": ()},
        data_boundary={"allowed": ("test-target",)},
        credential_boundary={"allowed": ()},
        workspace_boundary={"root": str(Path(root).resolve())},
        policy_version="test-policy-v1",
        owner_approval="test-owner-approval",
        created_at=now.isoformat(),
        expires_at=(now + timedelta(hours=1)).isoformat(),
    )


def make_test_authorization_context(request_id: str = "req-test", state_dir=None):
    """Build a real typed Owner AuthorizationContext for mission fixtures.

    INV-AUTH-3 closed the structural-only adapter: a fixture mission whose
    model-proposed tool calls must execute now carries a typed
    AuthorizationContext bound to the mission request_id, exactly like a
    production Owner-authenticated mission. The context is derived from
    issued Owner evidence and a captured policy snapshot; it never comes
    from model output.
    """
    from security.authorization_context import AuthorizationContext

    import security.owner_policy as owner_policy

    previous = owner_policy.STATE_PATH
    if state_dir is not None:
        owner_policy.STATE_PATH = Path(state_dir) / "owner-policy.json"
    try:
        evidence = owner_policy._issue_evidence("owner_token", request_id, "proof")
        policy = owner_policy.capture_policy_snapshot(request_id, evidence)
    finally:
        owner_policy.STATE_PATH = previous
    return AuthorizationContext(request_id=request_id, owner_evidence=evidence, policy_snapshot=policy)
