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


def make_test_owner_kwargs(instruction: str, request_id: str, *, principal: str = "test-owner") -> dict[str, Any]:
    """Issue a properly signed, request-bound Owner context for runtime tests."""
    from security.authorization_context import AuthorizationContext
    from security.owner_policy import OwnerInstructionSource, _issue_evidence, capture_policy_snapshot

    evidence = _issue_evidence(OwnerInstructionSource.OWNER_TOKEN.value, request_id, principal)
    policy = capture_policy_snapshot(request_id, evidence, instruction=instruction)
    context = AuthorizationContext(request_id=request_id, owner_evidence=evidence, policy_snapshot=policy)
    return {
        "request_id": request_id,
        "owner_identity_ref": evidence.proof_fingerprint,
        "owner_instruction": instruction,
        "policy_snapshot": policy.to_dict(),
        "authorization_context": context.to_dict(),
    }
