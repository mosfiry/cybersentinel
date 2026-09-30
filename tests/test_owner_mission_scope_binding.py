from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agent.agent_core import AgentCore
from agent.mission import Mission, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.planning import Plan
from security import owner_policy
from security.authorization_context import AuthorizationContext
from security.mission_authorization import MissionAuthorizationSnapshot
from security.scope import ProgramAuthorization, TargetIdentity, make_snapshot
import security.scope_store as scope_store
from security.scope_store import get_snapshot_for_owner_session, init_scope_store, save_snapshot
from owner_session_testutils import allow_owner_sessions


def _snapshot(snapshot_id: str, *, expires_at: str | None = None, owner_session_id: str = ""):
    authorization = ProgramAuthorization(
        program_id="manual-program-1",
        platform="owner-submitted",
        scope_version="v1",
        retrieved_at=datetime.now(timezone.utc).isoformat(),
        in_scope_assets=({"host": "api.example.test", "schemes": ["https"], "ports": [443], "paths": ["/api"]},),
        allowed_methods=("GET", "HEAD"),
        prohibited_methods=("POST", "PUT", "PATCH", "DELETE"),
        owner_session_id=owner_session_id,
    )
    target = TargetIdentity(
        target_id="api-prod",
        program_id=authorization.program_id,
        host="api.example.test",
        allowed_ports=(443,),
        allowed_paths=("/api",),
    )
    return make_snapshot(snapshot_id, authorization, [target], expires_at=expires_at)


def _init_store(tmp_path, monkeypatch, *owner_tokens):
    monkeypatch.setattr(scope_store, "SCOPE_DB_PATH", Path(tmp_path) / "scope-snapshots.sqlite3")
    allow_owner_sessions(monkeypatch, *owner_tokens)
    init_scope_store()


def test_persisted_scope_reference_requires_live_session_expiry_and_target_membership(tmp_path, monkeypatch):
    _init_store(tmp_path, monkeypatch, "owner-a", "owner-b")
    saved = save_snapshot(_snapshot("snapshot-owner-a"), owner_session_token="owner-a")

    assert get_snapshot_for_owner_session(
        saved.snapshot_id,
        "api-prod",
        owner_session_token="owner-a",
    ) == saved
    with pytest.raises(PermissionError, match="scope_snapshot_unavailable"):
        get_snapshot_for_owner_session("unknown-snapshot", "api-prod", owner_session_token="owner-a")
    with pytest.raises(PermissionError, match="scope_snapshot_unavailable"):
        get_snapshot_for_owner_session(saved.snapshot_id, "api-prod", owner_session_token="owner-b")
    with pytest.raises(PermissionError, match="scope_target_unavailable"):
        get_snapshot_for_owner_session(saved.snapshot_id, "not-a-member", owner_session_token="owner-a")

    expired = save_snapshot(
        _snapshot("snapshot-expired", expires_at=(datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()),
        owner_session_token="owner-a",
    )
    with pytest.raises(PermissionError, match="scope_snapshot_expired"):
        get_snapshot_for_owner_session(expired.snapshot_id, "api-prod", owner_session_token="owner-a")


def _stub_agent_core(monkeypatch, context, captured):
    class Router:
        def with_model_selection(self, _model_id):
            return self, {"mode": "automatic"}

    def capture_authorized(self, instruction, **kwargs):
        captured["instruction"] = instruction
        captured.update(kwargs)
        return "captured"

    core = AgentCore.__new__(AgentCore)
    core.router = Router()
    monkeypatch.setattr(AgentCore, "_auth", staticmethod(lambda _text, _token, _request_id: (context, "policy")))
    monkeypatch.setattr(AgentCore, "_run_owner_mission_authorized", capture_authorized)
    return core


def test_agent_core_derives_scoped_mission_authority_from_store_not_caller_scope_content(tmp_path, monkeypatch):
    _init_store(tmp_path, monkeypatch, "owner-a")
    saved = save_snapshot(_snapshot("snapshot-core-binding"), owner_session_token="owner-a")
    request_id = "core-binding-request"
    evidence = owner_policy.authenticate_owner("owner-a", request_id)
    policy = owner_policy.capture_policy_snapshot(request_id, evidence)
    context = AuthorizationContext(request_id, evidence, policy, session_id=evidence.session_id)
    captured = {}
    core = _stub_agent_core(monkeypatch, context, captured)

    result = core.run_owner_mission(
        "Inspect one persisted target",
        owner_session_token="owner-a",
        request_id=request_id,
        scope_context={
            "workspace_root": str(tmp_path),
            "scope_snapshot_id": saved.snapshot_id,
            "target_id": "api-prod",
            "program_id": "forged-program",
            "host": "attacker.example",
            "allowed_networks": ["0.0.0.0/0"],
            "allowed_credentials": ["caller-credential"],
            "owner_allowed_tools": ["scoped_http_probe"],
        },
        run=False,
    )

    assert result == "captured"
    mission_scope = captured["scope_context"]
    assert mission_scope["scope_snapshot_id"] == saved.snapshot_id
    assert mission_scope["target_id"] == "api-prod"
    assert mission_scope["program_id"] == "manual-program-1"
    assert mission_scope["workspace_root"] == str(tmp_path)
    assert mission_scope["scope_snapshot_fingerprint"] == captured["authorization_context"].scope_fingerprint
    assert mission_scope["owner_allowed_tools"] == ["scoped_http_probe"]
    assert not {"host", "allowed_networks", "allowed_credentials"} & set(mission_scope)
    assert captured["authorization_context"].scope_snapshot == saved
    assert captured["authorization_context"].session_id == "owner-a"


def test_agent_core_without_snapshot_preserves_repository_workspace_scope(tmp_path, monkeypatch):
    _init_store(tmp_path, monkeypatch, "owner-a")
    request_id = "legacy-workspace-request"
    evidence = owner_policy.authenticate_owner("owner-a", request_id)
    policy = owner_policy.capture_policy_snapshot(request_id, evidence)
    context = AuthorizationContext(request_id, evidence, policy, session_id=evidence.session_id)
    captured = {}
    core = _stub_agent_core(monkeypatch, context, captured)
    legacy_scope = {"workspace_root": str(tmp_path), "target_id": "cybersentinel-repository"}

    result = core.run_owner_mission(
        "Review repository",
        owner_session_token="owner-a",
        request_id=request_id,
        scope_context=legacy_scope,
        run=False,
    )

    assert result == "captured"
    assert captured["scope_context"] == legacy_scope
    assert captured["authorization_context"].scope_snapshot is None


def _runtime_mission(tmp_path, owner_session_token: str, snapshot, *, mission_id: str = "runtime-scope-binding"):
    request_id = f"request-{mission_id}"
    evidence = owner_policy.authenticate_owner(owner_session_token, request_id)
    policy = owner_policy.capture_policy_snapshot(request_id, evidence)
    context = AuthorizationContext(
        request_id,
        evidence,
        policy,
        scope_snapshot=snapshot,
        session_id=evidence.session_id,
    )
    scope_binding = {
        "workspace_root": str(tmp_path),
        "scope_snapshot_id": snapshot.snapshot_id,
        "program_id": snapshot.authorization.program_id,
        "target_id": "api-prod",
        "scope_snapshot_fingerprint": context.scope_fingerprint,
    }
    authorization = MissionAuthorizationSnapshot.create(
        owner_identity=str(evidence.owner_id),
        mission_id=mission_id,
        target_identity="api-prod",
        scope=("workspace",),
        allowed_actions=(),
        forbidden_actions=(),
        allowed_tools=(),
        time_window={"timezone": "UTC"},
        max_duration=300,
        rate_limits={},
        network_boundary={"allowed": ()},
        data_boundary={"allowed": ("api-prod",)},
        credential_boundary={"allowed": ()},
        workspace_boundary={"root": str(tmp_path)},
        policy_version=policy.policy_version,
        owner_approval=evidence.proof_fingerprint,
        expires_at=evidence.expires_at,
    )
    mission = Mission.create(
        "Inspect saved target",
        "Inspect saved target",
        Plan.initial("Inspect saved target"),
        mission_id=mission_id,
        authorization_context=context.to_dict(),
        scope_snapshot=scope_binding,
        request_id=request_id,
        owner_identity_ref=str(evidence.owner_id),
        authorization_snapshot=authorization.to_dict(),
        provenance={"authorization_snapshot_version": authorization.version},
    )
    runtime = MissionRuntime(
        MissionStore(tmp_path / f"{mission_id}.sqlite3"),
        executor=lambda *_args: {"success": True},
    )
    return runtime, mission


def test_runtime_requires_exact_persisted_snapshot_fingerprint_and_fails_closed(tmp_path, monkeypatch):
    _init_store(tmp_path, monkeypatch, "runtime-owner")
    saved = save_snapshot(_snapshot("snapshot-runtime"), owner_session_token="runtime-owner")
    runtime, mission = _runtime_mission(tmp_path, "runtime-owner", saved)

    assert runtime._mission_authorization(mission) == (True, "authorized")

    expected_fingerprint = mission.scope_snapshot["scope_snapshot_fingerprint"]
    mission.scope_snapshot["scope_snapshot_fingerprint"] = "0" * 64
    allowed, reason = runtime._mission_authorization(mission)
    assert allowed is False
    assert "binding differs" in reason

    mission.scope_snapshot["scope_snapshot_fingerprint"] = expected_fingerprint
    mission.scope_snapshot.pop("scope_snapshot_id")
    allowed, reason = runtime._mission_authorization(mission)
    assert allowed is False
    assert "identifier is missing" in reason


def test_runtime_blocks_expired_scope_before_any_tool_dispatch(tmp_path, monkeypatch):
    _init_store(tmp_path, monkeypatch, "runtime-owner")
    expired = save_snapshot(
        _snapshot("snapshot-runtime-expired", expires_at=(datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()),
        owner_session_token="runtime-owner",
    )
    runtime, mission = _runtime_mission(tmp_path, "runtime-owner", expired, mission_id="runtime-expired-scope")

    allowed, _reason = runtime._mission_authorization(mission)
    assert allowed is False



def test_resume_blocks_changed_scope_binding_after_owner_reauthentication(tmp_path, monkeypatch):
    from agent.mission import MissionStatus

    _init_store(tmp_path, monkeypatch, "resume-owner")
    saved = save_snapshot(_snapshot("snapshot-resume-binding"), owner_session_token="resume-owner")
    runtime, mission = _runtime_mission(tmp_path, "resume-owner", saved, mission_id="resume-changed-scope")
    mission.scope_snapshot["scope_snapshot_fingerprint"] = "f" * 64
    evidence = owner_policy.authenticate_owner("resume-owner", mission.request_id)
    core = AgentCore.__new__(AgentCore)
    core.store = runtime.store

    with pytest.raises(PermissionError, match="persisted mission scope binding is unavailable or changed"):
        core._resume_mission_authorized(
            mission,
            evidence=evidence,
            model_selection={},
            selection_changed=False,
            old_model_selection={},
            max_slices=None,
            heartbeat=None,
            run=False,
        )

    assert mission.status is MissionStatus.AUTHORIZATION_BLOCKED
    assert mission.error == "persisted mission scope binding is unavailable or changed"


def test_scoped_http_dispatch_passes_only_existing_strict_tool_context(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from agent import agent_core
    from agent.planning import PlanStep

    _init_store(tmp_path, monkeypatch, "dispatch-owner")
    saved = save_snapshot(_snapshot("snapshot-dispatch"), owner_session_token="dispatch-owner")
    request_id = "dispatch-scope-request"
    evidence = owner_policy.authenticate_owner("dispatch-owner", request_id)
    policy = owner_policy.capture_policy_snapshot(request_id, evidence)
    context = AuthorizationContext(
        request_id,
        evidence,
        policy,
        scope_snapshot=saved,
        session_id=evidence.session_id,
    )
    mission_id = "dispatch-scope-mission"
    url = "https://api.example.test/api/status"
    step = PlanStep(
        step_id="probe-1",
        objective="Read the persisted target endpoint",
        action="scoped_http_probe",
        retry_policy={"arguments": {"query": url}},
    )
    plan = Plan(version=1, objective="Read the persisted target endpoint", steps=(step,))
    authorization = MissionAuthorizationSnapshot.create(
        owner_identity=str(evidence.owner_id),
        mission_id=mission_id,
        target_identity="api-prod",
        scope=("persisted-scope",),
        allowed_actions=("scoped_http_probe",),
        forbidden_actions=(),
        allowed_tools=("scoped_http_probe",),
        time_window={"timezone": "UTC"},
        max_duration=300,
        rate_limits={"scoped_http_probe": 1},
        network_boundary={"allowed": ()},
        data_boundary={"allowed": ("api-prod",)},
        credential_boundary={"allowed": ()},
        workspace_boundary={"root": str(tmp_path)},
        policy_version=policy.policy_version,
        owner_approval=evidence.proof_fingerprint,
        expires_at=evidence.expires_at,
    )
    mission = Mission.create(
        "Read persisted target",
        "Read persisted target",
        plan,
        mission_id=mission_id,
        authorization_context=context.to_dict(),
        scope_snapshot={
            "workspace_root": str(tmp_path),
            "scope_snapshot_id": saved.snapshot_id,
            "program_id": saved.authorization.program_id,
            "target_id": "api-prod",
            "scope_snapshot_fingerprint": context.scope_fingerprint,
        },
        request_id=request_id,
        owner_identity_ref=str(evidence.owner_id),
        authorization_snapshot=authorization.to_dict(),
        provenance={"authorization_snapshot_version": authorization.version},
    )
    core = AgentCore.__new__(AgentCore)
    core.store = MissionStore(tmp_path / "dispatch-missions.sqlite3")
    proof = SimpleNamespace(proof_fingerprint="proof", snapshot_hash="snapshot", plan_hash="plan")
    observed = {}

    monkeypatch.setattr(agent_core, "authorize_tool", lambda *_args, **_kwargs: SimpleNamespace(allowed=True, decision=object()))
    monkeypatch.setattr(agent_core.MissionExecutionBoundary, "derive", lambda *_args, **_kwargs: proof)
    monkeypatch.setattr(agent_core.MissionExecutionBoundary, "validate", lambda *_args, **_kwargs: (True, "ok", ""))

    def capture_execution(name, argument, **kwargs):
        observed.update(name=name, argument=argument, **kwargs)
        return {"stubbed": True}

    monkeypatch.setattr(agent_core, "execute_tool", capture_execution)

    result = core._executor(mission, step, "dispatch-action-1")

    assert result["success"] is True
    assert observed["scope_context"] == {
        "program_id": saved.authorization.program_id,
        "target_id": "api-prod",
        "scope_snapshot_id": saved.snapshot_id,
        "url": url,
    }
    assert set(observed["scope_context"]) == {"program_id", "target_id", "scope_snapshot_id", "url"}
    assert observed["scope_context"]["url"] == observed["argument"]
