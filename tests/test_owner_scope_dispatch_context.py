from __future__ import annotations

from pathlib import Path
import threading

import pytest

from agent.agent_core import AgentCore
from agent.mission import MissionStore
from agent.mission_runtime import MissionRuntime
from agent.model_protocol import ModelTurn, ToolCallProposal
from agent.planning import Plan, PlanStep
from owner_session_testutils import allow_owner_sessions
from security import owner_policy
from security.authorization_context import AuthorizationContext, _fingerprint
from security.execution_boundary import MissionExecutionBoundary
from security.mission_authorization import MissionAuthorizationSnapshot
from security.scope import ProgramAuthorization, TargetIdentity, make_snapshot
import security.scope_store as scope_store
from security.scope_store import init_scope_store, save_snapshot
import tools.scoped_http_probe as scoped_probe


OWNER_SESSION = "scope-dispatch-test-owner"
PROGRAM_ID = "scope-dispatch-program"
TARGET_ID = "scope-dispatch-target"


def _persisted_snapshot(snapshot_id: str, owner_session_token: str):
    authorization = ProgramAuthorization(
        program_id=PROGRAM_ID,
        platform="owner-submitted",
        scope_version="v1",
        retrieved_at="2026-09-30T00:00:00+00:00",
        in_scope_assets=({"host": "api.example.test", "schemes": ["https"], "ports": [443], "paths": ["/api"]},),
        allowed_methods=("GET", "HEAD"),
        prohibited_methods=("POST", "PUT", "PATCH", "DELETE"),
        rate_limits={"requests_per_minute": 10},
        owner_session_id=owner_session_token,
    )
    target = TargetIdentity(
        target_id=TARGET_ID,
        program_id=PROGRAM_ID,
        host="api.example.test",
        allowed_ports=(443,),
        allowed_paths=("/api",),
    )
    return make_snapshot(snapshot_id, authorization, [target])


def _dispatch_runtime(tmp_path, monkeypatch, *, mission_id: str, urls: tuple[str, ...]):
    monkeypatch.setattr(scope_store, "SCOPE_DB_PATH", Path(tmp_path) / "scope-snapshots.sqlite3")
    allow_owner_sessions(monkeypatch, OWNER_SESSION)
    init_scope_store()
    saved = save_snapshot(
        _persisted_snapshot(f"snapshot-{mission_id}", OWNER_SESSION),
        owner_session_token=OWNER_SESSION,
    )

    request_id = f"request-{mission_id}"
    evidence = owner_policy.authenticate_owner(OWNER_SESSION, request_id)
    policy = owner_policy.capture_policy_snapshot(request_id, evidence)
    context = AuthorizationContext(
        request_id,
        evidence,
        policy,
        scope_snapshot=saved,
        session_id=evidence.session_id,
    )
    steps = tuple(
        PlanStep(
            step_id=f"probe-{index}",
            objective="Read the persisted target endpoint",
            action="scoped_http_probe",
            retry_policy={"arguments": {"query": url}},
        )
        for index, url in enumerate(urls)
    )
    plan = Plan(version=1, objective="Read the persisted target endpoint", steps=steps)
    authorization = MissionAuthorizationSnapshot.create(
        owner_identity=str(evidence.owner_id),
        mission_id=mission_id,
        target_identity=TARGET_ID,
        scope=("persisted-scope",),
        allowed_actions=("scoped_http_probe",),
        forbidden_actions=(),
        allowed_tools=("scoped_http_probe",),
        time_window={"timezone": "UTC"},
        max_duration=300,
        rate_limits={"scoped_http_probe": 10},
        network_boundary={"allowed": ()},
        data_boundary={"allowed": (TARGET_ID,)},
        credential_boundary={"allowed": ()},
        workspace_boundary={"root": str(tmp_path)},
        policy_version=policy.policy_version,
        owner_approval=evidence.proof_fingerprint,
        expires_at=evidence.expires_at,
    )
    runtime = MissionRuntime(
        MissionStore(Path(tmp_path) / f"{mission_id}.sqlite3"),
        executor=lambda *_args: {},
    )
    mission = runtime.create(
        "Read persisted target",
        "Read the persisted target endpoint",
        plan,
        mission_id=mission_id,
        authorization_context=context.to_dict(),
        scope_snapshot={
            "workspace_root": str(tmp_path),
            "scope_snapshot_id": saved.snapshot_id,
            "program_id": saved.authorization.program_id,
            "target_id": TARGET_ID,
            "scope_snapshot_fingerprint": context.scope_fingerprint,
        },
        request_id=request_id,
        owner_identity_ref=str(evidence.owner_id),
        authorization_snapshot=authorization.to_dict(),
        provenance={"authorization_snapshot_version": authorization.version},
    )
    assert runtime._mission_authorization(mission) == (True, "authorized")
    return runtime, mission, context, saved


class _NativeProbeModel:
    def __init__(self, urls: tuple[str, ...]):
        self.urls = urls

    def complete(self, _messages, _tools, *, mission_id, run_id, turn_id, plan_version):
        proposals = tuple(
            ToolCallProposal.create(
                "scoped_http_probe",
                {"query": url},
                mission_id=mission_id,
                run_id=run_id,
                turn_id=turn_id,
                action_id=f"action-{index}",
                tool_call_id=f"call-{index}",
                plan_version=plan_version,
                step_id=f"probe-{index}",
            )
            for index, url in enumerate(self.urls)
        )
        return ModelTurn(turn_id, tool_calls=proposals)


def _install_non_networking_handler(monkeypatch):
    calls: list[tuple[str, dict[str, str]]] = []
    lock = threading.Lock()

    def observe_after_registry_validation(argument, *, scope_context):
        with lock:
            calls.append((argument, dict(scope_context)))
        return {
            "success": True,
            "outcome": "response_received",
            "observation_only": True,
            "status": 200,
            "content_type": "text/plain",
            "byte_count": 0,
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "truncated": False,
        }

    # Registry proof and live-snapshot validation still run before this handler.
    # Replacing only the transport avoids making any network request in the test.
    monkeypatch.setattr(scoped_probe, "scoped_http_probe", observe_after_registry_validation)
    return calls


@pytest.mark.parametrize(
    ("route", "urls"),
    [
        ("fallback", ("https://api.example.test/api/fallback",)),
        ("native_serial", ("https://api.example.test/api/native-serial",)),
        (
            "native_parallel",
            (
                "https://api.example.test/api/native-parallel-a",
                "https://api.example.test/api/native-parallel-b",
            ),
        ),
    ],
    ids=["fallback-executor", "native-serial", "native-parallel"],
)
def test_scope_required_dispatch_uses_exact_per_call_context_and_real_registry_proof(
    route, urls, tmp_path, monkeypatch
):
    from security.execution_boundary import MissionExecutionBoundary

    runtime, mission, _context, saved = _dispatch_runtime(
        tmp_path,
        monkeypatch,
        mission_id=f"mission-{route}",
        urls=urls,
    )
    observed = _install_non_networking_handler(monkeypatch)
    proofs = []
    original_derive = MissionExecutionBoundary.derive

    def capture_real_proof(*args, **kwargs):
        proof = original_derive(*args, **kwargs)
        proofs.append(proof)
        return proof

    monkeypatch.setattr(MissionExecutionBoundary, "derive", staticmethod(capture_real_proof))

    if route == "fallback":
        core = AgentCore.__new__(AgentCore)
        core.store = runtime.store
        result = core._executor(mission, mission.plan.steps[0], "fallback-action")
        assert result["success"] is True, result
    else:
        mission = runtime.run_model_loop(
            mission.mission_id,
            _NativeProbeModel(urls),
            tools=[{"name": "scoped_http_probe"}],
            max_turns=1,
        )
        tool_results = mission.progress["model_loop"]["tool_results"]
        probe_results = [item for item in tool_results if item["name"] == "scoped_http_probe"]
        assert len(probe_results) == len(urls)
        assert all(item["ok"] is True for item in probe_results), probe_results

    assert len(observed) == len(urls)
    assert {argument for argument, _context in observed} == set(urls)
    for argument, context in observed:
        assert context == {
            "program_id": saved.authorization.program_id,
            "target_id": TARGET_ID,
            "scope_snapshot_id": saved.snapshot_id,
            "url": argument,
        }
        assert set(context) == {"program_id", "target_id", "scope_snapshot_id", "url"}

    # The per-call projection is intentionally narrower than the durable proof binding.
    assert len(proofs) == len(urls)
    assert all(proof.scope_hash == _fingerprint(mission.scope_snapshot) for proof in proofs)
    assert all(proof.scope_hash != _fingerprint(observed_context) for proof in proofs for _, observed_context in observed)
    assert {proof.scope_context_hash for proof in proofs} == {
        _fingerprint(context) for _argument, context in observed
    }


def test_registry_rejects_scope_context_different_from_signed_per_call_context(tmp_path, monkeypatch):
    from security.authorization import authorize_tool
    from tools.registry import execute

    url = "https://api.example.test/api/signed"
    runtime, mission, context, _saved = _dispatch_runtime(
        tmp_path,
        monkeypatch,
        mission_id="mission-signed-context-mismatch",
        urls=(url,),
    )
    decision = authorize_tool(["scoped_http_probe", url], context=context)
    assert decision.allowed
    per_call_context = MissionExecutionBoundary.scope_context_for_call(
        mission,
        tool="scoped_http_probe",
        argument=url,
        authorization_context=context,
    )
    proof = MissionExecutionBoundary.derive(
        mission,
        tool="scoped_http_probe",
        argument=url,
        decision=decision.decision,
        tool_call_id="signed-context-mismatch-call",
        scope_context=per_call_context,
    )
    wrong_context = {**per_call_context, "url": "https://api.example.test/api/other"}

    with pytest.raises(PermissionError, match="scope context differs from the execution proof"):
        execute(
            "scoped_http_probe",
            url,
            authorization_decision=decision.decision,
            scope_context=wrong_context,
            request_id=mission.request_id,
            tool_call_id="signed-context-mismatch-call",
            mission_authorization=MissionAuthorizationSnapshot.from_dict(mission.authorization_snapshot),
            mission_id=mission.mission_id,
            target_identity=TARGET_ID,
            execution_proof=proof,
            execution_class="MISSION_BOUND",
        )
