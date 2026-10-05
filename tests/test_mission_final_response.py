from __future__ import annotations

import json
from pathlib import Path

from agent.mission import Mission, MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.model_protocol import RouterNativeModel
from agent.planning import GoalVerification, Plan, VerificationCriterion, VerificationEvidence
from agent.trajectory import EventType


PROVIDER = "local_llama_cpp"
MODEL = "qwen3-4b-q4-k-m"


def _verified() -> GoalVerification:
    criterion = VerificationCriterion("status-current", "A status observation exists", "status", True)
    evidence = VerificationEvidence("status-current", True, "status", "a" * 64, {})
    return GoalVerification("Check system status", (criterion,), (evidence,), True, ())


def _mission(path: Path, *, owner_request: str = "Check system status"):
    store = MissionStore(path)
    mission = Mission.create(
        owner_request,
        "Check system status",
        Plan.initial("Check system status"),
        mission_id="mission-final-response",
        request_id="request-final-response",
        owner_identity_ref="owner:final-response",
    )
    mission.transition(MissionStatus.RUNNING, "controlled final-response test")
    mission.progress["model_loop"] = {
        "turns": [{
            "turn_id": "run:turn:1",
            "content": "",
            "provider": PROVIDER,
            "model": MODEL,
            "tool_calls": [{"name": "status", "arguments": {}}],
            "finish_reason": "tool_calls",
            "usage": {},
            "capability": "tool_calling",
        }],
        "tool_results": [{"tool_call_id": "status-1", "name": "status", "result": {"verified": True}}],
        "seen_call_ids": ["status-1"],
    }
    store.save(mission)
    return store, store.load(mission.mission_id)


class _ExactGenerationRouter:
    def __init__(self, *, content="The requested status check completed and its required evidence was verified.", tool_calls=None, provider=PROVIDER, model=MODEL):
        self.content = content
        self.tool_calls = [] if tool_calls is None else tool_calls
        self.provider = provider
        self.model = model
        self.calls = []

    def generate_for_provider(self, provider_name, model_name, messages, **kwargs):
        self.calls.append((provider_name, model_name, messages, kwargs))
        return {
            "content": self.content,
            "tool_calls": self.tool_calls,
            "provider": self.provider,
            "model": self.model,
            "capability": "generate",
            "finish_reason": "stop",
            "usage": {"completion_tokens": 24},
        }

    def generate(self, *_args, **_kwargs):
        raise AssertionError("final response must not use generic provider routing")

    def tool_calling(self, *_args, **_kwargs):
        raise AssertionError("final response must not offer tools")


def _call(runtime, mission, model, *, limit=8192, timeout=10.0):
    return runtime._complete_from_verified_evidence_after_budget(
        mission,
        budget="max_context_chars",
        limit=limit,
        run_id="run-final-response",
        turn_id="run-final-response:turn:2",
        model=model,
        context_char_limit=limit,
        context_message_limit=16,
        timeout_seconds=timeout,
    )


def test_verified_completion_uses_exact_provider_and_bounded_no_tools_summary(tmp_path: Path):
    store, mission = _mission(tmp_path / "missions.sqlite3")
    router = _ExactGenerationRouter()
    model = RouterNativeModel(router)
    model.trusted_provider = PROVIDER
    model.trusted_model = MODEL
    runtime = MissionRuntime(store, executor=lambda *_args: {}, verifier=lambda _mission: _verified())

    completed = _call(runtime, mission, model)

    assert completed is not None and completed.status is MissionStatus.GOAL_COMPLETED
    assert len(router.calls) == 1
    provider, model_name, messages, options = router.calls[0]
    assert (provider, model_name) == (PROVIDER, MODEL)
    assert len(messages) == 2
    assert all(message["role"] in {"system", "user"} for message in messages)
    assert all("tool_calls" not in message for message in messages)
    assert options["max_tokens"] == 128
    assert options["timeout"] == 10.0
    assert options["chat_template_kwargs"] == {"enable_thinking": False}
    assert completed.progress["final_model_turn"]["status"] == "generated_compact_no_tools"
    assert completed.progress["final_model_turn"]["tools_enabled"] is False
    assert completed.progress["final_model_turn"]["authority"] == "none"
    assert completed.progress["final_model_turn"]["untrusted"] is True
    assert completed.progress["final_model_turn"]["response_sha256"]
    final_event = next(item for item in completed.trajectory if item["event"] == EventType.MISSION_COMPLETED.value)
    assert final_event["data"]["model_final"] == router.content
    assert final_event["data"]["completion_source"] == "deterministic_evidence_plus_bound_provider_summary"
    assert store.load(completed.mission_id).status is MissionStatus.GOAL_COMPLETED


def test_unrequested_tool_proposal_is_discarded_and_never_executed_or_persisted(tmp_path: Path):
    store, mission = _mission(tmp_path / "missions.sqlite3")
    hostile = "DO_NOT_PERSIST_OR_EXECUTE_THIS_COMMAND"
    router = _ExactGenerationRouter(
        content="",
        tool_calls=[{
            "id": "hostile-call-1",
            "name": "run_project_tests",
            "arguments": {"command": hostile},
        }],
    )
    model = RouterNativeModel(router)
    model.trusted_provider = PROVIDER
    model.trusted_model = MODEL
    runtime = MissionRuntime(store, executor=lambda *_args: (_ for _ in ()).throw(AssertionError("no effect dispatch")), verifier=lambda _mission: _verified())

    completed = _call(runtime, mission, model)

    assert completed is not None and completed.status is MissionStatus.GOAL_COMPLETED
    assert len(router.calls) == 1
    assert completed.progress["final_model_turn"]["summary_attempt_status"] == "rejected_unrequested_tool_call"
    assert completed.progress["final_model_turn"]["status"] == "not_generated_resource_limited"
    assert not any(item["event"] == EventType.TOOL_EXECUTED.value for item in completed.trajectory)
    assert hostile not in json.dumps(completed.to_dict())
    final_event = next(item for item in completed.trajectory if item["event"] == EventType.MISSION_COMPLETED.value)
    assert final_event["data"]["final_model_generated"] is False


def test_unbound_or_mismatched_provider_fails_closed_without_any_fallback(tmp_path: Path):
    store, mission = _mission(tmp_path / "missions.sqlite3")
    router = _ExactGenerationRouter()
    model = RouterNativeModel(router)
    model.trusted_provider = "remote_provider"
    model.trusted_model = "remote-model"
    runtime = MissionRuntime(store, executor=lambda *_args: {}, verifier=lambda _mission: _verified())

    completed = _call(runtime, mission, model)

    assert completed is not None and completed.status is MissionStatus.GOAL_COMPLETED
    assert router.calls == []
    assert completed.progress["final_model_turn"]["summary_attempt_status"] == "not_generated_unbound_provider"


def test_oversized_owner_request_skips_summary_without_truncation(tmp_path: Path):
    owner_request = "x" * 4097
    store, mission = _mission(tmp_path / "missions.sqlite3", owner_request=owner_request)
    router = _ExactGenerationRouter()
    model = RouterNativeModel(router)
    model.trusted_provider = PROVIDER
    model.trusted_model = MODEL
    runtime = MissionRuntime(store, executor=lambda *_args: {}, verifier=lambda _mission: _verified())

    completed = _call(runtime, mission, model)

    assert completed is not None and completed.status is MissionStatus.GOAL_COMPLETED
    assert router.calls == []
    assert completed.progress["final_model_turn"]["summary_attempt_status"] == "not_generated_context_limit"
