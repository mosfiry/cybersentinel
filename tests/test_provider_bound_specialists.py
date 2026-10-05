from __future__ import annotations

import json
import hashlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
import threading

import pytest

from agent.intelligence_layer.graph import AgentGraphPolicy, TaskGraph
from agent.intelligence_layer.models import AgentLifecycle, TaskLifecycle
from agent.intelligence_layer.specialist_dispatch import run_ready_specialist_batch
from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.model_router import ModelRouter
from agent.planning import Plan, PlanStep
from agent.provider_api import CapabilityUnsupported, ProviderCapabilities, ProviderTimeout
from agent.execution_fence import ExecutionFence
from agent.mission_worker import MissionQueue
from security.mission_authorization import MissionAuthorizationSnapshot
from runtime_authorization import make_test_snapshot


@pytest.fixture(autouse=True)
def isolated_memory_db(tmp_path, monkeypatch):
    from agent import memory

    monkeypatch.setattr(memory, "MEMORY_DB_PATH", tmp_path / "memory.sqlite3")
    memory._init_memory_db()


def _plan(*steps: PlanStep) -> Plan:
    return Plan.initial("Run a bounded security analysis").replan(
        steps=steps,
        reason="provider-bound specialist control-plane test",
    )


def _runtime(tmp_path: Path, steps, specialist_generate, *, executor=None, strict_fence=False):
    policy = AgentGraphPolicy(
        max_agents=8,
        max_tasks=16,
        max_parallel_tasks=2,
        max_retries=1,
        enable_task_delegation=True,
    )
    store = MissionStore(tmp_path / "missions.sqlite3")
    runtime = MissionRuntime(
        store,
        executor=executor or (lambda *_args, **_kwargs: pytest.fail("specialist slice dispatched a tool")),
        authorization_snapshot_factory=make_test_snapshot,
        task_graph_policy=policy,
        specialist_generate=specialist_generate,
        require_execution_fence=strict_fence,
    )
    mission = runtime.create(
        "Analyze the supplied bounded task description",
        "Run a bounded security analysis",
        _plan(*steps),
        owner_identity_ref="test-owner",
    )
    mission.progress["initial_model_response"] = {"provider": "local", "model": "qwen-test"}
    store.save(mission)
    return runtime, mission.mission_id


def _proposal_response(provider="local", model="qwen-test", summary="bounded observation"):
    return {
        "content": json.dumps({
            "summary": summary,
            "recommendations": ["Review the parent task result"],
            "open_questions": [],
        }),
        "provider": provider,
        "model": model,
        "tool_calls": [],
    }


def _special_graph(mission):
    return TaskGraph.from_dict(mission.agent_task_graph_state["specialist_graph"]["graph"])


def test_model_router_exact_provider_never_falls_back():
    class Provider:
        capabilities = ProviderCapabilities(generate=True)

        def __init__(self, name, model, result=None, error=None):
            self.name, self.model = name, model
            self.result, self.error = result, error
            self.calls = 0

        def generate(self, messages, **kwargs):
            self.calls += 1
            if self.error:
                raise self.error
            return self.result

    active = Provider("local", "qwen-test", error=TimeoutError("unavailable"))
    fallback = Provider("remote", "cloud-model", {"content": "must not be returned"})
    router = ModelRouter([active, fallback])

    with pytest.raises(ProviderTimeout):
        router.generate_for_provider("local", "qwen-test", [{"role": "user", "content": "bounded"}], max_tokens=10)
    assert active.calls == 1
    assert fallback.calls == 0
    with pytest.raises(CapabilityUnsupported):
        router.generate_for_provider("remote", "different-model", [{"role": "user", "content": "bounded"}])
    assert fallback.calls == 0


def test_independent_children_run_in_parallel_with_isolated_context_and_no_effects(tmp_path):
    barrier = threading.Barrier(2)
    lock = threading.Lock()
    active = 0
    maximum = 0
    contexts = []
    tool_calls = []

    def provider(provider_name, model_name, messages, **kwargs):
        nonlocal active, maximum
        assert provider_name == "local" and model_name == "qwen-test"
        assert kwargs["max_tokens"] <= 384 and kwargs["timeout"] <= 30
        assert len(json.dumps(messages)) <= 4096
        payload = json.loads(messages[1]["content"].split("\n", 1)[1])
        assert set(payload) == {"child_task_id", "task_objective", "expected_observation"}
        if payload["task_objective"].startswith("Analyze alpha"):
            assert "SECRET-SIBLING" not in json.dumps(payload)
        if payload["task_objective"].startswith("Analyze beta"):
            assert "alpha-only" not in json.dumps(payload)
            assert "supersecret123" not in json.dumps(payload)
            assert "two words" not in json.dumps(payload)
            assert "ghp_12345678901234567890123456789012345" not in json.dumps(payload)
        with lock:
            active += 1
            maximum = max(maximum, active)
            contexts.append(payload)
        try:
            barrier.wait(timeout=4)
            return _proposal_response(summary=payload["task_objective"])
        finally:
            with lock:
                active -= 1

    runtime, mission_id = _runtime(
        tmp_path,
        (
            PlanStep("alpha", "Analyze alpha indicators", action="status", expected_observation="alpha-only"),
            PlanStep("beta", 'Analyze beta indicators SECRET-SIBLING API_KEY=supersecret123 password="two words" GitHub token ghp_12345678901234567890123456789012345', action="search", expected_observation="beta-only"),
            PlanStep("gamma", "Analyze gamma after alpha", prerequisites=("alpha",), action="status"),
        ),
        provider,
        executor=lambda *args, **kwargs: tool_calls.append(args) or pytest.fail("tool execution forbidden in specialist slice"),
    )

    completed = runtime.run_slice(mission_id)

    assert completed.checkpoint["status"] == "specialists_completed"
    assert maximum == 2
    assert len(contexts) == 2
    assert len({context["child_task_id"] for context in contexts}) == 2
    by_objective = {item["task_objective"]: json.dumps(item) for item in contexts}
    assert "beta-only" not in by_objective["Analyze alpha indicators"]
    beta_context = next(value for objective, value in by_objective.items() if objective.startswith("Analyze beta indicators"))
    assert "alpha-only" not in beta_context
    assert "supersecret123" not in beta_context
    assert "two words" not in beta_context
    assert "ghp_12345678901234567890123456789012345" not in beta_context
    assert tool_calls == []
    assert completed.action_history == []
    assert completed.evidence == []
    assert all(item["record_type"] == "UNTRUSTED_SPECIALIST_PROPOSAL" for item in completed.observations)
    assert all(item["authority"] == "none" for item in completed.observations)

    graph_state = completed.agent_task_graph_state["specialist_graph"]
    graph = TaskGraph.from_dict(graph_state["graph"])
    assert graph.policy.max_parallel_tasks == 2
    assert all(task.evidence_refs == () and task.artifacts == () for task in graph.tasks.values() if task.lifecycle is TaskLifecycle.COMPLETED)
    assert all(task.result_validation_state == "UNTRUSTED_PROPOSAL" for task in graph.tasks.values() if task.lifecycle is TaskLifecycle.COMPLETED)
    child_agents = [agent for agent in graph.agents.values() if agent.role == "mission_specialist_analyst"]
    assert child_agents
    completed_child_ids = {task.assigned_agent_id for task in graph.tasks.values() if task.lifecycle is TaskLifecycle.COMPLETED}
    assert all(agent.lifecycle is AgentLifecycle.COMPLETED for agent in child_agents if agent.agent_id in completed_child_ids)
    assert all(not agent.permission_scope.allowed_tools and not agent.permission_scope.allowed_actions for agent in child_agents)
    assert all(not agent.permission_scope.allowed_networks and not agent.permission_scope.allowed_credentials for agent in child_agents)
    assert all(not agent.permission_scope.workspace_root and not agent.permission_scope.scope for agent in child_agents)
    assert completed.agent_task_graph_state["specialist_graph"]["last_batch"]["provider_name"] == "local"


def test_unavailable_bound_provider_fails_children_without_using_fallback(tmp_path):
    class Provider:
        capabilities = ProviderCapabilities(generate=True)
        def __init__(self, name, model):
            self.name, self.model, self.calls = name, model, 0
        def generate(self, messages, **kwargs):
            self.calls += 1
            return _proposal_response(self.name, self.model)

    remote_fallback = Provider("remote", "cloud-model")
    router = ModelRouter([remote_fallback])
    runtime, mission_id = _runtime(
        tmp_path,
        (PlanStep("one", "Analyze one", action="status"), PlanStep("two", "Analyze two", action="search")),
        lambda provider, model, messages, **kwargs: router.generate_for_provider(provider, model, messages, **kwargs),
    )
    mission = runtime.store.load(mission_id)
    mission.progress["initial_model_response"] = {"provider": "local", "model": "qwen-test"}
    runtime.store.save(mission)

    result = runtime.run_slice(mission_id)

    graph = _special_graph(result)
    assert remote_fallback.calls == 0
    assert all(task.lifecycle is TaskLifecycle.FAILED for task in graph.tasks.values())
    assert all(task.result_validation_state == "PROVIDER_UNAVAILABLE" for task in graph.tasks.values())
    assert all(task.result["record_type"] == "SPECIALIST_PROVIDER_FAILURE" for task in graph.tasks.values())
    assert result.observations == []


def test_owner_authorization_recheck_denial_aborts_claim_before_provider_calls(tmp_path):
    provider_calls = []
    runtime, mission_id = _runtime(
        tmp_path,
        (PlanStep("one", "Analyze one", action="status"), PlanStep("two", "Analyze two", action="search")),
        lambda *args, **kwargs: provider_calls.append(args) or _proposal_response(),
    )
    original_check = runtime._mission_authorization
    checks = 0

    def revoked_after_claim(mission):
        nonlocal checks
        checks += 1
        if checks == 2:
            return False, "owner authorization no longer current"
        return original_check(mission)

    runtime._mission_authorization = revoked_after_claim
    result = runtime.run_slice(mission_id)

    graph = _special_graph(result)
    assert checks == 2
    assert provider_calls == []
    assert result.status is MissionStatus.SAFETY_BLOCKED
    assert result.checkpoint["status"] == "specialists_aborted"
    assert all(task.lifecycle is TaskLifecycle.FAILED for task in graph.tasks.values())
    assert all(task.result_validation_state == "AUTHORIZATION_BLOCKED" for task in graph.tasks.values())
    assert result.agent_task_graph_state["specialist_graph"]["active_batch"] is None


def test_provider_timeout_is_durable_ambiguous_and_dependent_specialist_is_blocked(tmp_path):
    calls = []

    def provider(provider_name, model_name, messages, **kwargs):
        payload = json.loads(messages[1]["content"].split("\n", 1)[1])
        calls.append(payload["child_task_id"])
        if payload["task_objective"] == "Analyze alpha":
            raise ProviderTimeout("private provider detail must not persist")
        return _proposal_response()

    runtime, mission_id = _runtime(
        tmp_path,
        (
            PlanStep("alpha", "Analyze alpha", action="status"),
            PlanStep("beta", "Analyze beta", action="search"),
            PlanStep("gamma", "Analyze gamma", prerequisites=("alpha",), action="status"),
        ),
        provider,
    )
    result = runtime.run_slice(mission_id)
    graph = _special_graph(result)
    task_by_step = {step_id: graph.tasks[task_id] for step_id, task_id in result.agent_task_graph_state["specialist_graph"]["step_task_ids"].items()}
    assert len(calls) == 2
    assert task_by_step["alpha"].lifecycle is TaskLifecycle.FAILED
    assert task_by_step["alpha"].result_validation_state == "QUARANTINED_PROVIDER_OUTCOME_UNKNOWN"
    assert "private provider detail" not in json.dumps(result.agent_task_graph_state)
    assert task_by_step["gamma"].lifecycle is TaskLifecycle.BLOCKED
    assert task_by_step["beta"].lifecycle is TaskLifecycle.COMPLETED


def test_in_flight_provider_batch_is_quarantined_on_recovery_without_replay(tmp_path):
    provider_calls = []
    runtime, mission_id = _runtime(
        tmp_path,
        (PlanStep("one", "Analyze one", action="status"), PlanStep("two", "Analyze two", action="search")),
        lambda *args, **kwargs: provider_calls.append(args) or _proposal_response(),
        executor=lambda *args, **kwargs: {"success": True, "result": {"parent_tool": "test-double"}},
    )
    mission = runtime.store.load(mission_id)
    snapshot = runtime._typed_mission_snapshot(mission)
    ready = runtime.task_graph_adapter.ready_specialist_steps(mission, snapshot)
    step_ids = tuple(step for step, _task_id in ready)
    mapping = dict(ready)
    batch_id = "recovery-test-batch"
    execution_ids = tuple(f"{batch_id}:{mapping[step]}" for step in step_ids)
    task_map = runtime.task_graph_adapter.claim_specialist_batch(
        mission, snapshot, step_ids, batch_id=batch_id,
        provider_name="local", model_name="qwen-test", execution_ids=execution_ids,
    )
    task_ids = tuple(task_map[step] for step in step_ids)
    mission.checkpoint = {
        "status": "in_flight_specialists", "batch_id": batch_id,
        "plan_version": mission.plan.version, "step_ids": list(step_ids),
        "task_ids": list(task_ids), "execution_ids": list(execution_ids),
        "task_execution_bindings": [
            {"task_id": task_id, "execution_id": execution_id}
            for task_id, execution_id in zip(task_ids, execution_ids)
        ],
        "provider_name": "local", "model_name": "qwen-test",
    }
    runtime.store.save(mission)

    recovered = runtime.run_slice(mission_id)
    graph = _special_graph(recovered)
    assert recovered.checkpoint["status"] == "specialists_quarantined"
    assert provider_calls == []
    assert all(graph.tasks[task_id].lifecycle is TaskLifecycle.FAILED for task_id in task_ids)
    assert all(graph.tasks[task_id].result_validation_state == "QUARANTINED_PROVIDER_OUTCOME_UNKNOWN" for task_id in task_ids)
    runtime.run_slice(mission_id)
    assert provider_calls == []


def test_in_flight_provider_batch_is_quarantined_after_owner_authorization_renewal(tmp_path):
    provider_calls = []
    runtime, mission_id = _runtime(
        tmp_path,
        (PlanStep("one", "Analyze one", action="status"), PlanStep("two", "Analyze two", action="search")),
        lambda *args, **kwargs: provider_calls.append(args) or _proposal_response(),
    )
    mission = runtime.store.load(mission_id)
    snapshot = runtime._typed_mission_snapshot(mission)
    ready = runtime.task_graph_adapter.ready_specialist_steps(mission, snapshot)
    step_ids = tuple(step for step, _task_id in ready)
    mapping = dict(ready)
    batch_id = "authorization-renewal-recovery"
    execution_ids = tuple(f"{batch_id}:{mapping[step]}" for step in step_ids)
    task_map = runtime.task_graph_adapter.claim_specialist_batch(
        mission, snapshot, step_ids, batch_id=batch_id,
        provider_name="local", model_name="qwen-test", execution_ids=execution_ids,
    )
    task_ids = tuple(task_map[step] for step in step_ids)
    bindings = [
        {"task_id": task_id, "execution_id": execution_id}
        for task_id, execution_id in zip(task_ids, execution_ids)
    ]
    mission.checkpoint = {
        "status": "in_flight_specialists", "batch_id": batch_id,
        "plan_version": mission.plan.version, "step_ids": list(step_ids),
        "task_ids": list(task_ids), "execution_ids": list(execution_ids),
        "task_execution_bindings": bindings,
        "provider_name": "local", "model_name": "qwen-test",
    }
    runtime.store.save(mission)
    renewed = MissionAuthorizationSnapshot.from_dict(mission.authorization_snapshot).amend(
        owner_approval="test-owner-approved-renewal",
        changes={},
    )
    mission.authorization_snapshot = renewed.to_dict()
    mission.provenance["authorization_snapshot_version"] = renewed.version
    runtime.store.save(mission)

    recovered = runtime.run_slice(mission_id)

    graph = _special_graph(recovered)
    assert recovered.checkpoint["status"] == "specialists_quarantined"
    assert provider_calls == []
    assert all(graph.tasks[task_id].lifecycle is TaskLifecycle.FAILED for task_id in task_ids)
    assert all(graph.tasks[task_id].result_validation_state == "QUARANTINED_PROVIDER_OUTCOME_UNKNOWN" for task_id in task_ids)


def test_owner_cancellation_discards_inflight_proposals(tmp_path):
    holder = {}
    provider_calls = []
    provider_barrier = threading.Barrier(2)
    cancel_lock = threading.Lock()
    cancellation_applied = False

    def provider(provider_name, model_name, messages, **kwargs):
        nonlocal cancellation_applied
        provider_calls.append(True)
        provider_barrier.wait(timeout=5)
        with cancel_lock:
            if not cancellation_applied:
                cancellation_applied = True
                mission = holder["runtime"].store.load(holder["mission_id"])
                holder["runtime"].task_graph_adapter.cancel(mission)
                mission.transition(MissionStatus.CANCELLED, "owner requested cancellation")
                holder["runtime"].store.save(mission)
        return _proposal_response()

    runtime, mission_id = _runtime(
        tmp_path,
        (PlanStep("one", "Analyze one", action="status"), PlanStep("two", "Analyze two", action="search")),
        provider,
        executor=lambda *args, **kwargs: pytest.fail("cancelled specialists must not dispatch tools"),
    )
    holder.update(runtime=runtime, mission_id=mission_id)

    cancelled = runtime.run_slice(mission_id)

    graph = _special_graph(cancelled)
    assert cancelled.status is MissionStatus.CANCELLED
    assert len(provider_calls) == 2
    assert cancelled.observations == []
    assert all(task.lifecycle is TaskLifecycle.CANCELLED for task in graph.tasks.values())
    assert all(task.result_validation_state == "CANCELLED_RESULT_DISCARDED" for task in graph.tasks.values())
    from agent import memory
    assert memory.MemoryProvider.get_memory_by_conversation(
        f"mission:{mission_id}",
        domain=memory.MemoryDomain.TASK_STATE,
        owner_identity_ref=cancelled.owner_identity_ref,
        mission_id=mission_id,
    ) == []


def test_scope_tampering_is_rejected_before_any_provider_call(tmp_path):
    calls = []
    runtime, mission_id = _runtime(
        tmp_path,
        (PlanStep("one", "Analyze one", action="status"), PlanStep("two", "Analyze two", action="search")),
        lambda *args, **kwargs: calls.append(args) or _proposal_response(),
    )
    mission = runtime.store.load(mission_id)
    snapshot = runtime._typed_mission_snapshot(mission)
    assert len(runtime.task_graph_adapter.ready_specialist_steps(mission, snapshot)) == 2
    state = mission.agent_task_graph_state["specialist_graph"]
    child = next(item for item in state["graph"]["agents"] if item["role"] == "mission_specialist_analyst")
    child["permission_scope"]["allowed_tools"] = ["status"]
    runtime.store.save(mission)

    blocked = runtime.run_slice(mission_id)

    assert calls == []
    assert blocked.status is MissionStatus.SAFETY_BLOCKED
    assert blocked.failures[-1]["boundary"] == "agent_task_graph"


def test_strict_worker_lease_validates_task_bound_child_fences_before_generation(tmp_path):
    calls = []
    plan = _plan(
        PlanStep("one", "Analyze one", action="status"),
        PlanStep("two", "Analyze two", action="search"),
    )
    store = MissionStore(tmp_path / "strict-missions.sqlite3")
    runtime = MissionRuntime(
        store,
        executor=lambda *_args, **_kwargs: pytest.fail("provider specialist must not dispatch tools"),
        authorization_snapshot_factory=make_test_snapshot,
        task_graph_policy=AgentGraphPolicy(max_agents=8, max_tasks=16, max_parallel_tasks=2, max_retries=0),
        require_execution_fence=True,
        specialist_generate=lambda provider, model, messages, **kwargs: _proposal_response(provider, model),
    )
    mission = runtime.create(plan.objective, plan.objective, plan, owner_identity_ref="test-owner")
    mission.progress["initial_model_response"] = {"provider": "local", "model": "qwen-test"}
    store.save(mission)
    queue = MissionQueue(tmp_path / "strict-queue.sqlite3", require_execution_fence=True, mission_store=store)
    queue.enqueue(mission.mission_id)
    identity = queue.register_worker("specialist-fence-test-worker")
    worker_fence = ExecutionFence.for_worker(queue, identity)
    claim = queue.claim_next(
        now=datetime.now(timezone.utc).isoformat(),
        worker_id=identity.worker_id,
        worker_instance_id=identity.worker_instance_id,
        runtime_generation=identity.runtime_generation,
        lease_seconds=600,
        execution_fence=worker_fence,
    )
    assert claim is not None
    first_execution = f"{mission.mission_id}:{mission.plan.version}:one:0"
    owner_fence = worker_fence.with_lease(claim).for_mission(
        mission, task_id="one", execution_id=first_execution,
    )
    store.bind_execution_claim(mission.mission_id, owner_fence)
    runtime.set_execution_fence(owner_fence)

    def provider(provider, model, messages, **kwargs):
        current = store.load(mission.mission_id)
        payload = json.loads(messages[1]["content"].split("\n", 1)[1])
        binding = next(item for item in current.checkpoint["task_execution_bindings"] if item["task_id"] == payload["child_task_id"])
        child_fence = runtime._fence_for(
            current,
            task_id=binding["task_id"],
            execution_id=binding["execution_id"],
        )
        assert child_fence is not None
        child_fence.assert_active_execution(current)
        calls.append((binding["task_id"], binding["execution_id"]))
        return _proposal_response(provider, model)

    runtime.specialist_generate = provider
    result = runtime.run_slice(mission.mission_id)
    assert result.checkpoint["status"] == "specialists_completed"
    assert len(calls) == 2
    assert len(set(calls)) == 2


def test_specialist_dispatch_does_not_run_when_fewer_than_two_tasks_are_ready(tmp_path):
    calls = []
    runtime, mission_id = _runtime(
        tmp_path,
        (
            PlanStep("one", "Analyze one", action="status"),
            PlanStep("two", "Analyze two after one", prerequisites=("one",), action="search"),
        ),
        lambda *args, **kwargs: calls.append(args) or _proposal_response(),
        executor=lambda *args, **kwargs: {"success": True, "result": {"read": True}},
    )
    result = runtime.run_slice(mission_id)
    assert calls == []
    # The ordinary parent runtime remains responsible for the authoritative tool action.
    assert result.current_step in {1, 2}


def test_specialist_outputs_live_in_schema4_memory_and_parent_reads_only_verified_refs(tmp_path):
    from agent import memory
    from agent.intelligence_layer.specialist_memory import (
        MAX_SPECIALIST_MEMORY_RECORD_BYTES,
        SpecialistChildMemoryStore,
        SpecialistMemoryError,
    )
    from agent.model_intelligence.context import ContextAssembler

    proposal = {
        "summary": "stored child summary password=\"never store this value\" Bearer abcdefghijklmnopqrstuvwxyz123456 -----BEGIN PRIVATE KEY-----hidden-material-----END PRIVATE KEY-----",
        "recommendations": ["Use bounded checks; API_KEY=sk-123456789012345678901234567890"],
        "open_questions": ["Is raw context kept?"],
    }

    def provider(provider_name, model_name, _messages, **_kwargs):
        return {
            "content": json.dumps(proposal),
            "provider": provider_name,
            "model": model_name,
            "tool_calls": [],
        }

    runtime, mission_id = _runtime(
        tmp_path,
        (PlanStep("alpha", "Analyze alpha MISSION_CONTEXT_SENTINEL", action="status"),
         PlanStep("beta", "Analyze beta", action="search")),
        provider,
    )
    completed = runtime.run_slice(mission_id)
    graph = _special_graph(completed)
    assert all(task.memory_refs and len(task.memory_refs) == 1 for task in graph.tasks.values())
    assert all(set(task.result) == {"record_type", "authority", "memory_ref"} for task in graph.tasks.values())
    assert all("stored child summary" not in json.dumps(task.to_dict()) and "never store this value" not in json.dumps(task.to_dict()) for task in graph.tasks.values())
    assert all("proposal" not in item and "stored child summary" not in json.dumps(item) for item in completed.observations)

    records = memory.MemoryProvider.get_memory_by_conversation(
        f"mission:{mission_id}",
        domain=memory.MemoryDomain.TASK_STATE,
        owner_identity_ref=completed.owner_identity_ref,
        mission_id=mission_id,
    )
    assert len(records) == 2
    assert all(item.trust_classification is memory.TrustClassification.UNTRUSTED_DATA for item in records)
    assert all(item.validation_state is memory.MemoryValidationState.UNVERIFIED for item in records)
    assert all(item.sensitivity is memory.MemorySensitivity.INTERNAL for item in records)
    assert all(len(item.content.encode("utf-8")) <= MAX_SPECIALIST_MEMORY_RECORD_BYTES for item in records)
    assert all(item.metadata["record_type"] == "UNTRUSTED_SPECIALIST_CHILD_MEMORY" for item in records)
    assert all(item.metadata["authority"] == "none" and item.metadata["tool_identity"] == "none" for item in records)
    assert all(item.metadata["provider"] == "local" and item.metadata["model"] == "qwen-test" for item in records)
    assert all(hashlib.sha256(json.dumps(json.loads(item.content)["proposal"], ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest() == item.metadata["result_digest"] for item in records)
    assert all("never store this value" not in item.content and "sk-123456789012345678901234567890" not in item.content for item in records)
    assert all("abcdefghijklmnopqrstuvwxyz123456" not in item.content and "hidden-material" not in item.content for item in records)
    assert all("MISSION_CONTEXT_SENTINEL" not in item.content for item in records)

    with sqlite3.connect(memory.MEMORY_DB_PATH) as db:
        assert db.execute("SELECT version FROM memory_schema_versions WHERE component='memory_items'").fetchone()[0] == 4

    state = completed.agent_task_graph_state["specialist_graph"]
    snapshot = runtime._typed_mission_snapshot(completed)
    service = SpecialistChildMemoryStore()
    task = next(iter(graph.tasks.values()))
    step_id = next(step for step, child_id in state["step_task_ids"].items() if child_id == task.task_id)
    ref = task.memory_refs[0]
    child_record = service.retrieve_for_child(
        memory_ref=ref,
        owner_identity_ref=completed.owner_identity_ref,
        mission_id=mission_id,
        agent_id=task.assigned_agent_id,
        task_id=task.task_id,
        expected_plan_fingerprint=completed.plan.fingerprint,
    )
    assert child_record is not None and child_record["trust"] == "untrusted_data"
    assert service.retrieve_for_child(memory_ref=ref, owner_identity_ref="foreign-owner", mission_id=mission_id, agent_id=task.assigned_agent_id, task_id=task.task_id, expected_plan_fingerprint=completed.plan.fingerprint) is None
    assert service.retrieve_for_child(memory_ref=ref, owner_identity_ref=completed.owner_identity_ref, mission_id="foreign-mission", agent_id=task.assigned_agent_id, task_id=task.task_id, expected_plan_fingerprint=completed.plan.fingerprint) is None
    assert service.retrieve_for_child(memory_ref=ref, owner_identity_ref=completed.owner_identity_ref, mission_id=mission_id, agent_id="foreign-agent", task_id=task.task_id, expected_plan_fingerprint=completed.plan.fingerprint) is None
    assert service.retrieve_for_child(memory_ref=ref, owner_identity_ref=completed.owner_identity_ref, mission_id=mission_id, agent_id=task.assigned_agent_id, task_id="foreign-task", expected_plan_fingerprint=completed.plan.fingerprint) is None

    parent_record = service.retrieve_for_parent(
        mission=completed,
        snapshot=snapshot,
        graph=graph,
        task_id=task.task_id,
        step_id=step_id,
        memory_ref=ref,
        authorization_version=runtime.task_graph_adapter._expected_authorization_version(completed),
    )
    assert parent_record["authority"] == "none" and parent_record["validation_state"] == "unverified"
    foreign_snapshot_payload = snapshot.to_dict()
    foreign_snapshot_payload["owner_identity"] = "foreign-owner"
    foreign_snapshot_payload["authorization_hash"] = ""
    foreign_snapshot = MissionAuthorizationSnapshot.from_dict(foreign_snapshot_payload)
    with pytest.raises(SpecialistMemoryError, match="memory_mission_binding_invalid"):
        service.retrieve_for_parent(
            mission=completed,
            snapshot=foreign_snapshot,
            graph=graph,
            task_id=task.task_id,
            step_id=step_id,
            memory_ref=ref,
            authorization_version=runtime.task_graph_adapter._expected_authorization_version(completed),
        )
    transient = runtime._specialist_memory_context(completed)
    assert len(transient) == 2
    assembled = ContextAssembler().build(completed, specialist_memory=transient, max_chars=100000)
    section = assembled.sections["specialist_memory"]
    assert section["trust"] == "untrusted_data" and section["authority"] == "none"
    assert len(section["items"]) == 2
    assert not any("stored child summary" in json.dumps(item) for item in completed.observations)
    budgeted = ContextAssembler().build(completed, specialist_memory=transient, max_chars=100)
    assert budgeted.sections["specialist_memory"]["items"][0]["record_type"] == "SPECIALIST_MEMORY_OMITTED_FOR_CONTEXT_BUDGET"

    step = next(item for item in completed.plan.steps if item.step_id == step_id)
    same_ref = service.persist_proposal(
        mission=completed,
        snapshot=snapshot,
        graph=graph,
        task_id=task.task_id,
        step_id=step_id,
        proposal=proposal,
        provider="local",
        model="qwen-test",
        authorization_version=runtime.task_graph_adapter._expected_authorization_version(completed),
    )
    assert same_ref["memory_ref"] == ref
    assert len(memory.MemoryProvider.get_memory_by_conversation(f"mission:{mission_id}", domain=memory.MemoryDomain.TASK_STATE, owner_identity_ref=completed.owner_identity_ref, mission_id=mission_id)) == 2
    changed = {**proposal, "summary": "different retry result"}
    with pytest.raises(ValueError, match="memory_idempotency_conflict"):
        service.persist_proposal(
            mission=completed,
            snapshot=snapshot,
            graph=graph,
            task_id=task.task_id,
            step_id=step.step_id,
            proposal=changed,
            provider="local",
            model="qwen-test",
            authorization_version=runtime.task_graph_adapter._expected_authorization_version(completed),
        )


def test_specialist_memory_rejects_corrupt_record_and_bounds_multibyte_payloads(tmp_path):
    from agent import memory
    from agent.intelligence_layer.specialist_memory import (
        MAX_SPECIALIST_MEMORY_RECORD_BYTES,
        SpecialistChildMemoryStore,
        SpecialistMemoryError,
        _bounded_proposal,
    )

    runtime, mission_id = _runtime(
        tmp_path,
        (PlanStep("one", "Analyze one", action="status"), PlanStep("two", "Analyze two", action="search")),
        lambda provider, model, _messages, **_kwargs: _proposal_response(provider, model),
    )
    completed = runtime.run_slice(mission_id)
    graph = _special_graph(completed)
    task = next(iter(graph.tasks.values()))
    ref = task.memory_refs[0]
    service = SpecialistChildMemoryStore()
    with sqlite3.connect(memory.MEMORY_DB_PATH) as db:
        db.execute("UPDATE memory_items SET content=? WHERE memory_id=?", ('{"tampered":true}', ref))
    with pytest.raises(SpecialistMemoryError, match="corrupt"):
        service.retrieve_for_child(
            memory_ref=ref,
            owner_identity_ref=completed.owner_identity_ref,
            mission_id=mission_id,
            agent_id=task.assigned_agent_id,
            task_id=task.task_id,
            expected_plan_fingerprint=completed.plan.fingerprint,
        )

    source_digest = "a" * 64
    safe, content, truncated = _bounded_proposal(
        {"summary": "🙂" * 1200, "recommendations": ["🙂" * 400], "open_questions": []},
        task_id="specialist:test",
        provider="local",
        model="qwen-test",
        source_digest=source_digest,
    )
    assert truncated is True
    assert len(content.encode("utf-8")) <= MAX_SPECIALIST_MEMORY_RECORD_BYTES
    assert len(safe["summary"]) < 1200
    with pytest.raises(SpecialistMemoryError, match="too_large"):
        _bounded_proposal(
            {"summary": "x" * 9000, "recommendations": [], "open_questions": []},
            task_id="specialist:test",
            provider="local",
            model="qwen-test",
            source_digest=source_digest,
        )
