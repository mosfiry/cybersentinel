from __future__ import annotations

import argparse
from dataclasses import replace
import json
import os
from pathlib import Path
import secrets
import sys
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.acceptance_result import apply_cleanup_gate

DEFAULT_RUNTIME_DIR = Path("/workspace/cybersentinel-acceptance-runtime/extracted/llama-b11146")
DEFAULT_MODEL_PATH = Path(
    "/workspace/cybersentinel-acceptance-runtime/state/manager/models/"
    "qwen3-4b-q4-k-m/Qwen3-4B-Q4_K_M.gguf"
)


class RecordingRouter:
    """Transparent trace proxy; every inference still reaches the real local router/provider."""

    def __init__(self, inner):
        self.inner = inner
        self.calls: list[dict[str, object]] = []
        self.planning_calls: list[dict[str, object]] = []
        self.lock = threading.Lock()

    def __getattr__(self, name):
        return getattr(self.inner, name)

    @staticmethod
    def _planning_messages(messages):
        prepared = [dict(item) if isinstance(item, dict) else item for item in messages]
        for item in prepared:
            if isinstance(item, dict) and item.get("role") == "user" and isinstance(item.get("content"), str):
                item["content"] = "/no_think\n" + item["content"]
                break
        return prepared

    def generate(self, messages, **kwargs):
        return self._record_planning_call(self.inner.generate, messages, **kwargs)

    def tool_calling(self, messages, tools, **kwargs):
        return self._record_planning_call(self.inner.tool_calling, messages, tools, **kwargs)

    def _record_planning_call(self, invoke, messages, *args, **kwargs):
        prepared = self._planning_messages(messages)
        call_id = uuid.uuid4().hex
        record: dict[str, object] = {
            "call_id": call_id,
            "phase": "parent_planning",
            "thread_id": threading.get_ident(),
            "start_ns": time.time_ns(),
            "message_count": len(prepared),
        }
        try:
            response = invoke(prepared, *args, **kwargs)
            record["result"] = "ok"
            record["provider"] = str(response.get("provider", ""))
            record["model"] = str(response.get("model", ""))
            record["response_chars"] = len(str(response.get("content", "")))
            record["finish_reason"] = str(response.get("finish_reason", ""))
            record["tool_call_count"] = len(response.get("tool_calls", ()))
            usage = response.get("usage")
            if isinstance(usage, dict) and type(usage.get("completion_tokens")) is int:
                record["completion_tokens"] = usage["completion_tokens"]
            return response
        except Exception as exc:
            record["result"] = "error"
            record["error_type"] = type(exc).__name__
            raise
        finally:
            record["end_ns"] = time.time_ns()
            with self.lock:
                self.planning_calls.append(record)

    def generate_for_provider(self, provider_name, model_name, messages, **kwargs):
        call_id = uuid.uuid4().hex
        record: dict[str, object] = {
            "call_id": call_id,
            "provider": str(provider_name),
            "model": str(model_name),
            "thread_id": threading.get_ident(),
            "start_ns": time.time_ns(),
            "message_count": len(messages),
        }
        try:
            response = self.inner.generate_for_provider(
                provider_name, model_name, messages, **kwargs
            )
            record["result"] = "ok"
            record["response_provider"] = str(response.get("provider", ""))
            record["response_model"] = str(response.get("model", ""))
            content = response.get("content", "")
            record["response_chars"] = len(content) if isinstance(content, str) else 0
            record["finish_reason"] = str(response.get("finish_reason", ""))
            usage = response.get("usage")
            if isinstance(usage, dict) and type(usage.get("completion_tokens")) is int:
                record["completion_tokens"] = usage["completion_tokens"]
            return response
        except Exception as exc:
            record["result"] = "error"
            record["error_type"] = type(exc).__name__
            raise
        finally:
            record["end_ns"] = time.time_ns()
            with self.lock:
                self.calls.append(record)


def emit(path: Path, payload: dict[str, object], *, code: int = 0) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
    if code:
        raise SystemExit(code)


def progress(message: str) -> None:
    print(f"[acceptance] {message}", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run one isolated real-Qwen parent Mission with two specialist child workers."
    )
    parser.add_argument("--runtime-dir", type=Path, default=DEFAULT_RUNTIME_DIR)
    parser.add_argument("--model-file", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    args = parser.parse_args()

    runtime_dir = args.runtime_dir.expanduser().resolve()
    model_path = args.model_file.expanduser().resolve()
    state_dir = args.state_dir.expanduser().resolve()
    artifact = args.artifact.expanduser().resolve()
    if not (runtime_dir / "llama-server").is_file() or not model_path.is_file():
        emit(artifact, {"status": "BLOCKED", "reason": "local_qwen_runtime_or_model_missing"}, code=2)
    state_dir.mkdir(parents=True, exist_ok=True)

    runtime = None
    evidence: dict[str, object] = {
        "schema": "real-multiagent-acceptance-v1",
        "status": "FAILED",
        "provider_requested": "qwen3-4b-q4-k-m",
        "model_file": str(model_path),
        "runtime_transport": "local_loopback_only",
        "evidence_scope": "isolated temporary Owner/Mission SQLite databases",
    }
    try:
        # Route all authority/session state to this run's private temporary root.
        import core.db as core_db
        core_db.DB_PATH = state_dir / "owner.sqlite3"
        with core_db.connect():
            pass

        from security.owner_password import OWNER_USERNAME, create_owner_account, login

        owner_password = secrets.token_urlsafe(32)
        create_owner_account(OWNER_USERNAME, owner_password)
        owner_session = login(OWNER_USERNAME, owner_password)

        from agent.local_runtime.catalog import get_model
        from agent.local_runtime.runtime import LlamaCppRuntime
        from agent.model_router import ModelRouter
        from agent.agent_core import AgentCore
        from agent.intelligence_layer.graph import AgentGraphPolicy
        from agent.mission import MissionStore
        from agent.intelligence_layer.models import DelegationDenied
        from agent.intelligence_layer.graph import TaskGraph

        spec = get_model("qwen3-4b-q4-k-m")
        progress("starting the existing local llama.cpp runtime on loopback")
        runtime = LlamaCppRuntime(runtime_dir)
        provider = runtime.start(spec, model_path)
        # Exercise the production planned-step MissionRuntime path. The local
        # Qwen model is still the real planner and specialist generator; the
        # canonical tools are dispatched one at a time rather than letting a
        # single native turn create an ambiguous multi-tool execution claim.
        provider.capabilities = replace(provider.capabilities, native_chat=False)
        evidence["execution_mode"] = "production_planned_step_mission_runtime"
        evidence["native_tool_loop_used"] = False
        progress("local Qwen provider is ready; creating the real Owner Mission")
        base_router = ModelRouter([provider])
        router = RecordingRouter(base_router)
        store = MissionStore(state_dir / "missions.sqlite3")
        policy = AgentGraphPolicy(
            max_agents=4,
            max_tasks=8,
            max_parallel_tasks=2,
            max_retries=0,
            enable_task_delegation=True,
        )
        core = AgentCore(
            router,
            store=store,
            max_iterations=12,
            task_graph_policy=policy,
            enable_specialist_agents=True,
        )
        objective = (
            "Run status and latest_intel; two parallel specialists; aggregate and verify."
        )
        progress("asking real Qwen to plan and persist the parent Mission")
        mission = core.run_owner_mission(
            objective,
            owner_session_token=owner_session["session_id"],
            completion_criteria=[{
                "criterion_id": "validated-status-snapshot",
                "description": "A status snapshot is independently validated.",
                "check": "status_snapshot",
                "required": True,
            }],
            scope_context={
                "scope": ["workspace"],
                "target_id": "multiagent-local-acceptance",
                "workspace_root": str(state_dir),
            },
            run=False,
        )
        parent_plan_valid = bool(mission.plan.steps) and mission.plan.steps[0].action != "__planning_failure__"
        if parent_plan_valid:
            progress("Qwen plan persisted; reauthenticating the Owner and resuming the same Mission")
            owner_session = login(OWNER_USERNAME, owner_password)
            mission = core.resume_mission(
                mission.mission_id,
                owner_session_token=owner_session["session_id"],
                max_slices=core.max_iterations,
            )
        else:
            progress("Qwen planning failed; no child or tool execution will be attempted")
        current = store.load(mission.mission_id)
        if current is None or not current.verify_integrity():
            raise AssertionError("parent mission integrity/persistence check failed")
        mission = current
        progress(f"parent Mission returned with status {mission.status.value}")

        plan_steps = [
            {
                "step_id": step.step_id,
                "action": step.action,
                "prerequisites": list(step.prerequisites),
            }
            for step in mission.plan.steps
        ]
        state = mission.agent_task_graph_state if isinstance(mission.agent_task_graph_state, dict) else {}
        specialist = state.get("specialist_graph") if isinstance(state.get("specialist_graph"), dict) else {}
        graph_raw = specialist.get("graph") if isinstance(specialist.get("graph"), dict) else {}
        graph = TaskGraph.from_dict(graph_raw) if graph_raw else None
        specialist_agents = []
        specialist_tasks = []
        unauthorized_denied = False
        if graph is not None:
            for agent in graph.agents.values():
                if agent.role == "mission_specialist_analyst":
                    specialist_agents.append(agent)
                    try:
                        agent.permission_scope.narrow(
                            target_identity=agent.permission_scope.target_identity,
                            scope=("workspace",),
                            allowed_tools=("status",),
                            allowed_actions=("status",),
                        )
                    except DelegationDenied:
                        unauthorized_denied = True
            specialist_tasks = [
                task for task in graph.tasks.values()
                if task.assigned_agent_id in {item.agent_id for item in specialist_agents}
            ]

        executed_tools = {
            str((item.get("observation") or {}).get("source", item.get("tool_name", item.get("tool", ""))))
            for item in mission.action_history
            if isinstance(item, dict) and item.get("status") == "completed"
        }
        batch_rows = mission.progress.get("specialist_batches", [])
        trace_calls = list(router.calls)
        planning_calls = list(router.planning_calls)
        starts = [int(item["start_ns"]) for item in trace_calls if isinstance(item.get("start_ns"), int)]
        ends = [int(item["end_ns"]) for item in trace_calls if isinstance(item.get("end_ns"), int)]
        overlapping = len(starts) >= 2 and max(starts[:2]) < min(ends[:2])
        child_records = [
            {
                "agent_id": agent.agent_id,
                "lifecycle": agent.lifecycle.value,
                "allowed_tools": list(agent.permission_scope.allowed_tools),
                "allowed_actions": list(agent.permission_scope.allowed_actions),
                "allowed_networks": list(agent.permission_scope.allowed_networks),
                "allowed_credentials": list(agent.permission_scope.allowed_credentials),
            }
            for agent in specialist_agents
        ]
        result_records = [
            {
                "task_id": task.task_id,
                "lifecycle": task.lifecycle.value,
                "authority": task.result.get("authority") if isinstance(task.result, dict) else None,
                "trust": task.result.get("trust") if isinstance(task.result, dict) else None,
                "validation_state": task.result_validation_state,
                "failure_code": task.result.get("failure_code") if isinstance(task.result, dict) else None,
                "failure_reason": task.result.get("failure_reason") if isinstance(task.result, dict) else None,
            }
            for task in specialist_tasks
        ]
        proposal_count = sum(
            1 for item in mission.observations
            if isinstance(item, dict) and item.get("record_type") == "UNTRUSTED_SPECIALIST_PROPOSAL"
        )
        checks = {
            "real_provider_identity": bool(planning_calls) and all(
                item.get("provider") == "local_llama_cpp" and item.get("model") == spec.model_id
                for item in planning_calls
            ) and bool(trace_calls)
            and all(item.get("provider") == "local_llama_cpp" and item.get("model") == spec.model_id for item in trace_calls),
            "two_independent_plan_steps": len(plan_steps) >= 2
            and all(not item["prerequisites"] for item in plan_steps[:2]),
            "two_real_specialist_children": len(specialist_agents) == 2 and len(specialist_tasks) == 2,
            "two_child_inferences_completed": len(trace_calls) == 2
            and all(item.get("result") == "ok" and int(item.get("response_chars", 0)) > 0 for item in trace_calls)
            and len(result_records) == 2
            and all(item.get("lifecycle") == "COMPLETED" for item in result_records),
            "parallel_child_dispatch_overlap": overlapping,
            "children_have_no_authority": len(child_records) == 2
            and all(not row["allowed_tools"] and not row["allowed_actions"]
                    and not row["allowed_networks"] and not row["allowed_credentials"]
                    for row in child_records),
            "unauthorized_child_action_denied": unauthorized_denied,
            "two_untrusted_proposals_aggregated": proposal_count >= 2,
            "both_real_read_tools_executed": {"status", "latest_intel"}.issubset(executed_tools),
            "owner_mission_validator_completed": mission.status.value == "GOAL_COMPLETED"
            and mission.verification_state.get("verified") is True,
            "mission_evidence_persisted": len(mission.evidence) >= 1 and mission.verify_integrity(),
        }
        passed = all(checks.values())
        evidence.update({
            "status": "PASS" if passed else "FAIL",
            "mission_id": mission.mission_id,
            "mission_status": mission.status.value,
            "provider": base_router.status(),
            "plan": plan_steps,
            "parent_planning_calls": planning_calls,
            "worker_calls": trace_calls,
            "specialist_batches": batch_rows,
            "child_agents": child_records,
            "child_tasks": result_records,
            "proposal_count": proposal_count,
            "executed_tools": sorted(executed_tools),
            "evidence_count": len(mission.evidence),
            "validator": mission.verification_state,
            "specialist_output_token_cap": 96,
            "checks": checks,
        })
    except SystemExit:
        raise
    except Exception as exc:
        evidence["error_type"] = type(exc).__name__
        evidence["error"] = str(exc)[:500]
    finally:
        runtime_stopped = runtime is None
        if runtime is not None:
            try:
                runtime.stop()
                runtime_stopped = True
            except Exception as exc:
                evidence["runtime_stop_error"] = type(exc).__name__
                evidence["status"] = "FAIL"
        evidence["runtime_stopped_cleanly"] = runtime_stopped
        apply_cleanup_gate(evidence, {"runtime_stopped_cleanly": runtime_stopped})
    emit(artifact, evidence, code=0 if evidence.get("status") == "PASS" else 1)


if __name__ == "__main__":
    main()
