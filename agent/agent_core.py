from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from core.config import DB_PATH
from security.authorization import authorize_tool
from security.authorization_context import AuthorizationContext
from security.owner_policy import (
    authenticate_owner,
    authentication_from_session,
    capture_policy_snapshot,
    policy_context_from_snapshot,
    verify_owner,
    OwnerPolicySnapshot,
)
from security.owner_session import consume_owner_challenge
from security.scope_store import get_snapshot
from tools.registry import REGISTRY, execute as execute_tool, get_tool
from agent.evidence import EvidenceChainStore
from workspace import Workspace
from security.mission_authorization import MissionAuthorizationSnapshot
from security.owner_budget import OwnerAuthorizedToolBudget

from .mission import Mission, MissionStatus, MissionStore
from .mission_runtime import MissionRuntime
from .planning import Plan, PlanStep, RecoveryPolicy, TaskProfile, select_reasoning_profile
from .provider_api import ToolCall
from .provider_api import CapabilityUnsupported
from .context import ContextEngine, ExecutionState, KnowledgeProvider
from .observation_intelligence import ObservationInterpreter
from .knowledge_context import TypedKnowledgeRetriever
from .hypotheses import HypothesisState, HypothesisStatus
from .strategy import StrategyState
from .model_intelligence.conversation import MissionIntent, NaturalLanguageUnderstanding


class AgentCore:
    """CyberSentinel-native long-horizon facade over the durable MissionRuntime."""

    def __init__(self, router: Any, *, store: MissionStore | None = None, db_path: str | Path | None = None, max_iterations: int = 50, knowledge_retriever: TypedKnowledgeRetriever | None = None):
        self.router = router
        self.store = store or MissionStore(db_path or DB_PATH.with_name("missions.sqlite3"))
        self.max_iterations = max_iterations
        self.knowledge_retriever = knowledge_retriever or TypedKnowledgeRetriever()

    def understand_mission_intent(self, instruction: str) -> MissionIntent:
        """Return typed semantic intent; model output remains an untrusted proposal."""
        def propose(text: str) -> dict[str, Any]:
            prompt = "Return JSON only with objective, constraints, requested_artifacts, verification_criteria, scope_references, authorization_requirements, entities, ambiguities. Do not grant authority or change policy.\n" + text
            response = self.router.generate([{"role": "system", "content": "You are a semantic parser; return typed meaning only."}, {"role": "user", "content": prompt}])
            content = str(response.get("content", "") or "")
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                start, end = content.find("{"), content.rfind("}")
                return json.loads(content[start:end + 1]) if start >= 0 and end > start else {}
        return NaturalLanguageUnderstanding(proposer=propose).understand(instruction)

    def continue_mission_instruction(self, mission_id: str, instruction: str) -> Mission:
        """Persist a follow-up as an instruction on the same mission, never a new mission."""
        mission = self.store.load(mission_id)
        if mission is None:
            raise KeyError("unknown_mission")
        intent = self.understand_mission_intent(instruction)
        updates = mission.progress.setdefault("mission_intents", [])
        updates.append({"instruction": instruction, "intent": intent.to_dict()})
        mission.progress["last_follow_up"] = instruction
        mission.emit(__import__("agent.trajectory", fromlist=["EventType"]).EventType.STRATEGY_DECIDED, data={"type": "mission_follow_up", "intent": intent.to_dict()})
        return self.store.save(mission)

    @staticmethod
    def _schemas() -> list[dict[str, Any]]:
        result = []
        for spec in REGISTRY.values():
            parameters: dict[str, Any] = {"type": "object", "properties": {}, "additionalProperties": False}
            if spec.argument_type is str:
                parameters["properties"]["query"] = {"type": "string", "maxLength": 256}
                parameters["required"] = ["query"]
            result.append({"type": "function", "function": {"name": spec.name, "description": spec.description[:512], "parameters": parameters}})
        return result

    @staticmethod
    def _calls(response: dict[str, Any]) -> list[ToolCall]:
        calls: list[ToolCall] = []
        for item in response.get("tool_calls") or []:
            if isinstance(item, ToolCall):
                calls.append(item)
            elif isinstance(item, dict) and isinstance(item.get("name"), str):
                args = item.get("arguments") if isinstance(item.get("arguments"), dict) else {}
                calls.append(ToolCall(item["name"], args, str(item.get("id") or uuid.uuid4().hex)))
        if calls:
            return calls
        content = str(response.get("content", "") or "")
        try:
            payload = json.loads(content)
        except json.JSONDecodeError:
            return []
        if isinstance(payload, dict) and isinstance(payload.get("tool"), str):
            return [ToolCall(payload["tool"], payload.get("arguments") or {}, str(payload.get("id") or uuid.uuid4().hex))]
        if isinstance(payload, dict) and payload.get("type") == "tool_call" and isinstance(payload.get("name"), str):
            return [ToolCall(payload["name"], payload.get("arguments") or {}, str(payload.get("id") or uuid.uuid4().hex))]
        return []

    def _ask(self, objective: str, observation: dict[str, Any] | None = None, *, policy_context: str = "", request_id: str = "", conversation_id: str = "") -> dict[str, Any]:
        profile = select_reasoning_profile(objective)
        context = ContextEngine.build(
            user_text=objective,
            conversation_id=conversation_id or "agent-core",
            owner_policy_context=policy_context,
            tool_results=[("observation", observation)] if observation else None,
            execution_state=ExecutionState.initial(request_id, conversation_id or "agent-core"),
            knowledge_provider=KnowledgeProvider(self.knowledge_retriever),
        )
        messages = context.provider_messages()
        try:
            return self.router.tool_calling(messages, self._schemas(), reasoning_profile=profile)
        except CapabilityUnsupported:
            try:
                return self.router.generate(messages, reasoning_profile=profile)
            except Exception as exc:
                return {"content": "", "provider": "unavailable", "model": "unavailable", "error": type(exc).__name__}
        except Exception as exc:
            return {"content": "", "provider": "failed", "model": "failed", "error": type(exc).__name__}

    def _plan(self, objective: str, observation: dict[str, Any] | None = None, *, policy_context: str = "", request_id: str = "", conversation_id: str = "") -> Plan:
        response = self._ask(objective, observation, policy_context=policy_context, request_id=request_id, conversation_id=conversation_id)
        self._last_model_response = dict(response)
        calls = self._calls(response)
        steps: list[PlanStep] = []
        for index, call in enumerate(calls, start=1):
            spec = get_tool(call.name)
            if spec is None:
                continue
            steps.append(PlanStep(
                step_id=f"step-{index}-{call.name}",
                objective=f"Execute proposed tool {call.name} and capture an observation",
                action=call.name,
                expected_observation="tool observation",
                authorization_requirement="owner" if spec.requires_owner else "",
                scope_requirement="scope" if spec.scope_required else "",
                retry_policy={"arguments": dict(call.arguments), "tool_call_id": call.call_id},
                verification=(f"step-{index}-{call.name}",),
            ))
        if not steps:
            if observation is not None:
                # A textual continuation after an observed action means that
                # the durable evidence should be verified now; it is not a
                # new executable step.
                return Plan.initial(objective, created_from="agent_core").replan(steps=(), reason="model final after observation")
            # No model call is an explicit planning failure, not a silent success.
            failure_class = "PROVIDER" if response.get("error") else "LOGIC"
            steps.append(PlanStep("planning-failure", "Recover from malformed or empty model proposal", action="__planning_failure__", expected_observation="replanned action", retry_policy={"failure_class": failure_class}))
        return Plan.initial(objective, created_from="agent_core").replan(steps=steps, reason="initial agent-core plan")

    def _observation_proposal(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Ask the configured model to interpret an observation, never to authorize it."""
        mission = payload.get("mission", {})
        policy_context = ""
        if mission.get("policy_snapshot"):
            policy_context = json.dumps(mission["policy_snapshot"], ensure_ascii=False, sort_keys=True)
        prompt = (
            "Interpret the following tool observation for a defensive mission. Return JSON only with fields "
            "summary, facts, new_evidence, contradictions, hypothesis_updates, unknowns, new_dependencies, "
            "recommended_strategy_change, replan_reason, confidence_changes, required_next_evidence, "
            "information_gain, triggers. The model proposes analysis only. Do not change Owner instruction, "
            "policy, authorization, identity, scope, or objective. Never mark a hypothesis CONFIRMED.\n" +
            json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
        )
        context = ContextEngine.build(
            user_text=prompt,
            conversation_id=str(mission.get("mission_id", "agent-core")),
            owner_policy_context=policy_context,
            execution_state=ExecutionState.initial(str(mission.get("request_id", "")), str(mission.get("mission_id", "agent-core"))),
            mission_context={"objective": mission.get("objective"), "owner_instruction": mission.get("owner_instruction"), "scope_snapshot": mission.get("scope_snapshot")},
            hypothesis_state=payload.get("hypothesis_state") or [],
            evidence_state=payload.get("evidence") or [],
            strategy_state=mission.get("strategy_state") or {},
            current_observation=payload.get("observation") or {},
            knowledge_provider=KnowledgeProvider(self.knowledge_retriever),
        )
        response = self.router.generate(context.provider_messages(), reasoning_profile=select_reasoning_profile(prompt))
        content = str(response.get("content", "") or "").strip()
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            start, end = content.find("{"), content.rfind("}")
            if start < 0 or end <= start:
                return {}
            return json.loads(content[start:end + 1])

    @staticmethod
    def _auth(text: str, owner_token: str, request_id: str, owner_session_id: str | None, owner_challenge: str | None) -> tuple[AuthorizationContext, dict[str, Any]]:
        if owner_session_id or owner_challenge:
            if not owner_session_id or not owner_challenge:
                raise PermissionError("owner challenge required")
            session_context = consume_owner_challenge(owner_session_id, owner_challenge, text, request_id)
            evidence = authentication_from_session(session_context, request_id)
            session_id = session_context.get("owner_session_id")
        else:
            evidence = authenticate_owner(text, owner_token, request_id)
            session_id = None
        snapshot = capture_policy_snapshot(request_id, evidence)
        return AuthorizationContext(request_id=request_id, owner_evidence=evidence, policy_snapshot=snapshot, session_id=session_id), policy_context_from_snapshot(snapshot)

    @staticmethod
    def _executor(mission: Mission, step: PlanStep, action_id: str) -> dict[str, Any]:
        if step.action == "__planning_failure__":
            return {"success": False, "failure_class": dict(step.retry_policy).get("failure_class", "LOGIC"), "error": "malformed, empty, or unknown tool proposal"}
        arguments = dict(step.retry_policy).get("arguments", {})
        argument = arguments.get("query") if isinstance(arguments, dict) else None
        raw = mission.authorization_context or {}
        context = AuthorizationContext.from_dict(raw)
        spec = get_tool(step.action)
        if spec is None:
            return {"success": False, "failure_class": "TOOL", "error": "unknown tool"}
        valid, reason = spec.validate(argument)
        if isinstance(arguments, dict) and set(arguments) - {"query"}:
            return {"success": False, "failure_class": "TOOL", "error": "invalid tool arguments"}
        if not valid:
            return {"success": False, "failure_class": "TOOL", "error": reason}
        item = step.action if argument is None else [step.action, argument]
        decision = authorize_tool(item, context=context)
        if not decision.allowed:
            return {"success": False, "failure_class": "AUTHORIZATION", "error": decision.reason}
        try:
            snapshot = MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot or {}))
            workspace_root = str(snapshot.workspace_boundary.get("root", "")).strip()
            if not workspace_root:
                raise PermissionError("mission workspace boundary required")
            workspace = Workspace(workspace_root)
            evidence_store = EvidenceChainStore(DB_PATH.with_name("evidence_chain.db"))
            target_identity = str((mission.scope_snapshot or {}).get("target_id") or snapshot.target_identity) if isinstance(mission.scope_snapshot, dict) else snapshot.target_identity
            from security.execution_proof import ExecutionAuthorizationProof
            from security.execution_boundary import MissionExecutionBoundary
            from .trajectory import EventType
            proof = MissionExecutionBoundary.derive(mission, tool=step.action, argument=argument, decision=decision.decision, tool_call_id=action_id)
            mission.emit(EventType.PROOF_CREATED, data={"tool_call_id": action_id, "proof_fingerprint": proof.proof_fingerprint, "snapshot_hash": proof.snapshot_hash, "plan_hash": proof.plan_hash})
            proof_ok, proof_reason, proof_code = ExecutionAuthorizationProof.validate_against_mission(proof, mission)
            mission.emit(EventType.PROOF_VERIFIED, data={"tool_call_id": action_id, "allowed": proof_ok, "reason": proof_reason})
            if not proof_ok:
                mission.emit(EventType.EXECUTION_REJECTED, data={"tool_call_id": action_id, "code": proof_code, "reason": proof_reason})
                return {"success": False, "failure_class": "AUTHORIZATION", "error": f"{proof_code}: {proof_reason}", "execution_id": action_id}
            value = execute_tool(step.action, argument, authorization_decision=decision.decision, scope_context=mission.scope_snapshot, request_id=mission.request_id, mission_authorization=snapshot, workspace=workspace, evidence_store=evidence_store, mission_id=mission.mission_id, target_identity=target_identity, execution_proof=proof)
            return {"success": True, "source": step.action, "criterion_id": "mission-goal", "result": value, "execution_id": action_id}
        except PermissionError as exc:
            return {"success": False, "failure_class": "AUTHORIZATION", "error": f"{type(exc).__name__}: {exc}", "execution_id": action_id}
        except Exception as exc:
            return {"success": False, "failure_class": "TOOL", "error": f"{type(exc).__name__}: {exc}", "execution_id": action_id}

    def run_owner_mission(self, instruction: str, *, owner_token: str, owner_session_id: str | None = None, owner_challenge: str | None = None, request_id: str | None = None, scope_context: dict[str, Any] | None = None, completion_criteria: list[dict[str, Any]] | None = None, run: bool = True) -> Mission:
        request_id = request_id or uuid.uuid4().hex
        authorization_context, policy_context = self._auth(instruction, owner_token, request_id, owner_session_id, owner_challenge)
        if isinstance(scope_context, dict) and scope_context.get("scope_snapshot_id"):
            snapshot = get_snapshot(scope_context["scope_snapshot_id"])
            if snapshot is None:
                raise PermissionError("invalid_scope_context")
            authorization_context = AuthorizationContext(
                request_id=authorization_context.request_id,
                owner_evidence=authorization_context.owner_evidence,
                policy_snapshot=authorization_context.policy_snapshot,
                scope_snapshot=snapshot,
                session_id=authorization_context.session_id,
            )
        plan = self._plan(instruction, policy_context=policy_context, request_id=request_id, conversation_id=request_id)
        task_profile = TaskProfile.from_proposal(instruction, {"task_type": "owner_mission", "horizon": "long_horizon", "complexity": "multi_step", "likely_tools": [step.action for step in plan.steps if step.action != "__planning_failure__"]})
        runtime = MissionRuntime(
            self.store,
            executor=self._executor,
            replanner=lambda mission, observation: self._plan(mission.objective, observation, policy_context=policy_context, request_id=mission.request_id, conversation_id=mission.mission_id),
            recovery_policy=RecoveryPolicy(),
            interpreter=ObservationInterpreter(proposer=self._observation_proposal),
            require_authorization_snapshot=True,
        )
        target_identity = str((scope_context or {}).get("target_id") or "local-workspace")
        workspace_root = str((scope_context or {}).get("workspace_root") or Path.cwd().resolve())
        # INV-SCOPE-2 (B-1 closure): the authorized tool scope is the Owner
        # budget intersected with the model request. The model plan can only
        # narrow the budget; it can never mint, widen, or redefine authority.
        owner_budget = OwnerAuthorizedToolBudget.from_owner_declaration(
            scope_context,
            policy_version=str(getattr(authorization_context.policy_snapshot, "policy_version", "owner-policy")),
            owner_approval=authorization_context.owner_evidence.proof_fingerprint,
        )
        model_requested_tools = tuple(step.action for step in plan.steps if step.action != "__planning_failure__")
        effective_tools = owner_budget.intersect(model_requested_tools)

        def authorization_snapshot_factory(created_mission: Mission) -> MissionAuthorizationSnapshot:
            return MissionAuthorizationSnapshot.create(
                owner_identity=created_mission.owner_identity_ref,
                mission_id=created_mission.mission_id,
                target_identity=target_identity,
                scope=tuple((scope_context or {}).get("scope", ("workspace",))),
                allowed_actions=effective_tools,
                forbidden_actions=tuple((scope_context or {}).get("forbidden_actions", ())),
                allowed_tools=effective_tools,
                time_window={"timezone": "UTC"},
                max_duration=max(60, created_mission.max_iterations * 60),
                rate_limits={tool: 1 for tool in effective_tools},
                network_boundary={"allowed": tuple((scope_context or {}).get("allowed_networks", ()))},
                data_boundary={"allowed": (target_identity,)},
                credential_boundary={"allowed": tuple((scope_context or {}).get("allowed_credentials", ()))},
                workspace_boundary={"root": workspace_root},
                policy_version=str(getattr(authorization_context.policy_snapshot, "policy_version", "owner-policy")),
                owner_approval=authorization_context.owner_evidence.proof_fingerprint,
                expires_at=authorization_context.owner_evidence.expires_at,
            )
        mission = runtime.create_from_owner_instruction(
            instruction,
            plan,
            authorization_context=authorization_context,
            scope_snapshot=scope_context,
            completion_criteria=completion_criteria or [{"criterion_id": "mission-goal", "description": "Owner objective has a verified successful observation", "check": "tool observation", "required": True}],
            provenance={"component": "AgentCore", "planner": "model_proposal", "task_profile": task_profile.to_dict(), "owner_budget": owner_budget.to_dict(), "model_requested_tools": list(model_requested_tools), "effective_tools": list(effective_tools)},
            authorization_snapshot_factory=authorization_snapshot_factory,
        )
        if getattr(self, "_last_model_response", None):
            mission.progress["initial_model_response"] = dict(self._last_model_response)
        mission.semantic_intent = NaturalLanguageUnderstanding().understand(instruction).to_dict()
        adaptive_knowledge = self.knowledge_retriever.retrieve_adaptive(instruction, required_evidence=("supporting evidence", "counter-evidence"), limit=5)
        mission.knowledge_context = list(adaptive_knowledge.get("results", ()))
        mission.progress["knowledge_retrieval"] = {key: value for key, value in adaptive_knowledge.items() if key != "results"}
        mission.strategy_state = StrategyState("initial_investigation", mission.objective).to_dict()
        if any(token in instruction.casefold() for token in ("investigate", "whether", "تحقق", "حقق", "حادث", "incident")):
            mission.hypotheses = [HypothesisState("H1", f"Primary explanation for: {mission.objective}", HypothesisStatus.ACTIVE, 0.5, provenance={"source": "owner_objective", "authority": None}).to_dict()]
        self.store.save(mission)
        if not run:
            return mission
        if plan.steps and plan.steps[0].action == "__planning_failure__":
            # Preserve the model's untrusted final text for presentation, but
            # do not execute a fabricated planning step or call the provider
            # repeatedly. Completion remains unavailable without evidence.
            return self.store.save(mission)
        # Every configured provider enters MissionRuntime. Providers that do
        # not advertise native tool calling use MissionRuntime's durable slice
        # planner; this is a compatibility mode inside the same engine, not a
        # second AgentTaskRuntime/core-engine execution path.
        capabilities = [getattr(provider, "capabilities", None) for provider in getattr(self.router, "providers", ())]
        if any(getattr(item, "native_chat", False) and getattr(item, "tool_calling", False) for item in capabilities):
            from .model_protocol import RouterNativeModel
            return runtime.run_model_loop(mission.mission_id, RouterNativeModel(self.router), tools=self._schemas(), max_turns=self.max_iterations)
        result = runtime.run_to_completion(mission.mission_id, max_slices=self.max_iterations)
        last_response = getattr(self, "_last_model_response", None)
        if isinstance(last_response, dict) and last_response.get("content"):
            result.progress["last_model_content"] = str(last_response["content"])
            result.progress["last_model_response"] = dict(last_response)
            self.store.save(result)
        # Text-only compatibility providers do not expose a native continuation
        # channel. A final interpretation is presentation-only: deterministic
        # verification has already decided the mission status.
        initial = result.progress.get("initial_model_response", {})
        if initial.get("tool_calls") and not result.progress.get("last_model_content"):
            try:
                final_response = self._ask(result.objective, result.observations[-1] if result.observations else None, policy_context=policy_context, request_id=result.request_id, conversation_id=result.mission_id)
                if final_response.get("content"):
                    result.progress["last_model_content"] = str(final_response["content"])
                    result.progress["last_model_response"] = dict(final_response)
                    self.store.save(result)
            except Exception:
                pass
        return result

    def resume_mission(self, mission_id: str, *, owner_token: str, max_slices: int | None = None) -> Mission:
        mission = self.store.load(mission_id)
        if mission is None:
            raise KeyError("unknown_mission")
        try:
            evidence = authenticate_owner("Owner resume mission", owner_token, mission.request_id)
        except PermissionError as exc:
            if mission.status is not MissionStatus.OWNER_INPUT_REQUIRED:
                if mission.status is MissionStatus.RECOVERY_REQUIRED:
                    mission.transition(MissionStatus.OWNER_INPUT_REQUIRED, "owner revalidation required after restore")
                else:
                    mission.transition(MissionStatus.OWNER_INPUT_REQUIRED, "owner revalidation failed after restore")
                mission.recovery_events.append({"event": "owner_revalidation_failed", "reason": str(exc)})
                self.store.save(mission)
            raise
        fresh_snapshot = capture_policy_snapshot(mission.request_id, evidence)
        try:
            old_authorization = MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot or {}))
            mission.authorization_snapshot = old_authorization.amend(owner_approval=evidence.proof_fingerprint, changes={}, expires_at=evidence.expires_at).to_dict()
            mission.provenance["authorization_snapshot_version"] = int(mission.authorization_snapshot["version"])
        except (KeyError, TypeError, ValueError, PermissionError):
            # INV-SCOPE-2 (B-1 closure): resume may only renew an existing
            # Owner-authorized snapshot. Authority is never re-derived from
            # the model plan at resume; a mission without a valid snapshot
            # fails closed instead of minting a new authorization scope.
            mission.status = MissionStatus.AUTHORIZATION_BLOCKED
            mission.recovery_events.append({"event": "authorization_renewal_failed", "reason": "INV-SCOPE-2: no authorization scope may be minted at resume"})
            self.store.save(mission)
            raise PermissionError("authorization snapshot cannot be renewed: no authorization scope may be minted at resume (INV-SCOPE-2)")
        old_scope_id = ((mission.authorization_context or {}).get("scope_snapshot_id") if isinstance(mission.authorization_context, dict) else None)
        fresh_scope = get_snapshot(str(old_scope_id)) if old_scope_id else None
        fresh_context = AuthorizationContext(request_id=mission.request_id, owner_evidence=evidence, policy_snapshot=fresh_snapshot, scope_snapshot=fresh_scope)
        mission.authorization_context = fresh_context.to_dict()
        mission.policy_snapshot = fresh_snapshot.to_dict()
        mission.recovery_events.append({"event": "owner_revalidated", "authorization_source": "owner_token", "evidence_fingerprint": fresh_context.owner_evidence_fingerprint})
        if mission.status is MissionStatus.OWNER_INPUT_REQUIRED:
            mission.transition(MissionStatus.READY, "owner authorization revalidated")
        self.store.save(mission)
        policy_context = policy_context_from_snapshot(fresh_snapshot)
        runtime = MissionRuntime(self.store, executor=self._executor, replanner=lambda current, observation: self._plan(current.objective, observation, policy_context=policy_context, request_id=current.request_id, conversation_id=current.mission_id), recovery_policy=RecoveryPolicy(), interpreter=ObservationInterpreter(proposer=self._observation_proposal), require_authorization_snapshot=True)
        return runtime.run_to_completion(mission_id, max_slices=max_slices or self.max_iterations)


__all__ = ["AgentCore"]
