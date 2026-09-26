from __future__ import annotations

import json
import re
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

from .mission import Mission, MissionStatus, MissionStore
from .trajectory import EventType
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
                prerequisites=(steps[-1].step_id,) if steps else (),
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
        snapshot = capture_policy_snapshot(request_id, evidence, instruction=text)
        return AuthorizationContext(request_id=request_id, owner_evidence=evidence, policy_snapshot=snapshot, session_id=session_id), policy_context_from_snapshot(snapshot)

    @staticmethod
    def _owner_allowed_tools(instruction: str) -> tuple[str, ...]:
        """Derive a conservative tool allowlist from authenticated Owner text, never model output."""
        text = str(instruction or "").casefold()
        intent_terms = {
            "status": ("status", "system status", "حالة النظام", "الحالة"),
            "latest_intel": ("latest intel", "latest_intel", "threat intelligence", "استخبارات التهديد"),
            "refresh_intel": ("refresh intel", "refresh_intel", "تحديث استخبارات"),
            "local_security_check": ("local_security_check", "local security check", "فحص أمني محلي", "فحص الشبكة المحلية"),
            "local_system_info": ("local_system_info", "system information", "معلومات النظام"),
            "search": ("search", "ابحث", "بحث", "استعلم"),
            "watch": ("watch", "watchlist", "راقب", "أضف مراقبة"),
            "unwatch": ("unwatch", "stop watching", "أوقف المراقبة", "إلغاء المراقبة"),
            "run_project_tests": ("run_project_tests", "run project tests", "run tests", "اختبر المشروع", "تشغيل الاختبارات"),
            "red_team_assess": ("red_team_assess", "red team assessment", "red-team assessment", "تقييم هجومي دفاعي"),
            "scoped_http_probe": ("scoped_http_probe", "scoped http probe", "http probe", "فحص http ضمن النطاق"),
        }
        allowed = set()
        for tool_name, phrases in intent_terms.items():
            for phrase in (tool_name.casefold(), *phrases):
                offset = text.find(phrase)
                if offset < 0:
                    continue
                prefix = text[max(0, offset - 80):offset]
                if re.search(r"(?:\bnot\b|\bno\b|\bnever\b|\bdon't\b|\bdo not\b|لا|عدم|بدون)(?:\W+\w+){0,5}\W*$", prefix):
                    continue
                allowed.add(tool_name)
                break
        return tuple(sorted(allowed))

    @staticmethod
    def _owner_proposal_allowed(instruction: str, step: PlanStep) -> tuple[bool, str]:
        text = str(instruction or "").casefold()
        if step.action not in AgentCore._owner_allowed_tools(text):
            return False, "proposed tool is not explicitly authorized by the Owner instruction"
        arguments = dict(step.retry_policy).get("arguments", {})
        argument = arguments.get("query") if isinstance(arguments, dict) else None
        if argument is None:
            return True, "authorized"
        value = str(argument).strip().casefold()
        if step.action in {"watch", "unwatch", "scoped_http_probe", "run_project_tests"}:
            if step.action == "run_project_tests" and value in {".", "./"} and any(token in text for token in ("test", "tests", "اختبر", "الاختبارات")):
                return True, "authorized"
            if value and value in text:
                return True, "authorized"
            try:
                from urllib.parse import urlsplit
                host = urlsplit(value).hostname
                if host and host.casefold() in text:
                    return True, "authorized"
            except ValueError:
                pass
            return False, "tool argument target/path is not present in Owner instruction"
        if step.action in {"search", "red_team_assess"}:
            stopwords = {"the", "and", "for", "with", "from", "about", "scope", "search", "find", "check", "analyze", "analyse", "assess", "latest", "information", "data", "ابحث", "بحث", "حلل", "تحقق", "عن", "في", "على", "من", "الى", "إلى", "المعلومات"}
            terms = {word for word in re.findall(r"[a-z0-9][a-z0-9._/-]{2,}", value) if word not in stopwords}
            if not terms or terms.issubset(set(re.findall(r"[a-z0-9][a-z0-9._/-]{2,}", text))):
                return True, "authorized"
            return False, "query includes terms not stated by the Owner"
        return False, "argument-bearing tool is not supported by the Owner-instruction policy"

    @staticmethod
    def _normalize_scope_context(scope_context: dict[str, Any] | None) -> dict[str, Any] | None:
        if scope_context is None:
            return None
        if not isinstance(scope_context, dict) or not scope_context.get("scope_snapshot_id"):
            raise PermissionError("scope context must reference a persisted Owner-approved snapshot")
        from security.scope_resolver import resolve
        snapshot_id = str(scope_context["scope_snapshot_id"])
        snapshot = get_snapshot(snapshot_id)
        target_id = str(scope_context.get("target_id", ""))
        if snapshot is None or str(scope_context.get("program_id", "")) != snapshot.authorization.program_id:
            raise PermissionError("scope snapshot or program identity is invalid")
        target = snapshot.target(target_id)
        if target is None:
            raise PermissionError("scope target is not present in the Owner-approved snapshot")
        url = str(scope_context.get("url", ""))
        method = str(scope_context.get("method", "GET")).upper()
        decision = resolve(snapshot_id, target_id, url, method=method, expected_program_id=snapshot.authorization.program_id, consume_rate=False)
        if not decision.allowed:
            raise PermissionError("scope context denied: " + decision.reason)
        return {"program_id": snapshot.authorization.program_id, "target_id": target.target_id, "scope_snapshot_id": snapshot_id, "url": decision.canonical_url or url, "method": method}

    def _authorization_snapshot_factory(self, authorization_context: AuthorizationContext, allowed_tools: tuple[str, ...], scope_context: dict[str, Any] | None):
        target_identity = str((scope_context or {}).get("target_id") or "local-workspace")
        workspace_root = str((scope_context or {}).get("workspace_root") or Path.cwd().resolve())

        def factory(mission: Mission) -> MissionAuthorizationSnapshot:
            return MissionAuthorizationSnapshot.create(
                owner_identity=mission.owner_identity_ref,
                mission_id=mission.mission_id,
                target_identity=target_identity,
                scope=tuple((scope_context or {}).get("scope", ("workspace",))),
                allowed_actions=allowed_tools,
                forbidden_actions=tuple((scope_context or {}).get("forbidden_actions", ())),
                allowed_tools=allowed_tools,
                time_window={"timezone": "UTC"},
                max_duration=max(60, mission.max_iterations * 60),
                rate_limits={tool: 1 for tool in allowed_tools},
                network_boundary={"allowed": tuple((scope_context or {}).get("allowed_networks", ()))},
                data_boundary={"allowed": (target_identity,)},
                credential_boundary={"allowed": tuple((scope_context or {}).get("allowed_credentials", ()))},
                workspace_boundary={"root": workspace_root},
                policy_version=str(getattr(authorization_context.policy_snapshot, "policy_version", "owner-policy")),
                owner_approval=authorization_context.owner_evidence.proof_fingerprint,
                expires_at=authorization_context.owner_evidence.expires_at,
            )
        return factory

    def owner_context_for_mission(self, mission: Mission, *, owner_token: str) -> AuthorizationContext:
        evidence = authenticate_owner("Owner mission control", owner_token, mission.request_id)
        if evidence.proof_fingerprint != mission.owner_identity_ref:
            raise PermissionError("Owner identity does not match the mission creator")
        policy = capture_policy_snapshot(mission.request_id, evidence, instruction=mission.owner_instruction or mission.owner_request)
        expected_policy = str((mission.policy_snapshot or {}).get("owner_policy_fingerprint", ""))
        if expected_policy and policy.owner_policy_fingerprint != expected_policy:
            raise PermissionError("Owner policy changed; mission requires explicit reauthorization")
        try:
            old_authorization = MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot or {}))
            mission.authorization_snapshot = old_authorization.amend(owner_approval=evidence.proof_fingerprint, changes={}, expires_at=evidence.expires_at).to_dict()
        except (KeyError, TypeError, ValueError, PermissionError) as exc:
            raise PermissionError("mission authorization snapshot cannot be renewed") from exc
        graph_state = mission.checkpoint.get("orchestration") if isinstance(mission.checkpoint, dict) else None
        if isinstance(graph_state, dict):
            graph_state = dict(graph_state)
            graph_state["authorization_hash"] = str(mission.authorization_snapshot["authorization_hash"])
            mission.checkpoint = {**mission.checkpoint, "orchestration": graph_state}
            mission.emit(EventType.AUTHORIZATION_CHECKED, data={"allowed": True, "reason": "Owner revalidated the existing mission snapshot without widening its boundaries", "authorization_hash": graph_state["authorization_hash"]})
        scope = None
        saved = mission.authorization_context or {}
        scope_id = str(saved.get("scope_snapshot_id") or "") if isinstance(saved, dict) else ""
        if scope_id:
            scope = get_snapshot(scope_id)
            if scope is None:
                raise PermissionError("mission scope snapshot no longer exists")
        context = AuthorizationContext(mission.request_id, evidence, policy, scope_snapshot=scope)
        mission.authorization_context = context.to_dict()
        mission.policy_snapshot = policy.to_dict()
        mission.provenance["authorization_snapshot_version"] = int(mission.authorization_snapshot.get("version", 1))
        self.store.save(mission)
        return context

    @staticmethod
    def _executor(mission: Mission, step: PlanStep, action_id: str) -> dict[str, Any]:
        if step.action == "__planning_failure__":
            return {"success": False, "failure_class": dict(step.retry_policy).get("failure_class", "LOGIC"), "error": "malformed, empty, or unknown tool proposal"}
        owner_allowed, owner_reason = AgentCore._owner_proposal_allowed(mission.owner_instruction or mission.owner_request, step)
        if not owner_allowed:
            return {"success": False, "failure_class": "AUTHORIZATION", "error": owner_reason}
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
            value = execute_tool(step.action, argument, authorization_decision=decision.decision, scope_context=mission.scope_snapshot, request_id=mission.request_id, mission_authorization=snapshot, workspace=workspace, evidence_store=evidence_store, mission_id=mission.mission_id, target_identity=target_identity)
            return {"success": True, "source": step.action, "criterion_id": "mission-goal", "result": value, "execution_id": action_id}
        except Exception as exc:
            return {"success": False, "failure_class": "TOOL", "error": f"{type(exc).__name__}: {exc}", "execution_id": action_id}

    def run_owner_mission(self, instruction: str, *, owner_token: str, owner_session_id: str | None = None, owner_challenge: str | None = None, request_id: str | None = None, scope_context: dict[str, Any] | None = None, completion_criteria: list[dict[str, Any]] | None = None, run: bool = True) -> Mission:
        request_id = request_id or uuid.uuid4().hex
        authorization_context, policy_context = self._auth(instruction, owner_token, request_id, owner_session_id, owner_challenge)
        scope_context = self._normalize_scope_context(scope_context)
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
        owner_allowed_tools = self._owner_allowed_tools(instruction)
        allowed_tools = tuple(sorted(set(owner_allowed_tools).intersection(REGISTRY)))
        authorization_snapshot_factory = self._authorization_snapshot_factory(authorization_context, allowed_tools, scope_context)
        completion = completion_criteria or [
            {"criterion_id": step.step_id, "description": f"Owner-requested step {step.step_id} completed", "check": "tool observation", "required": True}
            for step in plan.steps
        ]
        mission = runtime.create_owner_graph(
            instruction,
            plan,
            authorization_context=authorization_context,
            scope_snapshot=scope_context,
            completion_criteria=completion,
            owner_identity_ref=authorization_context.owner_evidence.proof_fingerprint,
            provenance={"component": "AgentCore", "planner": "model_proposal", "task_profile": task_profile.to_dict()},
            authorization_snapshot_factory=authorization_snapshot_factory,
            max_parallel=1,
            max_duration_seconds=int(getattr(authorization_context.policy_snapshot, "runtime_limits", {}).get("max_execution_time_seconds", 300)) if hasattr(authorization_context.policy_snapshot, "runtime_limits") else 300,
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
        if evidence.proof_fingerprint != mission.owner_identity_ref:
            raise PermissionError("Owner identity does not match the mission creator")
        fresh_snapshot = capture_policy_snapshot(mission.request_id, evidence, instruction=mission.owner_instruction or mission.owner_request)
        try:
            old_authorization = MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot or {}))
            mission.authorization_snapshot = old_authorization.amend(owner_approval=evidence.proof_fingerprint, changes={}, expires_at=evidence.expires_at).to_dict()
            mission.provenance["authorization_snapshot_version"] = int(mission.authorization_snapshot["version"])
        except (KeyError, TypeError, ValueError, PermissionError):
            if mission.authorization_snapshot:
                mission.transition(MissionStatus.AUTHORIZATION_BLOCKED, "authorization snapshot cannot be renewed")
                self.store.save(mission)
                raise PermissionError("authorization snapshot cannot be renewed")
            allowed_tools = tuple(self._owner_allowed_tools(mission.owner_instruction))
            owner_identity = mission.owner_identity_ref or evidence.proof_fingerprint
            mission.owner_identity_ref = owner_identity
            renewed = MissionAuthorizationSnapshot.create(owner_identity=owner_identity, mission_id=mission.mission_id, target_identity="local-workspace", scope=("workspace",), allowed_actions=allowed_tools, forbidden_actions=(), allowed_tools=allowed_tools, time_window={"timezone": "UTC"}, max_duration=max(60, mission.max_iterations * 60), rate_limits={tool: 1 for tool in allowed_tools}, network_boundary={"allowed": ()}, data_boundary={"allowed": ("local-workspace",)}, credential_boundary={"allowed": ()}, workspace_boundary={"root": str(Path.cwd().resolve())}, policy_version="owner-policy", owner_approval=evidence.proof_fingerprint, expires_at=evidence.expires_at)
            mission.authorization_snapshot = renewed.to_dict()
            mission.provenance["authorization_snapshot_version"] = int(renewed.version)
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
