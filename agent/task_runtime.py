from __future__ import annotations

import json
import hashlib
import threading
import time
import uuid
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from typing import Any, Callable

from agent.context import ContextEngine, ExecutionState, RuntimeLimits
from agent.memory import ConversationMemory, MemoryProvider, MemoryType, TrustClassification
from agent.provider_api import (
    MAX_PROVIDER_CALL_ID_CHARS,
    MAX_PROVIDER_LABEL_CHARS,
    MAX_PROVIDER_TEXT_CHARS,
    MAX_PROVIDER_TOOL_CALLS,
    MAX_PROVIDER_TOOL_NAME_CHARS,
    CapabilityUnsupported,
    InvalidModelResponse,
    ProviderError,
    ToolCall,
)
from agent.task import Task, TaskStatus
from agent.task_manager import TaskManager, TaskVersionConflictError
from agent.planning import select_reasoning_profile
from core.db import add_conversation_message, conversation_messages, ensure_conversation
from security.authorization import authorize_tool
from security.authorization_context import AuthorizationContext
from security.owner_policy import current_owner_policy_context, policy_context_from_snapshot
from tools.registry import REGISTRY, execute as execute_tool, get_tool


class AgentTaskRuntime:
    """Persistent, slice-based runtime. Every model/tool boundary is committed to SQLite."""

    def __init__(self, router: Any, executor: Callable[..., dict[str, Any]] | None = None, runtime_limits: RuntimeLimits | None = None):
        self.router = router
        self.executor = executor or self._default_executor
        self.limits = runtime_limits or RuntimeLimits.from_owner_policy()
        self._state_lock = threading.RLock()

    @staticmethod
    def _default_executor(command: str, *, owner_session_token: str, owner_session_id: str | None = None, scope_context: dict[str, Any] | None = None, authorization_context: AuthorizationContext | None = None, authorization_decision: Any = None) -> dict[str, Any]:
        parts = command.split(" ", 2)
        name = parts[1] if len(parts) > 1 else ""
        argument = parts[2] if len(parts) > 2 else None
        return {"ok": True, "result": execute_tool(name, argument, authorization_decision=authorization_decision, scope_context=scope_context)}

    @staticmethod
    def _schemas() -> list[dict[str, Any]]:
        from tools.registry import model_tool_definitions

        return model_tool_definitions()

    def _event(self, task: Task, event: str, data: dict[str, Any] | None = None) -> None:
        with self._state_lock:
            events = task.execution_state.setdefault("events", [])
            events.append({"event": event, "task_id": task.task_id, "conversation_id": task.conversation_id, "request_id": task.request_id, "step": task.current_step, "data": data or {}, "timestamp": time.time()})
            task.execution_state["events"] = events[-500:]
            TaskManager.update_task(task)

    @staticmethod
    def _tool_calls(response: dict[str, Any]) -> list[ToolCall]:
        if not isinstance(response, dict):
            raise InvalidModelResponse("task model returned a non-object response")
        calls: list[ToolCall] = []
        raw_calls = response.get("tool_calls")
        if raw_calls is None:
            return calls
        if not isinstance(raw_calls, (list, tuple)) or len(raw_calls) > MAX_PROVIDER_TOOL_CALLS:
            raise InvalidModelResponse("task model returned malformed tool calls")
        seen_call_ids: set[str] = set()
        for item in raw_calls:
            if isinstance(item, ToolCall):
                name, args, call_id = item.name, item.arguments, item.call_id
            elif isinstance(item, dict):
                name = item.get("name")
                args = item.get("arguments", {})
                call_id = item.get("id")
            else:
                raise InvalidModelResponse("task model returned a malformed tool call")
            if not isinstance(name, str) or len(name) > MAX_PROVIDER_TOOL_NAME_CHARS or not name.strip():
                raise InvalidModelResponse("task model returned a tool call without a valid name")
            if args is None:
                args = {}
            if not isinstance(args, dict):
                raise InvalidModelResponse("task model returned non-object tool arguments")
            spec = get_tool(name)
            if spec is None:
                raise InvalidModelResponse("task model returned an unknown tool name")
            valid, _reason, _normalized = spec.validate_input(args)
            if not valid:
                raise InvalidModelResponse("task model returned tool arguments outside the registered schema")
            if call_id is None:
                call_id = uuid.uuid4().hex
            elif not isinstance(call_id, str):
                raise InvalidModelResponse("task model returned malformed tool-call identity")
            elif call_id == "":
                call_id = uuid.uuid4().hex
            elif len(call_id) > MAX_PROVIDER_CALL_ID_CHARS:
                raise InvalidModelResponse("task model returned malformed tool-call identity")
            try:
                name.encode("utf-8")
                call_id.encode("utf-8")
            except UnicodeError as exc:
                raise InvalidModelResponse("task model returned invalid tool-call identity encoding") from exc
            if call_id in seen_call_ids:
                raise InvalidModelResponse("task model returned duplicate tool-call identifiers")
            seen_call_ids.add(call_id)
            calls.append(ToolCall(name, args, call_id))
        return calls

    @staticmethod
    def _parse(response: dict[str, Any]) -> tuple[str, Any]:
        if not isinstance(response, dict):
            raise InvalidModelResponse("task model returned a non-object response")
        for field_name in ("provider", "model", "capability"):
            metadata_value = response.get(field_name, "")
            if not isinstance(metadata_value, str) or len(metadata_value) > MAX_PROVIDER_LABEL_CHARS:
                raise InvalidModelResponse("task model returned malformed response identity metadata")
            try:
                metadata_value.encode("utf-8")
            except UnicodeError as exc:
                raise InvalidModelResponse("task model returned invalid response identity encoding") from exc
        content = response.get("content", "")
        if content is None:
            content = ""
        if not isinstance(content, str) or len(content) > MAX_PROVIDER_TEXT_CHARS:
            raise InvalidModelResponse("task model returned malformed or oversized text")
        try:
            content.encode("utf-8")
        except UnicodeError as exc:
            raise InvalidModelResponse("task model returned invalid text encoding") from exc
        calls = AgentTaskRuntime._tool_calls(response)
        if calls:
            return "tool_calls", calls
        try:
            value = json.loads(content)
        except json.JSONDecodeError:
            return "final", content
        if isinstance(value, dict) and value.get("type") in {"final", "final_answer"}:
            return "final", str(value.get("content", value.get("answer", "")))
        if isinstance(value, dict) and value.get("type") == "clarification":
            return "needs_input", str(value.get("question", "معلومات إضافية مطلوبة."))
        if isinstance(value, dict) and value.get("type") == "tool_call":
            name = value.get("name")
            arguments = value.get("arguments", {})
            if not isinstance(name, str) or len(name) > MAX_PROVIDER_TOOL_NAME_CHARS or not name.strip():
                raise InvalidModelResponse("task model returned a tool call without a valid name")
            if arguments is None:
                arguments = {}
            if not isinstance(arguments, dict):
                raise InvalidModelResponse("task model returned non-object tool arguments")
            spec = get_tool(name)
            if spec is None:
                raise InvalidModelResponse("task model returned an unknown tool name")
            valid, _reason, _normalized = spec.validate_input(arguments)
            if not valid:
                raise InvalidModelResponse("task model returned tool arguments outside the registered schema")
            return "tool_calls", [ToolCall(name, arguments, uuid.uuid4().hex)]
        return "final", content

    def create_task(self, conversation_id: str, objective: str, *, owner_session_id: str = "", authentication_method: str = "username_password", scope_context: dict[str, Any] | None = None, authorization_context: AuthorizationContext | None = None) -> Task:
        if authorization_context is not None and owner_session_id and authorization_context.session_id != owner_session_id:
            raise ValueError("task owner session does not match AuthorizationContext")
        if authorization_context is not None:
            owner_session_id = authorization_context.session_id or owner_session_id
        if scope_context is not None:
            required = {"program_id", "target_id", "scope_snapshot_id", "url"}
            if not required.issubset(scope_context):
                raise ValueError("incomplete_scope_context")
            from security.scope_store import get_snapshot
            snapshot = get_snapshot(scope_context["scope_snapshot_id"])
            if snapshot is None or snapshot.authorization.program_id != scope_context["program_id"] or snapshot.target(scope_context["target_id"]) is None:
                raise ValueError("invalid_scope_context")
        ensure_conversation(conversation_id, owner_session_id)
        request_id = authorization_context.request_id if authorization_context is not None else uuid.uuid4().hex
        task = TaskManager.create_task(conversation_id, request_id, owner_session_id, objective, authentication_method=authentication_method)
        bound_context = replace(authorization_context, task_id=task.task_id) if authorization_context is not None else None
        task.execution_state = {"tool_results": [], "evidence_refs": [], "memory_refs": [], "objective": objective, "events": [], "scope_context": scope_context, "authorization_context": bound_context.to_dict() if bound_context is not None else None}
        self._event(task, "task.created", {"objective": objective, "authentication_method": authentication_method})
        objective_item = ConversationMemory.store_conversation_memory(conversation_id, objective, MemoryType.ACTIVE_OBJECTIVE, source="task", provenance=f"task:{task.task_id}")
        recent_item = ConversationMemory.store_conversation_memory(conversation_id, objective, MemoryType.RECENT, source="conversation", provenance="user_message")
        task.execution_state["memory_refs"] = [objective_item.memory_id, recent_item.memory_id]
        TaskManager.update_task(task)
        return task

    def _valid_owner_session(self, task: Task, owner_session_token: str | None) -> bool:
        if isinstance(task.execution_state, dict) and task.execution_state.get("authorization_context"):
            try:
                self._authorization_context(task)
                return True
            except (PermissionError, ValueError, TypeError):
                return False
        from security import owner_password
        return owner_password.resolve_session(owner_session_token) is not None

    def _context(self, task: Task) -> Any:
        state = ExecutionState(
            request_id=task.request_id,
            conversation_id=task.conversation_id,
            task_id=task.task_id,
            step=task.current_step,
            tool_calls_used=len(task.tool_calls),
            remaining_steps=max(0, self.limits.max_execution_steps - task.current_step),
            provider=task.provider,
            model=task.model,
        )
        bound_auth = self._authorization_context(task)
        context = ContextEngine.build(
            user_text=task.objective,
            conversation_id=task.conversation_id,
            owner_policy_context=policy_context_from_snapshot(bound_auth.policy_snapshot) if bound_auth is not None else current_owner_policy_context(),
            conversation_messages=conversation_messages(task.conversation_id),
            tool_results=[(item.get("tool_name", "tool"), item.get("result") or {}) for item in task.tool_calls if item.get("result") is not None],
            execution_state=state,
            runtime_limits=self.limits,
            provider=task.provider,
            model=task.model,
        )
        if context.truncated:
            ConversationMemory.consolidate_memory(task.conversation_id, max_items=max(20, self.limits.max_context_messages * 2))
            self._event(task, "memory.updated", {"reason": "context_compaction", "context_hash": context.context_hash})
        task.execution_state["context_hash"] = context.context_hash
        task.execution_state["context_metadata"] = {"truncated": context.truncated, "messages": len(context.messages), "chars": sum(len(item.get("content", "")) for item in context.messages)}
        return context

    @staticmethod
    def _authorization_context(task: Task) -> AuthorizationContext | None:
        raw = task.execution_state.get("authorization_context") if isinstance(task.execution_state, dict) else None
        if not raw:
            return None
        context = AuthorizationContext.from_dict(dict(raw))
        if context.request_id != task.request_id or (context.task_id and context.task_id != task.task_id):
            raise PermissionError("task AuthorizationContext binding mismatch")
        return context

    def _ask_model(self, context: Any, objective: str = "") -> dict[str, Any]:
        payload = context.to_provider_payload()
        reasoning_profile = select_reasoning_profile(objective)
        try:
            return self.router.tool_calling(payload["messages"], self._schemas(), reasoning_profile=reasoning_profile)
        except CapabilityUnsupported:
            return self.router.generate(payload["messages"], reasoning_profile=reasoning_profile)

    @staticmethod
    def _argument(call: ToolCall) -> str | None:
        if not call.arguments:
            return None
        value = call.arguments.get("query")
        return value if isinstance(value, str) else None

    @staticmethod
    def _pending_tool_call(task: Task) -> dict[str, Any] | None:
        recovery = task.execution_state.get("recovery_required") if isinstance(task.execution_state, dict) else None
        if isinstance(recovery, dict):
            return recovery
        for item in task.tool_calls:
            if item.get("status") in {"in_flight", "unknown", "failed"}:
                return item
        # Older task records only persisted a tool.started event before dispatch.
        # Treat an unmatched start as ambiguous instead of replaying it on resume.
        started: dict[str, dict[str, Any]] = {}
        completed: set[str] = set()
        empty_id_starts = 0
        empty_id_completions = 0
        empty_id_tool = ""
        for event in task.execution_state.get("events", []) if isinstance(task.execution_state, dict) else []:
            if not isinstance(event, dict):
                continue
            data = event.get("data") if isinstance(event.get("data"), dict) else {}
            call_id = str(data.get("tool_call_id") or "")
            if event.get("event") == "tool.started":
                if call_id:
                    started[call_id] = {"tool_call_id": call_id, "tool_name": data.get("tool", ""), "status": "in_flight"}
                else:
                    empty_id_starts += 1
                    empty_id_tool = str(data.get("tool") or empty_id_tool)
            elif event.get("event") in {"tool.completed", "tool.outcome_unknown"}:
                if call_id:
                    completed.add(call_id)
                else:
                    empty_id_completions += 1
        recorded = {str(item.get("tool_call_id") or "") for item in task.tool_calls}
        for call_id, item in started.items():
            if call_id not in completed and call_id not in recorded:
                return item
        if empty_id_starts > empty_id_completions:
            return {"tool_call_id": "", "tool_name": empty_id_tool, "status": "in_flight"}
        return None

    def _mark_tool_recovery(self, task: Task, record: dict[str, Any], *, reason: str, result: dict[str, Any] | None = None) -> dict[str, Any]:
        call_id = str(record.get("tool_call_id") or "")
        result = result or {"ok": False, "error": "tool_outcome_unknown"}
        with self._state_lock:
            existing = next((item for item in task.tool_calls if item.get("tool_call_id") == call_id), None)
            if existing is not None and existing.get("status") == "in_flight":
                task.finish_tool_call(call_id, "unknown", result=result)
            if not isinstance(task.execution_state.get("recovery_required"), dict):
                details = {
                    "tool_call_id": call_id,
                    "tool_name": str(record.get("tool_name") or ""),
                    "risk_class": str(record.get("risk_class") or "unknown"),
                    "status": "unknown",
                    "reason": reason,
                    "request_id": task.request_id,
                }
                task.execution_state["recovery_required"] = details
                task.error = "tool_outcome_unknown"
                task.update_status(TaskStatus.WAITING_FOR_TOOL)
                self._event(task, "tool.outcome_unknown", details)
            else:
                task.error = "tool_outcome_unknown"
                if task.status != TaskStatus.WAITING_FOR_TOOL:
                    task.update_status(TaskStatus.WAITING_FOR_TOOL)
                TaskManager.update_task(task)
        return {"ok": False, "error": "tool_outcome_unknown", "recovery_required": True, "tool_call_id": call_id}

    def _run_one(self, task: Task, call: ToolCall, owner_session_token: str, owner_session_id: str | None) -> dict[str, Any]:
        tool_call_id = call.call_id or uuid.uuid4().hex
        if task.has_tool_call(tool_call_id):
            existing = next(item for item in task.tool_calls if item.get("tool_call_id") == tool_call_id)
            if existing.get("status") in {"in_flight", "unknown", "failed"}:
                return self._mark_tool_recovery(task, existing, reason="replayed call has an unresolved prior outcome", result=existing.get("result"))
            return existing.get("result") or {"ok": False, "error": "replayed_tool_call"}
        argument = self._argument(call)
        argument_sha256 = hashlib.sha256((argument or "").encode("utf-8")).hexdigest()
        item = call.name if argument is None else [call.name, argument]
        spec = get_tool(call.name)
        valid, reason = spec.validate(argument) if spec else (False, "unknown tool")
        if set(call.arguments) - {"query"}:
            valid, reason = False, "unknown tool argument"
        authorization_context = self._authorization_context(task)
        decision = authorize_tool(item, context=authorization_context) if authorization_context is not None else authorize_tool(item)
        self._event(task, "tool.selected", {"tool": call.name, "tool_call_id": tool_call_id})
        if spec is not None and spec.scope_required:
            scope_context = task.execution_state.get("scope_context")
            if authorization_context is None or authorization_context.scope_snapshot is None or not isinstance(scope_context, dict) or scope_context.get("scope_snapshot_id") != authorization_context.scope_snapshot.snapshot_id:
                valid, reason = False, "scope context is not bound to AuthorizationContext"
            elif not isinstance(scope_context, dict):
                valid, reason = False, "scope context required"
            else:
                from security.scope_resolver import resolve
                requested_url = argument if isinstance(argument, str) and "://" in argument else scope_context["url"]
                urls = [scope_context["url"]] if requested_url == scope_context["url"] else [scope_context["url"], requested_url]
                for checked_url in urls:
                    scope_decision = resolve(scope_context["scope_snapshot_id"], scope_context["target_id"], checked_url, method=scope_context.get("method", "GET"), expected_program_id=scope_context["program_id"], redirect_chain=scope_context.get("redirect_chain", []))
                    if not scope_decision.allowed:
                        valid, reason = False, "scope denied: " + scope_decision.reason
                        break
        if not decision.allowed or not valid:
            result = {"ok": False, "error": decision.reason if not decision.allowed else reason}
            task.record_tool_call(tool_call_id, call.name, "denied", request_id=task.request_id, owner_session_id=task.owner_session_id, result=result, argument=argument)
            self._event(task, "tool.completed", {"tool": call.name, "tool_call_id": tool_call_id, "status": "denied"})
            return result

        risk_class = spec.risk_class if spec is not None else "unknown"
        intent = {"tool_call_id": tool_call_id, "tool_name": call.name, "risk_class": risk_class, "status": "in_flight"}
        with self._state_lock:
            if not task.begin_tool_call(tool_call_id, call.name, request_id=task.request_id, owner_session_id=task.owner_session_id, argument_sha256=argument_sha256, risk_class=risk_class):
                existing = next((entry for entry in task.tool_calls if entry.get("tool_call_id") == tool_call_id), intent)
                return self._mark_tool_recovery(task, existing, reason="tool intent already exists", result=existing.get("result"))
            # _event commits the in-flight record to SQLite before any executor call.
            self._event(task, "tool.started", {"tool": call.name, "tool_call_id": tool_call_id, "risk_class": risk_class, "argument_sha256": argument_sha256})

        try:
            scope_context = task.execution_state.get("scope_context")
            if spec is not None and spec.scope_required:
                result = {"ok": True, "result": execute_tool(call.name, argument, authorization_decision=decision.decision, scope_context=scope_context, request_id=task.request_id)}
            else:
                result = self.executor(f"Owner {call.name}" + (f" {argument}" if argument else ""), owner_session_token=owner_session_token, owner_session_id=owner_session_id, scope_context=scope_context, authorization_context=authorization_context, authorization_decision=decision.decision)
            result = result if isinstance(result, dict) else {"ok": True, "result": result}
        except Exception as exc:
            result = {"ok": False, "error": type(exc).__name__}
            return self._mark_tool_recovery(task, intent, reason="executor raised after dispatch began", result=result)

        if result.get("ok", True) is False:
            return self._mark_tool_recovery(task, intent, reason="executor returned a non-success result after dispatch began", result=result)

        with self._state_lock:
            if not task.finish_tool_call(tool_call_id, "completed", result=result, argument=argument):
                existing = next((entry for entry in task.tool_calls if entry.get("tool_call_id") == tool_call_id), intent)
                return self._mark_tool_recovery(task, existing, reason="completion could not be durably bound to its intent", result={"ok": False, "error": "tool_outcome_unknown"})
            self._event(task, "tool.completed", {"tool": call.name, "tool_call_id": tool_call_id, "status": "completed"})
        if result.get("request_id"):
            task.execution_state.setdefault("evidence_refs", []).append(result["request_id"])
            self._event(task, "evidence.added", {"request_id": result["request_id"], "tool": call.name})
        memory_item = ConversationMemory.store_conversation_memory(task.conversation_id, json.dumps({"tool": call.name, "result": result}, ensure_ascii=False), MemoryType.TOOL_RESULT, source="tool", provenance=f"task:{task.task_id}", metadata={"tool_call_id": tool_call_id})
        task.execution_state.setdefault("memory_refs", []).append(memory_item.memory_id)
        self._event(task, "memory.updated", {"type": "tool_result", "tool_call_id": tool_call_id})
        return result

    def _guard_batch(self, task: Task, calls: list[ToolCall]) -> str | None:
        if len(task.tool_calls) + len(calls) > self.limits.max_tool_calls:
            return "max_tool_calls"
        counts: dict[str, int] = {}
        for item in task.tool_calls:
            name = item.get("tool_name")
            if isinstance(name, str) and name:
                counts[name] = counts.get(name, 0) + 1
        signatures = dict(task.execution_state.get("call_signatures", {}))
        last_signature = str(task.execution_state.get("last_signature", ""))
        for call in calls:
            counts[call.name] = counts.get(call.name, 0) + 1
            if counts[call.name] > self.limits.max_same_tool_calls:
                return "repeated_tool_loop"
            signature = json.dumps({"name": call.name, "arguments": call.arguments}, sort_keys=True, ensure_ascii=False)
            signatures[signature] = signatures.get(signature, 0) + 1
            if last_signature == signature and task.execution_state.get("last_result_hash") == task.execution_state.get("previous_result_hash"):
                return "no_progress_cycle"
            last_signature = signature
        task.execution_state["call_signatures"] = signatures
        task.execution_state["last_signature"] = last_signature
        return None

    def _guard_call(self, task: Task, call: ToolCall) -> str | None:
        """Compatibility wrapper around the atomic batch budget check."""
        return self._guard_batch(task, [call])

    def run_slice(self, task_id: str, *, owner_session_token: str = "", owner_session_id: str | None = None) -> Task:
        try:
            return self._run_slice_once(task_id, owner_session_token=owner_session_token, owner_session_id=owner_session_id)
        except TaskVersionConflictError:
            # A concurrent control request or worker advanced the durable row.
            # Never overwrite it with this stale in-memory snapshot.
            latest = TaskManager.get_task(task_id)
            if latest is None:
                raise KeyError("unknown_task")
            if latest.status is TaskStatus.EXECUTING and (latest.cancel_requested or latest.pause_requested):
                try:
                    if latest.cancel_requested:
                        latest.update_status(TaskStatus.CANCELLED)
                        self._event(latest, "task.cancelled")
                    else:
                        latest.update_status(TaskStatus.PAUSED)
                        TaskManager.update_task(latest)
                except TaskVersionConflictError:
                    return TaskManager.get_task(task_id) or latest
            return latest

    def _run_slice_once(self, task_id: str, *, owner_session_token: str = "", owner_session_id: str | None = None) -> Task:
        task = TaskManager.get_task(task_id)
        if task is None:
            raise KeyError("unknown_task")
        if not self._valid_owner_session(task, owner_session_token):
            raise PermissionError("owner authentication required")
        pending_tool = self._pending_tool_call(task)
        if pending_tool is not None:
            self._mark_tool_recovery(task, pending_tool, reason="task resumed with an unresolved tool dispatch")
            return task
        claimed = TaskManager.claim_task(task_id, task.owner_session_id, allow_paused=True)
        if claimed is None:
            return TaskManager.get_task(task_id) or task
        task = claimed
        if task.cancel_requested:
            task.update_status(TaskStatus.CANCELLED)
            self._event(task, "task.cancelled")
            TaskManager.update_task(task)
            return task
        if task.current_step >= self.limits.max_execution_steps:
            task.update_status(TaskStatus.PARTIAL_SUCCESS if task.tool_calls else TaskStatus.FAILED)
            task.error = "execution_window_limit"
            self._event(task, "task.failed", {"reason": task.error})
            TaskManager.update_task(task)
            return task
        task.increment_step()
        # Keep the task non-claimable while this synchronous slice is actively
        # requesting a model response or dispatching its proposed tools.
        self._event(task, "task.started", {"step": task.current_step})
        TaskManager.update_task(task)
        try:
            context = self._context(task)
            self._event(task, "assistant.started", {"context_hash": context.context_hash})
            response = self._ask_model(context, task.objective)
            latest = TaskManager.get_task(task_id)
            if latest is None:
                raise KeyError("unknown_task")
            if latest.task_version != task.task_version:
                raise TaskVersionConflictError("task row changed while awaiting model response")
            task.execution_state["reasoning_profile"] = select_reasoning_profile(task.objective).to_dict()
            kind, value = self._parse(response)
            task.provider = response.get("provider", task.provider)
            task.model = response.get("model", task.model)
            if kind == "final":
                task.result = {"answer": value, "provenance": {"provider": task.provider, "model": task.model}, "context_hash": context.context_hash}
                add_conversation_message(task.conversation_id, "assistant", value, {"task_id": task.task_id, "step": task.current_step})
                ConversationMemory.store_conversation_memory(task.conversation_id, value, MemoryType.RECENT, source="assistant", provenance=f"task:{task.task_id}")
                task.update_status(TaskStatus.COMPLETED if not task.tool_calls or all(item.get("status") == "completed" for item in task.tool_calls) else TaskStatus.PARTIAL_SUCCESS)
                self._event(task, "assistant.completed", {"chars": len(value)})
            elif kind == "needs_input":
                task.result = {"question": value}
                task.update_status(TaskStatus.NEEDS_INPUT)
                self._event(task, "assistant.completed", {"needs_input": True})
            else:
                unique_calls = []
                seen_batch_ids = set()
                for call in value:
                    if call.call_id and (call.call_id in seen_batch_ids or task.has_tool_call(call.call_id)):
                        raise InvalidModelResponse("task model returned duplicate tool-call identifiers")
                    if call.call_id:
                        seen_batch_ids.add(call.call_id)
                    unique_calls.append(call)
                value = unique_calls
                guarded = self._guard_batch(task, value)
                if guarded:
                    task.error = guarded
                    task.update_status(TaskStatus.PARTIAL_SUCCESS if task.tool_calls else TaskStatus.FAILED)
                    self._event(task, "task.failed", {"reason": guarded})
                elif len(value) > 1 and all((get_tool(call.name) and get_tool(call.name).risk_class in {"read", "network-read"}) for call in value):
                    with ThreadPoolExecutor(max_workers=min(len(value), 8)) as pool:
                        list(pool.map(lambda call: self._run_one(task, call, owner_session_token, owner_session_id), value))
                else:
                    for call in value:
                        if task.cancel_requested:
                            task.update_status(TaskStatus.CANCELLED)
                            self._event(task, "task.cancelled")
                            break
                        self._run_one(task, call, owner_session_token, owner_session_id)
                        if task.execution_state.get("recovery_required"):
                            break
                if not task.is_terminal and not task.execution_state.get("recovery_required"):
                    task.update_status(TaskStatus.WAITING_FOR_MODEL)
                if not task.is_terminal and not task.execution_state.get("recovery_required"):
                    task.save_resume_state({"next": "model", "step": task.current_step})
        except TaskVersionConflictError:
            raise
        except ProviderError as exc:
            task.increment_retry()
            kind = str(getattr(exc, "kind", "PROVIDER_FAILURE"))
            task.error = f"provider_failure:{kind}"
            attempts = [
                {key: str(item.get(key, "")) for key in ("provider", "model", "kind")}
                for item in getattr(exc, "attempts", ())
                if isinstance(item, dict)
            ]
            self._event(task, "model.provider_failure", {
                "kind": kind,
                "provider": str(getattr(exc, "provider", "") or ""),
                "model": str(getattr(exc, "model", "") or ""),
                "attempts": attempts,
                "retry_count": task.retry_count,
            })
            task.update_status(TaskStatus.PARTIAL_SUCCESS if task.tool_calls else TaskStatus.FAILED)
            self._event(task, "task.failed", {"reason": task.error, "retry_count": task.retry_count})
        except Exception as exc:
            task.increment_retry()
            task.error = type(exc).__name__
            task.update_status(TaskStatus.PARTIAL_SUCCESS if task.tool_calls else TaskStatus.FAILED)
            self._event(task, "task.failed", {"reason": task.error, "retry_count": task.retry_count})
        TaskManager.update_task(task)
        return task

    def run_to_completion(self, task_id: str, *, owner_session_token: str = "", owner_session_id: str | None = None, max_slices: int | None = None) -> Task:
        slices = 0
        while slices < (max_slices or self.limits.max_execution_steps):
            task = self.run_slice(task_id, owner_session_token=owner_session_token, owner_session_id=owner_session_id)
            slices += 1
            if task.is_terminal or task.pause_requested or task.cancel_requested or task.execution_state.get("recovery_required"):
                return task
        return TaskManager.get_task(task_id) or task
