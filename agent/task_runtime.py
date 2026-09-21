from __future__ import annotations

import json
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from typing import Any, Callable

from agent.context import ContextEngine, ExecutionState, RuntimeLimits
from agent.memory import ConversationMemory, MemoryProvider, MemoryType, TrustClassification
from agent.provider_api import ToolCall
from agent.task import Task, TaskStatus
from agent.task_manager import TaskManager
from core.db import add_conversation_message, conversation_messages, ensure_conversation
from security.authorization import authorize_tool
from security.authorization_context import AuthorizationContext
from security.owner_policy import current_owner_policy_context, policy_context_from_snapshot
from security.owner_session import DEFAULT_OWNER_SESSIONS
from tools.registry import REGISTRY, execute as execute_tool, get_tool


class AgentTaskRuntime:
    """Persistent, slice-based runtime. Every model/tool boundary is committed to SQLite."""

    def __init__(self, router: Any, executor: Callable[..., dict[str, Any]] | None = None, runtime_limits: RuntimeLimits | None = None):
        self.router = router
        self.executor = executor or self._default_executor
        self.limits = runtime_limits or RuntimeLimits.from_owner_policy()

    @staticmethod
    def _default_executor(command: str, *, owner_token: str, owner_session_id: str | None = None, scope_context: dict[str, Any] | None = None, authorization_context: AuthorizationContext | None = None, authorization_decision: Any = None) -> dict[str, Any]:
        parts = command.split(" ", 2)
        name = parts[1] if len(parts) > 1 else ""
        argument = parts[2] if len(parts) > 2 else None
        return {"ok": True, "result": execute_tool(name, argument, authorization_decision=authorization_decision, scope_context=scope_context)}

    @staticmethod
    def _schemas() -> list[dict[str, Any]]:
        schemas = []
        for spec in REGISTRY.values():
            parameters = {"type": "object", "properties": {}, "additionalProperties": False}
            if spec.argument_type is str:
                parameters["properties"]["query"] = {"type": "string", "maxLength": 256}
                parameters["required"] = ["query"]
            schemas.append({"type": "function", "function": {"name": spec.name, "description": spec.description[:512], "parameters": parameters}})
        return schemas

    @staticmethod
    def _event(task: Task, event: str, data: dict[str, Any] | None = None) -> None:
        events = task.execution_state.setdefault("events", [])
        events.append({"event": event, "task_id": task.task_id, "conversation_id": task.conversation_id, "request_id": task.request_id, "step": task.current_step, "data": data or {}, "timestamp": time.time()})
        task.execution_state["events"] = events[-500:]
        TaskManager.update_task(task)

    @staticmethod
    def _tool_calls(response: dict[str, Any]) -> list[ToolCall]:
        calls = []
        for item in response.get("tool_calls") or []:
            if isinstance(item, ToolCall):
                calls.append(item)
            elif isinstance(item, dict) and isinstance(item.get("name"), str):
                args = item.get("arguments") if isinstance(item.get("arguments"), dict) else {}
                calls.append(ToolCall(item["name"], args, str(item.get("id") or uuid.uuid4().hex)))
        return calls

    @staticmethod
    def _parse(response: dict[str, Any]) -> tuple[str, Any]:
        calls = AgentTaskRuntime._tool_calls(response)
        if calls:
            return "tool_calls", calls
        content = str(response.get("content", "") or "")
        try:
            value = json.loads(content)
        except json.JSONDecodeError:
            return "final", content
        if isinstance(value, dict) and value.get("type") in {"final", "final_answer"}:
            return "final", str(value.get("content", value.get("answer", "")))
        if isinstance(value, dict) and value.get("type") == "clarification":
            return "needs_input", str(value.get("question", "معلومات إضافية مطلوبة."))
        if isinstance(value, dict) and value.get("type") == "tool_call" and isinstance(value.get("name"), str):
            return "tool_calls", [ToolCall(value["name"], value.get("arguments") or {}, uuid.uuid4().hex)]
        return "final", content

    def create_task(self, conversation_id: str, objective: str, *, owner_session_id: str = "", authentication_method: str = "owner_token", scope_context: dict[str, Any] | None = None, authorization_context: AuthorizationContext | None = None) -> Task:
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

    def _valid_owner_session(self, task: Task, owner_session_id: str | None, owner_token: str) -> bool:
        if isinstance(task.execution_state, dict) and task.execution_state.get("authorization_context"):
            try:
                self._authorization_context(task)
                return True
            except (PermissionError, ValueError, TypeError):
                return False
        if owner_token:
            from security.owner_policy import verify_owner
            ok, _ = verify_owner("Owner task execution", owner_token)
            if ok:
                return True
        return bool(owner_session_id and owner_session_id == task.owner_session_id and DEFAULT_OWNER_SESSIONS.is_active(owner_session_id))

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

    def _ask_model(self, context: Any) -> dict[str, Any]:
        payload = context.to_provider_payload()
        try:
            return self.router.tool_calling(payload["messages"], self._schemas())
        except (AttributeError, NotImplementedError):
            return self.router.generate(payload["messages"])

    @staticmethod
    def _argument(call: ToolCall) -> str | None:
        if not call.arguments:
            return None
        value = call.arguments.get("query")
        return value if isinstance(value, str) else None

    def _run_one(self, task: Task, call: ToolCall, owner_token: str, owner_session_id: str | None) -> dict[str, Any]:
        if call.call_id and task.has_tool_call(call.call_id):
            existing = next(item for item in task.tool_calls if item.get("tool_call_id") == call.call_id)
            return existing.get("result") or {"ok": False, "error": "replayed_tool_call"}
        argument = self._argument(call)
        item = call.name if argument is None else [call.name, argument]
        spec = get_tool(call.name)
        valid, reason = spec.validate(argument) if spec else (False, "unknown tool")
        if set(call.arguments) - {"query"}:
            valid, reason = False, "unknown tool argument"
        authorization_context = self._authorization_context(task)
        decision = authorize_tool(item, context=authorization_context) if authorization_context is not None else authorize_tool(item)
        self._event(task, "tool.selected", {"tool": call.name, "tool_call_id": call.call_id})
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
            task.record_tool_call(call.call_id, call.name, "denied", request_id=task.request_id, owner_session_id=task.owner_session_id, result=result, argument=argument)
            self._event(task, "tool.completed", {"tool": call.name, "tool_call_id": call.call_id, "status": "denied"})
            return result
        self._event(task, "tool.started", {"tool": call.name, "tool_call_id": call.call_id})
        try:
            scope_context = task.execution_state.get("scope_context")
            if spec is not None and spec.scope_required:
                result = {"ok": True, "result": execute_tool(call.name, argument, authorization_decision=decision.decision, scope_context=scope_context)}
            else:
                result = self.executor(f"Owner {call.name}" + (f" {argument}" if argument else ""), owner_token=owner_token, owner_session_id=owner_session_id, scope_context=scope_context, authorization_context=authorization_context, authorization_decision=decision.decision)
            result = result if isinstance(result, dict) else {"ok": True, "result": result}
            status = "completed" if result.get("ok", True) else "failed"
        except Exception as exc:
            result = {"ok": False, "error": type(exc).__name__}
            status = "failed"
        task.record_tool_call(call.call_id, call.name, status, request_id=task.request_id, owner_session_id=task.owner_session_id, result=result, argument=argument)
        if result.get("request_id"):
            task.execution_state.setdefault("evidence_refs", []).append(result["request_id"])
            self._event(task, "evidence.added", {"request_id": result["request_id"], "tool": call.name})
        memory_item = ConversationMemory.store_conversation_memory(task.conversation_id, json.dumps({"tool": call.name, "result": result}, ensure_ascii=False), MemoryType.TOOL_RESULT, source="tool", provenance=f"task:{task.task_id}", metadata={"tool_call_id": call.call_id})
        task.execution_state.setdefault("memory_refs", []).append(memory_item.memory_id)
        self._event(task, "memory.updated", {"type": "tool_result", "tool_call_id": call.call_id})
        self._event(task, "tool.completed", {"tool": call.name, "tool_call_id": call.call_id, "status": status})
        return result

    def _guard_call(self, task: Task, call: ToolCall) -> str | None:
        if len(task.tool_calls) >= self.limits.max_tool_calls:
            return "max_tool_calls"
        signature = json.dumps({"name": call.name, "arguments": call.arguments}, sort_keys=True, ensure_ascii=False)
        signatures = task.execution_state.setdefault("call_signatures", {})
        signatures[signature] = signatures.get(signature, 0) + 1
        if signatures[signature] > self.limits.max_same_tool_calls:
            return "repeated_tool_loop"
        if task.execution_state.setdefault("last_signature", "") == signature and task.execution_state.get("last_result_hash") == task.execution_state.get("previous_result_hash"):
            return "no_progress_cycle"
        task.execution_state["last_signature"] = signature
        return None

    def run_slice(self, task_id: str, *, owner_token: str = "", owner_session_id: str | None = None) -> Task:
        task = TaskManager.get_task(task_id)
        if task is None:
            raise KeyError("unknown_task")
        if not self._valid_owner_session(task, owner_session_id, owner_token):
            raise PermissionError("owner authentication required")
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
        task.update_status(TaskStatus.WAITING_FOR_MODEL)
        self._event(task, "task.started", {"step": task.current_step})
        TaskManager.update_task(task)
        try:
            context = self._context(task)
            self._event(task, "assistant.started", {"context_hash": context.context_hash})
            response = self._ask_model(context)
            task.provider = response.get("provider", task.provider)
            task.model = response.get("model", task.model)
            kind, value = self._parse(response)
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
                task.update_status(TaskStatus.WAITING_FOR_TOOL)
                unique_calls = []
                seen_batch_ids = set()
                for call in value:
                    if call.call_id and (call.call_id in seen_batch_ids or task.has_tool_call(call.call_id)):
                        continue
                    if call.call_id:
                        seen_batch_ids.add(call.call_id)
                    unique_calls.append(call)
                value = unique_calls
                guarded = None
                for candidate in value:
                    guarded = self._guard_call(task, candidate)
                    if guarded:
                        break
                if guarded:
                    task.error = guarded
                    task.update_status(TaskStatus.PARTIAL_SUCCESS if task.tool_calls else TaskStatus.FAILED)
                    self._event(task, "task.failed", {"reason": guarded})
                elif len(value) > 1 and all((get_tool(call.name) and get_tool(call.name).risk_class in {"read", "network-read"}) for call in value):
                    with ThreadPoolExecutor(max_workers=min(len(value), 8)) as pool:
                        list(pool.map(lambda call: self._run_one(task, call, owner_token, owner_session_id), value))
                else:
                    for call in value:
                        if task.cancel_requested:
                            task.update_status(TaskStatus.CANCELLED)
                            self._event(task, "task.cancelled")
                            break
                        self._run_one(task, call, owner_token, owner_session_id)
                if not task.is_terminal and task.status == TaskStatus.WAITING_FOR_TOOL:
                    task.update_status(TaskStatus.WAITING_FOR_MODEL)
                if not task.is_terminal:
                    task.save_resume_state({"next": "model", "step": task.current_step})
        except Exception as exc:
            task.increment_retry()
            task.error = type(exc).__name__
            task.update_status(TaskStatus.PARTIAL_SUCCESS if task.tool_calls else TaskStatus.FAILED)
            self._event(task, "task.failed", {"reason": task.error, "retry_count": task.retry_count})
        TaskManager.update_task(task)
        return task

    def run_to_completion(self, task_id: str, *, owner_token: str = "", owner_session_id: str | None = None, max_slices: int | None = None) -> Task:
        slices = 0
        while slices < (max_slices or self.limits.max_execution_steps):
            task = self.run_slice(task_id, owner_token=owner_token, owner_session_id=owner_session_id)
            slices += 1
            if task.is_terminal or task.pause_requested or task.cancel_requested:
                return task
        return TaskManager.get_task(task_id) or task
