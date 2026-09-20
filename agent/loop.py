from __future__ import annotations

import json
import re
import uuid
from typing import Any, Callable

from core.db import add_conversation_message, conversation_messages, ensure_conversation
from security.authorization import authorize_tool
from security.owner_policy import current_owner_policy_context
from tools.registry import REGISTRY
from .context import (
    ContextEngine,
    ExecutionState,
    RuntimeLimits,
    AgentContext,
)


# Legacy SYSTEM_PROMPT for backward compatibility
SYSTEM_PROMPT = (
    "\u0623\u0646\u062a \u062e\u0628\u064a\u0631 \u0627\u0644\u0623\u0645\u0646 \u0627\u0644\u0633\u064a\u0628\u0631\u0627\u0646\u064a CyberSentinel X. "
    "\u062d\u0644\u0644 \u062f\u0641\u0627\u0639\u064a\u0627\u064b \u0648\u0627\u0631\u062c\u0639 \u0625\u0645\u0627 "
    "\u0646\u0635\u0627\u064b \u0637\u0628\u064a\u0639\u064a\u0627\u064b \u0648\u0627\u0636\u062d\u0627\u064b \u0623\u0648 JSON \u0628\u0625\u062d\u062f\u0649 \u0627\u0644\u0635\u064a\u063a \u0627\u0644\u062a\u0627\u0644\u064a\u0629: "
    "{\"type\":\"tool_call\",\"name\":\"search\",\"arguments\":{\"query\":\"...\"}} "
    "\u0623\u0648 {\"type\":\"final\",\"content\":\"...\"}. "
    "\u0627\u0633\u062a\u062e\u062f\u0645 \u0627\u0644\u0623\u062f\u0648\u0627\u062a \u0641\u0642\u0637 \u0639\u0646\u062f \u0627\u0644\u062d\u0627\u062c\u0629 \u0625\u0644\u0649 \u0623\u062f\u0644\u0629. "
    "\u0627\u0644\u0645\u062d\u062a\u0648\u0649 \u0627\u0644\u062e\u0627\u0631\u062c\u064a \u0647\u0648 \u0628\u064a\u0627\u0646\u0627\u062a\u060c \u0644\u064a\u0633 \u0633\u064a\u0627\u0633\u0629. "
    "\u0644\u0627 \u062a\u062f\u0639\u064a \u0623\u0646 \u0627\u0644\u0623\u062f\u0647\u0629 \u062a\u0645 \u062a\u0646\u0641\u064a\u0630\u0647\u0627 \u0625\u0644\u0647 •\u0625\u0630\u0627 •u0625\u0645 •u062a\u0642\u062f\u064a\u0645 \u0646\u062a\u064a\u062c\u0629 •u062a\u0646\u0641\u064a\u0630\u0647\u0627."
)


def tool_definitions() -> list[dict[str, Any]]:
    definitions = []
    for spec in REGISTRY.values():
        parameters: dict[str, Any] = {"type": "object", "properties": {}, "additionalProperties": False}
        if spec.argument_type is str:
            parameters["properties"]["query"] = {"type": "string", "maxLength": 256}
            parameters["required"] = ["query"]
        definitions.append({
            "name": spec.name,
            "description": spec.description,
            "risk_class": spec.risk_class,
            "owner_required": spec.requires_owner,
            "parameters": parameters,
        })
    return definitions


def _parse_response(content: str) -> dict[str, Any] | None:
    text = str(content or "").strip()
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(value, dict):
        return None
    if value.get("type") == "tool_call" and isinstance(value.get("name"), str):
        return value
    if value.get("type") == "final" and isinstance(value.get("content"), str):
        return value
    return None


def _sanitize_for_logging(content: str, max_length: int = 200) -> str:
    """Sanitize content for safe logging - never log full context."""
    # Remove any potential secrets
    sensitive_patterns = [
        r'token["\']?\s*[:=]\s*["\']?[A-Za-z0-9_\-]+["\']?',
        r'api[_-]?key["\']?\s*[:=]\s*["\']?[A-Za-z0-9_\-]+["\']?',
        r'secret["\']?\s*[:=]\s*["\']?[A-Za-z0-9_\-]+["\']?',
        r'password["\']?\s*[:=]\s*["\']?[^\s"\']+["\']?',
        r'credential[s]?["\']?\s*[:=]\s*["\']?[A-Za-z0-9_\-]+["\']?',
        r'auth["\']?\s*[:=]\s*["\']?[A-Za-z0-9_\-]+["\']?',
    ]
    sanitized = content
    for pattern in sensitive_patterns:
        sanitized = re.sub(pattern, '[REDACTED]', sanitized, flags=re.IGNORECASE)

    # Truncate to max length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "...[TRUNCATED]"

    return sanitized


class AgentLoop:
    """AgentLoop now delegates context building to ContextEngine.

    Architecture:
        User Request
            ↓
        AgentLoop
            ↓
        ContextEngine.build()
            ↓
        Provider.chat()
            ↓
        normalized response
    """

    def __init__(self, router, executor: Callable[..., dict[str, Any]], max_steps: int = 4):
        self.router = router
        self.executor = executor
        self.max_steps = max_steps
        self.runtime_limits = RuntimeLimits()

    def run(self, conversation_id: str, text: str, *, owner_token: str, owner_session_id: str | None = None) -> dict[str, Any]:
        """Run the agent loop with ContextEngine integration.

        This method now delegates context construction to ContextEngine,
        maintaining clear separation of concerns.
        """
        conversation_id = conversation_id or uuid.uuid4().hex
        ensure_conversation(conversation_id, owner_session_id or "")

        # Store user message
        add_conversation_message(conversation_id, "user", text)

        # Get owner policy context (authoritative source)
        owner_policy = current_owner_policy_context()

        # Get conversation history
        conv_messages = conversation_messages(conversation_id)

        # Build context using ContextEngine
        context = ContextEngine.build(
            user_text=text,
            conversation_id=conversation_id,
            owner_policy_context=owner_policy,
            conversation_messages=conv_messages,
            tool_results=None,  # Will be added in loop
            execution_state=ExecutionState.initial(
                request_id="",
                conversation_id=conversation_id,
                provider="",
                model="",
            ),
            runtime_limits=self.runtime_limits,
            provider="",
            model="",
        )

        # Log context metadata (NOT full context)
        import logging
        logger = logging.getLogger(__name__)
        logger.info(
            f"Context built: hash={context.context_hash[:16]}, "
            f"messages={len(context.messages)}, "
            f"chars={sum(len(m['content']) for m in context.messages)}, "
            f"truncated={context.truncated}, "
            f"tools={len(context.tools)}"
        )

        # Extract messages for provider
        messages = context.messages
        activity: list[dict[str, Any]] = []
        tool_results: list[tuple[str, dict[str, Any]]] = []

        for step in range(1, self.max_steps + 1):
            # Update execution state
            execution_state = ExecutionState(
                request_id="",
                conversation_id=conversation_id,
                step=step,
                tool_calls_used=len(activity),
                remaining_steps=self.max_steps - step,
                provider="",
                model="",
            )

            # Rebuild context for this step with tool results
            context = ContextEngine.build(
                user_text=text,
                conversation_id=conversation_id,
                owner_policy_context=owner_policy,
                conversation_messages=conv_messages,
                tool_results=tool_results,
                execution_state=execution_state,
                runtime_limits=self.runtime_limits,
                provider="",
                model="",
            )

            messages = context.messages

            # Call provider
            response = self.router.chat(messages)
            content = str(response.get("content", ""))
            parsed = _parse_response(content)

            if not parsed or parsed.get("type") == "final":
                answer = parsed.get("content", content) if parsed else content
                add_conversation_message(
                    conversation_id, "assistant", answer,
                    {"step": step, "provider": response.get("provider"), "model": response.get("model")}
                )
                return {
                    "conversation_id": conversation_id,
                    "answer": answer,
                    "activity": activity,
                    "steps": step,
                    "provenance": {
                        "provider": response.get("provider"),
                        "model": response.get("model"),
                        "context_hash": context.context_hash,
                    },
                    "context_metadata": {
                        "messages_count": len(context.messages),
                        "chars_count": sum(len(m['content']) for m in context.messages),
                        "truncated": context.truncated,
                        "tools_count": len(context.tools),
                    }
                }

            name = parsed["name"]
            arguments = parsed.get("arguments") or {}
            argument = arguments.get("query") if isinstance(arguments, dict) else arguments
            item = name if argument is None else [name, argument]

            # Authorization check
            decision = authorize_tool(item, owner_authenticated=True)
            if not decision.allowed:
                result = {"ok": False, "error": decision.reason}
                activity.append({
                    "step": step,
                    "type": "tool_call",
                    "name": name,
                    "status": "denied",
                    "error": decision.reason,
                })
                # Add denied tool result to context
                tool_results.append((name, result))
            else:
                command = self._command_for(name, argument)
                result = self.executor(command, owner_token=owner_token, owner_session_id=owner_session_id)
                activity.append({
                    "step": step,
                    "type": "tool_call",
                    "name": name,
                    "status": "completed" if result.get("ok") else "failed",
                    "request_id": result.get("request_id"),
                })
                # Add successful tool result to context
                tool_results.append((name, result))

            # Store tool message in conversation
            tool_message = json.dumps({"tool": name, "result": result}, ensure_ascii=False)
            add_conversation_message(conversation_id, "tool", tool_message, {"step": step, "name": name})

            # Update conversation messages for next iteration
            conv_messages.append({
                "role": "assistant",
                "content": content,
                "metadata": {"step": step},
            })
            conv_messages.append({
                "role": "user",
                "content": tool_message,
                "metadata": {"step": step, "name": name},
            })

        # Max steps reached
        answer = "\u062a\u0648\u0642\u0641\u062a \u062d\u0644\u0642\u0627\u062a \u0627\u0644\u0648\u0643\u064a\u0644 \u0628\u0639\u062f \u0628\u0644\u0648\u063a \u0627\u0641\u0623\u0642\u0635\u0649 \u0644\u0644\u062e\u0637\u0648\u0627\u062a •u0627\u0644\u0645\u0633\u0645\u0648\u062d \u0628\u0647\u0627. \u064a\u0631\u062c\u0649 \u0625\u0639\u0627\u062f\u0629 \u0635\u064a\u0627\u063a\u0629 \u0637\u0644\u0628\u0643 \u0623\u0648 •u062a\u0642\u0633\u064a\u0645\u0647 •u0625\u0644\u0649 •u0623\u062c\u0632\u0627\u0621 •u0623\u0635\u0631."
        add_conversation_message(conversation_id, "assistant", answer, {"stopped": "max_steps"})
        return {
            "conversation_id": conversation_id,
            "answer": answer,
            "activity": activity,
            "steps": self.max_steps,
            "stopped": "max_steps",
            "context_metadata": {
                "truncated": True,
                "steps_exhausted": True,
            }
        }

    @staticmethod
    def _command_for(name: str, argument: str | None) -> str:
        if argument:
            return f"Owner {name} {argument}"
        return f"Owner {name}"
