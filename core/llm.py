"""Deprecated compatibility shim.

The active planner path is agent.runtime.AgentRuntime -> ModelRouter -> Provider.
This module intentionally performs no network calls and is retained only so old
local imports fail safely with an explicit message during migration.
"""


def plan_with_llm(*_args, **_kwargs):
    raise RuntimeError("core.llm is retired; use agent.runtime.AgentRuntime.plan")


def model_status():
    return {"configured": False, "retired": True}
