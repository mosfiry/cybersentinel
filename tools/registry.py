from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

MAX_ARG_LENGTH = 256


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    risk_class: str
    requires_owner: bool
    argument_type: type | None
    handler: Callable[[str | None], Any]

    def validate(self, argument: Any) -> tuple[bool, str]:
        if self.argument_type is None:
            if argument is not None:
                return False, f"{self.name} does not accept an argument"
            return True, "valid"
        if not isinstance(argument, self.argument_type):
            return False, f"{self.name} requires a string argument"
        if not argument.strip():
            return False, f"{self.name} requires a non-empty string argument"
        if len(argument.strip()) > MAX_ARG_LENGTH:
            return False, "tool argument exceeds maximum length"
        return True, "valid"


def _status(_):
    from core.engine import status
    return status()


def _latest_intel(_):
    from core.intel import latest_intel
    return latest_intel(50)


def _refresh_intel(_):
    from core.intel import refresh_all
    return refresh_all()


def _local_security(_):
    from core.local_defense import local_security_check
    return local_security_check()


def _system_info(_):
    from core.local_defense import local_system_info
    return local_system_info()


def _search(argument):
    from core.db import search_all
    return search_all(argument or "", 50)


def _watch(argument):
    from core.db import add_watch, watches
    add_watch(argument or "")
    return {"keyword": argument, "watches": watches()}


def _unwatch(argument):
    from core.db import remove_watch, watches
    remove_watch(argument or "")
    return {"keyword": argument, "watches": watches()}


REGISTRY: dict[str, ToolSpec] = {
    "status": ToolSpec("status", "Read service status and recent audit events", "read", True, None, _status),
    "latest_intel": ToolSpec("latest_intel", "Read collected threat intelligence", "read", True, None, _latest_intel),
    "refresh_intel": ToolSpec("refresh_intel", "Collect defensive threat intelligence", "network-read", True, None, _refresh_intel),
    "local_security_check": ToolSpec("local_security_check", "Inspect local TCP listeners", "read", True, None, _local_security),
    "local_system_info": ToolSpec("local_system_info", "Read local system information", "read", True, None, _system_info),
    "search": ToolSpec("search", "Search local events and intelligence", "read", True, str, _search),
    "watch": ToolSpec("watch", "Add a local defensive watch keyword", "state-write", True, str, _watch),
    "unwatch": ToolSpec("unwatch", "Remove a local defensive watch keyword", "state-write", True, str, _unwatch),
}

KNOWN_TOOLS = frozenset(REGISTRY)


def get_tool(name: str) -> ToolSpec | None:
    return REGISTRY.get(name)


def execute(name: str, argument: str | None = None):
    spec = get_tool(name)
    if spec is None:
        raise ValueError("unknown tool")
    valid, reason = spec.validate(argument)
    if not valid:
        raise ValueError(reason)
    return spec.handler(argument)
