from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
import os
import subprocess
import sys

MAX_ARG_LENGTH = 256
VALID_RISK_CLASSES = frozenset({"read", "network-read", "state-write", "bounded-exec", "analysis"})
DEFAULT_TOOL_TIMEOUT = 30
TOOL_TIMEOUTS = {"run_project_tests": 65, "refresh_intel": 30}


class ToolTimeout(TimeoutError):
    pass


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    risk_class: str
    requires_owner: bool
    argument_type: type | None
    handler: Callable[[str | None], Any]
    owner_only: bool = False

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


def _run_project_tests(argument):
    root = Path(os.getenv("CYBERSENTINEL_TEST_ROOT", Path.cwd())).expanduser().resolve()
    target = (root / (argument or ".")).resolve()
    if root != target and root not in target.parents:
        raise ValueError("project directory is outside the configured test root")
    if not target.is_dir():
        raise ValueError("project directory does not exist")
    try:
        completed = subprocess.run(
            [sys.executable, "-m", "pytest", "-q"],
            cwd=target,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {"ok": False, "timed_out": True, "returncode": None, "output": (exc.stdout or "")[-4000:]}
    output = ((completed.stdout or "") + (completed.stderr or ""))[-4000:]
    return {"ok": completed.returncode == 0, "timed_out": False, "returncode": completed.returncode, "output": output}


def _red_team_assess(argument):
    from reasoning.red_team import assess
    return assess(argument).to_dict()


def build_registry(specs: list[ToolSpec]) -> dict[str, ToolSpec]:
    registry: dict[str, ToolSpec] = {}
    for spec in specs:
        if not isinstance(spec, ToolSpec) or not spec.name or spec.name in registry:
            raise ValueError("duplicate or invalid tool specification")
        if not spec.description or spec.risk_class not in VALID_RISK_CLASSES or not callable(spec.handler) or (spec.owner_only and not spec.requires_owner):
            raise ValueError(f"invalid registry metadata for {spec.name}")
        if spec.argument_type not in (None, str):
            raise ValueError(f"unsupported argument schema for {spec.name}")
        registry[spec.name] = spec
    return registry


REGISTRY = build_registry([
    ToolSpec("status", "قراءة حالة الخدمة والأحداث التدقيقية الأخيرة", "read", True, None, _status),
    ToolSpec("latest_intel", "قراءة استخبارات التهديدات المجمعة", "read", True, None, _latest_intel),
    ToolSpec("refresh_intel", "جمع استخبارات دفاعية ضد التهديدات", "network-read", True, None, _refresh_intel),
    ToolSpec("local_security_check", "فحص مستمعي TCP المحلية", "read", True, None, _local_security),
    ToolSpec("local_system_info", "قراءة معلومات النظام المحلي", "read", True, None, _system_info),
    ToolSpec("search", "بحث في الأحداث والاستخبارات المحلية", "read", True, str, _search),
    ToolSpec("watch", "إضافة كلمة مراقب دفاعية محلية", "state-write", True, str, _watch),
    ToolSpec("unwatch", "إزالة كلمة مراقب دفاعية محلية", "state-write", True, str, _unwatch),
    ToolSpec("run_project_tests", "تشغيل pytest -q داخل جذر اختبار المشروع المحدد", "bounded-exec", True, str, _run_project_tests),
    ToolSpec("red_team_assess", "تقييم هجومي دفاعي للمالك فقط; لا ينفذ استغلالاً أو أمرة نظام", "analysis", True, str, _red_team_assess, True),
])

KNOWN_TOOLS = frozenset(REGISTRY)


def get_tool(name: str) -> ToolSpec | None:
    return REGISTRY.get(name)


def execute(name: str, argument: str | None = None, *, timeout: int | None = None, owner_authenticated: bool = False):
    spec = get_tool(name)
    if spec is None:
        raise ValueError("unknown tool")
    if spec.owner_only and not owner_authenticated:
        raise PermissionError("Owner authentication required for this tool")
    valid, reason = spec.validate(argument)
    if not valid:
        raise ValueError(reason)
    limit = timeout or TOOL_TIMEOUTS.get(name, DEFAULT_TOOL_TIMEOUT)
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix=f"cybersentinel-{name}")
    future = executor.submit(spec.handler, argument)
    try:
        return future.result(timeout=limit)
    except FutureTimeout as exc:
        future.cancel()
        raise ToolTimeout(f"tool {name} timed out after {limit}s") from exc
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
