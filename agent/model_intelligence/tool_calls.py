from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Iterable
from .protocol import ToolCallProposal, ToolCallResult


def validate_proposals(proposals: Iterable[ToolCallProposal], *, mission_id: str, run_id: str, seen_call_ids: set[str] | None = None) -> list[str]:
    seen = set(seen_call_ids or ())
    errors: list[str] = []
    for item in proposals:
        if item.mission_id != mission_id: errors.append(f"{item.tool_call_id}:cross_mission")
        elif item.run_id != run_id: errors.append(f"{item.tool_call_id}:stale_run")
        elif not item.tool_call_id: errors.append("missing_tool_call_id")
        elif item.tool_call_id in seen: errors.append(f"{item.tool_call_id}:duplicate")
        else: seen.add(item.tool_call_id)
    return errors


def execute_bounded_parallel(proposals: list[ToolCallProposal], execute_one: Callable[[ToolCallProposal], ToolCallResult], *, max_workers: int = 4) -> list[ToolCallResult]:
    if len(proposals) <= 1:
        return [execute_one(item) for item in proposals]
    workers = max(1, min(int(max_workers), len(proposals)))
    results: list[ToolCallResult | None] = [None] * len(proposals)
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="cybersentinel-tool") as pool:
        futures = {pool.submit(execute_one, item): index for index, item in enumerate(proposals)}
        for future in as_completed(futures):
            results[futures[future]] = future.result()
    return [item for item in results if item is not None]


__all__ = ["execute_bounded_parallel", "validate_proposals"]
