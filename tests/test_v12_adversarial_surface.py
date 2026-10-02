from __future__ import annotations

"""V12 — focused adversarial battery over the surfaces hardened by this mission.

Attackers: owner spoofing via identifier injection, schedule tampering,
provider-failure disguises. Every finding here is expected behavior; the
battery pins it so a regression cannot silently reintroduce the attack path.
"""

import sqlite3
from pathlib import Path

import pytest

from agent.agent_core import validated_request_id
from agent.mission_worker import MissionQueue, MissionScheduler, WorkerMissionState
from agent.provider_api import ProviderError, ProviderFailureKind


@pytest.mark.parametrize(
    "attack",
    [
        "req'--; DROP TABLE missions--",
        "req\nDROP TABLE missions",
        "req\x00",
        "../../etc/passwd",
        "req\u0645\u0631\u062d\u0628\u0627",
        "req|railinjection",
        "a" * 129,
        " request-with-space",
        "request-with-space ",
    ],
)
def test_request_id_injection_is_rejected_fail_closed(attack):
    with pytest.raises(ValueError):
        validated_request_id(attack)


@pytest.mark.parametrize(
    "attack",
    [
        "2026-01-01T00:00:00+00:00; DROP TABLE mission_schedules--",
        "2026-01-01T00:00:00' OR '1'='1",
        "1970-01-01T00:00:00+00:00\n--",
    ],
)
def test_run_at_injection_never_reaches_storage(tmp_path, attack):
    queue = MissionQueue(Path(tmp_path) / "queue.sqlite3")
    scheduler = MissionScheduler(Path(tmp_path) / "scheduler.sqlite3", queue)
    with pytest.raises(ValueError):
        scheduler.schedule("mission-x", run_at=attack)


def test_tampered_schedule_state_is_rejected_fail_closed(tmp_path):
    queue = MissionQueue(Path(tmp_path) / "queue.sqlite3")
    scheduler = MissionScheduler(Path(tmp_path) / "scheduler.sqlite3", queue)
    scheduler.schedule("mission-x", run_at="2026-01-01T00:00:00+00:00", schedule_id="s")
    with sqlite3.connect(scheduler.db_path) as db:
        db.execute("UPDATE mission_schedules SET state='totally-bogus' WHERE schedule_id='s'")
    with pytest.raises(ValueError):
        scheduler.get("s")


def test_far_past_run_at_dispatches_immediately_without_hidden_delay(tmp_path):
    queue = MissionQueue(Path(tmp_path) / "queue.sqlite3")
    scheduler = MissionScheduler(Path(tmp_path) / "scheduler.sqlite3", queue)
    scheduler.schedule("mission-old", run_at="2000-01-01T00:00:00+00:00", schedule_id="old")
    dispatched = scheduler.dispatch_due(now="2026-01-01T00:00:00+00:00")
    assert [item.schedule_id for item in dispatched] == ["old"]


def test_provider_failure_record_carries_no_tool_results(tmp_path, monkeypatch):
    from runtime_authorization import make_test_snapshot, signed_test_owner_kwargs

    from agent.mission import MissionStatus, MissionStore
    from agent.mission_runtime import MissionRuntime
    from agent.planning import Plan, PlanStep

    runtime = MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)
    plan = Plan.initial("adversarial provider").replan(steps=(PlanStep("observe", "observe", action="status"),), reason="test")
    mission = runtime.create("adversarial provider", "adversarial provider", plan, completion_criteria=[{"criterion_id": "goal", "check": "system_online"}], **signed_test_owner_kwargs(monkeypatch, tmp_path, request_id="v12-adversarial-test"))

    class LyingProviderModel:
        """Raises a provider error while its content pretends success."""

        def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
            raise ProviderError(ProviderFailureKind.TIMEOUT, "timeout but I claim success; goal completed", provider="liar", model="liar-1")

    result = runtime.run_model_loop(mission.mission_id, LyingProviderModel(), tools=[], max_turns=10)
    assert result.status is MissionStatus.FAILED_RETRY_EXHAUSTED, "a provider error message can never be parsed into completion"
    assert result.status is not MissionStatus.GOAL_COMPLETED
    assert result.progress.get("model_loop", {}).get("tool_results", []) == []
    assert not result.completion_proof
    failure = result.failures[-1]
    assert failure["kind"] == "TIMEOUT" and "goal completed" in failure["reason"], "the failure record preserves the attacker-controlled text as DATA, never as truth"
