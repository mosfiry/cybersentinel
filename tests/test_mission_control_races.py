from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from threading import Event, Thread

import pytest

from runtime_authorization import make_test_snapshot
from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.mission_worker import MissionQueue, MissionWorker, WorkerMissionState
from agent.model_protocol import ModelTurn, ToolCallProposal
from agent.planning import Plan, PlanStep
from api.missions import MissionService


CONTROL_CASES = (
    ("cancel", MissionStatus.CANCELLED, WorkerMissionState.CANCELLED),
    ("pause", MissionStatus.PAUSED, WorkerMissionState.PAUSED),
)


def _setup(tmp_path: Path, *, steps: tuple[PlanStep, ...] | None = None):
    store = MissionStore(tmp_path / "missions.sqlite3")
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    effects: list[str] = []

    def execute(_mission, step, action_id):
        effects.append(action_id)
        return {"success": True, "source": step.action}

    runtime = MissionRuntime(
        store,
        executor=execute,
        authorization_snapshot_factory=make_test_snapshot,
    )
    plan = Plan.initial("perform bounded work").replan(
        steps=steps or (PlanStep("observe", "observe", action="status"),),
        reason="race regression fixture",
    )
    mission = runtime.create(
        "perform bounded work",
        "perform bounded work",
        plan,
        owner_identity_ref="owner-1",
    )
    service = MissionService(runtime, queue)
    return store, queue, runtime, service, mission, effects


def _control(service: MissionService, mission_id: str, owner: str, action: str):
    if action == "cancel":
        return service.cancel_mission(mission_id, owner_identity=owner)
    return service.pause_mission(mission_id, owner_identity=owner)


@pytest.mark.parametrize(("action", "expected_mission", "expected_queue"), CONTROL_CASES)
def test_control_winning_before_native_model_claim_prevents_callback_and_releases_owned_lease(
    tmp_path, monkeypatch, action, expected_mission, expected_queue
):
    store, queue, runtime, service, mission, effects = _setup(tmp_path)
    queue.enqueue(mission.mission_id, available_at="2000-01-01T00:00:00+00:00")
    model_claim_attempted = Event()
    allow_claim_write = Event()
    original_save = store.save
    blocked_once = False

    def blocked_save(candidate):
        nonlocal blocked_once
        if (
            not blocked_once
            and candidate.mission_id == mission.mission_id
            and (candidate.checkpoint or {}).get("status") == "model_in_flight"
        ):
            blocked_once = True
            model_claim_attempted.set()
            assert allow_claim_write.wait(5), "test did not release the model-claim barrier"
        return original_save(candidate)

    monkeypatch.setattr(store, "save", blocked_save)

    class NativeModel:
        calls = 0

        def complete(self, _messages, _tools, *, mission_id, run_id, turn_id, plan_version):
            self.calls += 1
            proposal = ToolCallProposal.create(
                "status",
                {},
                mission_id=mission_id,
                run_id=run_id,
                turn_id=turn_id,
                plan_version=plan_version,
                step_id="observe",
                action_id="model-proposed-action",
                tool_call_id="model-proposed-call",
            )
            return ModelTurn(turn_id, tool_calls=(proposal,))

    model = NativeModel()
    worker = MissionWorker(
        queue,
        runtime_factory=lambda: runtime,
        worker_id="worker-owner",
        resume_callback=lambda mission_id, _max_slices, _heartbeat: runtime.run_model_loop(
            mission_id, model, tools=[{"name": "status"}], max_turns=2
        ),
    )
    outcomes: list[object] = []
    failures: list[BaseException] = []

    def run_worker():
        try:
            outcomes.append(worker.run_once())
        except BaseException as exc:  # keep thread failures visible to the test
            failures.append(exc)

    thread = Thread(target=run_worker)
    thread.start()
    try:
        assert model_claim_attempted.wait(5), "worker did not reach the callback claim barrier"
        leased = queue.get(mission.mission_id)
        assert leased.state is WorkerMissionState.EXECUTING
        assert leased.lease_owner == "worker-owner"
        _control(service, mission.mission_id, "owner-1", action)
        still_owned = queue.get(mission.mission_id)
        assert still_owned.state is WorkerMissionState.EXECUTING
        assert still_owned.lease_owner == "worker-owner"
    finally:
        allow_claim_write.set()
        thread.join(timeout=8)

    assert not thread.is_alive()
    assert failures == []
    assert len(outcomes) == 1
    assert model.calls == 0, "control won the durable claim race; no model callback may start"
    assert effects == [], "no tool callback may follow a losing model claim"

    persisted = store.load(mission.mission_id)
    item = queue.get(mission.mission_id)
    assert persisted.status is expected_mission
    assert persisted.checkpoint["status"] == ("cancelled" if action == "cancel" else "paused")
    assert item.state is expected_queue
    assert item.lease_owner is None
    assert item.lease_expires_at is None
    assert outcomes[0].state is expected_queue


@pytest.mark.parametrize(("action", "expected_mission", "expected_queue"), CONTROL_CASES)
def test_control_between_worker_slices_stops_next_callback_and_pause_resume_does_not_duplicate_effects(
    tmp_path, action, expected_mission, expected_queue
):
    steps = (
        PlanStep("first", "first bounded action", action="first_action"),
        PlanStep("second", "second bounded action", action="second_action", prerequisites=("first",)),
    )
    store, queue, runtime, service, mission, effects = _setup(tmp_path, steps=steps)
    queue.enqueue(mission.mission_id, available_at="2000-01-01T00:00:00+00:00")
    first_slice_done = Event()
    allow_resume = Event()

    def resume_between_slices(mission_id, max_slices, heartbeat):
        # This slice claims and executes exactly one action, then leaves the
        # worker lease owned while the control request is committed.
        runtime.run_slice(mission_id)
        first_slice_done.set()
        assert allow_resume.wait(5), "test did not release the worker-resume barrier"
        return runtime.run_to_completion(mission_id, max_slices=max_slices, heartbeat=heartbeat)

    worker = MissionWorker(
        queue,
        runtime_factory=lambda: runtime,
        worker_id="worker-owner",
        resume_callback=resume_between_slices,
    )
    outcomes: list[object] = []
    failures: list[BaseException] = []

    def run_worker():
        try:
            outcomes.append(worker.run_once(max_slices=1))
        except BaseException as exc:
            failures.append(exc)

    thread = Thread(target=run_worker)
    thread.start()
    try:
        assert first_slice_done.wait(5), "worker did not finish the first slice"
        leased = queue.get(mission.mission_id)
        assert leased.state is WorkerMissionState.EXECUTING
        assert leased.lease_owner == "worker-owner"
        _control(service, mission.mission_id, "owner-1", action)
        still_owned = queue.get(mission.mission_id)
        assert still_owned.state is WorkerMissionState.EXECUTING
        assert still_owned.lease_owner == "worker-owner"
    finally:
        allow_resume.set()
        thread.join(timeout=8)

    assert not thread.is_alive()
    assert failures == []
    assert len(outcomes) == 1
    assert effects == [f"{mission.mission_id}:2:first:0"]
    persisted = store.load(mission.mission_id)
    item = queue.get(mission.mission_id)
    assert persisted.status is expected_mission
    assert persisted.checkpoint["status"] == ("cancelled" if action == "cancel" else "paused")
    assert item.state is expected_queue
    assert item.lease_owner is None
    assert item.lease_expires_at is None
    assert outcomes[0].state is expected_queue

    if action == "pause":
        service.resume_mission(mission.mission_id, owner_identity="owner-1")
        resumed_worker = MissionWorker(queue, runtime_factory=lambda: runtime, worker_id="worker-after-resume")
        resumed = resumed_worker.run_once(
            now=datetime.now(timezone.utc).isoformat(),
            max_slices=1,
        )
        assert resumed is not None
        assert effects == [f"{mission.mission_id}:2:first:0", f"{mission.mission_id}:2:second:1"]
        assert len(set(effects)) == len(effects)
        assert queue.get(mission.mission_id).lease_owner is None
    else:
        with pytest.raises(ValueError, match="terminal mission cannot be resumed"):
            service.resume_mission(mission.mission_id, owner_identity="owner-1")
        assert queue.enqueue(mission.mission_id).state is WorkerMissionState.CANCELLED


@pytest.mark.parametrize(("action", "expected_mission", "expected_queue"), CONTROL_CASES)
def test_control_winning_before_native_tool_claim_discards_unstarted_proposal(
    tmp_path, monkeypatch, action, expected_mission, expected_queue
):
    import tools.registry as registry

    store, queue, runtime, service, mission, _effects = _setup(tmp_path)
    queue.enqueue(mission.mission_id, available_at="2000-01-01T00:00:00+00:00")
    tool_claim_attempted = Event()
    allow_claim_write = Event()
    original_save = store.save
    blocked_once = False
    tool_effects: list[str] = []

    def blocked_save(candidate):
        nonlocal blocked_once
        if (
            not blocked_once
            and candidate.mission_id == mission.mission_id
            and (candidate.checkpoint or {}).get("status") == "in_flight"
        ):
            blocked_once = True
            tool_claim_attempted.set()
            assert allow_claim_write.wait(5), "test did not release the tool-claim barrier"
        return original_save(candidate)

    def execute_tool(*_args, **_kwargs):
        tool_effects.append("status")
        return {"success": True}

    monkeypatch.setattr(store, "save", blocked_save)
    monkeypatch.setattr(registry, "execute", execute_tool)

    class NativeModel:
        calls = 0

        def complete(self, _messages, _tools, *, mission_id, run_id, turn_id, plan_version):
            self.calls += 1
            proposal = ToolCallProposal.create(
                "status",
                {},
                mission_id=mission_id,
                run_id=run_id,
                turn_id=turn_id,
                plan_version=plan_version,
                step_id="observe",
                action_id="unstarted-action",
                tool_call_id="unstarted-tool-call",
            )
            return ModelTurn(turn_id, tool_calls=(proposal,))

    model = NativeModel()
    worker = MissionWorker(
        queue,
        runtime_factory=lambda: runtime,
        worker_id="worker-owner",
        resume_callback=lambda mission_id, _max_slices, _heartbeat: runtime.run_model_loop(
            mission_id, model, tools=[{"name": "status"}], max_turns=2
        ),
    )
    outcomes: list[object] = []
    failures: list[BaseException] = []

    def run_worker():
        try:
            outcomes.append(worker.run_once())
        except BaseException as exc:
            failures.append(exc)

    thread = Thread(target=run_worker)
    thread.start()
    try:
        assert tool_claim_attempted.wait(5), "worker did not reach the native tool claim barrier"
        leased = queue.get(mission.mission_id)
        assert leased.state is WorkerMissionState.EXECUTING
        assert leased.lease_owner == "worker-owner"
        _control(service, mission.mission_id, "owner-1", action)
        still_owned = queue.get(mission.mission_id)
        assert still_owned.state is WorkerMissionState.EXECUTING
        assert still_owned.lease_owner == "worker-owner"
    finally:
        allow_claim_write.set()
        thread.join(timeout=8)

    assert not thread.is_alive()
    assert failures == []
    assert len(outcomes) == 1
    assert model.calls == 1
    assert tool_effects == [], "the proposal was returned, but its durable tool claim lost to control"
    persisted = store.load(mission.mission_id)
    item = queue.get(mission.mission_id)
    assert persisted.status is expected_mission
    assert persisted.checkpoint["status"] == ("cancelled" if action == "cancel" else "paused")
    assert item.state is expected_queue
    assert item.lease_owner is None
    assert outcomes[0].state is expected_queue


@pytest.mark.parametrize(("action", "expected_mission", "expected_queue"), CONTROL_CASES)
def test_control_winning_before_slice_executor_claim_prevents_bounded_action(
    tmp_path, monkeypatch, action, expected_mission, expected_queue
):
    store, queue, runtime, service, mission, effects = _setup(tmp_path)
    queue.enqueue(mission.mission_id, available_at="2000-01-01T00:00:00+00:00")
    executor_claim_attempted = Event()
    allow_claim_write = Event()
    original_save = store.save
    blocked_once = False

    def blocked_save(candidate):
        nonlocal blocked_once
        if (
            not blocked_once
            and candidate.mission_id == mission.mission_id
            and (candidate.checkpoint or {}).get("status") == "in_flight"
        ):
            blocked_once = True
            executor_claim_attempted.set()
            assert allow_claim_write.wait(5), "test did not release the executor-claim barrier"
        return original_save(candidate)

    monkeypatch.setattr(store, "save", blocked_save)
    worker = MissionWorker(queue, runtime_factory=lambda: runtime, worker_id="worker-owner")
    outcomes: list[object] = []
    failures: list[BaseException] = []

    def run_worker():
        try:
            outcomes.append(worker.run_once(max_slices=1))
        except BaseException as exc:
            failures.append(exc)

    thread = Thread(target=run_worker)
    thread.start()
    try:
        assert executor_claim_attempted.wait(5), "worker did not reach the slice executor claim barrier"
        leased = queue.get(mission.mission_id)
        assert leased.state is WorkerMissionState.EXECUTING
        assert leased.lease_owner == "worker-owner"
        _control(service, mission.mission_id, "owner-1", action)
        still_owned = queue.get(mission.mission_id)
        assert still_owned.state is WorkerMissionState.EXECUTING
        assert still_owned.lease_owner == "worker-owner"
    finally:
        allow_claim_write.set()
        thread.join(timeout=8)

    assert not thread.is_alive()
    assert failures == []
    assert len(outcomes) == 1
    assert effects == [], "the executor checkpoint lost to control, so the bounded action must not start"
    persisted = store.load(mission.mission_id)
    item = queue.get(mission.mission_id)
    assert persisted.status is expected_mission
    assert persisted.checkpoint["status"] == ("cancelled" if action == "cancel" else "paused")
    assert item.state is expected_queue
    assert item.lease_owner is None
    assert outcomes[0].state is expected_queue


def test_replacement_runtime_does_not_overwrite_unresolved_model_claim(tmp_path):
    store, _queue, runtime, _service, mission, _effects = _setup(tmp_path)
    claimed = store.load(mission.mission_id)
    claimed.checkpoint = {
        "status": "model_in_flight",
        "kind": "native_model",
        "run_id": "prior-run",
        "turn_id": "prior-run:turn:1",
    }
    store.save(claimed)

    class NativeModel:
        calls = 0

        def complete(self, *_args, **_kwargs):
            self.calls += 1
            return ModelTurn("unexpected")

    model = NativeModel()
    result = runtime.run_model_loop(
        mission.mission_id,
        model,
        tools=[{"name": "status"}],
        max_turns=1,
    )

    assert result.status is MissionStatus.RECOVERY_REQUIRED
    assert model.calls == 0
    persisted = store.load(mission.mission_id)
    assert persisted.status is MissionStatus.RECOVERY_REQUIRED
    assert persisted.checkpoint["status"] == "model_in_flight"
