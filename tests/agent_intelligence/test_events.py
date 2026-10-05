from __future__ import annotations

import sqlite3

import pytest

from agent.intelligence_layer.events import (
    EventBus,
    EventConflict,
    EventError,
    EventIntegrityError,
    EventStore,
    HookAuthorizationError,
    HookDecision,
    HookPhase,
    HookRegistry,
    IntelligenceEventType as E,
)


def append(store: EventStore, key: str, event_type: E = E.TASK_STARTED, **kwargs):
    return store.append(
        owner_identity_ref="owner:1",
        mission_id="mission:1",
        event_type=event_type,
        idempotency_key=key,
        request_id="request:1",
        task_id="task:1",
        agent_id="agent:1",
        **kwargs,
    )


def test_event_chain_is_ordered_verifiable_and_idempotent(tmp_path):
    store = EventStore(tmp_path / "events.sqlite")
    first = append(store, "event:1", payload={"state": "ready"})
    repeated = append(store, "event:1", payload={"state": "ready"})
    second = append(store, "event:2", E.TASK_COMPLETED, payload={"state": "completed"})

    assert repeated.event_id == first.event_id
    assert first.sequence == 1 and second.sequence == 2
    assert second.previous_hash == first.event_hash
    assert store.verify_mission(owner_identity_ref="owner:1", mission_id="mission:1")
    assert [item.sequence for item in store.list(owner_identity_ref="owner:1", mission_id="mission:1")] == [1, 2]
    assert store.list(owner_identity_ref="owner:1", mission_id="mission:1", after_sequence=1)[0].event_id == second.event_id


def test_event_identity_idempotency_and_owner_scope_are_enforced(tmp_path):
    store = EventStore(tmp_path / "events.sqlite")
    record = append(store, "event:1", payload={"state": "started"})
    assert store.list(owner_identity_ref="owner:2", mission_id="mission:1") == []
    with pytest.raises(EventConflict, match="different event"):
        append(store, "event:1", payload={"state": "completed"})
    with sqlite3.connect(store.db_path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("UPDATE mission_events SET event_type = 'Forged' WHERE event_id = ?", (record.event_id,))
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM mission_events WHERE event_id = ?", (record.event_id,))


def test_sensitive_event_fields_and_common_credentials_are_redacted(tmp_path):
    store = EventStore(tmp_path / "events.sqlite")
    record = append(
        store,
        "event:secrets",
        payload={
            "api_token": "never-store-this",
            "summary": "authorization: Bearer abcdefghijklmnop and token=another-secret",
            "nested": [{"private_key": "also-never-store-this"}],
        },
    )
    assert record.payload["api_token"] == "[REDACTED]"
    assert "never-store-this" not in repr(record.payload)
    assert "[REDACTED]" in record.payload["summary"]
    assert record.payload["nested"][0]["private_key"] == "[REDACTED]"
    with pytest.raises(TypeError):
        record.payload["forged"] = "value"


def test_event_payload_tampering_breaks_integrity_verification(tmp_path):
    store = EventStore(tmp_path / "events.sqlite")
    record = append(store, "event:1", payload={"state": "ready"})
    with sqlite3.connect(store.db_path) as connection:
        connection.execute("DROP TRIGGER mission_events_no_update")
        connection.execute("UPDATE mission_events SET payload_json = ? WHERE event_id = ?", ('{"state":"forged"}', record.event_id))
    with pytest.raises(EventIntegrityError, match="integrity check"):
        store.verify_mission(owner_identity_ref="owner:1", mission_id="mission:1")


def test_event_bus_persists_before_observing_and_reports_subscriber_failures(tmp_path):
    bus = EventBus(EventStore(tmp_path / "events.sqlite"))
    observed = []
    bus.subscribe(E.MISSION_CREATED, lambda event: observed.append(event.event_id))
    bus.subscribe(E.MISSION_CREATED, lambda event: (_ for _ in ()).throw(RuntimeError("observer failed")))

    delivery = bus.publish(
        owner_identity_ref="owner:1", mission_id="mission:1", event_type=E.MISSION_CREATED,
        idempotency_key="mission:created", payload={"title": "demo"},
    )
    assert delivery.event.event_id in observed
    assert len(delivery.subscriber_failures) == 1
    assert bus.store.list(owner_identity_ref="owner:1", mission_id="mission:1")[0].event_id == delivery.event.event_id
    assert bus.unsubscribe(bus.subscribe(E.RUNTIME_STARTED, lambda _: None))


def test_before_hooks_are_owner_authorized_immutable_and_cannot_expand_authority():
    hooks = HookRegistry()
    checks = []
    active = {"allowed": True}
    def authorize(owner, mission, phase):
        checks.append((owner, mission, phase))
        return active["allowed"] and owner == "owner:1" and mission == "mission:1"
    def allow(invocation):
        with pytest.raises(TypeError):
            invocation.data["nested"]["value"] = "changed"
        return HookDecision(True, "policy check passed")
    hooks.register(
        hook_id="policy-check", owner_identity_ref="owner:1", mission_id="mission:1",
        phase=HookPhase.BEFORE_TOOL, handler=allow, authorization_check=authorize,
    )
    result = hooks.run(
        owner_identity_ref="owner:1", mission_id="mission:1", phase=HookPhase.BEFORE_TOOL,
        correlation_id="call:1", data={"nested": {"value": "safe"}},
    )
    assert result.allowed
    assert result.executed_hook_ids == ("policy-check",)
    assert len(checks) == 2


def test_before_hooks_veto_on_negative_decision_or_authorization_revocation():
    hooks = HookRegistry()
    active = {"allowed": True}
    authorize = lambda *_: active["allowed"]
    hooks.register(
        hook_id="deny-tool", owner_identity_ref="owner:1", mission_id="mission:1",
        phase=HookPhase.BEFORE_TOOL, handler=lambda _: HookDecision(False, "scope blocked"),
        authorization_check=authorize,
    )
    denied = hooks.run(
        owner_identity_ref="owner:1", mission_id="mission:1", phase=HookPhase.BEFORE_TOOL,
        correlation_id="call:1",
    )
    assert denied.allowed is False and denied.denied_reason == "scope blocked"

    active["allowed"] = False
    revoked = hooks.run(
        owner_identity_ref="owner:1", mission_id="mission:1", phase=HookPhase.BEFORE_TOOL,
        correlation_id="call:2",
    )
    assert revoked.allowed is False
    assert revoked.executed_hook_ids == ()
    assert revoked.failures == ("deny-tool:HookAuthorizationError",)


def test_hook_failures_fail_closed_before_effects_but_cannot_retroactively_veto_after_effects():
    hooks = HookRegistry()
    allowed = lambda *_: True
    hooks.register(
        hook_id="crash-before", owner_identity_ref="owner:1", mission_id="mission:1",
        phase=HookPhase.BEFORE_MISSION,
        handler=lambda _: (_ for _ in ()).throw(RuntimeError("hook failure")),
        authorization_check=allowed,
    )
    before = hooks.run(
        owner_identity_ref="owner:1", mission_id="mission:1", phase=HookPhase.BEFORE_MISSION,
        correlation_id="mission:create",
    )
    assert before.allowed is False and "failed closed" in before.denied_reason

    hooks.register(
        hook_id="invalid-observer", owner_identity_ref="owner:1", mission_id="mission:1",
        phase=HookPhase.AFTER_TOOL, handler=lambda _: HookDecision(False, "too late"),
        authorization_check=allowed,
    )
    after = hooks.run(
        owner_identity_ref="owner:1", mission_id="mission:1", phase=HookPhase.AFTER_TOOL,
        correlation_id="tool:done",
    )
    assert after.allowed is True
    assert after.failures == ("invalid-observer:EventError",)


def test_hook_registration_requires_current_authority_and_observer_returns_cannot_authorize():
    hooks = HookRegistry()
    with pytest.raises(HookAuthorizationError):
        hooks.register(
            hook_id="unauthorized", owner_identity_ref="owner:1", mission_id="mission:1",
            phase=HookPhase.BEFORE_PROVIDER, handler=lambda _: HookDecision(True),
            authorization_check=lambda *_: False,
        )
    hooks.register(
        hook_id="observer", owner_identity_ref="owner:1", mission_id="mission:1",
        phase=HookPhase.AFTER_PROVIDER, handler=lambda _: HookDecision(True),
        authorization_check=lambda *_: True,
    )
    result = hooks.run(
        owner_identity_ref="owner:1", mission_id="mission:1", phase=HookPhase.AFTER_PROVIDER,
        correlation_id="provider:1",
    )
    assert result.allowed is True
    assert result.failures == ("observer:EventError",)


def test_hook_decisions_are_audited_and_audit_failure_blocks_pre_effect(tmp_path, monkeypatch):
    store = EventStore(tmp_path / "events.sqlite")
    hooks = HookRegistry(store)
    hooks.register(
        hook_id="scope-guard", owner_identity_ref="owner:1", mission_id="mission:1",
        phase=HookPhase.BEFORE_TOOL, handler=lambda _: HookDecision(False, "outside scope"),
        authorization_check=lambda *_: True,
    )
    denied = hooks.run(
        owner_identity_ref="owner:1", mission_id="mission:1", phase=HookPhase.BEFORE_TOOL,
        correlation_id="tool:call:1",
    )
    assert denied.allowed is False
    audit = store.list(owner_identity_ref="owner:1", mission_id="mission:1")
    assert len(audit) == 1 and audit[0].event_type is E.HOOK_BLOCKED
    assert audit[0].payload["hook_id"] == "scope-guard"

    monkeypatch.setattr(store, "append", lambda **_: (_ for _ in ()).throw(OSError("disk unavailable")))
    failed_audit = hooks.run(
        owner_identity_ref="owner:1", mission_id="mission:1", phase=HookPhase.BEFORE_TOOL,
        correlation_id="tool:call:2",
    )
    assert failed_audit.allowed is False
    assert "audit:OSError" in failed_audit.failures[0]
