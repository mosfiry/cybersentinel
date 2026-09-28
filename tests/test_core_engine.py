from types import SimpleNamespace

import core.engine as engine


def test_handle_once_replays_completed_lifecycle_without_reexecution(monkeypatch):
    final_result = {"ok": True, "decision": "allow", "request_id": "replay-request"}
    monkeypatch.setattr(
        engine,
        "begin_lifecycle",
        lambda request_id, source: SimpleNamespace(
            status="completed", final_result=final_result, claimed=False
        ),
    )

    result = engine._handle_once("status", source="test", request_id="replay-request")

    assert result == {**final_result, "idempotent_replay": True}
    assert final_result == {"ok": True, "decision": "allow", "request_id": "replay-request"}


def test_handle_once_does_not_reexecute_unclaimed_lifecycle(monkeypatch):
    monkeypatch.setattr(
        engine,
        "begin_lifecycle",
        lambda request_id, source: SimpleNamespace(
            status="executing", final_result=None, claimed=False
        ),
    )

    result = engine._handle_once("status", source="test", request_id="active-request")

    assert result == {
        "ok": False,
        "decision": "in_progress",
        "request_id": "active-request",
        "lifecycle": "executing",
        "answer": "الطلب قيد التنفيذ أو يحتاج إلى recovery؛ لن تتم إعادة تنفيذه.",
    }


def test_handle_once_denies_request_when_owner_authentication_fails(monkeypatch):
    monkeypatch.setattr(
        engine,
        "begin_lifecycle",
        lambda request_id, source: SimpleNamespace(status="created", claimed=True),
    )
    monkeypatch.setattr(
        engine,
        "authenticate_owner",
        lambda text, owner_token, request_id: (_ for _ in ()).throw(
            PermissionError("invalid owner credentials")
        ),
    )
    events = []
    completions = []
    monkeypatch.setattr(
        engine,
        "add_event",
        lambda *args, **kwargs: events.append((args, kwargs)) or "auth-event",
    )
    monkeypatch.setattr(
        engine,
        "complete_lifecycle",
        lambda *args, **kwargs: completions.append((args, kwargs)),
    )

    result = engine._handle_once("status", source="test", request_id="auth-denied")

    assert result == {
        "ok": False,
        "decision": "deny",
        "request_id": "auth-denied",
        "answer": "مصادقة المالك مطلوبة.",
        "plan": [],
        "results": [],
        "lifecycle": "completed",
    }
    assert events[0][0][0:3] == ("auth", "Owner authentication", "invalid owner credentials")
    assert completions == [
        (("auth-denied", result), {"success": False, "error": "invalid owner credentials"})
    ]


def test_handle_once_does_not_fallback_after_owner_challenge_failure(monkeypatch):
    monkeypatch.setattr(
        engine,
        "begin_lifecycle",
        lambda request_id, source: SimpleNamespace(status="created", claimed=True),
    )
    monkeypatch.setattr(
        engine,
        "consume_owner_challenge",
        lambda *args, **kwargs: (_ for _ in ()).throw(PermissionError("expired owner challenge")),
    )

    def unexpected_token_fallback(*args, **kwargs):
        raise AssertionError("owner token authentication must not be attempted after challenge failure")

    monkeypatch.setattr(engine, "authenticate_owner", unexpected_token_fallback)
    monkeypatch.setattr(engine, "add_event", lambda *args, **kwargs: "auth-event")
    completions = []
    monkeypatch.setattr(
        engine,
        "complete_lifecycle",
        lambda *args, **kwargs: completions.append((args, kwargs)),
    )

    result = engine._handle_once(
        "status",
        source="test",
        request_id="challenge-denied",
        owner_session_id="session-1",
        owner_challenge="challenge-1",
    )

    assert result["decision"] == "deny"
    assert result["request_id"] == "challenge-denied"
    assert completions[0][1] == {"success": False, "error": "expired owner challenge"}


def test_summarize_covers_local_and_tool_result_branches():
    local = engine.summarize([], [], "local", "ignored")
    assert local == "يعمل النظام في الوضع المحلي المحدود؛ لم يتوفر مزود نموذج للمحادثة."

    results = [
        {"tool": "refresh_intel", "ok": True, "result": {"results": {"new": 2}}},
        {"tool": "local_security_check", "ok": True, "result": {"count": 3}},
        {"tool": "local_system_info", "ok": True, "result": {"platform": "Linux", "kernel": "6.8"}},
        {"tool": "latest_intel", "ok": True, "result": [{"id": 1}, {"id": 2}]},
        {"tool": "status", "ok": True, "result": {"event_counts": {"info": 2, "warning": 1}}},
        {"tool": "search", "ok": True, "result": {"events": [1], "intel": [2, 3]}},
        {"tool": "watch", "ok": True, "result": {}},
        {"tool": "unwatch", "ok": True, "result": {}},
        {"tool": "broken", "ok": False, "error": "provider unavailable"},
    ]

    summary = engine.summarize(results, results, "remote", "safe plan")
    assert "تم تنفيذ الخطة بعد اقتراحها والتحقق من صلاحياتها." in summary
    assert "منطق التخطيط: safe plan" in summary
    assert "استخبارات التهديد" in summary
    assert "العثور على 3 TCP listener" in summary
    assert "Linux / 6.8" in summary
    assert "أحدث بيانات الاستخبارات: 2 سجل" in summary
    assert "الأحداث: 3" in summary
    assert "البحث: 1 حدث و2 سجل استخبارات" in summary
    assert "watch: تم تحديث قائمة المراقبة" in summary
    assert "unwatch: تم تحديث قائمة المراقبة" in summary
    assert "فشل تنفيذ broken — السبب: provider unavailable" in summary


def test_handle_records_unexpected_error_when_lifecycle_exists(monkeypatch):
    class ActiveLifecycle:
        status = "executing"

    monkeypatch.setattr(
        engine,
        "_handle_once",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("unexpected failure")),
    )
    monkeypatch.setattr(engine, "get_lifecycle", lambda _request_id: ActiveLifecycle())
    transitions = []
    completions = []
    monkeypatch.setattr(
        engine,
        "transition_lifecycle",
        lambda *args, **kwargs: transitions.append((args, kwargs)),
    )
    monkeypatch.setattr(
        engine,
        "complete_lifecycle",
        lambda *args, **kwargs: completions.append((args, kwargs)),
    )

    result = engine.handle("status", request_id="error-request")

    assert result == {
        "ok": False,
        "decision": "failed",
        "request_id": "error-request",
        "lifecycle": "completed",
        "answer": "توقف التنفيذ بسبب خطأ مسجل.",
        "error": "unexpected failure",
        "plan": [],
        "results": [],
    }
    assert transitions == [(('error-request', "failed"), {"error": "unexpected failure"})]
    assert completions[0][0][0] == "error-request"
    assert completions[0][1] == {"success": False, "error": "unexpected failure"}


def test_handle_returns_unknown_lifecycle_when_error_happens_before_record(monkeypatch):
    monkeypatch.setattr(
        engine,
        "_handle_once",
        lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("early failure")),
    )
    monkeypatch.setattr(engine, "get_lifecycle", lambda _request_id: None)

    result = engine.handle("status", request_id="early-error")

    assert result["decision"] == "failed"
    assert result["request_id"] == "early-error"
    assert result["lifecycle"] == "unknown"
    assert result["error"] == "early failure"
