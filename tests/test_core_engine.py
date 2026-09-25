import core.engine as engine


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
