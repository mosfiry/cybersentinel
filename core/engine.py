from __future__ import annotations

import json
import uuid
from .db import add_event, recent, counts, search_all, add_watch, remove_watch, watches
from .policy import evaluate
from .trust import owner_request
from agent.runtime import AgentRuntime
from agent.evidence import observed
from security.authorization import authorize_plan, public_plan
from security.owner_policy import verify_owner, set_current_owner_instruction, load_state
from .version import PRODUCT_NAME, VERSION
from .context import ExecutionContext
from tools.registry import KNOWN_TOOLS, execute as execute_tool

TOOLS = KNOWN_TOOLS
RUNTIME = AgentRuntime()


def status():
    runtime = RUNTIME.status()
    state = load_state()
    return {
        "service": PRODUCT_NAME,
        "version": VERSION,
        "online": True,
        "event_counts": counts(),
        "watch_count": len(watches()),
        "watches": watches(),
        "llm": runtime["models"],
        "agent": runtime,
        "owner_policy": {
            "fingerprint": runtime["policy_fingerprint"],
            "updated_at": state.get("updated_at"),
            "source": state.get("source"),
        },
        "recent_events": recent(20),
    }


def execute(tool: str, argument: str | None = None):
    return execute_tool(tool, argument)


def handle(text, source="web", presented_token=None, owner_token=None):
    request_id = uuid.uuid4().hex
    owner_ok, owner_reason = verify_owner(text, owner_token)
    auth_event = add_event("auth", "Owner authentication", owner_reason, source, "info" if owner_ok else "warning", owner_ok, {"request_id": request_id, "decision": "allow" if owner_ok else "deny"})
    if not owner_ok:
        return {"ok": False, "decision": "deny", "request_id": request_id, "answer": "مصادقة المالك مطلوبة.", "plan": [], "results": []}
    set_current_owner_instruction(text, source)
    req = owner_request(text, source)
    decision = evaluate(req)
    policy_event = add_event("policy", "Policy evaluation", decision.reason, source, "info" if decision.allowed else "warning", decision.allowed, {"request_id": request_id, "decision": "allow" if decision.allowed else "deny", "parent_event": auth_event})
    if not decision.allowed:
        return {"ok": False, "decision": "deny", "request_id": request_id, "answer": decision.reason, "plan": [], "results": []}

    planned = RUNTIME.plan(text)
    authorized, errors = authorize_plan(planned["tools"], owner_authenticated=True)
    if errors:
        add_event("authorization", "Plan rejected", "; ".join(errors), source, "warning", True, {"request_id": request_id, "decision": "deny", "provider": planned.get("provider"), "model": planned.get("model")})
        return {"ok": False, "decision": "deny", "request_id": request_id, "answer": "تم رفض الخطة: " + "; ".join(errors), "plan": [], "results": []}
    serial_plan = public_plan(authorized)
    provenance = {"provider": planned.get("provider"), "model": planned.get("model"), "planner": planned.get("planner")}
    context = ExecutionContext(request_id, True, "authenticated-owner", RUNTIME.status()["policy_fingerprint"], provenance["provider"], provenance["model"])
    plan_event = add_event("plan", "Defensive plan", json.dumps(serial_plan, ensure_ascii=False), source, "info", True, {"request_id": request_id, **provenance, "plan": serial_plan, "parent_event": policy_event, "context": context.to_dict()})
    chain = (f"request:{request_id}", f"auth:{auth_event}", f"policy:{policy_event}", f"plan:{plan_event}")

    results = []
    for name, argument in authorized:
        try:
            result = execute(name, argument)
            results.append({"tool": name, "argument": argument, "ok": True, "result": result})
            execution_event = add_event("execution", "Tool executed", name, source, "info", True, {"request_id": request_id, "tool": name, **provenance, "parent_event": plan_event, "context": context.to_dict()})
            results[-1]["event_id"] = execution_event
        except Exception as exc:
            error = str(exc)
            results.append({"tool": name, "argument": argument, "ok": False, "error": error})
            execution_event = add_event("execution", "Tool execution failed", error, source, "warning", True, {"request_id": request_id, "tool": name, "error": error, **provenance, "parent_event": plan_event, "context": context.to_dict()})
            results[-1]["event_id"] = execution_event

    evidence = []
    for item in results:
        if item["ok"]:
            evidence.append(observed(f"{item['tool']} returned a result", item["tool"], {"request_id": request_id, "result": item["result"]}, 10, request_id=request_id, chain=chain + (f"execution:{item['event_id']}",)))
        else:
            evidence.append(observed(f"{item['tool']} execution failed", item["tool"], {"request_id": request_id, "error": item["error"]}, 0, request_id=request_id, chain=chain + (f"execution:{item['event_id']}",)))
    response_event = add_event("response", "Defensive response", "request completed", source, "info", True, {"request_id": request_id, **provenance, "result_count": len(results), "parent_event": plan_event})
    return {
        "ok": True,
        "decision": "allow",
        "request_id": request_id,
        "planner": planned.get("planner"),
        "provenance": provenance,
        "answer": summarize(serial_plan, results, planned.get("planner"), planned.get("rationale", "")),
        "plan": serial_plan,
        "results": results,
        "evidence": evidence,
        "execution_context": context.to_dict(),
        "evidence_chain": chain + (f"response:{response_event}",),
    }


def summarize(plan, results, planner, rationale):
    lines = [f"تم تنفيذ خطة دفاعية فعلية ({planner})."]
    if rationale:
        lines.append("منطق التخطيط: " + rationale)
    for item in results:
        tool = item["tool"]
        if not item["ok"]:
            lines.append(f"• فشل تنفيذ {tool} — السبب: {item['error']}")
        elif tool == "refresh_intel":
            value = item["result"]
            lines.append("• استخبارات التهديد: " + json.dumps(value.get("results", value), ensure_ascii=False))
        elif tool == "local_security_check":
            lines.append(f"• الفحص المحلي: تم العثور على {item['result']['count']} TCP listener.")
        elif tool == "local_system_info":
            lines.append(f"• النظام: {item['result'].get('platform')} / {item['result'].get('kernel')}")
        elif tool == "latest_intel":
            lines.append(f"• أحدث بيانات الاستخبارات: {len(item['result'])} سجل.")
        elif tool == "status":
            lines.append(f"• الحالة: ONLINE، الأحداث: {sum(item['result']['event_counts'].values())}.")
        elif tool == "search":
            lines.append(f"• البحث: {len(item['result']['events'])} حدث و{len(item['result']['intel'])} سجل استخبارات.")
        elif tool in ("watch", "unwatch"):
            lines.append(f"• {tool}: تم تحديث قائمة المراقبة.")
    return "\n".join(lines)
