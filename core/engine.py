from __future__ import annotations

import json
import uuid
from .db import add_event, recent, counts, watches, save_reasoning_memory
from .policy import evaluate
from .trust import owner_request
from agent.runtime import AgentRuntime
from agent.conversation import ConversationParser
from agent.evidence import observed
from security.authorization import authorize_plan, public_plan
from security.owner_policy import (
    authenticate_owner, authentication_from_session, capture_policy_snapshot,
    set_current_owner_instruction, load_state, load_policy, authority_snapshot, policy_context_from_snapshot,
)
from security.owner_session import consume_owner_challenge
from .version import PRODUCT_NAME, VERSION
from .context import ExecutionContext
from tools.registry import KNOWN_TOOLS, execute as execute_tool, get_tool
from security.plan_integrity import plan_hash
from .lifecycle import begin as begin_lifecycle, complete as complete_lifecycle, get as get_lifecycle, is_cancelled, recover_incomplete, transition as transition_lifecycle
from evaluation.critic import critique

TOOLS = KNOWN_TOOLS
RUNTIME = AgentRuntime()
recover_incomplete()


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
            "authority": authority_snapshot(),
        },
        "recent_events": recent(20),
    }


def execute(tool: str, argument: str | None = None, *, owner_authenticated: bool = False, scope_context: dict | None = None):
    return execute_tool(tool, argument, owner_authenticated=owner_authenticated, scope_context=scope_context)


def _handle_once(text, source="web", presented_token=None, owner_token=None, request_id=None, owner_session_id=None, owner_challenge=None, scope_context=None):
    request_id = request_id or uuid.uuid4().hex
    lifecycle = begin_lifecycle(request_id, source)
    if lifecycle.status == "completed":
        replay = dict(lifecycle.final_result or {"ok": False, "decision": "failed", "request_id": request_id})
        replay["idempotent_replay"] = True
        return replay
    if not lifecycle.claimed or lifecycle.status != "created":
        return {"ok": False, "decision": "in_progress", "request_id": request_id, "lifecycle": lifecycle.status, "answer": "الطلب قيد التنفيذ أو يحتاج إلى recovery؛ لن تتم إعادة تنفيذه."}
    owner_ok = False
    owner_reason = "owner authentication required"
    auth_evidence = None
    auth_context = {
        "owner_authenticated": False,
        "owner_session_id": None,
        "authentication_method": "none",
        "authenticated_at": None,
    }
    if owner_session_id or owner_challenge:
        try:
            auth_context = consume_owner_challenge(owner_session_id, owner_challenge, text, request_id)
            auth_evidence = authentication_from_session(auth_context, request_id)
            owner_ok, owner_reason = True, "owner-session-challenge"
        except PermissionError as exc:
            owner_reason = str(exc)
    else:
        try:
            auth_evidence = authenticate_owner(text, owner_token, request_id)
            owner_ok, owner_reason = True, "owner-authenticated"
            auth_context = {
                "owner_authenticated": True,
                "owner_session_id": None,
                "authentication_method": "owner_token",
                "authenticated_at": auth_evidence.authenticated_at,
            }
        except PermissionError as exc:
            owner_reason = str(exc)
    auth_event = add_event("auth", "Owner authentication", owner_reason, source, "info" if owner_ok else "warning", owner_ok, {"request_id": request_id, "decision": "allow" if owner_ok else "deny"})
    if not owner_ok:
        response = {"ok": False, "decision": "deny", "request_id": request_id, "answer": "مصادقة المالك مطلوبة.", "plan": [], "results": [], "lifecycle": "completed"}
        complete_lifecycle(request_id, response, success=False, error=owner_reason)
        return response
    if text.strip().casefold().startswith("owner instruction:"):
        instruction_text = text.split(":", 1)[1].strip()
        set_current_owner_instruction(instruction_text, source, auth_evidence=auth_evidence, request_id=request_id)
    policy_snapshot = capture_policy_snapshot(request_id, auth_evidence)
    conversation_intent = ConversationParser().understand(text)
    req = owner_request(text, source)
    decision = evaluate(req)
    policy_event = add_event("policy", "Policy evaluation", decision.reason, source, "info" if decision.allowed else "warning", decision.allowed, {"request_id": request_id, "decision": "allow" if decision.allowed else "deny", "parent_event": auth_event})
    if not decision.allowed:
        response = {"ok": False, "decision": "deny", "request_id": request_id, "answer": decision.reason, "plan": [], "results": [], "lifecycle": "completed"}
        complete_lifecycle(request_id, response, success=False, error=decision.reason)
        return response

    snapshot_context = policy_context_from_snapshot(policy_snapshot)
    planned = RUNTIME.plan(text, policy_context=snapshot_context)
    transition_lifecycle(request_id, "planned", provider=planned.get("provider", ""), model=planned.get("model", ""))
    authorized, errors = authorize_plan(planned["tools"], owner_evidence=auth_evidence, request_id=request_id, policy_snapshot=policy_snapshot, current_policy=snapshot_context)
    if errors:
        add_event("authorization", "Plan rejected", "; ".join(errors), source, "warning", True, {"request_id": request_id, "decision": "deny", "provider": planned.get("provider"), "model": planned.get("model")})
        response = {"ok": False, "decision": "deny", "request_id": request_id, "answer": "تم رفض الخطة: " + "; ".join(errors), "plan": [], "results": [], "lifecycle": "completed"}
        complete_lifecycle(request_id, response, success=False, error="; ".join(errors))
        return response
    serial_plan = public_plan(authorized)
    final_plan_hash = plan_hash(serial_plan)
    transition_lifecycle(request_id, "validated", plan_hash=final_plan_hash, provider=planned.get("provider", ""), model=planned.get("model", ""))
    transition_lifecycle(request_id, "authorized", plan_hash=final_plan_hash)
    provenance = {
        "provider": planned.get("provider"), "model": planned.get("model"), "planner": planned.get("planner"),
        "conversation_intent": conversation_intent.to_dict(),
    }
    context = ExecutionContext(
        request_id, True, "authenticated-owner", policy_snapshot.owner_policy_fingerprint,
        provenance["provider"], provenance["model"], authority_snapshot(),
        auth_context["owner_session_id"], auth_context["authentication_method"],
        auth_context["authenticated_at"], policy_snapshot.owner_instruction,
        policy_snapshot.owner_instruction_fingerprint, policy_snapshot.to_dict(), scope_context or {},
    )
    plan_event = add_event("plan", "Defensive plan", json.dumps(serial_plan, ensure_ascii=False), source, "info", True, {"request_id": request_id, **provenance, "plan": serial_plan, "plan_hash": final_plan_hash, "parent_event": policy_event, "context": context.to_dict()})
    chain = (f"request:{request_id}", f"auth:{auth_event}", f"policy:{policy_event}", f"plan:{plan_event}")

    results = []
    authorization_records = []
    evidence = []
    previous_evidence_hash = ""
    transition_lifecycle(request_id, "executing", plan_hash=final_plan_hash)
    for sequence, (name, argument) in enumerate(authorized, start=1):
        spec = get_tool(name)
        record = {"tool": name, "argument": argument, "risk_class": spec.risk_class, "owner_required": spec.requires_owner, "owner_authenticated": True, "policy_version": load_policy().version, "decision": "allow", "reason": "registry schema and Owner policy accepted", "plan_hash": final_plan_hash}
        authorization_records.append(record)
        add_event("authorization", "Tool authorization", name, source, "info", True, {"request_id": request_id, **record, "parent_event": plan_event})
        if plan_hash(public_plan(authorized)) != final_plan_hash:
            record["decision"] = "deny"
            record["reason"] = "plan integrity changed before execution"
            add_event("authorization", "Plan integrity failure", record["reason"], source, "warning", True, {"request_id": request_id, **record, "parent_event": plan_event})
            response = {"ok": False, "decision": "deny", "request_id": request_id, "answer": "تم رفض الخطة بسبب تغير سلامتها.", "plan": [], "results": [], "authorization": authorization_records, "lifecycle": "completed"}
            complete_lifecycle(request_id, response, success=False, error=record["reason"])
            return response
        if is_cancelled(request_id):
            error = "execution cancelled before tool start"
            results.append({"tool": name, "argument": argument, "ok": False, "cancelled": True, "error": error})
            execution_event = add_event("execution", "Tool execution cancelled", error, source, "warning", True, {"request_id": request_id, "tool": name, "plan_hash": final_plan_hash, "parent_event": plan_event})
            results[-1]["event_id"] = execution_event
            item_evidence = observed(f"{name} execution cancelled", name, {"request_id": request_id, "error": error}, 0, request_id=request_id, chain=chain + (f"execution:{execution_event}",), sequence=sequence, previous_hash=previous_evidence_hash)
            evidence.append(item_evidence)
            previous_evidence_hash = item_evidence["current_hash"]
            continue
        try:
            result = execute(name, argument, owner_authenticated=True, scope_context=scope_context)
            if name == "red_team_assess" and isinstance(result, dict):
                result["critic"] = critique(result).to_dict()
                save_reasoning_memory(request_id, result, result["critic"])
            results.append({"tool": name, "argument": argument, "ok": True, "result": result})
            execution_event = add_event("execution", "Tool executed", name, source, "info", True, {"request_id": request_id, "tool": name, **provenance, "plan_hash": final_plan_hash, "parent_event": plan_event, "context": context.to_dict()})
            results[-1]["event_id"] = execution_event
            item_evidence = observed(f"{name} returned a result", name, {"request_id": request_id, "result": result}, 10, request_id=request_id, chain=chain + (f"execution:{execution_event}",), sequence=sequence, previous_hash=previous_evidence_hash)
        except Exception as exc:
            error = str(exc)
            results.append({"tool": name, "argument": argument, "ok": False, "error": error})
            execution_event = add_event("execution", "Tool execution failed", error, source, "warning", True, {"request_id": request_id, "tool": name, "error": error, **provenance, "plan_hash": final_plan_hash, "parent_event": plan_event, "context": context.to_dict()})
            results[-1]["event_id"] = execution_event
            item_evidence = observed(f"{name} execution failed", name, {"request_id": request_id, "error": error}, 0, request_id=request_id, chain=chain + (f"execution:{execution_event}",), sequence=sequence, previous_hash=previous_evidence_hash)
        evidence.append(item_evidence)
        previous_evidence_hash = item_evidence["current_hash"]
        if is_cancelled(request_id):
            add_event("execution", "Cancellation observed", "cancellation requested after tool boundary", source, "warning", True, {"request_id": request_id, "tool": name, "parent_event": plan_event})
    response_event = add_event("response", "Defensive response", "request completed", source, "info", True, {"request_id": request_id, **provenance, "plan_hash": final_plan_hash, "result_count": len(results), "parent_event": plan_event})
    response = {
        "ok": True,
        "decision": "allow",
        "request_id": request_id,
        "planner": planned.get("planner"),
        "provenance": provenance,
        "plan_hash": final_plan_hash,
        "authorization": authorization_records,
        "answer": summarize(serial_plan, results, planned.get("planner"), planned.get("rationale", "")),
        "plan": serial_plan,
        "results": results,
        "evidence": evidence,
        "execution_context": context.to_dict(),
        "evidence_chain": chain + (f"response:{response_event}",),
        "lifecycle": "completed",
    }
    cancelled = is_cancelled(request_id)
    if cancelled:
        response["cancelled"] = True
        response["answer"] = "تم إيقاف التنفيذ عند أقرب حد آمن؛ النتائج السابقة موضحة كأدلة فاشلة أو ناجحة."
    complete_lifecycle(request_id, response, success=not cancelled and all(item["ok"] for item in results), error="execution cancelled" if cancelled else ("one or more tools failed" if any(not item["ok"] for item in results) else ""))
    return response


def handle(text, source="web", presented_token=None, owner_token=None, request_id=None, owner_session_id=None, owner_challenge=None, scope_context=None):
    request_id = request_id or uuid.uuid4().hex
    try:
        return _handle_once(text, source, presented_token, owner_token, request_id, owner_session_id, owner_challenge, scope_context)
    except Exception as exc:
        error = str(exc)[:500]
        current = get_lifecycle(request_id)
        if current and current.status != "completed":
            try:
                transition_lifecycle(request_id, "failed", error=error)
                response = {"ok": False, "decision": "failed", "request_id": request_id, "lifecycle": "completed", "answer": "توقف التنفيذ بسبب خطأ مسجل.", "error": error, "plan": [], "results": []}
                complete_lifecycle(request_id, response, success=False, error=error)
                return response
            except Exception:
                pass
        return {"ok": False, "decision": "failed", "request_id": request_id, "lifecycle": "unknown", "answer": "توقف التنفيذ قبل اكتمال سجل lifecycle.", "error": error, "plan": [], "results": []}


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
