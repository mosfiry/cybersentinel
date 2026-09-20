from __future__ import annotations
import json, re
from .db import add_event, recent, counts, search_all, add_watch, remove_watch, watches
from .policy import evaluate
from .trust import owner_request
from .intel import refresh_all, latest_intel
from .local_defense import local_security_check, local_system_info
from .llm import plan_with_llm, model_status
from agent.runtime import AgentRuntime
from security.owner_policy import verify_owner, set_current_owner_instruction, current_owner_policy_context, load_state

TOOLS={"status","latest_intel","refresh_intel","local_security_check",
       "local_system_info","search","watch","unwatch"}
RUNTIME=AgentRuntime()

def status():
    return {
        "service":"CyberSentinel X",
        "version":"FINAL",
        "online":True,
        "event_counts":counts(),
        "watch_count":len(watches()),
        "watches":watches(),
        "llm":model_status(),
        "agent":RUNTIME.status(),
        "owner_policy": {"fingerprint": RUNTIME.status()["policy_fingerprint"], "state": load_state(), "context": current_owner_policy_context()},
        "recent_events":recent(20),
    }

def deterministic_plan(text):
    t=text.casefold()
    tools=[]
    if any(x in t for x in ("حدّث","تحديث","استخبارات","threat","intel","cisa","kev","ثغرات")):
        tools.append("refresh_intel")
    if any(x in t for x in ("افحص الجهاز","فحص الجهاز","فحص محلي","افحص النظام","local check","local security")):
        tools.append("local_security_check")
    if any(x in t for x in ("معلومات الجهاز","system info","معلومات النظام")):
        tools.append("local_system_info")
    if any(x in t for x in ("آخر الأحداث","الاحداث","الأحداث","latest events")):
        tools.append("status")
    if any(x in t for x in ("آخر الثغرات","أحدث الثغرات","latest intel","latest vulnerabilities")):
        tools.append("latest_intel")
    if any(x in t for x in ("الحالة","status","كيف حال النظام")):
        tools.append("status")
    m=re.search(r"(?:ابحث عن|ابحث|بحث عن|search for|search)\s+(.+)",text,re.I)
    if m: tools.append(("search",m.group(1).strip()))
    m=re.search(r"(?:راقب|راقبة|watch)\s+(.+)",text,re.I)
    if m: tools.append(("watch",m.group(1).strip()))
    m=re.search(r"(?:أوقف مراقبة|الغاء مراقبة|unwatch)\s+(.+)",text,re.I)
    if m: tools.append(("unwatch",m.group(1).strip()))
    if not tools:
        tools=["status"]
    result=[]
    seen=set()
    for x in tools:
        key=x if isinstance(x,str) else x[0]
        if key not in seen:
            result.append(x); seen.add(key)
    return result

def make_plan(text):
    try:
        p=plan_with_llm(text)
        if p and p["tools"]:
            return p["tools"],p["rationale"],"llm"
    except Exception as exc:
        add_event("planner","LLM planner unavailable",str(exc),"llm","warning",False)
    return deterministic_plan(text),"Deterministic defensive planner","local"

def execute(tool):
    if tool=="status": return status()
    if tool=="latest_intel": return latest_intel(50)
    if tool=="refresh_intel": return refresh_all()
    if tool=="local_security_check": return local_security_check()
    if tool=="local_system_info": return local_system_info()
    raise ValueError("tool requires argument")

def handle(text,source="web",presented_token=None):
    owner_ok, owner_reason = verify_owner(text, presented_token)
    if not owner_ok:
        add_event("command","Owner authentication failed",text,source,"warning",False,{"decision":"deny","reason":owner_reason})
        return {"ok":False,"decision":"deny","answer":"مصادقة المالك مطلوبة.","plan":[],"results":[]}
    # The authenticated Owner instruction is the authoritative policy context for this decision.
    set_current_owner_instruction(text, source)
    req=owner_request(text,source)
    decision=evaluate(req)
    if not decision.allowed:
        add_event("command","Command denied",text,source,"warning",True,{"decision":"deny"})
        return {"ok":False,"decision":"deny","answer":decision.reason,"plan":[],"results":[]}

    plan,rationale,planner=make_plan(text)
    serial_plan=[x if isinstance(x,str) else list(x) for x in plan]
    add_event("plan","Defensive plan",json.dumps(serial_plan,ensure_ascii=False),
              source,"info",True,{"planner":planner,"plan":serial_plan})

    results=[]
    for item in plan:
        if isinstance(item,tuple):
            name,arg=item
            if name=="search":
                results.append({"tool":"search","result":search_all(arg,50),"query":arg})
            elif name=="watch":
                add_watch(arg); results.append({"tool":"watch","result":{"keyword":arg,"watches":watches()}})
            elif name=="unwatch":
                remove_watch(arg); results.append({"tool":"unwatch","result":{"keyword":arg,"watches":watches()}})
            continue
        if item not in TOOLS:
            continue
        try:
            results.append({"tool":item,"result":execute(item)})
        except Exception as exc:
            results.append({"tool":item,"error":str(exc)})

    add_event("execution","Defensive plan executed",
              json.dumps({"planner":planner,"plan":serial_plan,"result_count":len(results)},ensure_ascii=False),
              source,"info",True,{"planner":planner,"plan":serial_plan})
    return {
        "ok":True,"decision":"allow","planner":planner,
        "answer":summarize(plan,results,planner,rationale),
        "plan":serial_plan,"results":results,
        "evidence":[RUNTIME.verify_result("execution completed", "local-agent", {"planner":planner,"result_count":len(results)}, 10)]
    }

def summarize(plan,results,planner,rationale):
    lines=[f"تم تنفيذ خطة دفاعية فعلية ({planner})."]
    if rationale: lines.append("منطق التخطيط: "+rationale)
    for r in results:
        t=r["tool"]
        if "error" in r:
            lines.append(f"• {t}: فشل التنفيذ — {r['error']}")
        elif t=="refresh_intel":
            val=r["result"]; lines.append("• استخبارات التهديد: "+json.dumps(val.get("results",val),ensure_ascii=False))
        elif t=="local_security_check":
            lines.append(f"• الفحص المحلي: تم العثور على {r['result']['count']} TCP listener.")
        elif t=="local_system_info":
            lines.append(f"• النظام: {r['result'].get('platform')} / {r['result'].get('kernel')}")
        elif t=="latest_intel":
            lines.append(f"• أحدث بيانات الاستخبارات: {len(r['result'])} سجل.")
        elif t=="status":
            lines.append(f"• الحالة: ONLINE، الأحداث: {sum(r['result']['event_counts'].values())}.")
        elif t=="search":
            lines.append(f"• البحث عن «{r['query']}»: {len(r['result']['events'])} حدث و{len(r['result']['intel'])} سجل استخبارات.")
        elif t in ("watch","unwatch"):
            lines.append(f"• {t}: تم تحديث قائمة المراقبة.")
    return "\n".join(lines)
