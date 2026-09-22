# CyberSentinel X — Architecture and Acceptance Report

## Executive result

تم تنفيذ وتصحيح الجزء المطلوب من المرحلة داخل المستودع. النتيجة المؤكدة هي **314 اختبارًا ناجحًا** بعد التعديلات، مع تشغيل smoke test فعلي عبر مزود OpenAI-compatible حقيقي. لم أسجل اختبار 20+ model turns كنجاح؛ الاختبار الحقيقي المنفذ أنتج **2 model turns و1 real tool call** وانتهى بـ`GOAL_COMPLETED`، ولذلك يبقى long-horizon acceptance غير مكتمل.

## Start and final state

| Field | Result |
|---|---|
| `START_COMMIT` | `59e6950f3124c443237f08b7459c867b34a2b9d5` |
| `FINAL_COMMIT` | `ba37e6d` (يتغير إلى hash الـamend النهائي) |
| Branch | `main` |
| Required final state | `HEAD == origin/main`, working tree clean بعد الدفع |

## Authority correction

تم تصحيح نموذج السلطة في `security/authority.py` إلى الترتيب الذي حدده Owner:

```text
OWNER_INSTRUCTION > SYSTEM_PLATFORM > OWNER_POLICY
> DETERMINISTIC_ENFORCEMENT > AUTHORIZATION_SCOPE
> TOOL_RUNTIME > MODEL_OUTPUT > EXTERNAL_DATA
```

لم يكن التعديل تغيير أرقام فقط. أضيفت regression assertions على الترتيب، وبقيت الحدود المنصية ممثلة كـ`system_boundary_immutable`. كما بقيت آليات `set_current_owner_instruction` تتطلب `OwnerAuthenticationEvidence` typed ومقيدة بالطلب، وترفض boolean authentication. Model output وexternal data وmemory وtool results لا تملك مسارًا لإنشاء أو تعديل Owner Instruction أو AuthorizationContext أو ScopeSnapshot.

نتيجة authority regression: **PASS**. اختبارات mutation وmodel-side authorization وexternal-data authority الموجودة والجديدة نجحت ضمن suite.

## Runtime map and classification

المسار canonical الذي تم تقويته هو:

```text
Owner authentication
→ persistent Mission
→ MissionRuntime
→ ContextAssembler
→ ModelTurn / ToolCallProposal
→ typed validation
→ AuthorizationContext
→ ScopeResolver
→ Tool Registry
→ execution
→ Observation / Evidence
→ Hypothesis / Strategy
→ replan or continuation
→ deterministic verification
```

التصنيف الواقعي للملفات:

| Component | Classification | Evidence |
|---|---|---|
| `agent/mission_runtime.py` | **CANONICAL / IMPLEMENTED + VERIFIED** | Mission persistence, native model loop, checkpoint, observation, evidence, replan, verification, recovery tests |
| `agent/agent_core.py` | **LIVE FACADE** | Creates Owner-bound missions; selects native path only when provider advertises native chat + tool calling |
| `agent/task_runtime.py` | **LIVE COMPATIBILITY RUNTIME** | Still serves task endpoints and has independent task persistence; it is not silently claimed as removed |
| `agent/runtime.py` | **LEGACY LIVE FOR BRIDGE** | Used by `core.engine`; retained for compatibility because bridge and existing tests still call it |
| `agent/loop.py` | **LEGACY LIVE FOR COMPATIBILITY** | Imported by `bridge.py` and existing tests; structural preflight does not authenticate or execute sensitive tools |
| `agent/conversation.py` | **LEGACY COMPATIBILITY API** | Used by `core.engine` and evaluation benchmark; understanding layer cannot grant authority |
| `agent/conversation_provider.py` | **COMPATIBILITY ADAPTER** | Typed untrusted proposal parser; rejects authority fields |

لم أحذف هذه الملفات لأن repository ما زال يملك references تنفيذية واختبارات لها. حذفها الآن كان سيخلق كسرًا صامتًا في bridge وtask APIs، ولذلك النتيجة هنا هي **CANONICAL NATIVE MISSION PATH VERIFIED; FULL LEGACY RUNTIME REMOVAL NOT CLAIMED**.

## `/api/chat` behavior

حاليًا توجد ثلاثة compatibility modes، لكن حدود authorization ليست مختلفة:

1. `mode=mission` يصل إلى `AgentCore` ثم `MissionRuntime`.
2. provider-enabled general task يصل إلى `AgentTaskRuntime` مع نفس `Tool Registry` و`authorize_tool` وscope checks.
3. provider-disabled legacy chat يستخدم capability fallback محدودًا؛ لا يعرض تفاصيل provider الداخلية للمستخدم، ولا يصف نفسه كـmodel agent.

تم فصل user response عن `InternalDiagnostic` في `core/response.py`. عند غياب provider يقول المستخدم إن النظام يعمل في الوضع المحلي المحدود، بينما يبقى `no_model_provider_configured` في diagnostics الداخلية. هذا المسار **لا يحقق بعد إزالة كل runtime compatibility paths**؛ وهو limitation صريح، وليس PASS زائفة.

## Model and tool path

`MissionRuntime.run_model_loop` يستخدم `ContextAssembler` في كل turn، ويحوّل provider response إلى `ModelTurn` و`ToolCallProposal`. كل proposal يحمل `mission_id`, `run_id`, `turn_id`, `action_id`, `tool_call_id`, `request_id`, `plan_version`, وstep identity. يتم رفض cross-mission وstale-run وduplicate وmissing identity.

تم إصلاح native continuation protocol: عند وجود نتائج أدوات، يعاد بناء رسالة `assistant` تحتوي `tool_calls` قبل رسائل `tool`. هذا الإصلاح ثبتته استجابة provider الحقيقي؛ قبل الإصلاح رفض endpoint رسالة `tool` غير مسبوقة بـassistant tool call.

Parallel calls تستخدم bounded execution، وتؤدي authorization وscope validation لكل call، ثم تعيد النتائج بترتيب proposals الأصلي. لا تُستخدم parallelism لتجاوز أي security boundary.

## Observation, hypothesis, strategy, and recovery

Observation الناجح يمر عبر interpreter deterministic، ويحدث hypothesis/evidence/strategy state. توجد triggers للـhypothesis weakening/rejection، high-value evidence، critical unknown، low information gain، contradiction، scope change، وverification failure. Model output لا يستطيع وحده إعلان `CONFIRMED` أو `VERIFIED`.

الـin-flight checkpoint يحول النتيجة الغامضة بعد crash إلى `RECOVERY_REQUIRED`، ولا يعيد side effect تلقائيًا. Semantics المعلنة هي **at-most-once until reconciliation** عند عدم وجود receipt خارجي؛ لم يتم ادعاء exactly-once.

## Knowledge and corpus

`knowledge/fixtures/incident_cve_x.json` مصنف **SYNTHETIC_FIXTURE** ولا يستخدم كدليل Threat Intelligence حقيقي.

`cyber_data/phase6k3/lazarus_corpus.json` مصنف **REAL_CORPUS / PARTIAL_PUBLIC_COVERAGE** بالمعنى المحدود: يحتوي metadata وshort factual paraphrases من مصادر عامة منسوبة مثل MITRE وCISA وFBI وClearSky، وليس raw vendor reports أو corpus شاملًا. Manifest يذكر 6 sources و20 objects ويعلن صراحة `PARTIAL_NON_COMPREHENSIVE`. لذلك لا أصفه بأنه comprehensive live feed.

`AgentCore` يمرر adaptive hybrid retrieval إلى Mission knowledge state مع provenance، content hash، trust class، و`authority: None`. Knowledge remains untrusted data ولا يمنح execution permission أو policy authority.

## SSRF and scope

تمت مراجعة `search/ssrf.py`, `search/web_provider.py`, `security/scope_resolver.py`, وtool registry. لا تسمح URL validation إلا بـHTTP/HTTPS والمنافذ المسموحة، وتمنع metadata/private ranges والـblocked suffixes. أضيف فحص DNS عند network boundary: hostname غير القابل للحل أو الذي يحل إلى private address يُرفض. Redirects لا تُتبع تلقائيًا في HTTP clients، وscope resolver يفحص redirect chain عند وجودها. `scoped_http_probe` لا يعمل دون typed `AuthorizationDecision` وScopeSnapshot مربوطين بالبرنامج والهدف.

## Real-model and test classification

| Category | Result | Evidence |
|---|---|---|
| UNIT | **PASS** | 314 total suite includes protocol, authority, context, retrieval, parsing, and security tests |
| INTEGRATION | **PASS** | Mission/task/runtime integration and API tests |
| SECURITY | **PASS** | Authorization, scope, SSRF, owner evidence, replay, and mutation tests |
| REAL_MODEL | **SMOKE PASS** | `gpt-5-mini`, 2 real model turns, 1 real `status` tool call, final deterministic verification |
| REAL_TOOL | **PASS for bounded local tool** | Real `status` registry execution in smoke and existing local/integration tests |
| REAL_KNOWLEDGE | **PARTIAL / VERIFIED CORPUS LOADED** | Partial public paraphrase corpus with provenance; not a live external feed |
| CONTRADICTION | **MOCK-VERIFIED** | Scripted integration coverage; no claim of real-model contradiction |
| COMPACTION | **MOCK-VERIFIED** | Deterministic compaction fingerprints and preservation tests |
| RECOVERY / CRASH-RESUME | **MOCK-VERIFIED** | Persistent checkpoint/reconciliation tests; no external exactly-once claim |
| LONG_HORIZON | **FAIL / NOT ACCEPTED** | Only 2 real turns executed; required 20+ real turns not demonstrated |

The real smoke result was:

```text
provider: real-openai-compatible
model: gpt-5-mini
status: GOAL_COMPLETED
model_turns: 2
tool_calls: 1
verification.verified: true
```

## Files changed in this phase

### Added

- `core/response.py`
- `scripts/real_model_smoke.py`
- `tests/test_directive_acceptance.py`
- `docs/CYBERSENTINEL_X_ARCHITECTURE_ACCEPTANCE_REPORT.md`

### Modified

- `security/authority.py`
- `core/engine.py`
- `api/chat.py`
- `agent/task_runtime.py`
- `agent/model_intelligence/conversation.py`
- `agent/model_intelligence/context.py`
- `agent/model_protocol.py`
- `agent/agent_core.py`
- `agent/mission_runtime.py`
- `search/ssrf.py`
- `tests/test_phase6a1_hardening.py`
- `tests/test_phase6k4_deep_hardening.py`

### Deleted

- None. Legacy references remain active and are explicitly classified above.

## Known limitations

The required 20+ real-model long-horizon run with deliberate tool failure, contradiction, compaction during mission, crash/restart, resume, and final verification was not completed. The real smoke proves that the native path can reach a real model, real tool, continuation, and deterministic verification, but it does not prove long-horizon reliability. The repository still contains live compatibility runtimes for bridge/task endpoints; complete consolidation requires a separately planned migration of those public contracts and their tests.
