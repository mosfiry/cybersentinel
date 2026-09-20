# تقرير التسليم النهائي لمشروع CyberSentinel X

**الوثيقة:** Final Owner Handoff Report — التقرير المرجعي لاستمرارية المشروع

**التاريخ:** 2026-09-20

**المستودع:** [mosfiry/cybersentinel][1]

**مسار المشروع المحلي:** `/home/ubuntu/cybersentinel`

**اللغة:** العربية مع الإبقاء على أسماء الملفات والواجهات والمصطلحات البرمجية باللغة الإنجليزية عند الحاجة.

**الغرض:** تمكين أي مهندس أو وكيل أو خبير أمني لاحق من استكمال المشروع منفردًا دون فقدان قرارات التصميم أو حدود الصلاحيات أو حالة التنفيذ.

---

## 1. الخلاصة التنفيذية

CyberSentinel X هو وكيل أمن سيبراني محلي ذو توجه دفاعي. بدأ المشروع كمنصة تجمع بين Owner Policy وBridge Authentication وTool Registry وEvidence وLifecycle وReasoning، ثم تطور إلى Agent Platform قادرة على استقبال لغة طبيعية، الاحتفاظ بسياق المحادثة، اختيار أدوات مسجلة، تنفيذ الطلبات المصرح بها عبر محرك حتمي، وتقديم نتيجة قابلة للتدقيق.

الهدف النهائي ليس إنشاء نموذج يطلق أوامر عشوائية، وليس تحويل المعرفة الأمنية أو النصوص الخارجية إلى صلاحيات تنفيذ. الهدف هو بناء **وكيل يفهم السؤال الأمني، يبحث عن الأدلة، يكوّن فرضيات متعددة، يطلب المعلومات الناقصة، يستعمل أدوات محدودة ومصرحًا بها، يوضح درجة اليقين، ويحفظ علاقة الطلب بالسياسة والتفويض والتنفيذ والدليل**.

الوضع الحالي موزع على ثلاث نقاط مهمة:

| المستوى | الفرع أو الـCommit | الحالة |
|---|---|---|
| النسخة المرجعية المدموجة | `main` عند `46a2c2f` | تشمل Chat Gateway وConversation Memory وAgent Loop الأساسي وواجهات Chat وSSE. |
| Phase 1 | `feature/agent-runtime-2.0` عند `d86c66d` | جاهزة في PR مستقل وتضيف Runtime 2.0 بحدود Policy وأنواع نتائج واضحة. |
| Phase 2 | `feature/native-tool-calling` عند `5d10d1f` | جاهزة في PR مستقل مبني على Phase 1 وتضيف Provider abstraction وNative Tool Calling وFailover واختبارات Phase 2. |

روابط Pull Requests:

- [PR #10 — Upgrade Agent Loop to policy-bounded Runtime 2.0][2]
- [PR #11 — Add native tool calling provider abstraction][3]

نتيجة الاختبارات على فرع Phase 2:

```text
49 passed
```

نتيجة الاختبارات على فرع Phase 1 قبل Phase 2:

```text
43 passed
```

نتيجة الاختبارات على `main` قبل Phase 1 وPhase 2:

```text
40 passed
```

---

## 2. مبدأ السلطة: Owner هو مالك النموذج والسياسة

### 2.1 التعريف الملزم

> **الـOwner هو مالك النموذج ومالك التطبيق ومالك التشغيل. صلاحية Owner هي أعلى صلاحية تطبيقية فوق النموذج، وفوق الأدوات، وفوق البيانات، وفوق المعرفة المسترجعة، وفوق التعليمات التي يكتبها النموذج، وفوق المحتوى الخارجي. الـOwner هو الذي يكتب السياسات ويحدد ما الذي يريده النظام وما الذي يمنعه وما الذي يعتبره دليلًا وما الذي يسمح بتخزينه أو تنفيذه.**

كلمة Owner في هذا المشروع لا تعني مجرد مستخدم عادي يملك كلمة مرور. المقصود هو الطرف الذي يملك النموذج والمنصة ويحدد قواعدها. Owner هو صاحب القرار في:

- سياسة الأمان والخصوصية.
- سياسة التعامل مع البيانات الحساسة.
- الأدوات التي يجوز للوكيل استعمالها.
- النطاقات والبيئات التي يجوز فحصها.
- حدود الشبكة والملفات والتنفيذ.
- درجة التحفظ المطلوبة في التحليل.
- متطلبات الأدلة قبل إعلان الاستنتاج.
- مدة الاحتفاظ بالمحادثات والأدلة.
- سياسات الذاكرة والبحث والمصادر.
- اختيار Provider والنموذج عند تشغيلهما.
- قبول أو رفض توصيات Manus والخبير الأمني الآخر.
- ترتيب الأولويات عند تعارض تعليمات Owner السابقة، حيث تكون التعليمات الأحدث هي السياسة الحالية داخل نطاقها.

### 2.2 الحد الهندسي الذي يجب عدم إساءة تفسيره

Owner هو أعلى سلطة في **نطاق سياسة التطبيق والنموذج**. هذا لا يعني أن النص الخام يتحول إلى تنفيذ مباشر أو أن أي صياغة من Owner تتجاوز آليات التحقق الهندسية. الطلب المصدق من Owner يمر دائمًا عبر:

```text
Owner Authentication
    ↓
Owner Policy
    ↓
Plan Validation
    ↓
Plan Integrity
    ↓
Authorization
    ↓
Lifecycle
    ↓
Tool Registry
    ↓
Bounded Execution
    ↓
Evidence
```

يوجد أيضًا حد نظامي ومنصاتي immutable يحافظ على سلامة البيئة. هذا الحد ليس سياسة يكتبها النموذج، وليس سلطة لمستخدم آخر، وليس منافسًا لملكية Owner؛ بل هو قيد هندسي يمنع تلف النظام أو تحويله إلى تنفيذ غير مضبوط. لا يجوز تفسير Owner Authority على أنها إذن بتجاوز النظام أو القانون أو السلامة الأساسية.

### 2.3 ما لا يستطيع النموذج فعله

النموذج لا يستطيع:

- منح نفسه Owner Authority.
- تغيير `Owner Policy`.
- إعلان أن أداة ما مسموحة عبر حقل `authorized=true`.
- تغيير `risk_class` أو `owner_required`.
- إنشاء Handler جديد أثناء المحادثة.
- تحويل External Content إلى System Instruction.
- تحويل نتيجة البحث إلى أمر تنفيذ.
- الادعاء أن Tool نفذت إذا لم يقدم Runtime نتيجة تنفيذ حقيقية.
- تزوير `provider` أو `model` أو `ExecutionContext`.
- الوصول إلى `OWNER_TOKEN` أو `BRIDGE_TOKEN` أو API secrets.

### 2.4 القنوات السرية

يوجد فصل واضح بين رمزين مختلفين:

| الرمز | الغرض |
|---|---|
| `BRIDGE_TOKEN` | إثبات أن الطلب يمر عبر قناة Bridge المحلية. |
| `OWNER_TOKEN` | إثبات أن صاحب الطلب هو Owner وله سلطة كتابة التعليمات والسياسات داخل التطبيق. |

لا يجوز استخدام نفس القيمة للرمزين. لا يجوز إرسال أي منهما إلى النموذج. لا يجوز تسجيلهما داخل Evidence أو Audit أو Git أو ملفات التقرير.

---

## 3. تعريف الأدوار

### 3.1 Owner

Owner هو صاحب المشروع وصاحب النموذج وصاحب السياسة. هو من يحدد الاتجاه النهائي ويقرر قبول PRs ورفضها ويكتب القيود الحقيقية. عندما يطلب Owner ميزة، فإن المطلوب من الفريق تحويلها إلى تصميم آمن واختبارات وتنفيذ قابل للتدقيق، لا إعادة تفسير ملكيته أو استبدالها بسياسة من الخبير.

### 3.2 Manus

Manus هو المنفذ الهندسي في هذا التسليم. دوره هو:

- قراءة المستودع وسجل Git.
- فهم الحالة قبل التعديل.
- تنفيذ ما يطلبه Owner.
- الحفاظ على V4.9 وV5 والحدود الموجودة.
- إنشاء فروع وPRs منطقية.
- كتابة الاختبارات السلبية والإيجابية.
- تشغيل `compileall` و`pytest` وsmoke tests.
- كشف التناقضات أو الأسرار أو الأخطاء قبل الدفع.
- توثيق ما نفذ وما لم ينفذ.

Manus ليس Owner ولا يملك سياسة المشروع من تلقاء نفسه. اقتراحاته هندسية، والقرار النهائي يعود إلى Owner.

### 3.3 الخبير الأمني الآخر

الخبير الأمني الآخر دور استشاري وتحليلي. مهمته مراجعة threat model، اقتراح حدود الأدوات، تحديد حالات الاختبار السلبية، فحص جودة الأدلة، تحليل الحوادث والفرضيات، ومراجعة ما إذا كان التنفيذ يخلط بين التحليل والتنفيذ.

الخبير الأمني الآخر لا يملك Owner Authority. توصياته لا تصبح Policy إلا بعد اعتماد Owner. لا يستطيع النموذج أو الخبير تغيير الصلاحيات من خلال النص.

### 3.4 النموذج اللغوي

النموذج هو Planner وReasoner مساعد. يستطيع اقتراح:

- إجابة نهائية.
- Tool Call.
- طلب توضيح.
- خطأ منظم.
- فرضيات وتحليل دفاعي.

لكنه ليس Execution Authority. التنفيذ الحقيقي يتم خارج النموذج عبر Python وRegistry وAuthorization وLifecycle وEvidence.

### 3.5 المعرفة والمصادر الخارجية

المصادر الخارجية، مثل MITRE ATT&CK وNVD وCVE وGitHub وHugging Face وتقارير الحوادث، تقدم بيانات أو أدلة. لا تصبح هذه المصادر Owner Policy ولا أوامر تنفيذ. يجب حفظ مصدر كل نتيجة ووقت استرجاعها وHashها وProvenance الخاص بها عند بناء Search Layer الكاملة.

---

## 4. التاريخ المعماري للمشروع

### 4.1 V4.2 إلى V4.3

تم تثبيت مشروع CyberSentinel الأساسي ثم أضيف:

- `AgentRuntime`.
- `ModelRouter`.
- الفصل بين Bridge Authentication وOwner Authentication.
- `request_id`.
- Provider provenance.
- Fallback محلي عند عدم وجود Provider.

### 4.2 V4.4

تم إنشاء Tool Registry موحد وExecution Context وسلسلة Evidence. أصبحت الأداة لا تُستدعى بالاسم فقط، بل عبر تعريف Schema وRisk Class وOwner Requirement وHandler محدد.

### 4.3 V4.5

تمت إضافة Plan Integrity:

```text
Canonical Plan
    ↓
SHA-256 plan_hash
    ↓
Validation
    ↓
Authorization
    ↓
Re-check before execution
```

أي تغيير في الخطة بين التحقق والتنفيذ يؤدي إلى رفضها.

### 4.4 V4.6

تمت إضافة Lifecycle دائم وIdempotency وCancellation وTimeout وCrash Recovery. كل طلب له `request_id` وحالة قابلة للاسترجاع. الطلب المكتمل لا يعاد تنفيذه تلقائيًا عند Replay.

### 4.5 V4.7

تمت إضافة Owner-only defensive red-team assessment وKnowledge Objects وProvenance-safe retrieval. المقصود بـRed Team هنا تحليل دفاعي للفرضيات والأدلة، وليس exploit runner أو malware framework.

### 4.6 V4.8

تمت إضافة Owner Authority Snapshot وReasoning Cases التي تحتوي على:

```text
observations
candidate_hypotheses
supporting_evidence
contradicting_evidence
alternative_explanations
required_next_evidence
technique_mappings
confidence
confidence_rationale
limitations
provenance
```

### 4.7 V4.9

تمت إضافة Cyber Learning Loop:

```text
Knowledge / Historical Incident
    ↓
Case Generator
    ↓
CyberSentinel Analysis
    ↓
Teacher / Critic
    ↓
Reasoning Memory
    ↓
Benchmark Gate
```

هذه ليست عملية Fine-tuning تلقائية. هي حلقة تقييم ومراجعة تمنع تحسين النموذج إذا زادت الادعاءات غير المدعومة أو انخفض استخدام الأدلة أو زادت حساسية Prompt Injection.

### 4.8 V5.0 Owner Sessions وExpert Modes

في commit:

```text
d2181f4 Add V5 owner sessions and expert reasoning core
```

تمت إضافة:

- Owner Session.
- One-time Challenge.
- رفض Replay للتحدي.
- ربط الجلسة بـ`ExecutionContext`.
- Attacker View تحليلي.
- Defender View تحليلي.
- انتقالات reasoning بين منظور المهاجم والمدافع.
- الحفاظ على التنفيذ الدفاعي وعدم تحويل التحليل إلى تنفيذ هجومي.

### 4.9 Agent Platform الأساسية

في commit:

```text
46a2c2f Build conversational agent platform and chat gateway
```

تمت إضافة:

- `Conversation Memory` مستقلة.
- `AgentLoop` أولي.
- `POST /api/chat`.
- `GET /api/chat/stream`.
- `GET /api/session/<id>`.
- `GET /api/tools`.
- واجهة محادثة Web محدثة.
- حفظ Conversation ID.
- عرض Tool Activity.
- دعم SSE مبدئي.

### 4.10 Phase 1 — Runtime 2.0

في commit:

```text
d86c66d Upgrade agent loop to policy-bounded runtime 2.0
```

تمت إضافة:

- `RuntimeLimits`.
- `max_steps`.
- `max_tool_calls`.
- `max_execution_time_seconds`.
- `max_context_messages`.
- `max_context_chars`.
- `max_result_chars`.
- أنواع `final_answer` و`tool_call` و`clarification` و`error`.
- تقليص Context عند تجاوزه الحد.
- تقليص Tool Results.
- Provider failure آمن بلا تسريب التفاصيل.
- طلب Clarification عند نقص المعلومات.

### 4.11 Phase 2 — Native Tool Calling

في commit:

```text
5d10d1f Add native tool calling provider abstraction
```

تمت إضافة:

- `ProviderCapabilities`.
- `ProviderResponse`.
- `ToolCall`.
- `LLMProvider` Protocol.
- `generate()`.
- `stream()` abstraction.
- `tool_calling()`.
- OpenAI-compatible native Tool Calling عند تفعيله صراحةً.
- Safe JSON fallback.
- Capability-aware ModelRouter.
- Provider failover.
- Registry-derived tool schemas.
- Tool Call IDs.
- Multi-tool boundary.
- اختبارات Provider metadata forgery وsecret non-disclosure.

---

## 5. البنية الحالية

المسار العام في النسخة الحالية هو:

```text
Web UI / API Client
        ↓
Bridge Authentication
        ↓
Owner Token أو Owner Session Challenge
        ↓
Chat API
        ↓
Conversation Memory
        ↓
Agent Runtime 2.0
        ↓
Provider API
        ↓
ModelRouter
        ↓
Concrete Provider أو Safe Fallback
        ↓
Tool Call Normalization
        ↓
Tool Name وArgument Validation
        ↓
Owner Policy وAuthorization
        ↓
Existing Core Engine
        ↓
Plan Hash وLifecycle
        ↓
Tool Registry
        ↓
Bounded Handler
        ↓
Evidence Chain وAudit
        ↓
Tool Result
        ↓
Agent Context
        ↓
Final Answer أو Clarification أو Error
```

المبادئ الأساسية:

```text
LLM = Planner
Tool Registry = Capability Boundary
Authorization = Decision Boundary
Engine/Lifecycle/Evidence = Execution Boundary
Owner = Highest Application Authority and Policy Author
```

---

## 6. الملفات الرئيسية ووظيفة كل ملف

### Agent

| الملف | الوظيفة |
|---|---|
| `agent/runtime.py` | التخطيط الحالي المتوافق مع V4.9 وV5. |
| `agent/loop.py` | Agent Runtime 2.0 وConversation Loop وnative/fallback Tool Calls. |
| `agent/provider_api.py` | ProviderResponse وToolCall وProviderCapabilities وLLMProvider. |
| `agent/providers.py` | OpenAI-compatible Provider وgenerate وnative tool calling وstream capability. |
| `agent/model_router.py` | اختيار Provider وcapability discovery وfailover وprovenance. |
| `agent/evidence.py` | بناء والتحقق من Evidence Chain. |

### Core

| الملف | الوظيفة |
|---|---|
| `core/engine.py` | تنفيذ الطلب الكامل من Owner Authentication إلى Lifecycle وEvidence. |
| `core/context.py` | ExecutionContext وAuthority Snapshot وProvider Model context. |
| `core/db.py` | SQLite events وintel وexecutions وreasoning memory وconversation memory. |
| `core/lifecycle.py` | الحالات الدائمة وclaim وcancel وrecovery وidempotency. |
| `core/intel.py` | جمع وقراءة استخبارات التهديد المحلية. |
| `core/local_defense.py` | الفحوص المحلية الدفاعية المحدودة. |
| `core/policy.py` | تقييم سياسة الطلب. |

### Security

| الملف | الوظيفة |
|---|---|
| `security/owner_policy.json` | Owner Policy وRuntime Limits. |
| `security/owner_policy.py` | تحميل Policy وOwner Authentication وAuthority Snapshot وRuntime Limits. |
| `security/owner_session.py` | Owner Session وOne-time Challenge. |
| `security/authorization.py` | Authorization الحتمي للخطة والأداة. |
| `security/plan_integrity.py` | Canonicalization وPlan Hash والتحقق من الخطة. |

### Tools

| الملف | الوظيفة |
|---|---|
| `tools/registry.py` | المصدر الوحيد للأدوات وSchemas وMetadata وHandler execution. |

### API وWeb

| الملف | الوظيفة |
|---|---|
| `bridge.py` | HTTP Gateway وBridge Auth وChat وSSE وExecution endpoints. |
| `api/chat.py` | Chat service وConversation retrieval وSSE event conversion. |
| `web/index.html` | واجهة المحادثة العربية RTL. |
| `web/app.js` | إرسال Chat requests وعرض Tool Activity وحفظ Conversation ID. |
| `web/style.css` | التصميم الحالي للواجهة. |

### Evaluation وReasoning

| المسار | الوظيفة |
|---|---|
| `reasoning/` | Reasoning Cases وRed Team وExpert Modes. |
| `evaluation/` | Critic وBenchmark Gate وLearning Loop. |
| `tests/` | اختبارات الأمن والبنية والتشغيل وRuntime وProvider. |

---

## 7. Owner Authentication وقنوات API

### 7.1 Bridge Authentication

الـBridge يعمل افتراضيًا على:

```text
http://127.0.0.1:8787/
```

وهو محلي افتراضيًا. لا ينبغي نشره على LAN أو الإنترنت قبل إضافة TLS أو Reverse Proxy موثوق وACL وRate Limiting وSecret Manager ومراجعة أمنية.

### 7.2 Owner Token

`OWNER_TOKEN` يثبت أن الطلب صادر من Owner. لا يكفي وجود كلمة `Owner` داخل النص. النص لا يصبح مصادقًا عليه من تلقاء نفسه.

### 7.3 Owner Session

يمكن إنشاء Owner Session ثم استعمال Challenge أحادي الاستخدام. يتم تمرير:

```text
X-CyberSentinel-Owner-Session
X-CyberSentinel-Owner-Challenge
```

ولا يجوز إعادة استخدام Challenge.

### 7.4 الواجهات الحالية

```text
POST /api/owner/session
POST /api/chat
GET  /api/chat/stream
GET  /api/session/<conversation_id>
GET  /api/tools
GET  /api/status
POST /api/command
GET  /api/execution/<request_id>
GET  /api/reasoning/<request_id>
POST /api/cancel
```

`/api/chat` يحفظ Conversation Memory ثم يشغل Agent Runtime عند وجود Provider، أو يستخدم Core Engine المحلي عند عدم وجود Provider.

`/api/chat/stream` يقدم أحداثًا آمنة حاليًا من النوع:

```text
started
 tool_activity
completed
```

وسيجري تطويره لاحقًا إلى Structured Events كاملة كما هو موضح في خارطة الطريق.

---

## 8. Conversation Memory وReasoning Memory

تم الفصل بين أنواع الذاكرة بدل وضع كل شيء في Prompt واحد.

### Conversation Memory

تخزن:

```text
conversation_id
role
content
metadata
created_at
updated_at
```

وتستعمل للحفاظ على محادثة المستخدم وسياق Tool Results.

### Reasoning Memory

تخزن Reasoning Cases وCritic Reports المرتبطة بـ`request_id`. لا تُستخدم كبديل لمحادثة المستخدم.

### Execution History

تسجل الطلبات والأدوات وحالات Lifecycle والنتائج وCancellation وFailure.

### Owner Policy

تبقى مستقلة عن الذاكرة. النموذج لا يستطيع تعديلها عبر Conversation Memory أو Tool Result أو External Content.

---

## 9. Tool Registry الحالي

الأدوات الحالية هي:

| الأداة | الوظيفة | التصنيف |
|---|---|---|
| `status` | قراءة حالة الخدمة وسجل الأحداث الأخير. | `read` |
| `latest_intel` | قراءة استخبارات التهديد المجمعة. | `read` |
| `refresh_intel` | جمع استخبارات دفاعية. | `network-read` |
| `local_security_check` | قراءة TCP listeners المحلية. | `read` |
| `local_system_info` | قراءة معلومات النظام. | `read` |
| `search` | البحث في الأحداث والاستخبارات المحلية. | `read` |
| `watch` | إضافة كلمة مراقبة محلية. | `state-write` |
| `unwatch` | إزالة كلمة مراقبة محلية. | `state-write` |
| `run_project_tests` | تشغيل `pytest -q` فقط داخل root مضبوط. | `bounded-exec` |
| `red_team_assess` | تحليل دفاعي Owner-only بلا exploit أو shell. | `analysis` |

أصبحت `ToolSpec` تدعم Metadata إضافية:

```text
network_required
timeout
max_output
supports_streaming
idempotent
side_effects
capabilities
```

أي Tool جديدة يجب أن تمر بهذه القواعد:

1. اسم فريد.
2. وصف محدود الحجم.
3. Risk Class معروف.
4. Handler قابل للاستدعاء.
5. Schema صالح.
6. Owner requirement صريح.
7. Timeout وMax Output محددان.
8. Side Effects معلنة.
9. Idempotency معلنة.
10. اختبارات إيجابية وسلبية قبل الدمج.

`run_project_tests` ليس Shell عامًا. المسار محصور داخل `CYBERSENTINEL_TEST_ROOT` والأمر الفعلي ثابت.

`red_team_assess` تحليل دفاعي. لا يملك Handler لتنفيذ Exploit أو Persistence أو Credential Access أو Malware Deployment.

---

## 10. Plan Integrity وAuthorization وEvidence

قبل التنفيذ، تتحول الخطة إلى صيغة Canonical ثم يحسب:

```text
plan_hash = SHA-256(canonical_plan)
```

يتم تسجيل Hash داخل:

- Lifecycle.
- Plan Event.
- Authorization Record.
- Execution Event.
- Evidence Chain.

قبل كل Tool Handler، يعاد حساب Hash. إذا تغيرت الخطة بعد التحقق، يرفض التنفيذ.

قرار Authorization يحتوي على:

```text
tool
argument
risk_class
owner_required
owner_authenticated
policy_version
decision
reason
plan_hash
```

Evidence Chain تسجل العلاقة:

```text
request
  → auth
  → policy
  → plan
  → authorization
  → execution
  → evidence
  → response
```

كل Evidence تتضمن:

```text
request_id
sequence
previous_hash
current_hash
source
observation
result
confidence أو severity
```

بهذا يمكن معرفة من أرسل الطلب، وأي Policy كانت فعالة، وأي Provider اقترح الخطة، وأي Tool نفذت، وما النتيجة، وهل حدث Cancellation أو Failure، وهل تغير الدليل بعد تسجيله.

---

## 11. Agent Runtime 2.0 بالتفصيل

Runtime 2.0 يبدأ من:

```text
User Message
    ↓
Conversation Context
    ↓
Provider
    ↓
Response Normalization
    ↓
final_answer / tool_call / clarification / error
```

إذا كان الرد Tool Call:

```text
Tool Call
    ↓
Tool Call Count Check
    ↓
Name Validation
    ↓
Argument Validation
    ↓
Authorization
    ↓
Existing Engine
    ↓
Tool Result
    ↓
Conversation Memory
    ↓
Provider Again
```

إذا كانت البيانات ناقصة، يطلب الوكيل Clarification ولا يخترعها.

إذا فشل Provider، يرجع Runtime Error آمنًا ولا يسجل تفاصيل Credential أو Network internals.

إذا وصل Runtime إلى حد `max_steps` أو `max_tool_calls` أو `max_execution_time_seconds`، يتوقف بوضوح ولا يدعي النجاح.

---

## 12. Phase 2 بالتفصيل

### ProviderResponse

تم توحيد استجابة Providers في `ProviderResponse` بدل الاعتماد على dict غير منظم فقط.

### Native Tool Calling

عندما تكون `supports_tool_calling=true`، يستعمل Runtime الاستجابة الأصلية. لا يحولها إلى JSON نصي ثم يعيد تفسيرها.

### Safe JSON Fallback

إذا لم تتوفر capability، يستعمل Router `generate()` ثم parser المنظم الحالي. لا يؤدي fallback إلى تجاوز Authorization.

### Failover

يختبر Router Provider الأول، ثم ينتقل إلى Provider بديل عند الفشل. كل Provider يخضع لفحص capabilities مستقل.

### Streaming

الـabstraction موجودة، لكن OpenAI-compatible SSE HTTP adapter الحقيقي غير منفذ بعد. لذلك capability الحالية هي `false`، ولا يتم الادعاء بأن streaming مكتمل. هذا قرار مقصود لمنع fake integration.

### Provenance

`provider` و`model` و`capability` تأتي من Router والـAdapter، وليس من النص الذي يولده النموذج.

---

## 13. نتائج الاختبارات والتحقق

على فرع Phase 2 تم تنفيذ:

```bash
.venv/bin/python -m compileall -q .
.venv/bin/python -m pytest -q
git diff --check
```

النتيجة:

```text
49 passed in 0.85s
```

تشمل الاختبارات:

- Owner Authentication.
- الفصل بين Bridge Token وOwner Token.
- Owner Session وChallenge.
- Conversation Memory.
- Runtime Limits.
- Clarification.
- Final Answer.
- Provider Failure.
- Tool Call Count.
- Context bounds.
- Tool Result bounds.
- Unknown Tool.
- Invalid Argument.
- Extra Argument.
- Native Tool Calling.
- JSON fallback.
- Multiple Tool Calls.
- Tool Call ID.
- Provider failover.
- Forged provider metadata.
- Secret non-disclosure.
- Registry schema generation.
- Streaming event safety.
- Plan Integrity.
- Evidence Chain.
- Lifecycle.
- Cancellation.
- Crash Recovery.
- Reasoning Cases.
- Critic.
- Benchmark Gate.

تم كذلك إجراء smoke test فعلي سابقًا على Gateway المحلي، وشمل:

```text
/api/health
/api/tools
/api/chat
/api/chat/stream
```

وكانت النتيجة:

```text
health = true
tools = 10
chat_ok = true
authentication_method = owner_token
SSE = started → tool_activity → completed
```

---

## 14. ما نريد الحصول عليه في النهاية

نريد CyberSentinel X Agent Platform حقيقية تستطيع:

1. فهم الأسئلة الأمنية باللغة الطبيعية.
2. تمييز السؤال الواضح من السؤال الناقص.
3. طلب Clarification بدل اختراع البيانات.
4. بناء Context محدود ومناسب.
5. استعمال Conversation Memory ذات صلة فقط.
6. استدعاء أدوات Registry فقط.
7. استعمال Native Tool Calling عند توفره.
8. استخدام JSON fallback آمن عند عدم توفر Native Tool Calling.
9. اختيار Provider بناءً على capability وPolicy وavailability.
10. الانتقال إلى Provider بديل عند الفشل.
11. الاحتفاظ بـTool Call IDs.
12. ربط Tool Call بالتفويض والتنفيذ والنتيجة.
13. البحث في مصادر متعددة مع Provenance وContent Hash.
14. مقارنة الأدلة بدل اعتبار نتيجة واحدة حقيقة مطلقة.
15. إنتاج فرضيات متعددة.
16. عرض الأدلة المؤيدة والمعارضة.
17. عرض التفسيرات البديلة.
18. حساب Confidence مع تبرير.
19. حفظ Reasoning Case قابل للتدقيق.
20. تشغيل Teacher/Critic وBenchmark Gate.
21. دعم الملفات بعد Safe Ingestion وQuarantine وHash.
22. تنفيذ المهام البرمجية داخل Sandbox مستقل فقط.
23. دعم Long-running Tasks مع Queue وPause وResume وCancel وRetry.
24. تقديم Structured Streaming آمن.
25. توفير Web UI احترافية.
26. توفير Android Client يمر عبر Authenticated API ولا يتصل بالأدوات مباشرة.
27. إبقاء Owner هو صاحب النموذج وصاحب السياسة وصاحب القرار الأعلى داخل التطبيق.

---

## 15. ما لا نريد الحصول عليه

لا نريد أن يتحول المشروع إلى:

- Arbitrary host shell.
- Exploit runner.
- Credential dumper.
- Malware deployment framework.
- Reverse shell controller.
- Remote scanner غير مقيد.
- أداة تجاوز مصادقة.
- أداة Persistence خارج النطاق.
- نموذج يغير صلاحياته من خلال Prompt.
- نموذج يقرأ الأسرار من البيئة.
- Corpus خارجي يصبح Policy تلقائيًا.
- Tool Schema يمكن للنموذج تعديله أثناء المحادثة.
- Tool Call Native يمر دون Validation.
- Provider يعلن عن نفسه أنه authorized ويتم تصديقه.
- Streaming يسرب Chain-of-thought أو Secrets.
- نظام يعلن نجاحًا لم يحدث.
- نظام يعرض ثقة عالية دون Evidence.
- Reasoning Memory قابلة للتعديل بلا سجل.
- دمج Provider غير منفذ فعليًا تحت اسم integration complete.

---

## 16. خارطة الطريق القادمة

### المرحلة 3 — Agent Context Engine

إنشاء:

```text
agent/context.py
```

ليجمع:

```text
System Instructions
Owner Policy
Current User Message
Conversation History
Relevant Memory
Relevant Knowledge
Available Tools
Previous Tool Results
Current Execution State
Provider Context
```

المطلوب:

- عدم إدخال `OWNER_TOKEN` أو `BRIDGE_TOKEN` أو API secrets.
- تقليص Context بسياسة واضحة.
- ترتيب الرسائل حسب relevance وrecency وprovenance.
- منع Tool Results الخارجية من تعديل System أو Owner Policy.
- اختبار Provider تجريبي يبحث عن الأسرار داخل Prompt ويثبت عدم ظهورها.

### المرحلة 4 — Tool Orchestration

تطوير Registry إلى منصة أدوات كاملة مع lifecycle events:

```text
discovered
selected
validated
authorized
started
progress
completed
failed
cancelled
```

ويجب أن تظهر هذه الأحداث في Evidence وفي Structured Streaming.

### المرحلة 5 — Search Layer

إنشاء:

```text
search/
```

مع `SearchProvider` موحد ومصادر قابلة للإضافة:

```text
Web
Local Knowledge
Files
GitHub
CVE/NVD
MITRE
Threat Intelligence
```

كل نتيجة يجب أن تحمل:

```text
source
url/reference
retrieved_at
content_hash
provenance
```

### المرحلة 6 — External Integrations

إنشاء:

```text
integrations/
```

والبدء بـ:

```text
GitHub
NVD
MITRE ATT&CK
Hugging Face
```

ثم إضافة VirusTotal وShodan وSIEM وEDR وCloud وThreat Intelligence adapters لاحقًا. لا تعد integration مكتملة ما لم يوجد adapter حقيقي واختبار حقيقي.

### المرحلة 7 — Files وAttachments

إضافة File Ingestion للأنواع:

```text
PDF
TXT
JSON
CSV
LOG
CODE
IMAGE
```

مع:

- Maximum size.
- Allowed MIME types.
- Timeout.
- Path traversal prevention.
- عدم تنفيذ الملفات.
- Quarantine للأنواع الخطرة.
- Content Hash.
- Provenance.
- Safe parsing.

### المرحلة 8 — Sandbox Execution

إنشاء طبقة منفصلة:

```text
execution/
```

مثل:

```text
SandboxExecutor
```

مع:

```text
CPU limit
memory limit
time limit
filesystem isolation
network policy
process limit
output limit
```

لا يجوز أن يحصل النموذج على Shell حر على المضيف.

### المرحلة 9 — Cyber Expert Core

تحويل Expert Modes إلى capabilities حقيقية داخل Agent:

```text
General Reasoning
Attacker Perspective
Defender Perspective
Threat Hunting
Incident Response
Detection Engineering
Vulnerability Analysis
Security Architecture
```

يجب أن تندمج هذه capabilities مع Evidence وCounter-evidence وAlternative Explanations وConfidence وLimitations.

### المرحلة 10 — Reasoning Quality

إضافة Validator يكشف:

```text
unsupported_claim
missing_evidence
contradiction
invented_source
invented_tool_result
confidence_mismatch
premature_conclusion
correlation_as_causation
```

وربطه بـTeacher/Critic وBenchmark Gate.

### المرحلة 11 — Memory Architecture

إنشاء طبقات مستقلة:

```text
memory/conversation
memory/semantic
memory/reasoning
memory/execution
memory/preferences
```

مع بقاء Owner Policy خارج الذاكرة القابلة لتعديل النموذج.

### المرحلة 12 — Long-running Tasks

إنشاء Task Manager:

```text
queued
running
progress
completed
failed
cancelled
paused
```

مع:

```text
pause
cancel
resume
retry
```

وحفظ الحالة بحيث يستطيع المستخدم إغلاق الواجهة والعودة لاحقًا.

### المرحلة 13 — Real Streaming

توسيع SSE إلى Structured Events:

```text
conversation.started
assistant.started
assistant.delta
tool.selected
tool.started
tool.progress
tool.completed
evidence.added
reasoning.updated
assistant.completed
task.failed
task.cancelled
```

يجب ألا تتضمن هذه الأحداث Chain-of-thought أو Secrets أو Authorization internals.

### المرحلة 14 — Professional Chat UI

إضافة:

```text
Conversation list
New conversation
Message composer
Streaming
Markdown
Code blocks
Tables
Attachments
Tool activity
Sources
Execution status
Cancel
Retry
Copy
Export
```

ويجب عرض نشاط مفهوم للمستخدم مثل:

```text
Searching security sources
8 sources reviewed
Running local analysis
Analysis completed
Reviewing evidence
3 relevant findings
```

بدل أسماء Python functions أو internal registry calls.

### المرحلة 15 — Android Client

بعد استقرار API:

```text
Android
    ↓
Authenticated API
    ↓
Agent Gateway
    ↓
Agent Runtime
```

لا يتصل Android مباشرة بالأدوات. يدعم لاحقًا Chat وAttachments وHistory وTool Activity وTask Status وCancel.

---

## 17. طريقة متابعة المشروع لمن يأتي بعدنا

### 17.1 قراءة الحالة أولًا

يجب عدم بدء العمل من ملف كود واحد. ابدأ بـ:

```bash
git fetch --all --prune
git branch -a
git log --all --oneline --decorate -12
git status --short --branch
```

### 17.2 ترتيب PRs

الترتيب المقترح:

```text
main
  ↓
PR #10 — feature/agent-runtime-2.0
  ↓
PR #11 — feature/native-tool-calling
  ↓
Phase 3 Context Engine
  ↓
Phase 4 Tool Orchestration
  ↓
Phase 5 Search Layer
```

لا تدمج PR #11 قبل مراجعة أن قاعدة PR هي Phase 1 أو بعد دمج Phase 1 بالطريقة التي يختارها Owner.

### 17.3 Baseline قبل كل مرحلة

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m compileall -q .
pytest -q
git diff --check
```

### 17.4 مسار تنفيذ أي Feature جديدة

```text
Owner Requirement
    ↓
Threat Model
    ↓
Data Contract
    ↓
Authorization Boundary
    ↓
Implementation
    ↓
Negative Tests
    ↓
Compile + Pytest
    ↓
Smoke Test
    ↓
Secret Scan
    ↓
Review
    ↓
Separate PR
    ↓
Owner Decision
```

### 17.5 قواعد لا يجوز كسرها

يجب أن يحافظ أي عمل لاحق على:

- Owner أعلى سلطة تطبيقية.
- Owner هو كاتب Policy ومالك النموذج.
- External Content ليس Policy.
- Model Output ليس Execution Authority.
- Bridge Authentication منفصلة عن Owner Authentication.
- Tool Registry هو Capability Boundary الوحيد.
- Authorization حتمية خارج النموذج.
- Plan Hash قبل التنفيذ.
- Evidence Chain قابلة للتحقق.
- Lifecycle صادق في النجاح والفشل والإلغاء.
- Reasoning Memory محمية.
- Runtime Limits مستقلة عن النموذج.
- Native Tool Calls ليست Trusted تلقائيًا.
- Provider Metadata لا تمنح صلاحيات.
- Secrets لا تدخل Context.
- لا fake integrations في التوثيق.
- لا يتم إضافة أدوات هجومية نشطة أو تنفيذ Host Shell عشوائي ضمن هذا المسار الدفاعي.

---

## 18. القرار التصميمي النهائي

CyberSentinel X ليس مشروعًا هدفه جعل النموذج أكثر عدوانية أو إعطاءه سيطرة مباشرة على الجهاز. هو مشروع هدفه جعل الوكيل:

```text
أكثر فهمًا
أكثر انضباطًا
أكثر صدقًا
أكثر اعتمادًا على الأدلة
أكثر قابلية للتدقيق
```

الـOwner، باعتباره **مالك النموذج ومالك التشغيل ومالك السياسة**، يكتب القواعد ويحدد ما يريده وما لا يريده. Manus ينفذ التطوير الهندسي الذي يطلبه Owner. الخبير الأمني الآخر يراجع ويقترح ويكشف المخاطر. النموذج يحلل ويقترح. المعرفة الخارجية تقدم أدلة. Registry وAuthorization وLifecycle وEvidence تمنع انتقال النص أو المعرفة إلى تنفيذ غير مقصود.

تعريف النجاح النهائي هو:

> **وكيل CyberSentinel يفهم الأسئلة الأمنية، يبحث عن الأدلة، يستخدم الأدوات المصرح بها، يطلب المعلومات الناقصة، يميز بين الحقيقة والفرضية، يشرح سبب استنتاجه، يحتفظ بسياقه، ويتعلم من أخطائه عبر Critic وBenchmark، مع بقاء Owner مالك النموذج وكاتب السياسة وصاحب أعلى سلطة تطبيقية فوق النموذج والأدوات والبيانات والمصادر الخارجية.**

---

## المراجع

[1]: https://github.com/mosfiry/cybersentinel "CyberSentinel X source repository"

[2]: https://github.com/mosfiry/cybersentinel/pull/10 "PR #10 — Upgrade Agent Loop to policy-bounded Runtime 2.0"

[3]: https://github.com/mosfiry/cybersentinel/pull/11 "PR #11 — Add native tool calling provider abstraction"

[4]: https://attack.mitre.org/ "MITRE ATT&CK knowledge base"

[5]: https://nvd.nist.gov/developers/vulnerabilities "National Vulnerability Database developer documentation"

[6]: https://www.cve.org/Downloads "CVE Program downloads and data resources"

[7]: https://cwe.mitre.org/ "MITRE Common Weakness Enumeration"

[8]: https://github.com/SigmaHQ/sigma "Sigma generic signature format"

[9]: https://github.com/VirusTotal/yara "YARA pattern-matching tool"

[10]: https://suricata.io/ "Suricata open-source threat detection engine"

[11]: https://huggingface.co/datasets "Hugging Face datasets platform"

[12]: https://github.com/github/securitylab "GitHub Security Lab"
