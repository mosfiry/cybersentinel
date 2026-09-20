# تقرير التسليم الفني الكامل لمشروع CyberSentinel X

**الإصدار الحالي:** 4.9.0  
**الفرع المرجعي:** `main`  
**آخر Commit:** `5e478b47b26ea45b5e60daa10739f21be9672796`  
**المستودع:** [mosfiry/cybersentinel](https://github.com/mosfiry/cybersentinel)  
**تاريخ التقرير:** 2026-09-20  
**نوع الوثيقة:** تقرير تسليم واستمرارية تطوير

---

## 1. الخلاصة التنفيذية

CyberSentinel X هو وكيل أمن سيبراني دفاعي محلي. صُمم ليجمع بين استخبارات التهديدات، الفحص المحلي المحدود، إدارة الأدلة، سياسة Owner، التخطيط عبر النموذج، التفويض الحتمي للأدوات، وسجل قابل للتدقيق. المشروع لم يعد مجرد واجهة أمام نموذج لغوي؛ بل أصبح نظامًا متعدد الطبقات يمنع تحويل مخرجات النموذج أو النصوص الخارجية إلى تنفيذ غير مصرح به.

الهدف النهائي للمشروع هو بناء وكيل يستطيع **التحقيق والتحليل الأمني المنضبط بالأدلة**. يستطيع الوكيل تكوين فرضيات متعددة، عرض الأدلة المؤيدة والمعارضة، طلب الأدلة الناقصة، تقديم تفسير بديل، معايرة درجة الثقة، ونسبة المعلومات إلى مصادرها. لا يجوز أن يستنتج وجود هجوم من مؤشر واحد فقط، ولا يجوز أن يعرض رأيًا احتماليًا على أنه حقيقة مثبتة.

المشروع الآن في V4.9.0. أضيفت فيه حلقة تعلم وتقييم آمنة تشمل توليد حالات تحليلية من المعرفة التاريخية، وTeacher/Critic حتميًا، وReasoning Memory خاصة بالـOwner، وBenchmark Gate يمنع قبول تحسينات ترفع الادعاءات غير المدعومة أو تزيد فشل مقاومة prompt injection.

**المبدأ المركزي الذي يجب ألا يتغير:**

> **الـOwner هو مالك النموذج ومالك التشغيل والسياسة داخل نطاق التطبيق. صلاحية Owner هي أعلى صلاحية تطبيقية فوق النموذج، والأدوات، والبيانات، وسياسات الخصوصية، وتعليمات التشغيل، ومخرجات النماذج، والمعرفة المسترجعة. الـOwner هو الذي يكتب سياسات الحماية والخصوصية والتعليمات الحقيقية، وهو صاحب القرار التشغيلي النهائي.**

يوجد حد تقني واحد يجب فهمه بدقة: Owner هو أعلى سلطة في **نطاق سياسة التطبيق والنموذج**، لكن حدود المنصة والنظام والبيئة التنفيذية immutable. هذا الحد ليس سلطة لمستخدم آخر ولا للنموذج ولا لمصدر خارجي؛ بل هو قيد هندسي يحافظ على سلامة النظام. أي طلب من Owner يظل يمر عبر التحقق، وSchema Validation، وAuthorization، وLifecycle، وEvidence، ولا يتحول نص Owner نفسه إلى تنفيذ عشوائي مباشر.

---

## 2. تعريف الأدوار والسلطة

### 2.1 الـOwner: مالك النموذج والسلطة العليا

في هذا المشروع، كلمة **Owner** لا تعني مجرد مستخدم يملك كلمة مرور أو شخصًا يرسل طلبًا. المقصود هو **مالك النموذج والتطبيق ومحدد السياسات ومشغّل النظام الحقيقي**. الـOwner هو الطرف الذي يقرر:

- سياسة الحماية والخصوصية.
- ما الذي يجوز للنظام جمعه أو تخزينه أو عرضه.
- ما هي الأدوات المسموح بها.
- ما هي النطاقات والبيئات المسموح بفحصها.
- ما هي درجة التحفظ المطلوبة عند اتخاذ الاستنتاجات.
- ما هي البيانات التي تعتبر حساسة.
- كيف تُدار الذاكرة والأدلة.
- كيف تتم مراجعة النموذج وتقييمه.
- ما هي الأولويات عند تعارض تعليمات سابقة.

في حال تعارض تعليمات Owner حديثة مع تعليمات Owner سابقة، تكون التعليمات الأحدث هي السياسة الحالية ضمن النطاق الذي تنطبق عليه. أما النموذج فلا يستطيع تعديل Owner Policy، ولا يستطيع منح نفسه صلاحية، ولا يستطيع جعل بيانات خارجية أعلى من Owner.

المصادقة التقنية للـOwner تتم من خلال `OWNER_TOKEN`. كلمة `Owner` داخل النص ليست وسيلة مصادقة. أما `BRIDGE_TOKEN` فهو لمصادقة قناة HTTP المحلية فقط. لا يوجد fallback بين الرمزين.

### 2.2 Manus

Manus هو المنفذ الهندسي والمساعد المسؤول عن تنفيذ التغييرات التي يطلبها الـOwner. دوره يشمل قراءة المستودع، تحليل الكود، تنفيذ التطوير، إضافة الاختبارات، تشغيل التحقق، إنشاء الفروع والـPull Requests، ودمج التغييرات عند وجود تفويض واضح.

Manus ليس مالكًا للنموذج، ولا يكتب سياسة المشروع من نفسه، ولا يستطيع تغيير أولوية Owner. Manus يقدم اقتراحات هندسية وتحذيرات أمنية، لكن القرار التشغيلي والسياساتي يعود إلى Owner.

### 2.3 الخبير الأمني الآخر

الخبير الأمني الآخر هو دور استشاري وتحليلي. مهمته مراجعة المخاطر، اقتراح بنية أكثر صلابة، تحديد الاختبارات السلبية، فحص حدود الأدوات، تحليل الحوادث التاريخية، وتحديد الأدلة الناقصة.

لا يملك الخبير الأمني الآخر سلطة Owner. توصياته ليست سياسة تلقائية، ولا يستطيع تحويل مخرج النموذج إلى أمر تنفيذ. توصيته تدخل مسار التقييم، ثم يقرر Owner ما إذا كانت ستصبح سياسة أو تغييرًا في الكود.

### 2.4 النموذج اللغوي

النموذج اللغوي Planner فقط. يمكنه اقتراح خطة منظمة ضمن Schema مغلق، لكنه لا ينفذ الأدوات، ولا يصرح لنفسه، ولا ينشئ Handler جديدًا، ولا يقرر أن النص الخارجي أصبح سياسة، ولا يغير Owner Policy.

التنفيذ الحقيقي يتم من خلال Python deterministic authorization وTool Registry، وليس من خلال إرادة النموذج.

### 2.5 المعرفة والمصادر الخارجية

المعرفة المسترجعة من ATT&CK وCVE وCWE وSigma وYARA وSuricata وGitHub وHugging Face وتقارير الحوادث هي **مرجع أو دليل** فقط. وجود المعلومة في مصدر خارجي لا يجعلها أمرًا، ولا يرفعها إلى مستوى Owner Policy، ولا يسمح لها بتشغيل أداة.

---

## 3. الخط الزمني للإصدارات

| الإصدار | Commit مختصر | النتيجة الرئيسية |
|---|---|---|
| V4.2 | `cc3e311` | استيراد مشروع CyberSentinel X الأساسي ذي Owner Policy. |
| V4.3 | `affa4aa` | اعتماد `AgentRuntime` و`ModelRouter`، فصل `BRIDGE_TOKEN` عن `OWNER_TOKEN`، وإضافة provenance و`request_id`. |
| V4.4 | `b84b8ad` | إنشاء Tool Registry موحد، Schemas لكل أداة، ExecutionContext، وسلسلة Evidence. |
| V4.5 | `ee891df` | Plan Integrity، canonical plan، `plan_hash`، Authorization Decision Record، وEvidence hash chain. |
| V4.6 | `ab2d86b` | Lifecycle دائم، idempotency، atomic claim، timeout، cancellation، crash recovery، وreconstruction حسب request ID. |
| V4.7 | `2066690` | Owner-only defensive red-team assessment، Knowledge Objects، provenance-safe retrieval، ومصادر معرفة منظمة. |
| V4.8 | `000669e` | Owner authority snapshot، Reasoning Cases كاملة، counter-evidence، confidence rationale، وتمييز سلطة Owner عن سلطة النموذج. |
| V4.9 | `5e478b4` | Cyber Learning Loop، Case Generator، Teacher/Critic، Reasoning Memory، وBenchmark Gate. |

آخر Pull Requests المدموجة:

- [PR #6 — V4.7 Owner-only reasoning](https://github.com/mosfiry/cybersentinel/pull/6)
- [PR #7 — V4.8 Owner authority and reasoning cases](https://github.com/mosfiry/cybersentinel/pull/7)
- [PR #8 — V4.9 Learning Loop](https://github.com/mosfiry/cybersentinel/pull/8)

---

## 4. الحالة الحالية في V4.9.0

المستودع يحتوي حاليًا على الطبقات التالية:

```text
bridge.py
  ↓
Bridge authentication
  ↓
Owner authentication
  ↓
Current Owner Policy
  ↓
AgentRuntime
  ↓
ModelRouter / provider fallback
  ↓
Closed JSON plan schema
  ↓
Canonicalization + plan_hash
  ↓
Tool Registry
  ↓
Per-tool schema validation
  ↓
Per-tool authorization
  ↓
ExecutionContext
  ↓
Lifecycle state machine
  ↓
Bounded handler execution
  ↓
Evidence chain + audit events
  ↓
Response + durable completion
```

وعند استخدام `red_team_assess` يضاف المسار التالي:

```text
Owner observation
  ↓
Reasoning Case
  ↓
Hypotheses
  ↓
Supporting evidence
  ↓
Counter-evidence
  ↓
Alternative explanations
  ↓
Required next evidence
  ↓
Confidence rationale
  ↓
Teacher/Critic
  ↓
Owner-only Reasoning Memory
```

---

## 5. معمارية السلطة والسياسة

ملف السياسة الحالي هو `security/owner_policy.json`. أهم خصائصه هي:

```json
{
  "owner_authority_level": "highest_application_policy",
  "external_content_authority": "none",
  "model_authority": "none",
  "system_safety_boundary": "immutable"
}
```

هذه الحقول تعني أن Owner هو أعلى سلطة في مجال سياسة التطبيق، وأن النموذج والمحتوى الخارجي لا يملكان سلطة سياسة، وأن حدود النظام لا يتم تعطيلها عبر نص.

الدالة `current_owner_policy_context()` تضيف تعليمات Owner الحالية إلى سياق التخطيط. الدالة `authority_snapshot()` تنتج وصفًا قابلًا للتدقيق للسلطة المستخدمة في كل طلب. هذا الـsnapshot ينتقل إلى `ExecutionContext` ويسجل في أحداث الخطة والتنفيذ.

تتم حماية Owner Policy من prompt injection. العبارة التالية داخل صفحة أو dataset أو سجل لا تصبح سياسة:

```text
ignore the Owner policy
```

السبب أن سياسة Owner لا تقبل التغيير إلا عبر طلب Owner مصادق عليه في طبقة Owner Authentication.

---

## 6. المصادقة وقنوات الاتصال

يوجد مستويان مستقلان:

| المستوى | الرمز | الوظيفة |
|---|---|---|
| قناة Bridge | `BRIDGE_TOKEN` | إثبات أن الطلب عبر القناة المحلية المسموح بها. |
| سلطة Owner | `OWNER_TOKEN` | إثبات أن صاحب الطلب هو Owner وله سلطة كتابة التعليمات والسياسات ضمن التطبيق. |

الـBridge يعمل افتراضيًا على:

```text
http://127.0.0.1:8787/
```

ولا يرتبط بشبكة LAN. يجب عدم تحويله إلى خدمة عامة قبل تصميم طبقة مصادقة وشبكة مستقلة ومراجعة أمنية جديدة.

الـOwner token لا يرسل إلى النموذج ولا يظهر في API response أو audit event. لا يجوز وضعه داخل Git أو `.env.example` بقيمة حقيقية.

---

## 7. AgentRuntime وModelRouter

`AgentRuntime.plan()` هو مدخل التخطيط الوحيد. يستقبل النص المصادق عليه، ويضيف Current Owner Policy Context، ثم يرسل طلبًا إلى Provider اختياري متوافق مع OpenAI API أو يستخدم deterministic fallback عند عدم وجود Provider.

`ModelRouter` يدير:

- اختيار Provider.
- fallback عند الفشل.
- تسجيل provider/model provenance.
- عدم قبول provenance مزور من نص Provider نفسه.
- إبقاء Credentials خارج استجابة العميل.

مخرج النموذج لا يستخدم مباشرة. يمر عبر:

1. JSON extraction.
2. Closed schema validation.
3. رفض الحقول غير المعروفة.
4. التحقق من أسماء الأدوات.
5. التحقق من نوع arguments.
6. الحد الأقصى لطول الوسيط.
7. الحد الأقصى لحجم الخطة.
8. Authorization حتمي خارج النموذج.

إذا فشل Provider أو أعاد JSON غير صالح، يعمل fallback الدفاعي المحلي. لا يعني ذلك أن النموذج حصل على صلاحية إضافية؛ بل يعني أن الخطة الحتمية هي التي تستخدم.

---

## 8. Tool Registry والأدوات الحالية

`tools/registry.py` هو المصدر الموحد لتعريف الأدوات. كل `ToolSpec` يحتوي على الاسم والوصف وRisk Class وOwner requirement ونوع argument وhandler، مع `owner_only` عند الحاجة.

الأدوات الحالية هي:

| الأداة | الوظيفة | التصنيف |
|---|---|---|
| `status` | قراءة حالة الخدمة وسجل الأحداث الأخير. | `read` |
| `latest_intel` | قراءة آخر استخبارات تهديد محلية. | `read` |
| `refresh_intel` | جمع استخبارات دفاعية. | `network-read` |
| `local_security_check` | قراءة TCP listeners المحلية. | `read` |
| `local_system_info` | قراءة معلومات النظام. | `read` |
| `search` | البحث في الأحداث والاستخبارات المحلية. | `read` |
| `watch` | إضافة كلمة مراقبة محلية. | `state-write` |
| `unwatch` | إزالة كلمة مراقبة محلية. | `state-write` |
| `run_project_tests` | تشغيل `pytest -q` فقط داخل `CYBERSENTINEL_TEST_ROOT`. | `bounded-exec` |
| `red_team_assess` | تحليل دفاعي Owner-only بلا exploit أو shell. | `analysis` |

تمت حماية Registry من duplicate names، وhandler غير صالح، وrisk class غير صحيح، وschema مفقود، و`owner_only` بلا `requires_owner`.

`run_project_tests` ليس shell عامًا. الأمر ثابت، والمسار محصور داخل root، ولا يستطيع النموذج تغيير الأمر أو تمرير shell flags أو الخروج من المسار المحدد.

`red_team_assess` لا ينفذ scanning أو exploitation أو credential access أو persistence أو malware deployment. وظيفته بناء تحليل واحتمالات وأدلة ناقصة.

---

## 9. Plan Integrity وAuthorization

قبل التنفيذ، يتم تحويل الخطة إلى public canonical form ثم حساب:

```text
plan_hash = SHA-256(canonical_plan)
```

يتم حفظ `plan_hash` في Lifecycle وAudit وEvidence. قبل كل handler call يعاد حساب hash للتأكد من أن الخطة لم تتغير بين validation والتنفيذ.

كل قرار تفويض يتضمن:

```text
tool
risk_class
owner_required
owner_authenticated
policy_version
decision
reason
plan_hash
```

المعنى الأمني هو أن النموذج يقترح، لكن Registry وAuthorization هما اللذان يقرران. لا يستطيع النموذج كتابة `allow=true` داخل الخطة والتغلب على Python authorization.

---

## 10. ExecutionContext وEvidence Chain

`ExecutionContext` الموحد يحمل:

- `request_id`.
- هوية Owner المصادق عليها.
- Policy fingerprint.
- Provider وmodel provenance.
- Owner authority snapshot.

كل Evidence يحمل:

- request ID.
- chain identifiers.
- sequence.
- previous hash.
- current hash.
- المصدر.
- النتيجة.
- تقييم severity أو confidence.

السلسلة المنطقية هي:

```text
request
  → authentication
  → policy
  → plan
  → authorization
  → execution
  → evidence
  → response
```

تسمح هذه السلسلة بالإجابة عن الأسئلة التالية:

- من أرسل الطلب؟
- هل كان Owner مصادقًا؟
- ما Policy fingerprint؟
- أي Provider/model اقترح الخطة؟
- ما الأدوات التي تم تفويضها؟
- ما arguments التي مرت بالـSchema؟
- ما نتيجة التنفيذ؟
- هل حدث timeout أو cancellation أو failure؟
- هل تغيرت Evidence بعد تسجيلها؟

---

## 11. Lifecycle وIdempotency وRecovery

لكل طلب `request_id` وسجل دائم في SQLite. الحالات الأساسية هي:

```text
created
planned
validated
authorized
executing
succeeded / failed
completed
```

تم تنفيذ:

- Atomic claim لمنع تشغيل طلبين متزامنين بنفس ID.
- Replay للطلب المكتمل بدل تشغيله مرة ثانية.
- Transition validation لمنع انتقالات غير منطقية.
- Timeout مستقل لكل Tool.
- Cooperative cancellation عند حدود الأدوات.
- تسجيل cancellation كفشل أو توقف، لا كنجاح.
- Crash recovery للطلبات العالقة.
- Reconstruction حسب `/api/execution/<request_id>`.

القاعدة المهمة هي أن النظام لا يسجل النجاح إذا لم ينفذ الأداة فعليًا، ولا يخفي الفشل خلف رسالة نجاح.

---

## 12. Knowledge Layer ومصادر الأمن السيبراني

أنشئت طبقة Knowledge Objects موحدة تحتوي على provenance وsource type وcontent hash وmappings وconfidence وevidence.

مصدر خارجي لا يدخل مباشرة إلى النظام. المسار الصحيح هو:

```text
Dataset / Repository / Advisory
  ↓
Revision pin
  ↓
File inspection
  ↓
License check
  ↓
Secret and PII scan
  ↓
Prompt-injection / poisoning scan
  ↓
Quality assessment
  ↓
Normalization
  ↓
Retrieval
```

المصادر المرجعية المحتملة تشمل MITRE ATT&CK وNVD وCVE وCWE وSigma وYARA وSuricata وتقارير الحوادث وSecurity Advisories. يجب الاحتفاظ بترخيص كل مصدر وإصداره وhash الخاص بالملف، لأن وجود المادة على GitHub أو Hugging Face لا يعني تلقائيًا أن استخدامها التدريبي مسموح.

المحتوى الهجومي أو PoC أو archives أو notebooks أو pickle/model loaders لا يتحول تلقائيًا إلى system policy أو executable tool. يتم عزله أو رفضه أو تحويله إلى ملاحظة تحليلية منزوعة التنفيذ عند الحاجة.

---

## 13. V4.8 Reasoning Cases

الحالة التحليلية ليست مقالًا ولا إجابة نهائية محفوظة. تحتوي على:

```text
case_id
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

عند وصول ملاحظة مثل:

```text
php-fpm -> sh -> curl during deployment
```

لا يسمح النظام بقول “هذا اختراق” تلقائيًا. يضع فرضيات مثل:

- Compromised web application.
- Legitimate deployment script.
- Unexpected command execution.

ثم يطلب process tree وcommand line وHTTP timeline وdeployment logs وdestination reputation وfile changes. إذا ظهر في الملاحظة أن النشاط مرتبط بـdeployment، يسجل ذلك كـcounter-evidence يحتاج تحققًا بدل تجاهله.

يتم حساب `case_id` بشكل deterministic من المحتوى المنظم، ولا يتم اختراع evidence غير موجودة في observation أو retrieval.

---

## 14. V4.9 Cyber Learning Loop

حلقة التعلم الحالية ليست fine-tuning تلقائيًا. هي حلقة تقييم وتحسين قابلة للمراجعة:

```text
Knowledge / historical incident
  ↓
Case Generator
  ↓
CyberSentinel analysis
  ↓
Teacher / Critic
  ↓
Reasoning Memory
  ↓
Benchmark Gate
  ↓
Regression comparison
```

### 14.1 Case Generator

`reasoning/case_generator.py` يحول Knowledge Object إلى Reasoning Case. يخفض الثقة عندما تكون الحالة مستخرجة من مصدر مرجعي، ويضيف limitations توضح أن المصدر لا يثبت أن النشاط خبيث.

### 14.2 Teacher/Critic

`evaluation/critic.py` ينتج تقريرًا حتميًا عن جودة الاستدلال. يفحص missing evidence وpoor confidence وbad alternatives وmapping errors وignored counter-evidence. لاحقًا يجب توسيعه ليكشف بصورة أدق unsupported claims وpremature conclusions وsource errors.

### 14.3 Reasoning Memory

تخزن SQLite case وcritic report لكل `request_id` خاص بـ`red_team_assess`. endpoint:

```text
GET /api/reasoning/<request_id>
```

يتطلب Bridge token وOwner token معًا. هذا يسمح بالإجابة عن “لماذا استنتج الوكيل ذلك؟” من سجل حقيقي وليس من تفسير لاحق مخترع.

### 14.4 Benchmark Gate

`evaluation/gate.py` يقارن baseline مع candidate. لا يمر التحسين إذا زادت unsupported claims أو prompt-injection failures، أو انخفض evidence usage.

المقارنة المطلوبة مستقبلًا تكون بين:

```text
A = Base Model
B = Base Model + Cyber RAG
C = Base Model + Cyber RAG + Reasoning Cases
```

وتستخدم الحالات المخفية نفسها. لا تُقبل زيادة accuracy إذا كانت مصحوبة بزيادة الادعاءات غير المدعومة.

---

## 15. الاختبارات والنتيجة الحالية

تم تنفيذ والتحقق من:

```text
python3 -m compileall -q .
python3 -m pytest -q
```

النتيجة الحالية:

```text
29 passed in 0.57s
```

تشمل الاختبارات:

- فصل Bridge token عن Owner token.
- رفض Owner authentication عند غياب الرمز.
- Planner schema وprovider fallback.
- Tool Registry integrity.
- Unknown tools وinvalid arguments.
- Plan integrity وtamper detection.
- Evidence chain وprevious/current hashes.
- Lifecycle وidempotency وconcurrency.
- Cancellation وtimeout وcrash recovery.
- Owner-only red-team assessment.
- Knowledge poisoning وprompt-injection fields.
- Case generation من knowledge reference.
- Critic findings.
- Benchmark gate regression.

كما نجح HTTP smoke test لـV4.9:

- Owner يستطيع قراءة Reasoning Memory ويحصل على `200`.
- غير Owner يحصل على `403`.
- الذاكرة تحتوي case وcritic report.
- لا توجد secrets أو databases أو runtime state متتبعة في Git.
- لا توجد executable attack handlers داخل Registry.

---

## 16. طريقة التشغيل المحلي

```bash
git clone https://github.com/mosfiry/cybersentinel.git
cd cybersentinel
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
```

يجب إنشاء قيمتين مختلفتين وعشوائيتين:

```dotenv
BRIDGE_TOKEN=<random bridge secret>
OWNER_TOKEN=<different random owner secret>
```

ثم:

```bash
python -m compileall -q .
pytest -q
python bridge.py
```

يفتح المستخدم:

```text
http://127.0.0.1:8787/
```

لا يجوز استخدام نفس القيمة للرمزين. لا يجوز وضع قيم حقيقية في `.env.example` أو Git. إذا تم تشغيل Provider خارجي، يجب تقييد endpoint والتأكد من عدم إرسال Owner token أو أسرار النظام إلى النموذج.

---

## 17. ما نريد الحصول عليه في النهاية

النتيجة المطلوبة ليست وكيلًا هجوميًا. النتيجة المطلوبة هي CyberSentinel يمتلك القدرات التالية:

1. يفهم الحوادث والهجمات التاريخية كحالات تحليل، لا كأوامر تنفيذ.
2. يميز بين correlation وcausation.
3. لا يستنتج من indicator واحد.
4. يعرض فرضيات متعددة.
5. يبحث عن evidence مؤيدة ومعارضة.
6. يقدم تفسيرًا benign بديلًا عند وجوده.
7. يطلب الدليل الناقص.
8. يعاير confidence.
9. ينسب المعلومات إلى مصادرها وhashes وإصداراتها.
10. يقاوم prompt injection وdata poisoning.
11. يشرح سبب الاستنتاج من سجل Reasoning فعلي.
12. يحافظ على Owner فوق كل مصادر المعرفة والنموذج والأدوات.
13. ينفذ أدوات دفاعية محدودة فقط عبر Registry وAuthorization.
14. يمنع النموذج من إنشاء أدوات أو تعديل الصلاحيات.
15. يحتفظ بدليل قابل للتدقيق لكل طلب.
16. يتعلم من أخطائه عبر benchmark وcritic، لا عبر حفظ إجابات غير مفهومة.

---

## 18. ما لا نريد الحصول عليه

لا نريد أن يتحول CyberSentinel إلى:

- Exploit runner.
- Credential dumper.
- Malware deployment framework.
- Arbitrary shell agent.
- Reverse shell controller.
- Remote scanner غير مقيد.
- أداة تجاوز مصادقة.
- أداة persistence على أنظمة خارج النطاق.
- نموذج يتعلم تنفيذ attack payloads من corpus غير موثوق.
- نموذج يمنح نفسه صلاحية بحجة أن الطلب من Owner داخل نص غير مصادق.
- نظام يخلط بين knowledge وpolicy.
- نظام يعلن نجاحًا لم يحدث.
- نظام يحفظ تفسيرًا بعديًا لا يستند إلى reasoning record حقيقي.

صلاحية Owner تعني أن Owner هو صاحب القرار الأعلى في **ما يسمح به التطبيق**، لا أن النصوص المسترجعة أو النموذج يستطيعان تزويد النظام بقدرة تنفيذية غير موجودة في الكود.

---

## 19. خارطة الطريق التالية

### المرحلة A: إكمال Benchmark الحقيقي

يجب إنشاء benchmark مخفي يتضمن حالات benign وmalicious وambiguous. يجب قياس evidence usage وunsupported claims وcounter-evidence وalternative quality وconfidence calibration وsource attribution وprompt-injection resistance.

### المرحلة B: توسيع Teacher/Critic

يجب إضافة كشف حقيقي لـ:

- unsupported claims.
- premature conclusion.
- source error.
- mapping error.
- ignored counter-evidence.
- hallucinated evidence.
- correlation presented as causation.

ويجب أن تكون تقارير Critic نفسها قابلة للتدقيق وليست ناتجة عن حكم غير قابل للتفسير.

### المرحلة C: تحسين Reasoning Memory

ينبغي إضافة versioning للحالة، وربط كل تحديث بـOwner instruction وpolicy fingerprint وknowledge hashes. يجب منع تعديل memory التاريخية دون سجل تصحيح واضح.

### المرحلة D: Dataset Governance

قبل تحميل أي Dataset يجب تثبيت revision، حفظ license، فحص secrets وPII، فحص poisoning، فحص الملفات التنفيذية، وتصنيف المادة إلى defensive أو synthetic أو offensive أو license-uncertain. لا ينتقل أي مصدر مباشرة إلى fine-tuning.

### المرحلة E: مقارنة النماذج

تتم مقارنة Base Model وBase+RAG وBase+RAG+Reasoning Cases على benchmark ثابت. لا يبدأ LoRA أو fine-tuning قبل إثبات أن التحسين لا يرفع unsupported claims ولا يقلل calibration.

### المرحلة F: تقوية Owner Authority

ينبغي لاحقًا استبدال token طويل الأجل بآلية أقوى، مثل key-based authentication أو local OS identity أو hardware-backed secret، مع rotation وrevocation وسجل Owner policy changes. يجب أيضًا إضافة اختبار يمنع forged Owner identity في كل endpoint حساس.

### المرحلة G: الإنتاج

قبل أي تشغيل خارج localhost يجب إضافة TLS أو reverse proxy موثوق، network ACL، rate limiting، secret manager، backup مشفر، log retention policy، وincident response procedure. لا ينبغي نشر الجسر كما هو على الإنترنت.

---

## 20. قواعد الاستمرارية لمن يكمل المشروع

الشخص أو الوكيل الذي سيكمل التطوير يجب أن يبدأ دائمًا من `origin/main` ويتحقق من النسخة والاختبارات قبل تعديل الكود:

```bash
git fetch origin main
git checkout -B main origin/main
python3 -m compileall -q .
python3 -m pytest -q
```

يجب عدم إعادة بناء الطبقات التي تم تثبيتها. أي تغيير جديد يجب أن يحافظ على:

- Owner أعلى سلطة تطبيقية.
- عدم قبول External Content كسياسة.
- عدم قبول Model Output كتنفيذ.
- الفصل بين Bridge Authentication وOwner Authentication.
- Tool Registry كممر وحيد للأدوات.
- Authorization حتمي خارج النموذج.
- plan hash قبل التنفيذ.
- Evidence chain قابلة للتحقق.
- Lifecycle صادق في النجاح والفشل والتوقف.
- Reasoning Memory محمية بالـOwner.
- Benchmark Gate يمنع التحسينات الوهمية.
- عدم إضافة active attack tooling دون قرار جديد صريح من Owner ومراجعة أمنية مستقلة، وحتى عند وجود القرار يجب الالتزام بحدود النظام والمنصة والقانون.

أي feature جديدة يجب أن تمر بهذا المسار:

```text
Owner requirement
  ↓
Threat model
  ↓
Data contract
  ↓
Authorization boundary
  ↓
Implementation
  ↓
Negative tests
  ↓
Compile + pytest
  ↓
Smoke test
  ↓
Secret and sensitive-file scan
  ↓
Review
  ↓
Merge to main
```

---

## 21. قرار التصميم النهائي

CyberSentinel X ليس مشروعًا هدفه جعل النموذج “أكثر عدوانية”. هدفه جعله **أكثر فهمًا وانضباطًا وصدقًا وقابلية للتدقيق**.

الـOwner، باعتباره مالك النموذج ومالك التشغيل، يكتب السياسة ويحدد الخصوصية والحماية والتعليمات. Manus ينفذ التطوير الذي يطلبه Owner. الخبير الأمني الآخر يراجع ويقترح ويحذر. النموذج يحلل ويقترح. المعرفة الخارجية تقدم أدلة. Registry وAuthorization وLifecycle وEvidence هي التي تمنع الانزلاق من التحليل إلى التنفيذ غير المقصود.

وعليه فإن تعريف النجاح هو:

> **وكيل يفهم الهجمات ويحللها ويتعلم من أخطائه ويشرح أدلته، مع بقاء Owner مالك النموذج وصاحب السلطة العليا، وعدم امتلاك النموذج أو corpus أو أي مصدر خارجي قدرة على منح نفسه صلاحيات تنفيذية.**

---

## المراجع

[1]: https://github.com/mosfiry/cybersentinel "CyberSentinel X source repository"
[2]: https://attack.mitre.org/ "MITRE ATT&CK knowledge base"
[3]: https://nvd.nist.gov/developers/vulnerabilities "National Vulnerability Database developer documentation"
[4]: https://www.cve.org/Downloads "CVE Program downloads and data resources"
[5]: https://cwe.mitre.org/ "MITRE Common Weakness Enumeration"
[6]: https://github.com/SigmaHQ/sigma "Sigma generic signature format"
[7]: https://github.com/VirusTotal/yara "YARA pattern-matching tool"
[8]: https://suricata.io/ "Suricata open-source threat detection engine"
[9]: https://huggingface.co/datasets "Hugging Face datasets platform"
[10]: https://github.com/github/securitylab "GitHub Security Lab"
