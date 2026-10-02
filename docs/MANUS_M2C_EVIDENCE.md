# أدلة M2.c — ExternalEffectIntent على مخزن السلطة

## النتيجة وحدود checkpoint

أُضيفت إلى `MissionStore` واجهة داخلية لحفظ intent أثر خارجي، سجل محاولاته، ونتيجته على ملف SQLite السلطوي نفسه. اجتازت اختبارات حالة المستودع والاختبارات المرتبطة أدناه. هذا **قبول لطبقة المستودع والحالات فقط**؛ لم يُدمج adapter dispatch في runtime الإنتاجي، ولذلك يظل شرط `DISPATCHING` قبل كل استدعاء فعلي **UNVERIFIED**. لا يعني هذا checkpoint تفعيل supervisor أو حماية أي مسار inline قائم.

بدأ العمل من الفرع `manus/durable-runtime-fencing` عند `0ea1b8bd09a69e22a0e50dd1e6210ee0e7be0044`؛ كان `HEAD` و`origin/manus/durable-runtime-fencing` متطابقين، وكان tracked/untracked working tree نظيفًا. هذا هو parent المقصود للـcheckpoint، ولا يُسجل SHA ذاتي هنا.

## بروتوكول الحالة الدائم

| الانتقال | الضمان في المستودع |
|---|---|
| لا يوجد intent → `PREPARED` | `prepare()` ينشئ `effect_id` و`idempotency_key` حتميين للعمل المنطقي، يسجل المحاولة وclaim generation، ويحفظ checkpoint المهمة في معاملة واحدة. لا يُخزن payload الخام؛ يُخزن digest. |
| `PREPARED` → `DISPATCHING` | `mark_dispatching()` يقبل المحاولة المحضرة للـclaim الحالي فقط. يجب على adapter أن يلتزم باستدعائه وcommit قبل بدء الاتصال؛ **لا يوجد ربط adapter يفرض ذلك بعد في هذا checkpoint**. |
| `DISPATCHING` → `CONFIRMED` | `confirm()` يحفظ receipt/observation وmission/evidence/ledger مع تغيير حالة intent ذريًا، بعد فحص claim وrevision الحاليين. لا يقبل تأكيدًا ثانيًا للحالة المحسومة. |
| `DISPATCHING` → `DEFINITE_NOT_SENT` | `mark_definitely_not_sent()` يرفض غياب proof غير فارغ يثبت أن الاتصال لم يبدأ. يعاد التسليح فقط عبر `rearm_definitely_not_sent()` الصريح وبالمفتاح نفسه؛ لا يثبت الاختبار قدرة مزود حي على تقديم هذا البرهان. |
| `DISPATCHING` → `FAILED` | يُحفظ فقط مع سبب نهائي صريح؛ الحالة لا يعاد إرسالها تلقائيًا. |
| `DISPATCHING` → `UNKNOWN` | `recover_dispatching()` بعد restart/reclaim يحول كل intents غير المحسومة إلى `UNKNOWN` و`OWNER_RECONCILIATION_REQUIRED`، ويحفظ المهمة `RECOVERY_REQUIRED` في المعاملة نفسها. لا يقبل `prepare()` إعادة dispatch لهذه الحالة. |
| `PREPARED` مع reclaim قبل `DISPATCHING` | تُغلق المحاولة القديمة كـ`DEFINITE_NOT_SENT` وفق بوابة البروتوكول، وتُسجل محاولة جديدة تحت generation الحالية مع بقاء `effect_id` ومفتاح idempotency ثابتين. هذا الضمان مشروط مستقبلًا بأن كل adapter يعبر بوابة `DISPATCHING`. |

`effect_id` مشتق من هوية mission/task/request المتاحة و`logical_action_id`، بينما digest الأداة والمدخلات يمنع إعادة استخدام الهوية نفسها لحمولة مختلفة. يسجل كل attempt claim generation الأصلي، ويُسجل أيضًا worker/generation الذي حفظ النتيجة عند اختلافه بسبب reclaim. لا تنشأ هوية جديدة لمجرد إعادة المحاولة.

## الذرية والحراسة

`MissionStore.__init__` يهيئ جدولي `external_effect_intents` و`external_effect_attempts` وindexes باستخدام `CREATE ... IF NOT EXISTS` فقط؛ لم تُنقل أو تُحذف بيانات legacy. أُخرجت كتابة المهمة الحالية إلى `_save_mission_in_transaction()` في `agent/mission.py:179-251` لكي تستخدمها عملية تأكيد الأثر على **الاتصال/المعاملة نفسها**.

في `agent/effect_intent.py:192-210` يتحقق كل تعديل من نوع claim الحالي، هوية mission، payload integrity hash، وrevision المحملة، بعد `BEGIN IMMEDIATE`. تبدأ `prepare()` في `agent/effect_intent.py:256-367` intent والمحاولة وcheckpoint ذريًا. انتقال `DISPATCHING` في `:368-455` يطلب generation وworker وlease المطابقين للمحاولة المحضرة. يحفظ `confirm()` في `:582-652` receipt والحالة وmission observation/action/evidence و`mission_evidence_events` ذريًا؛ يثبت trigger failure في الاختبار أن rollback يشملها جميعًا. معالجة crash/reclaim موجودة في `:523-581`، والتسليح الصريح لـ`DEFINITE_NOT_SENT` في `:653-695`.

يوفر `MissionStore.with_claim()` و`_ClaimBoundMissionStore` في `agent/mission.py:254-276` واجهة effect-intent تربط العمليات بآخر snapshot claim يحدّثه worker. تظل الكتابات التي تستخدم `MissionStore` مباشرة بلا claim خارج هذا الضمان، كما في M2.a/b.

## فحص مسار dispatch الفعلي

لم أغير `agent/mission_runtime.py` أو `agent/agent_core.py` أو `tools/registry.py` أو `bridge.py` لأن الفحص لم يجد مسارًا إنتاجيًا يربط `MissionWorker` بالمنفّذ. `MissionWorker.run_once()` يستقبل runtime عبر factory (`agent/mission_worker.py:385-465`)، لكن لا توجد callsite إنتاجية تنشئ `MissionWorker`. بالمقابل، `AgentCore.run_owner_mission()` ينشئ `MissionRuntime` مباشرة ويشغّل `run_model_loop()` أو `run_to_completion()` (`agent/agent_core.py:229-311`)، ويصل المنفذ inline إلى `tools.registry.execute()` (`agent/agent_core.py:197-227`; `agent/mission_runtime.py:241-355,377-408`; `tools/registry.py:276-343`). كما أن `bridge.py:82-87` يبني `MissionRuntime` و`MissionQueue` على ملفين منفصلين، ولا يوصلهما بـ`MissionWorker`.

لذلك لم أضع `PREPARED`/`DISPATCHING` حول هذا المسار inline، ولم أغير `/api/chat` أو دلالات executor/provider. لا تثبت الاختبارات أن timeout أو `Future.cancel()` أو crash في المسار الفعلي يحفظ `UNKNOWN`، ولا أن dispatch لا يعاد بعد restart فيه. يلزم checkpoint تكامل لاحق يربط worker/runtime/adapter بعد اجتياز حد claim واحد؛ حتى ذلك الحين يظل dispatch integration **UNVERIFIED**.

## الاختبارات والنتائج

كل اختبارات M2.c تنشئ قواعدها في `tmp_path`، وتستخدم claims وأدوات محلية حتمية فقط؛ لا sleeps أو network أو provider أو external targets.

- `python -m pytest tests/test_effect_intent_recovery.py tests/test_external_effect_unknown.py -q` — **12 passed**. تشمل `PREPARED` وإعادة الفتح، stale A مقابل reclaim B، revision قديم تحت claim صحيح، المفتاح الثابت، claim-bound facade، رفض التحولات المتعارضة، proof لعدم الإرسال، failure النهائي، والهجرة الإضافية.
- `python -m pytest tests/test_effect_intent_recovery.py tests/test_external_effect_unknown.py tests/test_mission_evidence_atomicity.py tests/test_verification_proof_persistence.py tests/test_mission_store_fencing.py tests/test_mission_queue_fencing.py tests/test_governed_execution.py tests/test_deterministic_goal_verification.py tests/test_agent_core_state.py tests/test_crash_restart_resume.py tests/test_phase6k7b_mission_runtime.py -q` — **76 passed**.
- `python -m pytest tests/test_agent_adaptive_loop.py -q` — **24 passed**.
- `python -m compileall -q agent workspace tools api bridge.py tests/test_effect_intent_recovery.py tests/test_external_effect_unknown.py` — **pass**؛ لم يدخل `web/`.
- `git diff --check` — **pass** في التحقق النهائي قبل commit.

الاختبارات الأساسية: `tests/test_effect_intent_recovery.py:48-286` و`tests/test_external_effect_unknown.py:14-146`. اختبار crash يحفظ `DISPATCHING` ثم يفتح `MissionStore` جديدًا تحت claim B، فيثبت `UNKNOWN` و`RECOVERY_REQUIRED` ورفض fake dispatch الثانية؛ اختبار confirmation يثبت صف evidence/ledger واحدًا ويرفض التكرار؛ trigger يحقن فشلًا بعد تحديث intent وقبل نجاح حفظ mission، فيتراجع كل من receipt والحالة وmission/evidence.

## حدود الضمان والبيانات المحمية

- لا ادعاء بـ**exactly-once**: SQLite لا يفرض fencing أو idempotency على خدمة خارجية.
- تبقى TOCTOU بين commit `DISPATCHING` وبين قبول الطرف الآخر للاتصال؛ لا يمكن لقفل SQLite إيقاف اتصال خارجي بدأ.
- لا يوجد Owner UI/API أو reconciler متصل بهذه الحالات. يظل `UNKNOWN` ظاهرًا في `MissionStore.effect_intents` وmission payload بحالة `RECOVERY_REQUIRED`؛ يلزم reconciler/Owner route لاحق يثبت receipt أو عدم الإرسال ويحدث intent وmission معًا. إعادة الحالة من UNKNOWN ليست retry آليًا.
- لا يوجد provider acceptance أو اختبار حي، ولم تُستخدم credentials أو أهداف خارجية.
- لا يوجد supervisor cutover أو تغيير في `/api/chat` أو API shape أو Vibe/Desktop/Electron/Windows/`web/` أو بيانات المستخدم.

قُرئت بصمات SHA-256 فقط للملفات الثلاثة المحمية قبل العمل وبعده؛ لم تُفتح كقواعد، ولم تُنقل أو تُحذف أو تُstage. يجب أن تتطابق قيم قبل/بعد كما يلي:

| الملف | SHA-256 قبل | SHA-256 بعد |
|---|---|---|
| `knowledge.sqlite3` | `93e78ed6bd85bbb8eb4c9cf5e92105739e220bdf87f92d5e75bba7b1c124bd7b` | `93e78ed6bd85bbb8eb4c9cf5e92105739e220bdf87f92d5e75bba7b1c124bd7b` |
| `memory.sqlite3` | `a617102b1153d4cf220d8cbeae0c804f5b830856cbcf7d48251e13a86f01f227` | `a617102b1153d4cf220d8cbeae0c804f5b830856cbcf7d48251e13a86f01f227` |
| `tasks.sqlite3` | `69bbc1fba28b48a97d02c6ced0cb7e0e2952ec5b0d5eb6ffb95cfb1a4759f3d8` | `69bbc1fba28b48a97d02c6ced0cb7e0e2952ec5b0d5eb6ffb95cfb1a4759f3d8` |
