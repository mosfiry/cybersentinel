# M2.d.supervisor-module — أدلة lifecycle الداخلي

## الحالة والنطاق

نُفذ هذا checkpoint على الفرع `manus/durable-runtime-fencing` من base المحلي/البعيد المطابق `4e3ef0116cca27be58fcb8287390da4fbab508ae`، وparent المتوقع للـcommit هو SHA نفسه. أُضيفت وحدة lifecycle داخلية صريحة فقط: `agent/mission_supervisor.py`، واختبار قبول `tests/test_mission_supervisor.py`.

هذا **ليس production cutover**. لا يبدأ supervisor عند import أو الإنشاء؛ يجب أن يستدعيه lifecycle مُدار لاحقًا عبر `start()` و`stop()`. لم يُربط بـ`bridge.py` أو routes أو APIs، ولم يتغير `/api/chat` أو contract/auth/Owner/scope/policy. لا يعمل أي supervisor تلقائيًا نتيجة هذا checkpoint.

## عقد التشغيل والتعافي

- `MissionSupervisor.start()` ينشئ thread واحدًا صراحةً، ويرفض بدء نسخة ثانية للكومبو نفسه `(SQLite authority path, worker_id)` داخل العملية. يمكن لعاملين بهويتين مختلفتين التنافس على queue نفسها، ويظل `MissionQueue.claim_next()` هو صاحب claim الذري.
- `stop()` يطلب التوقف عبر `threading.Event` ولا يقاطع `MissionWorker.run_once()` قسرًا. ينتظر العملية الحالية؛ إن انتهت المهلة يعيد `False` وتبقى العملية والـclaim كما هما، ولا ينفذ supervisor queue ack أو يكتب `FAILED`/`COMPLETED` بنفسه.
- poll/backoff تصاعدي ومحدود بـ`max_backoff`. يحتفظ المشرف بآخر استثناء في `last_exception`/`last_error` ولا يحوله إلى إقرار queue. إذا انهار العامل بعد عبور حد dispatch، يبقى lease/intent الدائمان قابلين للاسترداد.
- عند كل دورة، يستدعي المشرف `recover_expired()` قبل `run_once()`؛ يعيد ذلك leases المنتهية فقط. لا يستدعي `recover_after_restart()` الذي يبطل كل leases النشطة بلا تمييز، لأن بدء مشرف ثانٍ قد يسحب claim من مشرف حي. بعد انتهاء lease، يطالب العامل بالـclaim؛ ثم ينفذ `MissionWorker.run_once()` ربط claim-bound store و`recover_dispatching()` قبل تشغيل `MissionRuntime`، فتتحول `DISPATCHING` غير محسومة إلى `UNKNOWN/RECOVERY_REQUIRED` قبل أي إعادة dispatch.
- lease غير المنتهية بعد crash لا تُسحب قسرًا؛ تنتظر صلاحيتها/انتهائها وفق protocol الحالي. هذه مهلة استرداد مقصودة لحماية عامل آخر ما زال حيًا.
- أخطاء التنفيذ الخارجي بعد دخول handler تبقى مبهمة: dispatcher يثبت `UNKNOWN`، وmission لا تتحول إلى إكمال ناجح أو retry آلي. توقف supervisor لا يدّعي exactly-once ولا يستطيع إلغاء أثر خارجي بدأ بالفعل.

## اختبارات القبول

`tests/test_mission_supervisor.py` يختبر باستخدام SQLite محلية حقيقية، و`MissionQueue` و`MissionWorker` و`MissionRuntime` و`MissionEffectDispatcher` و`tools.registry` مع synthetic handler محلي، دون mocks لإثبات ضمانات queue/worker:

1. بدء صريح يستهلك mission مؤهلة، ويحفظ intent كـ`CONFIRMED` وmission كـ`GOAL_COMPLETED`.
2. توقف عند الخمول بلا claim، وتوقف أثناء handler محجوب بـ`Event`: لا ينهي المشرف الطلب قسرًا، ويعود بعد فك الحاجز بنتيجة معروفة فقط.
3. بدء مكرر للكائن نفسه أو لهوية worker نفسها في العملية مرفوض.
4. مشرفان بهويتي worker مختلفتين يتنافسان على queue واحدة؛ handler يُستدعى مرة واحدة، والclaim الفائز يُحسم عبر SQLite queue الفعلية.
5. استثناء handler بعد `DISPATCHING` يبقى `UNKNOWN/RECOVERY_REQUIRED` وqueue في `WAITING_FOR_TOOL`، لا `FAILED` أو `COMPLETED`.
6. crash مُحاكى بعد `DISPATCHING` ثم إعادة فتح SQLite وانتهاء lease: supervisor الجديد يعيد استرداد الصف قبل claim، وworker يحول intent إلى `UNKNOWN` قبل runtime/dispatch؛ لا توجد call ثانية.
7. مسار الخمول يتحقق من أن البناء وحده لا يشغّل loop، كما يُتحقق من backoff ضمن الحد المكوّن.

النتائج:

- `python -m pytest tests/test_mission_supervisor.py -q` — **12 passed** (7 lifecycle/queue cases plus 5 invalid polling/backoff configurations).
- targeted regression عبر ملفات M2.a–M2.d (`test_effect_intent_recovery`, `test_external_effect_unknown`, `test_mission_evidence_atomicity`, `test_verification_proof_persistence`, `test_mission_store_fencing`, `test_mission_queue_fencing`, `test_governed_execution`, `test_deterministic_goal_verification`, `test_agent_core_state`, `test_crash_restart_resume`, `test_phase6k7b_mission_runtime`, `test_tool_continuity`, `test_native_model_protocol`, `test_owner_authority_refactor`, `test_m2d_dispatch_integration`, و`test_mission_supervisor`) — **116 passed**.
- `python -m pytest tests/test_agent_adaptive_loop.py -q` — **24 passed**.
- `python -m compileall -q agent/mission_supervisor.py agent/mission_worker.py agent/mission_runtime.py agent/effect_dispatch.py tests/test_mission_supervisor.py tests/test_m2d_dispatch_integration.py` — ناجح.
- متغيرات مزودي الخدمة الحية أزيلت من بيئة عملية pytest فقط. لم تُشغّل full suite أو اختبارات network/provider حي.

## قواعد SQLite المحمية

قورنت بصمات SHA-256 فقط قبل التعديل وبعد الاختبارات؛ لم تُفتح الملفات كقواعد، ولم تُحذف أو تُنقل أو تُعدل أو تُstage. القيم متطابقة:

| الملف | SHA-256 قبل | SHA-256 بعد الاختبارات |
|---|---|---|
| `knowledge.sqlite3` | `93e78ed6bd85bbb8eb4c9cf5e92105739e220bdf87f92d5e75bba7b1c124bd7b` | `93e78ed6bd85bbb8eb4c9cf5e92105739e220bdf87f92d5e75bba7b1c124bd7b` |
| `memory.sqlite3` | `a617102b1153d4cf220d8cbeae0c804f5b830856cbcf7d48251e13a86f01f227` | `a617102b1153d4cf220d8cbeae0c804f5b830856cbcf7d48251e13a86f01f227` |
| `tasks.sqlite3` | `69bbc1fba28b48a97d02c6ced0cb7e0e2952ec5b0d5eb6ffb95cfb1a4759f3d8` | `69bbc1fba28b48a97d02c6ced0cb7e0e2952ec5b0d5eb6ffb95cfb1a4759f3d8` |

## ما لم يتغير وما لا يثبته هذا الدليل

لم تتغير `agent/mission_worker.py` أو `agent/mission_runtime.py` أو `agent/effect_dispatch.py`؛ استُخدمت الواجهات الإنتاجية الحالية كما هي. لم تتغير `bridge.py`, `api/*`, `/api/chat`, `web/`, Vibe/Desktop/Electron/Windows أو ملفات plan/todo التاريخية. لا يثبت هذا checkpoint تشغيل supervisor في production، أو وجود lifecycle host يستدعيه، أو cutover/مسار API، أو منع سباق TOCTOU لدى مزود خارجي، أو exactly-once. تبقى الخطوة المنفصلة التالية `M2.d.cutover`، غير منفذة هنا.
