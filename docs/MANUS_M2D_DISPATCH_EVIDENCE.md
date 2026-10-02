# M2.d.dispatch — أدلة تكامل بوابة الإرسال

## الحالة والحدود

نُفذ هذا الجزء على `manus/durable-runtime-fencing` في worktree الوحيد `/workspace/cybersentinel-m0-20261002-1329`، من base محلي/بعيد مطابق `0799147d7dacdbf24487e10e2384d94e4c515d9a` مع شجرة نظيفة قبل التغيير. هذا **تكامل dispatch مختبَر، وليس production cutover**؛ لا يفعّل supervisor ولا يغيّر `/api/chat` أو واجهة عامة. يسجل `LAST_GOOD_SHA` القاعدة السابقة، لا SHA ذاتيًا.

## مسار الإرسال الفعلي

| الموضع | الدور المثبت |
|---|---|
| `agent/mission_worker.py:MissionWorker.run_once()` (السطر 403) | يربط runtime الحقيقي بـ`MissionStore.with_claim()`، ثم يثبت `MissionRuntime.bind_worker_dispatch()` قبل بدء التنفيذ. عند claim جديد يستدعي `recover_dispatching()` قبل أي slice، فلا يعيد إرسال أثر بقي `DISPATCHING`. إذا تعذّر فحص intents، أو بقي intent كذلك بعد خطأ حفظ، لا يحوّل العامل المهمة إلى `FAILED`. |
| `agent/mission_runtime.py:MissionRuntime.bind_worker_dispatch()` (38) | لا يركّب البوابة إلا على واجهة `ClaimBoundEffectIntentRepository`، ويحتفظ بمسار inline القديم دون تغيير عندما لا يكون runtime مربوطًا بعامل. |
| `agent/mission_runtime.py:MissionRuntime.run_slice()` (541، dispatch عند 606) | يمرر executor الفعلي عبر البوابة. هوية المحاولة المنطقية من `mission/plan version/step/current index` وpayload الخطوة؛ لذلك يعاد استخدام effect/idempotency key عند reclaim لنفس الخطوة. يسمح باستئناف `PREPARED` فقط عندما يطابق intent والخطوة، ويحافظ على effect id في checkpoint حتى إعادة التحضير. |
| `agent/mission_runtime.py:MissionRuntime.run_model_loop()` (295) و`_run_parallel_model_calls()` (452) | تمرر tool calls التي تصل مباشرة إلى `tools.registry.execute()` عبر البوابة نفسها في worker mode. تنفذ المجموعة المتوازية تسلسليًا في هذا الوضع حتى لا تتنافس confirmation متعددة على mission revision واحد؛ يبقى السلوك المتوازي القديم خارج worker mode كما هو. |
| `agent/effect_dispatch.py:MissionEffectDispatcher.dispatch()` (34) | يستدعي واجهة claim-bound بالترتيب `prepare` ثم `mark_dispatching`، وينادي handler فقط بعد نجاح commit لـ`DISPATCHING`. النتيجة المقبولة تمر إلى `confirm` الموجودة في repository، التي تحفظ receipt وmission observation/action/evidence معًا. بعد دخول handler، يحاول الخطأ غير المعروف تثبيت `UNKNOWN`; وإذا تعذر ذلك يبقى `DISPATCHING` كي يعالجه العامل التالي. |
| `agent/effect_intent.py` | أعيد استخدام انتقالات M2.c الحالية: `prepare` (256)، `mark_dispatching` (368)، `mark_unknown` (523)، `recover_dispatching` (551)، `confirm` (582)، والواجهة claim-bound (696). لم تتغير state machine أو schema في هذا الجزء. |

اختبر المسار بأداة محلية synthetic مسجلة عبر `tools.registry` الفعلي وقاعدة SQLite مؤقتة. داخل handler نفسه قرأت الاختبارات قاعدة authority وتحققت من أن `DISPATCHING` والمفتاح الثابت وcheckpoint ذي `claim_generation` الصحيح سبقوا دخول الأداة؛ بعد الرد تحققت من أن الحالة صارت `CONFIRMED` ومن وجود observation/evidence واحدة فقط. اختبر worker أيضًا مساري Registry الفردي والمتوازي، وليس executor mock يتجاوز حدود الإنتاج.

## ما تثبته الاختبارات وما لا تثبته

`tests/test_m2d_dispatch_integration.py` يضم سبع حالات: نتيجة موثوقة وتأكيد ذري؛ reclaim للعامل B أثناء handler محجوب بـ`threading.Event` ثم رفض عودة A القديمة بلا كتابة mission/evidence/intent أو queue acknowledgement؛ restart بعد crash عقب `DISPATCHING` وتحويله إلى `UNKNOWN/RECOVERY_REQUIRED` بلا call ثانية؛ rollback كامل عند فشل حفظ confirmation مع عدم تسجيل `FAILED`؛ retry بعد `PREPARED` يحفظ effect/idempotency key نفسه ويسجل generation المحاولة الجديدة؛ ومسارا Registry native الفردي والمتوازي يمران بالبوابة. لا تستخدم الاختبارات sleeps أو network أو provider حيًا؛ كل قواعدها في `tmp_path`.

مجموعة الانحدار شغلت `tests/test_effect_intent_recovery.py`, `tests/test_external_effect_unknown.py`, `tests/test_mission_evidence_atomicity.py`, `tests/test_verification_proof_persistence.py`, `tests/test_mission_store_fencing.py`, `tests/test_mission_queue_fencing.py`, `tests/test_governed_execution.py`, `tests/test_deterministic_goal_verification.py`, `tests/test_agent_core_state.py`, `tests/test_crash_restart_resume.py`, `tests/test_phase6k7b_mission_runtime.py`, `tests/test_tool_continuity.py`, `tests/test_native_model_protocol.py`, `tests/test_owner_authority_refactor.py` و`tests/test_m2d_dispatch_integration.py`؛ النتيجة **104 passed**. `tests/test_m2d_dispatch_integration.py` وحده: **7 passed**. `tests/test_agent_adaptive_loop.py`: **24 passed**. أزيل متغيرا live-provider من عملية pytest فقط. نجح `python -m compileall -q agent/effect_dispatch.py agent/mission_runtime.py agent/mission_worker.py tests/test_m2d_dispatch_integration.py` و`git diff --check`. لم تُشغّل full suite؛ لم يُختبر provider حي أو خدمة خارجية.

يثبت هذا حد قاعدة البيانات: commit دائم لـ`DISPATCHING` قبل استدعاء handler، وإكمال قديم fenced بعد reclaim، و`UNKNOWN` يمنع retry آليًا. **لا تمنع SQLite سباق TOCTOU مع الخدمة الخارجية**: قد ينتهي claim بعد commit وقبل أن تستقبل الخدمة الطلب، أو يقع crash عند الحد؛ لذلك لا يُدّعى إلغاء الأثر الخارجي أو exactly-once. اختبار Registry هنا محلي فقط ولا يثبت fencing يطبقه مزود خارجي.

بقي مسار AgentCore/Workspace inline و`EvidenceChainStore` كما كان؛ لم تتغير `agent/agent_core.py` أو `tools/registry.py` أو API/auth/Owner/scope/policy/provider semantics. يغطي `tests/test_verification_proof_persistence.py` سلوك legacy ضمن المجموعة، ولا يعني ذلك أن سجل Workspace المنفصل صار fenced. لم تتغير شجرة release closure أو `main` أو Vibe/Desktop/Electron/Windows أو `web/`، ولم تُفعّل production supervisor.

## ملفات SQLite المحمية

قورنت بصمات SHA-256 فقط قبل التغيير وبعده؛ لم تُفتح الملفات كقواعد، ولم تُنقل أو تُحذف أو تُعدل أو تُstage. تطابقت القيم:

| الملف | SHA-256 قبل | SHA-256 بعد |
|---|---|---|
| `knowledge.sqlite3` | `93e78ed6bd85bbb8eb4c9cf5e92105739e220bdf87f92d5e75bba7b1c124bd7b` | `93e78ed6bd85bbb8eb4c9cf5e92105739e220bdf87f92d5e75bba7b1c124bd7b` |
| `memory.sqlite3` | `a617102b1153d4cf220d8cbeae0c804f5b830856cbcf7d48251e13a86f01f227` | `a617102b1153d4cf220d8cbeae0c804f5b830856cbcf7d48251e13a86f01f227` |
| `tasks.sqlite3` | `69bbc1fba28b48a97d02c6ced0cb7e0e2952ec5b0d5eb6ffb95cfb1a4759f3d8` | `69bbc1fba28b48a97d02c6ced0cb7e0e2952ec5b0d5eb6ffb95cfb1a4759f3d8` |
