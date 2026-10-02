# حالة المهمة — M1 Lease Semantics

| الحقل | القيمة |
|---|---|
| `CURRENT_PHASE` | `M1` — fencing محلي عند حد `MissionQueue` فقط. |
| `CURRENT_CHECKPOINT` | التنفيذ والاختبار اكتملَا؛ مراجعة diff والالتزام الذري بانتظار الإتمام. قاعدة العمل `49d4044ff7929455959f1ca22ccb6be52ac096c5`، أبوه `b17a70ba44463e7a35d8b8e9d6b9ecc0c8773bd8`. يُسجل SHA الناتج في commit توثيقي لاحق، لا ذاتيًا هنا. |
| `COMPLETED_PHASES` | `M0`; تنفيذ M1 واختباراته مكتملان بانتظار checkpoint git. |
| `ACTIVE_WORK` | مراجعة نهائية لنطاق الملفات والـdiff ثم إنشاء commit M1؛ لا يبدأ M2. |
| `LAST_GOOD_SHA` | `49d4044ff7929455959f1ca22ccb6be52ac096c5` — قاعدة M1 التي جرى التحقق منها؛ لا يصف هذا الحقل commit الجاري إنشاؤه. |
| `BRANCH` | `manus/durable-runtime-fencing` |
| `REMOTE` | `origin https://github.com/mosfiry/cybersentinel.git`; كان الفرع البعيد عند SHA البداية نفسه عند بدء التنفيذ، ويعاد فحصه قبل push وبعده. |
| `WORKTREE` | `/workspace/cybersentinel-m0-20261002-1329` |
| `BASE_SHA` | `49d4044ff7929455959f1ca22ccb6be52ac096c5`، الأب `b17a70ba44463e7a35d8b8e9d6b9ecc0c8773bd8`. |

## المنجز في M1

- أضيفت هوية claim مستقلة (`lease_id`, `generation`, `acquired_at`) وحالة heartbeat، مع snapshot immutable تفصل claim عن `worker_id`.
- heartbeat وqueue updates وrelease وterminal acknowledgement تتطلب snapshot الحالية وغير المنتهية. generation تزداد ذريًا ولا تُعاد عند release أو recovery أو requeue؛ انتهاء المهلة يرفض الكتابة فورًا قبل recovery.
- أضيف ترحيل تراكمي لقاعدة lease القديمة مع إبقاء قيم `lease_owner` و`lease_expires_at` ورفض اعتبارها claim token. حافظ `MissionService.start_mission()` على شكل الاستجابة السابق دون إرسال token جديد.
- لم يُضف `task_id` لأنه غير موجود في MissionQueue. لم تتغير Owner authentication أو authorization/scope/policy. لا تغييرات خارج الملفات المسموح بها.
- تفاصيل العقد والحدود في `docs/MANUS_LEASE_SEMANTICS.md`؛ أضيفت حقائق M1 المتغيرة إلى `docs/MANUS_FENCING_INVENTORY.md` مع إبقاء نتائج M0 التاريخية.

## التحقق والاختبارات

| الأمر | النتيجة | الزمن |
|---|---|---:|
| انحدار M0 الأولي: `python -m pytest tests/test_mission_queue_fencing.py -q` قبل الإصلاح | فشل متوقع واحد: قُبل heartbeat القديم بعد expiry/reclaim وإعادة استخدام `worker_id`. |
| `python -m pytest tests/test_mission_queue_fencing.py -q` بعد الإصلاح | `7 passed` | `0.17s` |
| `python -m pytest tests/test_mission_queue_fencing.py tests/test_autonomous_foundation.py tests/test_governed_execution.py -q` | `48 passed` | `1.62s` |
| `python -m compileall -q .` | exit 0 | `0.426s` في التحقق المعزول النهائي |
| `python -m pytest -q` | `711 passed, 1 skipped`؛ الاختبار المتجاوز `tests/test_real_provider_long_horizon.py:35` لأنه يتطلب بيانات اعتماد provider حي غير مضبوطة. | `14.94s` في clone المصدر (`15.79s` في التحقق المعزول مع `-rs`) |
| تحقق معزول نهائي | نسخ محتوى clone الحالي إلى `/tmp/cybersentinel-m1-validation-20261002` دون `.git` وشغّل compileall وsuite؛ أنشأت قواعد الاختبار هناك فقط. |

قبل أول تشغيل اختبارات لم توجد ملفات قاعدة SQLite/DB محلية أو متعقبة في clone. أنشأت اختبارات المشروع لاحقًا ملفات ignored هي `knowledge.sqlite3`, `memory.sqlite3`, `tasks.sqlite3` في جذر clone؛ حُفظت كاملة دون تعديل في `/tmp/m1-test-databases-20261002` مع التحقق من SHA-256، ولم تُحذف. بعد نقلها لا توجد قاعدة SQLite/DB في جذر clone. كل اختبارات M1 نفسها استخدمت `tmp_path`، والتحقق الكامل الأخير أنشأ قواعده في نسخة `/tmp` المعزولة.

لم يُشغّل provider حي أو هدف خارجي. محاولة استخدام `/usr/bin/time` تعذرت لعدم وجوده؛ أُعيد القياس بمؤقت Python. فشلان وسيطان في اختبارات الوقت التاريخي صُحّحا بإضافة `now` ثابت إلى الاختبارين، ثم اجتازت المجموعة المركزة؛ لا إخفاق اختبار متبقٍ.

## الحدود والمخاطر المتبقية

M1 يثبت fencing عند حد صف queue فقط. لا يثبت fencing عابرًا لمخازن mission/evidence/proof ولا ذرية dispatch/الأثر الخارجي، ولا يحدد نتيجة عملية خارجية انقطعت بعد أن بدأت. لم يضف M1 supervisor؛ يذكر جرد M0 أنه لا يوجد مستهلك إنتاجي موثق لـMissionWorker/scheduler. يلزم M2 اختيار مسار التشغيل الإنتاجي وربط حالة `RECOVERY_REQUIRED` بمصالحة قبل retry، مع إبقاء حدود ربط المخازن والآثار الخارجية منفصلة. لا تدّعِ هذه المرحلة ضمان تنفيذ بعينه عبر الانهيار.

## الخطوة التالية — M2 بعد checkpoint M1

1. اختيار وتوثيق مسار التشغيل الإنتاجي بين queue مع supervisor حي والمسار المتزامن الحالي، وتحديد موضع عبور claim إلى التنفيذ.
2. تصميم reconciliation قبل retry عند dispatch/timeout أو crash غير محسوم، وإضافة اختبارات لعامل قديم بعد reclaim ولنتيجة أثر خارجي غير معروفة.
3. إبقاء cross-store fencing والذرية الخارجية خارج M1؛ الحفاظ على Owner authorization وscope/policy دون تغيير.
