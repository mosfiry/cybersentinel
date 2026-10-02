# أدلة M2.a — atomic fenced mission write

## النطاق والنتيجة

نُفّذت M2.a فقط على الفرع `manus/durable-runtime-fencing` انطلاقًا من base حي `b81742b59afd612f627f82dc6db1beca1a7d2a3a`. كان local working tree نظيفًا، وطابق `HEAD` وSHA البعيد هذا الـbase، وثبتت علاقة ancestry قبل التعديل. Parent المباشر المقصود للـcheckpoint هو الـbase نفسه؛ لا يتضمن هذا الملف SHA ذاتيًا للـcommit.

أُضيفت كتابة mission fenced تتحقق من claim الحالي وتنفذ revision/CAS داخل معاملة `BEGIN IMMEDIATE` واحدة وعلى اتصال/ملف SQLite واحد. الانحدار الحتمي يثبت: A generation 1، ثم reclaim للعامل B generation 2؛ كتابة A تُرفض بلا تغيير صف mission (payload أو revision) أو ownership row، وكتابة B تنجح. لا sleeps أو provider أو external targets.

## أدلة المصدر والاختبارات

| الملف | الدليل |
|---|---|
| `agent/mission.py:82-83` | `revision` داخلية للكائن، غير مضمنة في `to_dict()`، لذلك لا تتغير public response payload. |
| `agent/mission.py:162-169` | إضافة عمود revision إلى schema مع `ALTER TABLE` additive/idempotent لقواعد mission القديمة، مع default `0` للصفوف القائمة. |
| `agent/mission.py:171-218` | `MissionStore.save`: يبدأ `BEGIN IMMEDIATE`، يتحقق من snapshot/generation/worker/lease/expiry عبر `MissionQueue._require_current_claim` على الاتصال نفسه، ثم ينفذ revision/hash CAS أو insert. تحديث كائن mission يقع بعد نجاح commit. |
| `agent/mission.py:220-250` | استعادة revision عند load وربط claim بواجهة store التي يستخدمها runtime. |
| `agent/mission_worker.py:402-427` | `MissionWorker.run_once` يربط runtime store بالclaim، ويرفض fail-closed أي store غير `MissionStore` أو مسار SQLite منفصل، ويحدث claim المربوط بعد heartbeat. |
| `tests/test_mission_store_fencing.py:44-83` | انحدار A/B: generation 1 ثم 2، رفض A مع تطابق صف mission كاملًا وownership row، وقبول B مع زيادة revision. |
| `tests/test_mission_store_fencing.py:85-112` | rollback على SQLite حقيقي باستخدام trigger يحقن فشل الكتابة؛ يثبت بقاء صف mission والـownership كما كانا. |
| `tests/test_mission_store_fencing.py:114-139` | migration schema additive/idempotent وإعادة فتح store دون فقد payload أو revision. |
| `tests/test_mission_store_fencing.py:141-192` | يمر اختبار stale/reclaim عبر `MissionWorker` نفسه؛ لا يُكتب payload العامل A بعد أن يطالب B. |
| `tests/test_mission_store_fencing.py:185-233` | fail-closed إذا اختلف ملفا mission/queue أو لم يقدم runtime مخزنًا يدعم fenced MissionStore؛ لا يبدأ runtime في الحالتين. |
| `tests/test_mission_queue_fencing.py` | regressions الحالية للـqueue؛ بقي عقدها العام كما هو. |

### Test-first record والنتائج

- على commit الأساس، قبل إصلاح التنفيذ: `python -m pytest tests/test_mission_store_fencing.py tests/test_mission_queue_fencing.py -q` سجّل **4 failed, 7 passed**. شملت الإخفاقات غياب معامل `claim` في `MissionStore.save`، غياب revision schema/internal field، وكتابة العامل A القديمة للـmission بعد generation 2 للعامل B.
- أثناء المراجعة أُضيف انحدار fail-closed؛ قبل guard المناسب سجّل **1 failed, 12 passed**، وفشل تحديدًا لأن runtime ذي store غير fenced لم يُرفض.
- بعد الإصلاح النهائي، الأمر نفسه: **13 passed**.
- `python -m compileall -q .`: ناجح.
- `python -m pytest -q`: **717 passed, 1 skipped**. فُرض غياب `CYBERSENTINEL_LIVE_PROVIDER_KEY` و`CYBERSENTINEL_LIVE_ROUTER_FACTORY` في عملية الاختبار حتى لا يعمل اختبار المزود الحي.
- `python -m pytest tests/test_agent_adaptive_loop.py -q`: **24 passed**.
- لا يستخدم الاختبار الخارجي/المزوّد الحي؛ استدعاء `scoped_http_probe` في مجموعة المشروع placeholder حتمي، واختبارات HTTP الموجودة محلية.

## حدود الضمان وما لم يُنفّذ

- الذرية هنا **محلية لملف SQLite واحد**. يجب أن يمرر runtime في `MissionWorker` ملف authority نفسه إلى `MissionStore` و`MissionQueue`؛ العامل يرفض اختلاف المسارين. لا `lease_status()` منفصل يتبعه write على اتصال آخر، ولا `ATTACH` متعدد الملفات أو افتراض journal mode.
- ترحيل هذه المرحلة additive يضيف revision إلى ملف mission الذي يفتحه `MissionStore`. لم تُنقل صفوف أو ملفات legacy، ولم تُحذف/تُستبدل بيانات. لا ادعاء بذرية crash عبر قواعد متعددة.
- **لم يتحقق write-fencing للمسار الإنتاجي الحالي `/api/chat`.** يبقى handler/`AgentCore` على مساره inline بلا claim، وتهيئة `bridge.py` الحالية تفصل ملف missions عن ملف queue ولا يوجد supervisor production cutover في M2.a. `MissionWorker` أصبح fail-closed ومربوطًا عندما يستعمل store/queue من ملف authority واحد، لكن هذا لا يعني أن المسار القديم أو عاملًا آخر بلا binding محمي. توصيل supervisor/API-cutover قرار M2.d خارج النطاق.
- لم تُنفّذ M2.b (evidence/proof atomicity)، أو M2.c (ExternalEffectIntent)، أو M2.d (supervisor/API cutover). لا ضمان لمنع عامل قديم من إصدار evidence/proof أو إرسال أثر خارجي، ولا exactly-once.
- لم تُعدّل Owner auth/scope/policy أو public response contract أو `web/` أو Desktop/Electron/Windows؛ لم يُستخدم live provider أو external target.

## جرد قواعد الاختبار داخل clone

كان الجرد قبل الاختبارات خاليًا من ملفات SQLite في جذر clone. بعد full suite ظهرت الملفات ignored التالية في جذر `/workspace/cybersentinel-m0-20261002-1329`؛ وفق التعليمات بقيت في مكانها ولم تُحذف أو تُنقل أو تُstage:

| الملف | الحجم | SHA-256 |
|---|---:|---|
| `knowledge.sqlite3` | 20,480 bytes | `93e78ed6bd85bbb8eb4c9cf5e92105739e220bdf87f92d5e75bba7b1c124bd7b` |
| `memory.sqlite3` | 28,672 bytes | `a617102b1153d4cf220d8cbeae0c804f5b830856cbcf7d48251e13a86f01f227` |
| `tasks.sqlite3` | 24,576 bytes | `69bbc1fba28b48a97d02c6ced0cb7e0e2952ec5b0d5eb6ffb95cfb1a4759f3d8` |

كل قواعد اختبار M2.a نفسها أُنشئت عبر `tmp_path`. لم تُفتح قواعد المستخدم خارج clone.
