# M1 — دلالات Lease الطابور

ينفّذ M1 fencing محليًا عند حد `MissionQueue` في SQLite. لا يغيّر صلاحية Owner أو `AuthorizationDecision` أو snapshots الخاصة بـscope/policy؛ هوية lease دليل ملكية لعملية queue بعينها فقط.

## هوية claim والحقول

`worker_id` يعرّف العامل/العملية، ولا يعرّف claim. قد يعاد استخدامه بعد انتهاء lease؛ لذلك لا يكفي وحده لتفويض heartbeat أو كتابة حالة. لكل claim هوية منفصلة في `LeaseClaimSnapshot` تتكون من:

| الحقل | الدلالة |
|---|---|
| `mission_id` | صف المهمة الموجود في الطابور. |
| `worker_id` | هوية العامل، منفصلة عن هوية claim. |
| `lease_id` | معرّف جديد وفريد لكل claim. |
| `generation` | إصدار ملكية متزايد لكل صف؛ يبدأ claim الأول بعد التهيئة عند 1. |
| `acquired_at` | وقت اكتساب claim؛ لا يتغير مع heartbeat. |
| `expires_at` | موعد انتهاء snapshot الحالية. |

الـsnapshot مجمّد وغير قابل للتعديل. يحدّث `heartbeat()` وقت heartbeat وموعد الانتهاء في التخزين، ثم يعيد snapshot جديدة تحمل `lease_id` و`generation` و`acquired_at` نفسها و`expires_at` الجديدة. لا يجوز متابعة استخدام snapshot قديمة بعد تجديد المهلة؛ عملياتها تُرفض.

في التخزين تبقى الأعمدة المتوافقة `lease_owner` و`lease_expires_at`؛ `lease_owner` هو `worker_id` وليس claim token. أضيفت `lease_id` و`lease_generation` و`lease_acquired_at` و`lease_heartbeat_at`. لا يحتوي هذا الطابور على `task_id`، ولذلك لم يُضف هذا الحقل.

## الحالات الرسمية

| الحالة | التعريف وسلوك حد الطابور |
|---|---|
| `LEASE_VALID` | تطابق snapshot الصف الحالي و`lease_id` و`generation` و`worker_id` ووقت الاكتساب والانتهاء، والوقت الحالي أسبق من `expires_at`. فقط هذه الحالة تسمح بعملية حساسة. |
| `LEASE_EXPIRED` | الوقت الحالي بلغ `expires_at` أو تجاوزه. تُرفض heartbeat والكتابة والإقرار والتحرير فورًا، حتى إن لم يعمل recovery بعد. |
| `LEASE_LOST` | لا يوجد صف/claim مطابق، أو snapshot قديمة لا تطابق وقت الانتهاء الحالي بعد heartbeat؛ لا تمنح صلاحية. |
| `LEASE_REVOKED` | أُزيلت الهوية الحالية قبل انتهاء snapshot بسبب release أو إعادة إدراج أو recovery أو إقرار نهائي. تبقى generation محفوظة. |
| `STALE_WORKER` | `worker_id` في snapshot لا يطابق العامل المخزن للـclaim الحالي. |
| `FENCED_WORKER` | generation في snapshot أقدم من generation الحالية، أو لا تطابق هوية lease/acquired_at ضمن الإصدار الحالي. يُرفض العامل القديم حتى لو عاد `worker_id` نفسه. |
| `RECOVERY_REQUIRED` | نتيجة تنفيذ قد يكون أثرها الخارجي قد بدأ لكن لا يُعرف هل اكتمل؛ يلزم reconciliation قبل تقرير إعادة التنفيذ. هذه حالة تفسير/تعافٍ وليست lease صالحة أو إقرارًا بأن الأثر لم يقع. M1 يعرّفها ولا ينفّذ مصالحة عابرة للمخازن. |

`MissionQueue.lease_status()` يعيد حالة snapshot دون تغيير التخزين، وعمليات الرفض ترفع `LeaseLostError` مع `lease_status` المقابل. الحالات `RECOVERY_REQUIRED` و`LEASE_VALID` ظاهرة في enum العقد؛ الأولى ليست ناتجًا من تحقق lease، والثانية نتيجة تحقق ناجح.

## ثوابت التنفيذ

- `claim_next()` يكتسب القفل عبر `BEGIN IMMEDIATE` ويزيد generation ذريًا لكل claim جديد، حتى إن كان `worker_id` معاد الاستخدام.
- كل من `heartbeat()` و`update()` و`release()` و`acknowledge()` يتطلب snapshot الحالية غير المنتهية، ويفحصها ويغيّر الصف ضمن معاملة SQLite واحدة. terminal update هو إقرار queue، ولا يوجد broker Ack منفصل.
- عند انتهاء المهلة لا يستطيع العامل القديم تجديد lease أو تحديث الصف أو تحريره أو إقراره؛ لا يعتمد الرفض على تشغيل recovery.
- release وrecovery وrequeue/`enqueue()` والإقرار النهائي يمسحون الحقول النشطة، لكن لا يصفّرون generation ولا يعيدون تفعيل `lease_id` سابق. claim اللاحق يحصل على generation أعلى ومعرّف جديد.
- مقارنة الانتهاء تعتمد اللحظة الزمنية مع تسوية الطوابع الزمنية إلى UTC، والحد دقيق: عند `now == expires_at` تكون الحالة منتهية.
- اختبار ABA يثبت generation 1 ثم 2 عند إعادة استخدام `worker_id` نفسه، ويرفض من claim الأول heartbeat والكتابة وrelease وacknowledge.

## ترحيل التخزين القديم وحدود التوافق

عند فتح قاعدة قديمة تُضاف الأعمدة الجديدة دون حذف أو استبدال أي عمود أو صف. تبقى قيم `lease_owner` و`lease_expires_at` القديمة محفوظة، لكن لا يُنشأ منها `LeaseClaimSnapshot`: لا يوجد token أو generation تاريخي يمكن إثباته. لذلك لا تستطيع واجهات الكتابة الجديدة قبول تلك القيم وحدها؛ تنتهي المهلة القديمة أو ينفّذ recovery قائم لإتاحة claim جديد يبدأ عند generation 1. اختبارات الترحيل تستخدم قواعد مؤقتة تحت `tmp_path` فقط.

`MissionService.start_mission()` يحتفظ بشكل الاستجابة السابق ولا يرسل `lease_id` أو generation أو snapshot إلى API. وتبقى الأعمدة العامة القديمة كما كانت؛ إضافة حقول داخلية إلى `QueueItem` لا توسّع العقد العام.

## ما لا يثبته M1

هذه ضمانات عند حد صف الطابور فقط. لا يثبت M1 أن كتابة mission أو evidence أو proof في مخازنها المنفصلة fenced ذريًا مع queue، ولا يجعل dispatch أو الآثار الخارجية ذرية، ولا يقرر نتيجة أثر بدأ قبل timeout. تبقى reconciliation للأثر غير المحسوم وتوصيل/اختيار مسار تشغيل إنتاجي للمستهلك/supervisor ضمن M2؛ وتبقى ضمانات ربط الأثر الخارجي وسجل الأدلة والمخازن المنفصلة ضمن M2/M3 بحسب التصميم. لا تُشغّل هذه المرحلة مزودًا حيًا أو هدفًا خارجيًا، ولا تدّعي ضمان تنفيذ بعينه عبر الانهيار.

## اختبارات M1

الانحدار أُضيف أولًا وشُغّل على أساس M0 قبل التعديل، وفشل كما هو متوقع لأن heartbeat القديم قُبل بعد استرداد الصف ثم إعادة claim بـ`worker_id` نفسه. بعد التعديل اجتازت مجموعة M1 المركزة:

```text
python -m pytest tests/test_mission_queue_fencing.py -q
7 passed
```

واجتازت كذلك اختبارات الطابور/العامل والتفويض ذات الصلة:

```text
python -m pytest tests/test_mission_queue_fencing.py tests/test_autonomous_foundation.py tests/test_governed_execution.py -q
48 passed
```

واجتاز التحقق الكامل في clone المصدر ثم في نسخة مؤقتة معزولة: `python -m compileall -q .` (exit 0) و`python -m pytest -q` (`711 passed, 1 skipped`). سبب التجاوز الوحيد أن `tests/test_real_provider_long_horizon.py` يتطلب بيانات اعتماد provider حي غير مضبوطة؛ لم يُشغّل provider حي أو هدف خارجي. الأوقات التفصيلية وإجراءات حفظ قواعد الاختبار موجودة في `MANUS_MISSION_STATE.md`.
