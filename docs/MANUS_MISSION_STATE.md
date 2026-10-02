# حالة المهمة — M2.c

| الحقل | القيمة |
|---|---|
| `CURRENT_PHASE` | `M2.c` — مستودع ExternalEffectIntent وحالاته على ملف authority؛ dispatch integration في runtime الإنتاجي **UNVERIFIED** ولا يعني cutover. |
| `CURRENT_CHECKPOINT` | طبقة repository/state machine مقبولة بالاختبارات المركزة؛ parent المباشر `0ea1b8bd09a69e22a0e50dd1e6210ee0e7be0044`؛ لا يُسجل SHA ذاتيًا هنا. |
| `LAST_GOOD_SHA` | `0ea1b8bd09a69e22a0e50dd1e6210ee0e7be0044` — base المطابق قبل هذا checkpoint، وليس SHA ذاتيًا. |
| `BRANCH` | `manus/durable-runtime-fencing` |
| `REMOTE_BASE_SHA` | `0ea1b8bd09a69e22a0e50dd1e6210ee0e7be0044` — SHA البعيد المطابق قبل التعديل في هذا checkpoint. |
| `COMPLETED_PHASES` | `M0`, `M1`, `M2.a`, `M2.b`, `M2.c (repository/state-machine layer)`؛ dispatch الفعلي ما زال **UNVERIFIED**. |
| `ACTIVE_WORK` | `M2.c repository acceptance complete; no worker/adapter integration, supervisor cutover, or full-suite claim.` |
| `WORKTREE` | `/workspace/cybersentinel-m0-20261002-1329` |
| `DESIGN` | `docs/MANUS_M2_ARCHITECTURE.md`; الأدلة في `docs/MANUS_M2A_EVIDENCE.md`, `docs/MANUS_M2B_EVIDENCE.md`, `docs/MANUS_M2C_EVIDENCE.md`. |
| `NEXT_ACTION` | `M2.d` فقط بعد قبول طبقة M2.c: ربط adapter/worker والتحقق من dispatch fencing قبل أي supervisor cutover؛ لا يُنفذ هذا هنا. |
| `NEXT_TEST_COMMAND` | `python -m pytest tests/test_effect_intent_recovery.py tests/test_external_effect_unknown.py -q` |
| `CHECKPOINT_VERIFICATION` | M2.c + regressions: 76 passed؛ adaptive: 24 passed؛ compileall للملفات خارج `web/`: pass؛ focused M2.c: 12 passed؛ لا full-suite أو live-provider/network test. انظر `docs/MANUS_M2C_EVIDENCE.md`. |

## وضع تنفيذ M2.c

- أُضيف `PREPARED` و`DISPATCHING` و`CONFIRMED` و`DEFINITE_NOT_SENT` و`FAILED` و`UNKNOWN`، مع attempt history مربوطة بـclaim generation، ومفاتيح effect/idempotency ثابتة للعمل المنطقي نفسه.
- prepare/checkpoint، confirmation/result/evidence، وcrash-to-UNKNOWN تُحفظ على ملف SQLite السلطوي ومعاملة واحدة؛ الكتابات تفحص claim الحالي وmission revision.
- الاختبارات تثبت `UNKNOWN` بعد reopen/reclaim ورفض الإرسال التلقائي، وrollback الذري. لكنها تختبر واجهة المستودع الفعلية مع قواعد مؤقتة، لا adapter يستدعي أداة خارجية.
- لم يوجد مسار إنتاجي يربط `MissionWorker` بمسارات `AgentCore`/`MissionRuntime` inline؛ لذلك **DISPATCH INTEGRATION=UNVERIFIED**، و`/api/chat`/supervisor لم يتغيرا. التفاصيل في `docs/MANUS_M2C_EVIDENCE.md`.

## وضع تنفيذ M2.a

- أُثبت اختبار A/B أحمر على base قبل الإصلاح ثم أخضر بعده؛ revision CAS والتحقق من claim يقعان في transaction واحدة على authority file نفسه.
- **write-fencing للمسار الإنتاجي الحالي غير متحقق:** `/api/chat` ما زال inline بلا claim، وتهيئة bridge تفصل mission وqueue. لا يُدّعى أن الكود يحمي هذا المسار أو أي عامل لا يستخدم binding. لم يحدث supervisor/API cutover.
- المخاطر والحدود الدقيقة وجرد قواعد الاختبار ignored موثقة في `docs/MANUS_M2A_EVIDENCE.md`.

## الأساس التاريخي المحفوظ

- كان HEAD المنشور عند بدء العمل `579387ff58910c14d8ca277cfdd68535220be846` على الفرع `manus/durable-runtime-fencing`، وطابق `git ls-remote` قبل التعديل. كانت الشجرة نظيفة، وparent M2 design المقصود هو SHA نفسه.
- checkpoint تنفيذ M1 التاريخي هو `4df8958ef38f49254eb35108e24060a8000d7c29`؛ وسجل M1 السابق نتائج اختبارات queue/fencing. المرجع التفصيلي التاريخي باقٍ في هذا الملف قبل checkpoint وفي `docs/MANUS_LEASE_SEMANTICS.md` و`docs/MANUS_FENCING_INVENTORY.md`.
- لا تعدّل جرد M0/M1 التاريخي لإظهار deployment أو قبول لم يحدث. لم تُجرَ migration لبيانات قديمة في M2 design.

## القرار والمخاطر المعروفة

يعتمد التصميم على queue+supervisor كسلطة التنفيذ الإنتاجية الوحيدة بعد cutover صريح في M2.d. إلى أن تثبت M2.a–M2.c المخزن والكتابات fenced، يبقى `/api/chat` على تنفيذه المتزامن الحالي، ولا يعمل supervisor كسلطة ثانية. عند cutover يحافظ handler على عقد HTTP المتزامن لكنه ينتظر نتيجة supervisor، فلا ينفذ المهمة inline.

مخاطر/مجهولات رئيسية:

- mission وqueue وscheduler وtask/evidence موزعة حاليًا بين قواعد SQLite؛ لا تُفترض ذرية كتابة عبر ملفات. إعداد `journal_mode` الحالي غير مثبت. التصميم يوصي بملف SQLite سلطوي واحد/repository transaction؛ وتوثيق SQLite الرسمي يذكر قيد ذرية `ATTACH` مع WAL: [ATTACH DATABASE](https://sqlite.org/lang_attach.html) و[WAL](https://www.sqlite.org/wal.html).
- فحص lease ثم كتابة mission في مخزن آخر لا يوفّر fencing عابرًا للمخازن. يجب أن يصبح تحقق claim وكتابة mission/evidence/proof/intent ذرّيًا في repository واحد.
- أثر خارجي قد يبدأ ثم تضيع نتيجته. تبقى المهمة `RECOVERY_REQUIRED` والـintent `OWNER_RECONCILIATION_REQUIRED` بلا retry آلي؛ لا exactly-once عام. توجد race/TOCTOU بين فحص DB ونداء الخدمة، وSQLite لا يستطيع إلغاء أثر بدأ بالفعل.
- `/api/chat` قد يستمر متزامنًا أطول من مهلات العميل أو الوسيط بعد cutover، بينما supervisor يواصل العمل بعد انقطاع HTTP. واجهة async أو UI قرار phase منفصل إذا تقرر.
- القدرات الخارجية (idempotency keys/receipts)، إعدادات تشغيل supervisor، وربط كل صفوف legacy لم تُثبت بعد؛ أي تعارض في migration يبقى محفوظًا ولا يحل باستبدال أو حذف.
- `M3–M15` خارج M2؛ تبنى لاحقًا من checkpoint M2 المقبول وفق مراحل مستقلة، دون إعادة تعريفها أو الادعاء بإنجازها هنا.

## الخطوة التالية

`NEXT_ACTION=M2.d` (بعد قبول طبقة repository في M2.c؛ dispatch integration ما زال UNVERIFIED)

M2.c repository/state-machine layer مكتمل ومقبول. يبقى unknown ظاهرًا ويتطلب reconciliation صريحًا؛ لا يوجد Owner UI/API يغيره، ولا يُسمح بإعادة dispatch آلية. في M2.d يجب وصل عامل/adapter فعلي بعد إثبات مصدره وحدود authority، ثم فقط تقييم supervisor cutover.

لا تبدأ supervisor/API cutover قبل إثبات أن كل dispatch يكتب `DISPATCHING` على authority قبل بدء الاتصال، وأن timeout/reclaim/crash ينتج `UNKNOWN` بلا retry. سجلات M2.a/M2.b التاريخية أعلاه وفي ملفات أدلتها محفوظة.
