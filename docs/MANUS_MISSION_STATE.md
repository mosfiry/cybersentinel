# حالة المهمة — M2.d.dispatch

| الحقل | القيمة |
|---|---|
| `CURRENT_PHASE` | `M2.d.dispatch` — تكامل claim-bound `MissionWorker` مع `MissionRuntime` وeffect-intent gate مختبَر محليًا؛ supervisor/API production cutover **UNVERIFIED**. |
| `CURRENT_CHECKPOINT` | dispatch integration فقط؛ parent المباشر `0799147d7dacdbf24487e10e2384d94e4c515d9a`؛ لا يُسجل SHA ذاتيًا هنا. |
| `LAST_GOOD_SHA` | `0799147d7dacdbf24487e10e2384d94e4c515d9a` — base المطابق قبل هذا checkpoint، وليس SHA ذاتيًا. |
| `BRANCH` | `manus/durable-runtime-fencing` |
| `REMOTE_BASE_SHA` | `0799147d7dacdbf24487e10e2384d94e4c515d9a` — SHA البعيد المطابق قبل التعديل في هذا checkpoint. |
| `COMPLETED_PHASES` | `M0`, `M1`, `M2.a`, `M2.b`, `M2.c (repository/state-machine layer)`, `M2.d.dispatch`؛ supervisor cutover ما زال **UNVERIFIED**. |
| `ACTIVE_WORK` | `M2.d.dispatch integration tested; no production supervisor/API cutover or full-suite claim.` |
| `WORKTREE` | `/workspace/cybersentinel-m0-20261002-1329` |
| `DESIGN` | `docs/MANUS_M2_ARCHITECTURE.md`; الأدلة في `docs/MANUS_M2A_EVIDENCE.md`, `docs/MANUS_M2B_EVIDENCE.md`, `docs/MANUS_M2C_EVIDENCE.md`, `docs/MANUS_M2D_DISPATCH_EVIDENCE.md`. |
| `NEXT_ACTION` | `M2.d.supervisor` — cutover خطوة مستقلة وغير منفذة هنا. |
| `NEXT_TEST_COMMAND` | `python -m pytest tests/test_m2d_dispatch_integration.py -q` |
| `CHECKPOINT_VERIFICATION` | M2.d.dispatch: focused 7 passed؛ مجموعة M2.a–M2.c والمسارات المتأثرة 104 passed؛ adaptive 24 passed؛ compileall للملفات المتأثرة خارج `web/` و`git diff --check` ناجحان. لم تُشغل full suite أو live-provider/network tests. انظر `docs/MANUS_M2D_DISPATCH_EVIDENCE.md`. |

## وضع تنفيذ M2.d.dispatch

- يربط `MissionWorker.run_once()` الـclaim snapshot ببوابة `MissionEffectDispatcher` قبل أي executor أو Registry handler في worker-bound `MissionRuntime`، ويحوّل `DISPATCHING` غير المكتمل عند reclaim إلى `UNKNOWN/RECOVERY_REQUIRED` قبل تشغيل أي slice.
- الاختبارات المحلية تثبت commit الحالة قبل دخول handler، confirmation ذريًا مع mission/evidence، رفض نتيجة العامل القديم بعد reclaim، restart بلا إعادة إرسال، rollback عند فشل الحفظ، ومفتاحًا ثابتًا عبر retry بعد `PREPARED`. مسارا native الفردي والمتوازي يمران بالبوابة؛ المتوازي يُسلسل في worker mode.
- هذا **dispatch integration tested but not production cutover**. لا يثبت حماية مسارات inline خارج Worker، ولا exactly-once أو منع خدمة خارجية من استقبال call عبر سباق TOCTOU. لا تغييرات في API أو supervisor.

## وضع تنفيذ M2.c

- أُضيف `PREPARED` و`DISPATCHING` و`CONFIRMED` و`DEFINITE_NOT_SENT` و`FAILED` و`UNKNOWN`، مع attempt history مربوطة بـclaim generation، ومفاتيح effect/idempotency ثابتة للعمل المنطقي نفسه.
- prepare/checkpoint، confirmation/result/evidence، وcrash-to-UNKNOWN تُحفظ على ملف SQLite السلطوي ومعاملة واحدة؛ الكتابات تفحص claim الحالي وmission revision.
- الاختبارات تثبت `UNKNOWN` بعد reopen/reclaim ورفض الإرسال التلقائي، وrollback الذري. لكنها تختبر واجهة المستودع الفعلية مع قواعد مؤقتة، لا adapter يستدعي أداة خارجية.
- عند checkpoint M2.c لم يكن `MissionWorker` مربوطًا بمسارات `AgentCore`/`MissionRuntime`؛ كان **DISPATCH INTEGRATION=UNVERIFIED** حينها، وتجاوزه الآن أدلة M2.d أعلاه. لم يتغير `/api/chat` أو supervisor. التفاصيل التاريخية في `docs/MANUS_M2C_EVIDENCE.md`.

## وضع تنفيذ M2.a

- أُثبت اختبار A/B أحمر على base قبل الإصلاح ثم أخضر بعده؛ revision CAS والتحقق من claim يقعان في transaction واحدة على authority file نفسه.
- **write-fencing للمسار الإنتاجي الحالي غير متحقق:** `/api/chat` ما زال inline بلا claim، وتهيئة bridge تفصل mission وqueue. لا يُدّعى أن الكود يحمي هذا المسار أو أي عامل لا يستخدم binding. لم يحدث supervisor/API cutover.
- المخاطر والحدود الدقيقة وجرد قواعد الاختبار ignored موثقة في `docs/MANUS_M2A_EVIDENCE.md`.

## الأساس التاريخي المحفوظ

- كان HEAD المنشور عند بدء العمل `579387ff58910c14d8ca277cfdd68535220be846` على الفرع `manus/durable-runtime-fencing`، وطابق `git ls-remote` قبل التعديل. كانت الشجرة نظيفة، وparent M2 design المقصود هو SHA نفسه.
- checkpoint تنفيذ M1 التاريخي هو `4df8958ef38f49254eb35108e24060a8000d7c29`؛ وسجل M1 السابق نتائج اختبارات queue/fencing. المرجع التفصيلي التاريخي باقٍ في هذا الملف قبل checkpoint وفي `docs/MANUS_LEASE_SEMANTICS.md` و`docs/MANUS_FENCING_INVENTORY.md`.
- لا تعدّل جرد M0/M1 التاريخي لإظهار deployment أو قبول لم يحدث. لم تُجرَ migration لبيانات قديمة في M2 design.

## القرار والمخاطر المعروفة

يعتمد التصميم على queue+supervisor كسلطة التنفيذ الإنتاجية الوحيدة بعد cutover صريح في M2.d.supervisor. إلى أن تنفذ تلك الخطوة المستقلة، يبقى `/api/chat` على تنفيذه المتزامن الحالي، ولا يعمل supervisor كسلطة ثانية. عند cutover يحافظ handler على عقد HTTP المتزامن لكنه ينتظر نتيجة المهمة التي نفذها supervisor، فلا ينفذها handler inline.

مخاطر/مجهولات رئيسية:

- mission وqueue وscheduler وtask/evidence موزعة حاليًا بين قواعد SQLite؛ لا تُفترض ذرية كتابة عبر ملفات. إعداد `journal_mode` الحالي غير مثبت. التصميم يوصي بملف SQLite سلطوي واحد/repository transaction؛ وتوثيق SQLite الرسمي يذكر قيد ذرية `ATTACH` مع WAL: [ATTACH DATABASE](https://sqlite.org/lang_attach.html) و[WAL](https://www.sqlite.org/wal.html).
- فحص lease ثم كتابة mission في مخزن آخر لا يوفّر fencing عابرًا للمخازن. يجب أن يصبح تحقق claim وكتابة mission/evidence/proof/intent ذرّيًا في repository واحد.
- أثر خارجي قد يبدأ ثم تضيع نتيجته. تبقى المهمة `RECOVERY_REQUIRED` والـintent `OWNER_RECONCILIATION_REQUIRED` بلا retry آلي؛ لا exactly-once عام. توجد race/TOCTOU بين فحص DB ونداء الخدمة، وSQLite لا يستطيع إلغاء أثر بدأ بالفعل.
- `/api/chat` قد يستمر متزامنًا أطول من مهلات العميل أو الوسيط بعد cutover، بينما supervisor يواصل العمل بعد انقطاع HTTP. واجهة async أو UI قرار phase منفصل إذا تقرر.
- القدرات الخارجية (idempotency keys/receipts)، إعدادات تشغيل supervisor، وربط كل صفوف legacy لم تُثبت بعد؛ أي تعارض في migration يبقى محفوظًا ولا يحل باستبدال أو حذف.
- `M3–M15` خارج M2؛ تبنى لاحقًا من checkpoint M2 المقبول وفق مراحل مستقلة، دون إعادة تعريفها أو الادعاء بإنجازها هنا.

## الخطوة التالية

`NEXT_ACTION=M2.d.supervisor` (بعد قبول repository وdispatch integration؛ هذه الخطوة لم تبدأ)

طبقة M2.c وتكامل M2.d.dispatch مقبولان بالاختبارات المحددة. يبقى `UNKNOWN` ظاهرًا ويتطلب reconciliation صريحًا؛ لا يوجد Owner UI/API يغيره، ولا يُسمح بإعادة dispatch آلية. الخطوة التالية فقط هي تقييم/تنفيذ supervisor cutover ضمن نطاق مستقل.

لم يحدث supervisor/API cutover في هذا checkpoint. يلزم قبل تشغيله مراجعة حدود authority والتكاملات المتبقية وخطة cutover، مع الحفاظ على سجلات M2.a–M2.d وأدلتها كما هي.
