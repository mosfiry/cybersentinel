# حالة المهمة — M2 Architecture Design

| الحقل | القيمة |
|---|---|
| `CURRENT_PHASE` | `M2` — تصميم اختيار سلطة التنفيذ وربط claim بكتابات mission/evidence/proof/intents. |
| `CURRENT_CHECKPOINT` | `design` — وثيقة تصميم فقط؛ لا تنفيذ M2. commit هذا checkpoint أبوه `579387ff58910c14d8ca277cfdd68535220be846`؛ لا يُسجل SHA ذاتيًا هنا. |
| `LAST_GOOD_SHA` | `579387ff58910c14d8ca277cfdd68535220be846` — HEAD المنشور الذي تحقق قبل التعديل؛ ليس commit هذا checkpoint. |
| `BRANCH` | `manus/durable-runtime-fencing` |
| `REMOTE_BASE_SHA` | `579387ff58910c14d8ca277cfdd68535220be846` — نتيجة `git ls-remote origin refs/heads/manus/durable-runtime-fencing` قبل العمل. |
| `COMPLETED_PHASES` | `M0`, `M1` — M0 جرد توثيقي؛ M1 تنفيذ محلي لlease fencing في queue واختباراته وcheckpointه السابق. لا يعني ذلك اكتمال M2 أو deployment/قبول حي. |
| `ACTIVE_WORK` | `implementation not started` |
| `WORKTREE` | `/workspace/cybersentinel-m0-20261002-1329` |
| `DESIGN` | `docs/MANUS_M2_ARCHITECTURE.md` — قرار queue+supervisor كسلطة إنتاجية وحيدة بعد cutover M2.d، مع إبقاء `/api/chat` متزامنًا حتى ذلك الحين. |
| `NEXT_ACTION` | `M2.a` |
| `NEXT_TEST_COMMAND` | `python -m pytest tests/test_mission_store_fencing.py tests/test_mission_queue_fencing.py -q` (اختبار مستقبلي للخطوة M2.a؛ لم يُشغّل في checkpoint التصميم). |
| `CHECKPOINT_VERIFICATION` | شُغّل `git diff --check` فقط، ورُوجعت مسارات diff و`git status`. لا اختبار وظيفي أو compile أو قبول/deployment في هذا checkpoint. |

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

`NEXT_ACTION=M2.a`

اختبار القبول المخطط (لا يُشغّل إلا ضمن تنفيذ M2.a):

```bash
python -m pytest tests/test_mission_store_fencing.py tests/test_mission_queue_fencing.py -q
```

يجب أن يضيف M2.a انحدار stale A/B حتميًا: يطالب A، ثم يطالب B generation التالية، ويرفض أي كتابة mission من A بلا تغيير لصف B أو mission revision، ويقبل كتابة B. لا تبدأ M2.b قبل قبول ذلك وتسجيل checkpoint مستقل.
