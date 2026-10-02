# حالة المهمة — M2.b

| الحقل | القيمة |
|---|---|
| `CURRENT_PHASE` | `M2.b` — claim-fenced mission-owned evidence chain + حفظ verification state مع mission؛ لا يعني cutover إنتاجيًا. |
| `CURRENT_CHECKPOINT` | `M2.b` مقبول بالاختبارات المركزة؛ parent المباشر `8724cd16b63f28f41260952e6119f18dcbbb072f`؛ لا يُسجل SHA ذاتيًا هنا. |
| `LAST_GOOD_SHA` | `8724cd16b63f28f41260952e6119f18dcbbb072f` — checkpoint M2.a المنشور والمتحقق قبل M2.b وparent المقصود لهذا checkpoint. |
| `BRANCH` | `manus/durable-runtime-fencing` |
| `REMOTE_BASE_SHA` | `8724cd16b63f28f41260952e6119f18dcbbb072f` — SHA البعيد المطابق قبل التعديل في هذا checkpoint. |
| `COMPLETED_PHASES` | `M0`, `M1`, `M2.a`, `M2.b` — M2.b يثبت worker mission-owned evidence append فقط تحت claim/revision في authority file نفسه؛ Workspace legacy chain وinline `/api/chat` بلا fencing. |
| `ACTIVE_WORK` | `M2.b acceptance complete; no full-suite/cutover claim; next M2.c` |
| `WORKTREE` | `/workspace/cybersentinel-m0-20261002-1329` |
| `DESIGN` | `docs/MANUS_M2_ARCHITECTURE.md`; أدلة M2.a في `docs/MANUS_M2A_EVIDENCE.md` وأدلة M2.b وحدوده في `docs/MANUS_M2B_EVIDENCE.md`. |
| `NEXT_ACTION` | `M2.c` — ExternalEffectIntent PREPARED/DISPATCHING/outcome/UNKNOWN، crash recovery وreconciliation صريح؛ لا retry آلي ولا M2.d cutover. |
| `NEXT_TEST_COMMAND` | `python -m pytest tests/test_effect_intent_recovery.py tests/test_external_effect_unknown.py -q` |
| `CHECKPOINT_VERIFICATION` | M2.b+M2.a targeted: 64 passed؛ adaptive: 24 passed؛ compileall للملفات خارج `web/`: pass؛ `git diff --check`: pass؛ full suite لم تُشغّل حفاظًا على حدود `web/` وقواعد SQLite. انظر `docs/MANUS_M2B_EVIDENCE.md`. |

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

`NEXT_ACTION=M2.c`

ابدأ M2.c من checkpoint M2.b المنشور: أضف حالات intent الدائمة `PREPARED` و`DISPATCHING` والنتيجة المعروفة/`UNKNOWN`، ثم crash recovery إلى `RECOVERY_REQUIRED` و`OWNER_RECONCILIATION_REQUIRED` بلا retry تلقائي. اختبرها فقط بأدوات fake محلية عبر:

```bash
python -m pytest tests/test_effect_intent_recovery.py tests/test_external_effect_unknown.py -q
```

لا تبدأ supervisor/API cutover؛ يظل M2.d منفصلًا بعد قبول M2.c.
