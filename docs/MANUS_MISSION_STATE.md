# حالة المهمة — M0

| الحقل | القيمة |
|---|---|
| `CURRENT_PHASE` | `M0` |
| `CURRENT_CHECKPOINT` | وثائق M0 فقط؛ SHA الخاص بالالتزام الأول سيُسجّل في تحديث checkpoint لاحق بدل وضع SHA ذاتي داخل الالتزام. |
| `COMPLETED_PHASES` | `M0` — inventory حي وسجل حالة. |
| `ACTIVE_WORK` | لا يوجد؛ M1 لم يبدأ. |
| `LAST_GOOD_SHA` | `NOT_RECORDED_YET` — يُملأ بعد إنشاء أول التزام M0 في تحديث checkpoint منفصل. |
| `BRANCH` | `manus/durable-runtime-fencing` |
| `BRANCH_BASE_SHA` | `8a3fd109c0e586db13ed48a7371ac9ad06465b74` — main الحي عند التحقق. |
| `BRANCH_BASE_PARENT` | `be24ae326c710145d192f13e167ef02bf2f51792` |
| `WORKTREE` | `/workspace/cybersentinel-m0-20261002-1329` |
| `REMOTE` | `origin https://github.com/mosfiry/cybersentinel.git` |
| `REMOTE_BRANCH_STATUS` | لم يكن الفرع موجودًا على remote عند فحص refs؛ النشر لم يُنفّذ بعد وقت إنشاء هذا السجل. |

## النطاق المنجز

- أُعيد التحقق من `HEAD` و`main` والفروع الحية مباشرة من GitHub، وسُجّلت بيانات commit الوصفية المسموح بها للفروع المحددة في `docs/MANUS_FENCING_INVENTORY.md`.
- أُنشئ clone جديد من `main` الحي وفرع محلي معزول عليه؛ لم تُستخدم شجرة العمل القديمة.
- أُجري جرد للكود والاختبارات والـAPI والـCI على الملفات المتعقبة، مع إبقاء أصول العميل والفروع المحمية خارج التعديل والقراءة.
- تغييرات M0 المسموح بها: هاتان الوثيقتان فقط. لا تغييرات Python أو واجهات أو حزم عميل.

## التحقق والاختبارات

| الحقل | القيمة |
|---|---|
| `PRE_COMMIT_DIFF_CHECK` | يُشغّل `git diff --check` بعد إعداد الوثيقتين؛ ليس اختبارًا وظيفيًا. |
| `TEST_COMMANDS` | لم تُشغّل في M0. |
| `PROJECT_TEST_COMMANDS` | `python -m compileall -q .` و`python -m pytest -q` موثقتان في `docs/TESTING.md`، لكنهما مؤجلتان عمدًا خارج نطاق M0. |
| `LIVE_ACCEPTANCE` | لم يُشغّل؛ لم يبدأ أي worker supervisor أو tick حي. |
| `KNOWN_FAILURES` | لا توجد نتيجة اختبار فاشلة من M0؛ الاختبارات لم تُشغّل. المخاطر المصدرية في inventory ليست أعطالًا جرى استنساخها. |

## الخطوة التالية المسجلة فقط — M1 غير مبدوء

قبل أي تنفيذ، اعتمد مسار تشغيل واحدًا للمهام: queue مع supervisor حي، أو المسار المتزامن الحالي. بعد ذلك صمّم واختبر fencing token متزايدًا يرتبط ذريًا بكل claim/reclaim ويُشترط في heartbeat وكتابات الحالة النهائية، ثم أضف اختبارات ABA بالـworker ID نفسه، اكتمال worker قديم بعد reclaim، والانهيار/timeout بعد dispatch أثر خارجي مع مصالحة قبل retry. حافظ على `AuthorizationDecision` وOwner authentication وscope/policy snapshots كما هي؛ لا توسّع الصلاحيات. هذه ملاحظة handoff فقط وليست إذنًا أو تنفيذًا لمرحلة M1.
