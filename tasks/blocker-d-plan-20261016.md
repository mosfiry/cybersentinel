# خطة التنفيذ: CyberSentinel Blocker D — 2026-10-16

## الهدف

معالجة العوائق التشغيلية التي تمنع Mission من الإكمال الآمن، مع صون Owner authorization وScope Firewall وExecution Fence وعقد ToolSpec. العمل حصريًا على الفرع `fix/blocker-d-review-20261010`؛ لا دمج في `main` ولا tag/release `v5.2.0`.

## خط الأساس والحماية

- HEAD قبل العمل: `9e95fbbac83ea7edd6b6613f8956e0fd6abc0699`، والأب `f915490c28e3a0cdbd65a2a0b214b99ab167225b`.
- baseline المتوقع `34cca3b54f316b9989994e9327be1b91e306409b` سلف للفرع.
- GitHub المباشر: الفرع `9e95fbb…`؛ `main`=`8a3fd109c0e586db13ed48a7371ac9ad06465b74`؛ `v5.1.0` مفكوك إلى `26739d9b01b3b1ff492854e7e21789be20b1be0e`؛ صفحة Releases تعرض `v5.1.0` أحدث إصدار ولا تعرض `v5.2.0`.
- نقاط الحفظ قبل التنفيذ: `safety/blocker-d-pre-remediation-20261016` و` safety/blocker-d-pre-remediation-20261016-9e95fbb`، مع bundles كاملة متحققة في `/workspace/cybersentinel-review-checkpoint-20261016/`.
- `tasks/plan.md` و`tasks/todo.md` موجودان ويحتويان خطة M3 V10–V16 غير مكتملة؛ لا يُستبدلان. هذه الخطة وقائمتها منفصلتان.
- لا Windows تفاعلي في الجهاز الحالي. Windows backend الحالي محجوب fail-closed، وLinux runner لا يملك cgroup v2 مفوضة قابلة للكتابة. لا يدّعي الاختبار المحلي إثباتًا لهذين الجانبين.

## قرارات التصميم

1. لا Windows `Popen` عادي ولا تفعيل للـbackend قبل AppContainer/LPAC + ACL/ملفات + شبكة default-deny + disk/resource limits مثبتة + Job Object وإثبات Windows أصلي.
2. Linux `RLIMIT_AS` يبقى حدًا لكل عملية فقط؛ لا يعلن backend متاحًا دون cgroup v2 مفوضة ذات memory/pids aggregate limits وlauncher يدخل cgroup قبل `exec` وتنظيف موثوق. غياب التفويض يعني عدم التنفيذ.
3. مصدر الحقيقة لحالة Mission وقرار الإلغاء/dispatch هو CAS دائم وفنس التنفيذ في SQLite؛ قفلا OS للطلب والكتابة ينسقان النقل فقط ولا يحلان محل CAS. يُنشر cancel marker النهائي تحت قفل الكتابة نفسه المستخدم لكل socket write؛ لا يعاد الأثر الخارجي الملتبس تلقائيًا.
4. MCP deadline يشمل طابور executor وDNS وقفل الطلب والنقل؛ يبدأ `request_guard` بعد DNS، ثم يبقى حتى إغلاق socket. resolver bounded ومراقب للإلغاء؛ لا يعاد إرسال أثر بدأ إرساله.
5. أدلة القبول تعتمد receipt بدء OS حقيقي مربوطًا بالـMission والنداء والنتيجة. لا تسمح ببيانات أسرار أو نصوص exceptions الخام، ولا تصطنع نجاحًا أو أحداثًا.
6. Lifecycle acceptance يطلق التطبيق المثبت تحت Job مملوك للاختبار، ويتحقق من identity/creation time والـtree، وينهي Job المقصود فقط، ثم يستعيد Mission من الحالة الدائمة.

## مراحل التنفيذ واشتراطاتها

### المرحلة 0 — تحقق المستودع ونقطة الحفظ (مكتملة)

- تطابق GitHub/الفرع والبصمات وحالة clean.
- تحقق bundle baseline وإنشاء bundle/branch لرأس `9e95fbb` قبل تعديل الملفات.

### المرحلة 1 — توثيق التصميم قبل المصدر (مكتملة مبدئيًا)

- تحديث `docs/architecture/WINDOWS_PROCESS_SANDBOX_DESIGN_AR.md` بتصميم fail-closed، تفاصيل Linux cgroups وWindows Job/AppContainer، عقود الإلغاء/MCP/الأدلة/lifecycle، ومراجع المنصة.
- حفظ الفروق بcommit توثيقي منفصل قبل أي تعديل مصدر.

### المرحلة 2 — إغلاق سباقات Owner cancellation وdispatch والاستعادة

- CAS دائم ينسق marker مع transition `RESERVED → DISPATCHED` ويُبقي التحقق من fence/authorization.
- terminal state غير قابل للاستبدال بطلب cancel قديم؛ لا تستخدم `enqueue` لتنفيذ cancel.
- recovery/start/resume يتعاملان مع marker الدائم؛ no-effect فقط قبل dispatch المثبت؛ تحرير lock قبل handler طويل.
- الاختبارات: dispatch-vs-cancel عبر عمليات؛ cancel بعد terminal؛ restart/marker؛ non-process reservation؛ handler blocking.

### المرحلة 3 — حماية MCP executor من الإرسال المتأخر

- deadline من `submit` عبر DNS bounded وقفل request حتى أول إرسال/اكتمال النقل؛ token يعاد فحصه عند worker وsend boundary. DNS يسبق قفل الطلب، وخانات resolver محدودة؛ الإلغاء/المهلة تعيدان المستدعي قبل اكتمال resolver المحجوز دون إنشاء socket متأخر.
- يوقظ `.intent` watcher لإغلاق الاتصال فورًا، لكنه ليس commit دائمًا؛ يثبت `.cancel` تحت send lock بعد خروج أي socket write نشط. بعدها ينتظر Owner request gate حتى الإغلاق ثم يُنفذ CAS؛ لا retry لأثر بدأ إرساله، وnotification الإلغاء تبقى خاضعة لإعادة فحص Owner/Mission/Scope/Fence.
- الاختبارات: ازدحام كل worker؛ RPC ينتهي في الطابور؛ Owner cancel أثناء DNS/الاتصال/الكتابة/قراءة الرد؛ marker بعد الإغلاق؛ race عند أول send؛ إرسال واحد فقط؛ رفض notification المنتهك للنطاق.

### المرحلة 4 — عقد sandbox والحد الإجمالي وprocess receipts

- تدقيق جميع إطلاقات العمليات وToolSpec. الحفاظ على fail-closed Windows. لا يكفي Job منفرد.
- استلزام aggregate cgroup v2 Linux أو إرجاع unavailable/setup failure بلا `Popen`; عدم خفض RLIMIT الحالي. تمييز OOM الفعلي عن signal خارجي.
- دليل `process_started` بعد OS start فقط، PID موجب، timestamp وربطه بـdispatch/mission/task/action/call/result؛ فشل إنشاء process المثبت يصنف no-effect، والملتبس يبقى recovery required.
- اختبار shared contract وغياب backend/فشل setup/رفض التفويض والمسار/الشبكة/timeout/cancel/resources/cleanup/عدم بدء العملية.

### المرحلة 5 — أدلة القبول والتعقيم

- جعل verifier يرفض `ToolExecuted` أو evidence دون receipt OS start حقيقي ومطابق.
- allowlists/فحص secret-like لكل IDs والأكواد، وإزالة raw API/PowerShell exception وtraceback من artifacts؛ عدم تسجيل الأسرار أو البيانات غير الضرورية.
- اختبارات حذف/تزوير/عدم تطابق PID/timestamp/call؛ token/PAT/bearer مصطنع في كل حقل مقبول؛ Mission لا تكتمل بلا الأحداث المطلوبة.

### المرحلة 6 — عملية التطبيق في Windows acceptance

- آلية إطلاق موحدة أصلية تحت Job Object بامتلاك handles؛ إنشاء معلّق ثم assign/verify/resume، وحصر الإنهاء في Job الذي أطلقته الجولة.
- تحقق executable path/creation time/Job membership وCDP ownership؛ حفظ Mission ID والسجلات، إغلاق وانتظار tree بالكامل، ثم إعادة التشغيل والاستعادة من checkpoint دون replay.
- إذا لم تتوفر native Windows APIs أو إثبات الهوية، فشل صريح بلا process sweep/PID-only kill.

### المرحلة 7 — الاختبار والقبول والتقرير

- focused tests ثم كامل Linux suite وcompileall وdiff hygiene وsecret scan.
- تشغيل Windows build/CI على exact SHA في فرع المراجعة فقط. لا تعتبر mocks أو نجاح Linux إثباتًا لـWindows.
- إن بقي backend Windows أو cgroup integration غير مثبت، صنف النتيجة `PARTIALLY VERIFIED` أو `BLOCKED` بحسب الأثر؛ لا تعلن PASS.
- التحقق مستقلاً من عدم تغير `main` و`v5.1.0` وعدم وجود tag/release `v5.2.0`.

## ترتيب الالتزامات

- commit 1: التصميم المحدث والخطة/السجل فقط.
- commit 2+: تغييرات ذرية صغيرة حسب مراحل 2–6، مع اختبارات مرتبطة بكل إصلاح.
- الدفع، إن تم، non-force إلى `fix/blocker-d-review-20261010` فقط. لا تعدّل refs محمية ولا تنشئ release.

## المخاطر والقيود

| الخطر | المعالجة |
|---|---|
| عدم توافر AppContainer/ACL/حصة قرص أو Windows runtime أصلي | يظل Windows execution محجوبًا مع سبب رفض دقيق؛ لا fallback |
| لا يوجد cgroup delegation في runner الحالي | لا تنفذ process sandbox محليًا؛ لا تدّعِ إثبات aggregate limits |
| اختلاف terminal/cancel عبر مخازن SQLite | transaction واحدة/attached DB مع rollback journal أو رفض آمن؛ لا Python lock كضمان |
| MCP أثر خارجي بدأ قبل timeout | نتيجة ambiguous بلا replay، وnotification إلغاء منفصلة بعد authorization/scope checks |
| OS DNS resolver لا يقبل الإنهاء عند التعليق | لا يُمسك قفلًا أثناء DNS؛ أربعة daemon slots كحد أقصى، وإلا fail-closed عند امتلائها؛ لا socket من نتيجة متأخرة |
| اختلاف دلالات lock عبر أنظمة الملفات/المضيفين | قصر التشغيل على filesystem محلي ذي دلالات قفل متحققة؛ لا ادعاء distributed locking، وWindows `msvcrt.locking` يحتاج قبولًا أصليًا |
| crash بعد `.intent` وقبل/أثناء cancel CAS | fail-closed ومنع dispatch؛ لا مسح تلقائي، والتعافي يتطلب مطابقة marker مع SQLite وOwner authority قبل أي رفع للحظر |
| تلاعب أو تسريب عبر acceptance artifacts | receipts مربوطة، إسقاط allowlist، حذف النص الحر، ورفض السلسلة غير المكتملة |
| harness غير قادر على إثبات العملية التي أطلقها | لا قتل أو restart بالاسم/PID وحده؛ الاختبار يفشل بوضوح |

## معيار الاكتمال

لا تكتمل المهمة باكتمال الكود فقط. يجب أن تتوافق النتيجة مع سجلات التنفيذ والأحداث الفعلية، نجاح اختبارات Linux، وجود دليل Windows أصلي عند ادعاء نجاحه، سلامة checkpoints والـOwner/scope/fence، وعدم تعديل `main` أو tags/releases المحمية.

## حالة التنفيذ والتحقق — 2026-10-17

- **نفذ برمجيًا:** CAS دائمة للإلغاء/dispatch/terminal/recovery؛ bounded DNS cancellation؛ `.intent` للإيقاظ و`.cancel` النهائي المتسلسل مع كل socket write عبر per-Mission OS send gate؛ request gate ممتد لدورة HTTP؛ Linux cgroup-v2 aggregate limits مع fail-closed إذا لم يوجد delegation؛ process receipts؛ verifier وallowlists للأدلة؛ harness lifecycle مملوك عبر Win32 Job Object.
- **الاختبارات المركزة بعد إصلاح السباق:** `tests/test_dispatch_gate.py tests/test_mcp_client.py tests/test_pinned_http.py tests/test_external_effect_ledger.py` → `73 passed`.
- **Linux full suite النهائي الحالي:** `python -m pytest -q` → `1992 passed, 25 skipped, 4 warnings` (exit 0)، ثم `compileall` للملفات المتغيرة و`git diff --check` دون أخطاء. بقيت اختبارات التكامل المعتمدة على capability الفعلية gated؛ probe سابق أعاد `cgroup_v2_delegation_unavailable`. تحذيرات multiprocessing/fork لا تفشل الاختبارات.
- **المراجعة المستقلة:** لا findings بمستوى P1/P2 في مسار إلغاء Owner وكتابة MCP بعد إضافة send gate. حدود المراجعة: لم يُشغّل Windows native؛ وقد تصل بايتات سبق أن قبلها kernel socket buffer إلى النظير بعد لحظة marker، لكن لا تبدأ كتابة تطبيقية جديدة بعد `.cancel` النهائي ولا يحدث Owner SQLite CAS قبل إغلاق الطلب.
- **الحالة:** **PARTIALLY VERIFIED**؛ لا توجد أدلة قبول Windows أصلية. لا يتوفر backend Windows AppContainer/LPAC، لذلك يظل Windows process execution fail-closed (`windows_appcontainer_backend_unimplemented`). `WindowsOwnedJob` يدير lifecycle المقبول فقط ولا يثبت عزل Mission process. Linux `cgroup_v2_delegation_unavailable` يمنع إثبات تشغيل sandbox فعلي في هذه البيئة.
- **المتبقي:** secret scan، commits ذرية، push fast-forward لفرع المراجعة فقط بعد فحص العمل؛ Windows build/Job acceptance لا يمكن إثباتهما دون Windows أصلي؛ لا دمج إلى `main` ولا tag/release `v5.2`.
