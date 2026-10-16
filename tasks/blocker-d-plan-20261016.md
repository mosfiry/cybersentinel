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
3. مصدر الحقيقة لإلغاء Owner والـdispatch وحالة Mission هو CAS دائم وفنس التنفيذ في SQLite، لا locks/events محلية. لا يعاد الأثر الخارجي الملتبس تلقائيًا.
4. MCP deadline يشمل طابور executor ويتحقق مجددًا عند send boundary؛ إلغاء queued future ومنع الإرسال المتأخر، مع إبقاء الأثر الذي بدأ إرساله ملتبسًا دون retry.
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

- deadline من قبل `submit` حتى حد إرسال socket؛ future cancellation عند الانتظار/الإلغاء؛ token/deadline عند worker boundary.
- لا retry لأثر بدأ إرساله. إرسال notification الإلغاء مستقل مع إعادة فحص Owner/Mission/Scope/Fence حتى بعد deadline التنفيذ.
- الاختبارات: ازدحام كل worker؛ RPC ينتهي في الطابور ولا يرسل بعد تحريره؛ race عند send؛ إرسال واحد فقط؛ رفض cancel notification المنتهك للنطاق.

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
| تلاعب أو تسريب عبر acceptance artifacts | receipts مربوطة، إسقاط allowlist، حذف النص الحر، ورفض السلسلة غير المكتملة |
| harness غير قادر على إثبات العملية التي أطلقها | لا قتل أو restart بالاسم/PID وحده؛ الاختبار يفشل بوضوح |

## معيار الاكتمال

لا تكتمل المهمة باكتمال الكود فقط. يجب أن تتوافق النتيجة مع سجلات التنفيذ والأحداث الفعلية، نجاح اختبارات Linux، وجود دليل Windows أصلي عند ادعاء نجاحه، سلامة checkpoints والـOwner/scope/fence، وعدم تعديل `main` أو tags/releases المحمية.
