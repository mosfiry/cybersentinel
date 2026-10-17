# قائمة تنفيذ Blocker D — 2026-10-16

## التحضير
- [x] التحقق read-only من GitHub والفرع والبصمات و`main` و`v5.1.0` وغياب `v5.2.0` في صفحة Releases.
- [x] التحقق من baseline ancestor ومن نظافة الفرع عند `9e95fbb`.
- [x] التحقق من bundle baseline وإنشاء bundle منفصل كامل لرأس ما قبل remediation.
- [x] مراجعة الملفات/ToolSpecs ومسارات process launch والمشاكل العشرة من المراجعة المستقلة السابقة.
- [x] توثيق التصميم المنقح قبل تغييرات المصدر.

## المهمة 1: CAS الإلغاء وdispatch والنهائية
- [x] جعل queue cancel marker وeffect dispatch يتنافسان عبر CAS دائم وفنس، لا lock محليًا فقط.
- [x] منع stale cancellation من تغيير terminal Mission/queue.
- [x] استعادة marker أثناء restart ومنع READY/start/resume حتى معالجة الإلغاء.
- [x] إغلاق `RESERVED` no-effect فقط عند إثبات عدم dispatch، وفصل lock القصير عن handler.
- [x] اختبارات عبر أكثر من process، race terminal، recovery، reservation وhandler طويل.

## المهمة 2: deadline وإلغاء MCP
- [x] جعل deadline يحتسب وقت طابور executor ويصل إلى حد إرسال الطلب.
- [x] إلغاء Future إذا كانت queued، واستخدام token يمنع أي إرسال متأخر.
- [x] إبقاء external outcome ambiguous بلا retry إذا بدأ الإرسال.
- [x] السماح بإشعار cancellation مستقل بعد إعادة فحص Owner/Mission/Scope/Fence حتى مع انتهاء deadline.
- [x] نقل قفل الطلب وOS request gate إلى ما بعد DNS، وإبقاؤه حتى إغلاق connection كاملًا.
- [x] جعل DNS deadline-aware وcancel-aware بعامل daemon محدود (أربعة slots)؛ لا تنشئ نتيجة resolver المتأخرة socket، وامتلاء السعة يفشل مغلقًا.
- [x] إضافة per-Mission OS `send_guard` يحيط بإعادة تفويض أول send وcallback dispatch وكل socket write، ويثبت `.cancel` النهائي تحت القفل نفسه.
- [x] فصل `.intent` interrupt signal عن `.cancel` النهائي؛ watcher يغلق socket فورًا، وأي write نشط يخرج من القسم الحرج قبل durable marker النهائي.
- [x] اختبارات DNS cancellation، partial body write، response-read socket close، race بين فحص الإلغاء وأول send، وsubprocess cross-process send-lock.

## المهمة 3: عقد process sandbox وLinux موارد إجمالية
- [x] تثبيت inventory لكل عمليات subprocess، مع إبقاء browser/local-model كمسارات مستقلة محدودة.
- [x] عدم إعلان Linux backend متاحًا دون delegated cgroup v2 aggregate memory/pids وcleanup.
- [x] عدم تنفيذ `Popen` عند غياب متطلبات cgroup أو فشل تهيئتها.
- [x] إضافة OOM/resource classification دون خلط timeout/cancel أو command failure.
- [x] اشتراط عدادات `memory.events.local`/`memory.events` و`pids.events` المكتملة، وإرجاع فشل sandbox آمن عند تعذر attribution بدل تخمين سبب OOM/SIGKILL.
- [x] توفير process-start receipt وتصنيف فشل البدء المثبت مقابل الحالة الملتبسة.
- [x] اختبار عقد fail-closed؛ **السماح بتشغيل sandbox حقيقي غير متاح هنا** لأن probe الإنتاج أعاد `cgroup_v2_delegation_unavailable`.
- [x] إحاطة OpenSSL وخادم MCP في acceptance بحد زمني وملكية شجرة: Job Object على Windows، وcgroup عند إعداده أو process-group cleanup متحقق على POSIX.

## نقطة تحقق A — baseline سابق
- [x] المجموعة المركزة `python -m pytest -q tests/test_windows_acceptance_harness.py tests/test_windows_process_job.py tests/test_process_sandbox_contract.py` → 300 passed, 4 skipped، exit 0 (قبل capability gates).
- [x] المجموعة الكاملة السابقة `python -m pytest -q` → 1973 passed, 25 skipped, 4 warnings، exit 0. تخطت اختبارات process integration التي تتطلب backend حيًا عبر probe الإنتاج `cgroup_v2_delegation_unavailable`؛ لم تُستخدم محاكاة لإثبات sandbox.

## المهمة 4: verifier وأدلة القبول والخصوصية
- [x] اشتراط process_started حقيقي وPID موجب وtimestamp صالح وربط كل الهوية والنتيجة.
- [x] استخدام allowlists/secret pattern guard للأكواد وIDs.
- [x] حذف raw exception/traceback من PowerShell/API acceptance artifacts؛ full E2E يحتفظ فقط ببيانات الخطأ المنقحة ولا ينشئ sidecar خامًا.
- [x] اختبارات سلبية للأدلة الناقصة/غير المتطابقة والأسرار في الحقول المقبولة.
- [x] عدم قبول إكمال Mission دون timeline/evidence/terminal status الحقيقي.
- [x] full E2E يسجل الخطأ عبر `safe_acceptance_error` ويمتنع عن إنشاء `failure-traceback.txt` خام؛ اختُبر غياب sidecar صراحة.

## المهمة 5: harness إغلاق/إعادة فتح التطبيق
- [x] تنفيذ الإطلاق وإعادة الإطلاق عبر Job Object مملوك للاختبار مع process handle محفوظ.
- [x] تنفيذ تحقق executable path وcreation time وJob membership وCDP.
- [x] إنهاء Job المقصود والتحقق من كل الأعضاء بدل PID-only `taskkill` أو process sweep.
- [x] إرجاع PowerShell exit code غير صفري لأي نتيجة غير `PASS` كي لا يمر فشل harness في CI.
- [ ] تشغيل اختبار Job الأصلي وإثبات استعادة Mission/السجلات على Windows حقيقي؛ غير متاح في البيئة الحالية.
- [x] الفشل بوضوح إذا تعذر إثبات هوية العملية.

## المهمة 6: التحقق والتقرير والتسليم
- [x] full `python -m pytest -q` → `2019 passed, 27 skipped, 4 warnings`؛ exit 0.
- [x] اختبار helper مركّز لشجرة processes وcgroup وacceptance sanitizer؛ smoke فعلي أنشأ شهادة قصيرة العمر وشغّل/أوقف MCP fixture على loopback، وكلها PASS.
- [x] اختبارات مركزة `tests/test_dispatch_gate.py tests/test_mcp_client.py tests/test_pinned_http.py tests/test_external_effect_ledger.py` بعد send-lock → `73 passed`.
- [x] `compileall` للملفات المتغيرة و`git diff --check` بعد التغييرات الأخيرة.
- [x] مراجعة cancellation/send السابقة لم تجد P1/P2؛ المراجعة النهائية الإضافية عثرت على attribution وfixture-cleanup gaps، أُغلقت مع regression tests.
- [x] secret-shape scan للأسطر المضافة والملفات الجديدة: `0` matches؛ canaries في اختبارات sanitizer مركبة من أجزاء وليست credentials صالحة.
- [ ] Windows build/CI على SHA الجديد وWindows Job acceptance؛ يتطلب Windows أصليًا غير متاح.
- [x] فحص remote refs قبل التسليم: `main` و`v5.1.0` كما هما، ولا `v5.2*` tag، وفرع المراجعة ما زال هدف التغييرات.
- [x] تقسيم التغييرات إلى commits ذرية، ثم normal fast-forward push لفرع `fix/blocker-d-review-20261010` فقط؛ لا merge أو force-push أو release.
- [x] نتيجة الأدلة الحالية **PARTIALLY VERIFIED** لا PASS؛ لا ادعاء قبول Windows.

## متابعة 2026-10-17: Windows sandbox fail-closed
- [x] فحص أدلة Windows الأصلية من التشغيل `39002439803`؛ ميّزت بين نجاح ملكية/تنظيف Job للتطبيق وبين عدم وجود sandbox وتنفيذ Mission.
- [x] وثّقت الحاجز الفعلي: AppContainer/LPAC وACL workspace-only ومنع الشبكة وحدود الكتابة/القرص وJob-bound dispatch/receipt غير منفذة أو غير مثبتة؛ بقي Windows execution fail-closed.
- [x] أضفت اختباراً أصلياً لرفض `spawn` قبل callback الخاص بـdispatch، وأي `Popen` أو start marker؛ سيعمل ضمن اختبارات Windows المحمولة في desktop-build.
- [ ] لا تفعيل ولا ادعاء قبول Windows حتى تنفذ الضوابط كاملة وتنجح اختبارات Windows الأصلية الإيجابية والسلبية وقبول Mission المتكامل.
- **النتيجة الحالية:** `RESOURCE_BLOCKED` عند `run_project_tests` متوقع وآمن وفق الدليل؛ لا يجوز تحويله إلى نجاح. استعادة المهمة ذات السلسلة الغائبة تظل غير مثبتة.
- [x] التحقق المحلي المركّز: `365 passed, 7 skipped`؛ المجموعة الكاملة: `2081 passed, 28 skipped, 4 warnings`.
- [x] `compileall` و`git diff --check` اجتازا؛ strict secret/sensitive-file scan: صفر ملفات حساسة متتبعة وصفر أنماط أسرار.
