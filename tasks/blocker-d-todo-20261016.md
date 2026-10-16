# قائمة تنفيذ Blocker D — 2026-10-16

## التحضير
- [x] التحقق read-only من GitHub والفرع والبصمات و`main` و`v5.1.0` وغياب `v5.2.0` في صفحة Releases.
- [x] التحقق من baseline ancestor ومن نظافة الفرع عند `9e95fbb`.
- [x] التحقق من bundle baseline وإنشاء bundle منفصل كامل لرأس ما قبل remediation.
- [x] مراجعة الملفات/ToolSpecs ومسارات process launch والمشاكل العشرة من المراجعة المستقلة.
- [x] توثيق التصميم المنقح قبل تغييرات المصدر.

## المهمة 1: CAS الإلغاء وdispatch والنهائية
- [ ] اجعل queue cancel marker وeffect dispatch يتنافسان عبر CAS دائم وفنس، لا lock محليًا فقط.
- [ ] امنع stale cancellation من تغيير terminal Mission/queue.
- [ ] استعد marker أثناء restart وامنع READY/start/resume حتى معالجة الإلغاء.
- [ ] أغلق `RESERVED` no-effect فقط عند إثبات عدم dispatch، وافصل lock القصير عن handler.
- [ ] اختبارات عبر أكثر من process، race terminal، recovery، reservation وhandler طويل.

## المهمة 2: deadline وإلغاء MCP
- [ ] اجعل deadline يحتسب وقت طابور executor ويصل إلى حد إرسال الطلب.
- [ ] ألغ Future إذا كانت queued، واستعمل token يمنع أي إرسال متأخر.
- [ ] أبقِ external outcome ambiguous بلا retry إذا بدأ الإرسال.
- [ ] اسمح بإشعار cancellation مستقل فقط بعد إعادة فحص Owner/Mission/Scope/Fence حتى مع انتهاء deadline.
- [ ] اختبارات ازدحام executor وsend race والنطاق/الإلغاء.

## المهمة 3: عقد process sandbox وLinux موارد إجمالية
- [ ] ثبت inventory لكل عمليات subprocess، مع إبقاء browser/local-model كمسارات مستقلة محدودة.
- [ ] لا تعلن Linux backend متاحًا دون delegated cgroup v2 aggregate memory/pids وcleanup.
- [ ] لا تنفذ `Popen` عند غياب متطلبات cgroup أو فشل تهيئتها.
- [ ] أضف OOM/resource classification دون خلط timeout/cancel أو command failure.
- [ ] وفر process-start receipt صحيحًا وتصنيف فشل بدء العملية المؤكد مقابل الحالة الملتبسة.
- [ ] اختبارات مشتركة لكل حالات العقد وعدم التنفيذ عند فشل التهيئة.

## نقطة تحقق A
- [ ] اجتياز مصفوفة cancellation/MCP/sandbox المركزة.
- [ ] فحص `git diff --check` وsecret scan بعد كل مجموعة.
- [ ] مراجعة مستقلة read-only للمسارات التي تغيرت.

## المهمة 4: verifier وأدلة القبول والخصوصية
- [ ] اشترط process_started حقيقيًا، PID موجبًا، timestamp صالحًا وربط كل الهوية والنتيجة.
- [ ] استخدم allowlists/secret pattern guard للأكواد وIDs.
- [ ] احذف raw exception/traceback من PowerShell/API acceptance artifacts.
- [ ] اختبارات سلبية للأدلة الناقصة/غير المتطابقة والأسرار في الحقول المقبولة.
- [ ] لا تقبل إكمال Mission دون timeline/evidence/terminal status الحقيقي.

## المهمة 5: harness إغلاق/إعادة فتح التطبيق
- [ ] إطلاق التطبيق المثبت وإعادة إطلاقه عبر Job Object مملوك لعملية الاختبار مع process handle محفوظ.
- [ ] تحقق executable path وcreation time وJob membership وارتباط CDP.
- [ ] إنهاء Job المقصود والتحقق من كل الأعضاء بدل PID-only `taskkill` أو process sweep.
- [ ] حفظ Mission identity والسجلات والـcheckpoint؛ استعادة فعلية بلا replay غير آمن أو تجاوز موافقة.
- [ ] فشل واضح إذا تعذر إثبات هوية العملية.

## المهمة 6: التحقق والتقرير والتسليم
- [ ] تشغيل الاختبارات المركزة ثم كامل Linux test suite؛ تسجيل الأوامر وexit codes.
- [ ] تشغيل compileall/py_compile/diff/secret scans.
- [ ] إنشاء Windows build/CI على فرع المراجعة فقط والتحقق من exact SHA حيث أمكن.
- [ ] عدم اعتبار mocks أو Linux نجاحًا لـWindows؛ وصف قيود cgroup وWindows بوضوح.
- [ ] تأكيد `main` و`v5.1.0` بلا تغيير، وعدم وجود `v5.2.0` tag/release.
- [ ] commits ذرية وواضحة؛ لا merge إلى main ولا force-push ولا release.
- [ ] التقرير النهائي PASS/PARTIALLY VERIFIED/BLOCKED/FAIL بناء على الأدلة.
