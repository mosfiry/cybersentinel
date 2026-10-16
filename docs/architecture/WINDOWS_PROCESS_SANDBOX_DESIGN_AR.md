# تصميم Windows sandbox لعمليات المهمة

**الحالة:** تصميم ومراجعة مخاطر قبل التنفيذ — لا يمثل اعتمادًا لـWindows backend ولا إثبات قبول Windows.

**نقطة المراجعة:** الفرع `fix/blocker-d-review-20261010`، commit `34cca3b54f316b9989994e9327be1b91e306409b`.

## 1. القرار الأمني

يبقى تشغيل `run_project_tests` على Windows **محجوبًا افتراضيًا** إلى أن يتوفر backend ينجح في اختبارات Windows أصلية تغطي هوية العملية، حدود الملفات والشبكة والموارد، الإلغاء، وتنظيف كامل شجرة الأبناء. لا يُعد `subprocess.Popen` بصلاحيات المستخدم، أو Job Object منفرد، أو اختبار Linux يحاكي `sys.platform == "win32"` دليلًا على sandbox.

يحافظ هذا القرار على Owner authorization وScope Firewall وExecution Fence: يظل فحص التفويض والحدود قبل dispatch، ولا تُنشأ أدلة نجاح أو `GOAL_COMPLETED` عند غياب backend أو فشل تهيئته. لا يُعاد تنفيذ عملية ملتبسة بعد timeout أو crash تلقائيًا.

## 2. النطاق وجرد العمليات

### أدوات المهمة وحدود الوصول

- `run_project_tests` هو أداة التنفيذ الوحيدة المسجلة حاليًا في ToolRegistry (`tools/registry.py`، `ToolSpec` عند 239–270 والتعريف عند 852–863). يقبل أمر pytest ثابتًا فقط، ويشترط Owner وMission Workspace وExecutionContext ومخزن أدلة محميًا بـExecution Fence.
- `Workspace.run_shell`, `run_process`, `develop`, `git_readonly` و`ProcessManager.start` في `workspace/environment.py` هي واجهات تشغيل داخلية. جميعها تصل إلى `_sandbox_popen`؛ لا ينبغي أن يضيف أي منها مسار تشغيل مضيف غير محكوم. مسار `git_readonly` مقيد باستعلامات Git ثابتة.
- `tools/browser.py` يطلق Chromium عبر Playwright. هذا مسار منفصل: يعتمد sandbox المتصفح الخاص بـChromium، dead proxy، وScope Firewall القائم، ولا يجوز أن يتحول إلى وسيلة تنفيذ أو وصول شبكي بديلة.

### عمليات المنتج والقبول غير المصنفة كأداة تنفيذ

- `agent/local_runtime/runtime.py` يشغّل `llama-server` المحلي، و`agent/local_runtime/hardware.py` يشغّل أدوات استطلاع عتاد محددة. هذه خدمات/استطلاعات موثوقة نسبيًا وليست تصريحًا بتنفيذ محتوى المشروع. يلزم حصر executable والوسائط والبيئة والمهلة وهوية العملية عند إدارتها؛ ولا تُسجل على أنها عمليات sandbox لاختبارات المشروع.
- scripts وعمليات القبول وعمليات worker هي أدوات تشغيل/اختبار وليست ToolSpecs متاحة للمهمة. لكنها تخضع لحدود آمنة خاصة بها. تحديدًا، لا يجوز أن ينهي harness تطبيقًا باستهداف اسم العملية أو مسحًا واسعًا أو `taskkill /PID /T` غير مربوط بإطلاق القبول.

## 3. عقد sandbox المشترك

يفصل التصميم بين عقد محايد المنصة وبين backend لكل نظام:

- **طلب التنفيذ** محدود ومثبت: argv ثابت، مسار عمل داخل جذر Owner المصرح به، هوية Mission/request/tool-call، ExecutionContext وفنس التنفيذ، بيئة قليلة ومحددة، سياسة شبكة، حدود زمن/موارد، ومسارات artifacts المسموح بها.
- **واجهة backend** تتضمن فحص قدرات المنصة قبل dispatch، تهيئة العزل، تشغيلًا بإيصال بدء صادر من backend، مراقبة الحالة والإلغاء، ثم إغلاقًا يؤكد انتهاء كل العمليات التابعة. لا يقبل العقد تشغيلًا افتراضيًا بصلاحيات المضيف عند غياب backend.
- **بيانات النتيجة** تفصل بين حالة بدء العملية والنتيجة النهائية؛ وتحتوي هوية backend وإصداره، سببًا آليًا آمنًا، exit code عند وجوده، timeout/cancellation/resource-limit flags، وهاشات/مراجع artifacts. لا تحفظ الأسرار أو environment أو command output الخام غير الضروري.
- **الأسباب المميزة التي يجب أن تبقى قابلة للتدقيق:** `authorization_denied`، `backend_unavailable`، `sandbox_setup_failed`، `resource_limit_exceeded`، `timed_out`، `cancelled`، `command_failed`، `succeeded`. يظل `RESOURCE_BLOCKED` حالة Mission كما هي ولا يختزل هذه الأسباب إلى نجاح أو إلى سبب مشترك. `dispatch_attempted=false` وغياب إيصال بدء العملية شرط عند الرفض أو غياب/فشل تهيئة العزل.
- لا ينشر النظام حدث بدء تنفيذ أو يسجل dispatch قبل اجتياز التفويض والسياسة وتهيئة backend وبدء العملية وفق primitive المعتمد. أحداث الاقتراح/فحص التفويض تبقى متميزة عن أحداث بدء العملية ونتيجتها.

## 4. ملف Linux الذي يجب الحفاظ عليه

المسار المثبت حاليًا في `Workspace._sandbox_popen` يستخدم rootless Bubblewrap و`prlimit`: namespaces للمستخدم والشبكة وPID وIPC وUTS، صلاحيات capabilities مسقطة، بيئة نظيفة، workspace للقراءة فقط، مجلدات tmpfs محدودة، ملف تقرير مربوطًا منفردًا، حدود وقت/CPU/ذاكرة/ملفات/عمليات، ومراقبة إلغاء. يجب نقل هذا التنفيذ إلى backend Linux دون تغيير السلوك أو تخفيف الضوابط، وإبقاء الاختبارات القائمة ناجحة. لا يجعل هذا الوصف ادعاءً بأن Linux profile يحمي من كل ثغرات النواة أو أن مجلد workspace نفسه خالٍ من أسرار وضعها المستخدم.

## 5. متطلبات backend Windows المقترح

### عزل الملفات والهوية والشبكة

- لا يُشغّل كود pytest في token المستخدم العادي. يستخدم backend Windows هوية AppContainer/LPAC مخصصة للتشغيل أو عزلًا افتراضيًا مكافئًا، مع قائمة capabilities خالية من صلاحيات الشبكة افتراضيًا. لا يُمنح `internetClient` أو `privateNetworkClientServer` إلا بسياسة صريحة ومراجعة؛ والسياسة الحالية لا تمنح شبكة.
- تُعطى هوية العزل صلاحية قراءة/تنفيذ لمحتوى مساحة العمل الموافق عليها فقط، وكتابة إلى مسارات مؤقتة وartifacts صريحة فقط. يُمنع الوصول إلى ملفات المستخدم الأخرى وبيانات الاعتماد وقاعدة التطبيق ومفاتيحها. يلزم تحقق ACL فعلي، مع استبعاد/حجب أسرار مساحة العمل المعروفة أو تجهيز نسخة إدخال لا تحتويها؛ لا يكفي تمرير `cwd` أو تغيير متغيرات البيئة.
- غياب backend أو capability أو ACL متوقعة أو مسار موثق لسياسة الشبكة يعني رفض التنفيذ قبل بدء العملية.

### إدارة العمليات والموارد

- يُجهز Job Object منفصل لكل تشغيل، وتُضبط حدوده قبل التنفيذ: `KILL_ON_JOB_CLOSE`، حد عدد العمليات، CPU/memory/وقت العملية وفق ما يدعمه Windows فعليًا، مع منع breakaway. ينشأ child في حالة معلقة، ويُعيّن إلى الـJob، وتُتحقق عضويته وحدود Job/هوية token قبل استئنافه. فشل `AssignProcessToJobObject` أو أي تحقق يعني عدم استئناف child وتنظيف handles.
- Job Object وسيلة لإدارة شجرة العمليات وحدودها، وليس حدًا أمنيًا للملفات أو الشبكة. AppContainer/ACL أو VM/container معزول يحقق بقية الحدود. إغلاق/إلغاء التنفيذ يجب أن ينهي Job المملوك لهذا التشغيل فقط، ثم ينتظر انتهاء أعضائه ويتحقق من عدم وجود عملية تابعة باقية.
- لا توفر حدود Job وحدها حدًا موثوقًا لحجم الملفات على القرص. يجب أن يثبت backend حدًا إجماليًا للكتابة (مثل مساحة مؤقتة ذات حصة OS فعلية أو VM/قرص محدود) أو يظل backend غير متاح. لا يُستعاض عن ذلك بحد حجم artifact داخل Python فقط، لأن كود الاختبار غير الموثوق يستطيع الكتابة مباشرة.
- Restricted Token يُقيّم كطبقة إضافية لتقليل privileges/SIDs، لكنه ليس بديلًا عن AppContainer أو ACL، ولا يضاف إلا بعد إثبات توافقه مع طريقة تشغيل Python والاختبارات على Windows. البديل الأقوى المحتمل Windows Sandbox/Hyper-V، لكنه يعتمد على دعم النظام والإصدار والتشغيل الفعلي ولا يُفترض توفره.

## 6. التسجيل والأدلة

سجل قبول آمن ومقيد الحقول يسجل: معرف التشغيل وإصدار التطبيق وبصمته، معرف Mission/request/tool call عند توفرها، sequence/timestamp للأحداث، `kind` و`reason_code` وبيانات خام منقحة/محددة الحقول، backend/profile والسبب الدقيق للرفض أو فشل الإعداد، إثبات بدء العملية وهوية launch/job ونتيجة الأمر الفعلية، الحدود المطبقة، مراجع الأدلة وهاشاتها وسلسلتها، حالة Mission النهائية، ودورة الإغلاق وإعادة الفتح والاستعادة.

لا يتضمن السجل كلمات مرور Owner أو الرموز أو environment أو نصًا حرًا غير منقح. كل سجل فشل يظل فشلًا؛ لا يصنع harness أحداثًا أو أدلة لإكمال السلسلة، ولا يستنتج نجاحًا من HTTP 200 أو اختفاء نافذة.

## 7. آلية قبول التطبيق وإعادة Mission

يجب أن يكون launch الأصلي للتطبيق المثبت والإطلاق بعد restart عبر آلية واحدة موثقة تحتفظ بهوية العملية الحية وJob Object حتى نهاية دورة القبول. يُتحقق من executable path ووقت إنشاء العملية وPID ومقابلة process handle وعضوية Job؛ ويكون الإنهاء عبر handle/Job الذي أنشأه harness لا عبر إعادة حل PID من `taskkill`.

بعد الإنهاء، ينتظر harness إشارة Job الفارغ، يتحقق من زوال عملية التطبيق واتصال CDP، ثم يعيد تشغيل نفس executable المثبت ونفس ملف profile المؤقت. يجري فحص Owner من جديد، ويعيد قراءة سجل Mission وسلسلة الأدلة وقاعدة البيانات؛ ولا يرسل resume إلا بعد إثبات حفظ حالة pause، وصحة Owner/runtime، وثبات سجل التنفيذ وعدم وجود إجراء سابق ملتبس. لا يُعاد تنفيذ أداة سابقة غير آمنة تلقائيًا. إن تعذر إثبات هوية/شجرة العملية، يفشل الاختبار بوضوح دون إنهاء واسع.

## 8. خطة الاختبارات ومعيار التمكين

اختبارات العقد المشتركة: نجاح backend موثق، backend غائب، فشل إعداد العزل قبل dispatch، رفض التفويض، مسار خارج workspace، منع قراءة ملف حساس/خارج workspace، منع الشبكة، timeout وcancellation، كل حد موارد، تنظيف الأبناء، failure/exit code حقيقي، وعدم إنشاء دليل تنفيذ دون بدء فعلي.

اختبارات Linux المستقلة تحافظ على Bubblewrap/prlimit كما هو. اختبارات Windows مستقلة يجب أن تكون على Windows أصلي وتشغل عمليات فعلية داخل backend الحقيقي؛ الم mocks واختبارات Linux لا تثبت سلوك Windows. اختبار القبول يثبت التثبيت/Owner/الاستدلال المحلي، إنشاء Mission، الأداة المعزولة ونتيجتها، الأدلة و`GOAL_COMPLETED` فقط بعد التحقق، إغلاق Job وإعادة فتح التطبيق، استعادة Mission، سلامة قاعدة البيانات والصلاحيات.

لا يُفعّل Windows backend ولا يُمنح `PASS` إلا بعد اجتياز الاختبارات الأصلية كاملة على Windows. إذا لم تكن البيئة أو سياسة النظام أو حصة القرص متاحة، تبقى الحالة `BLOCKED`/`PARTIALLY VERIFIED` وفق الأدلة، مع `dispatch_attempted=false` عند عدم البدء.

## 9. مراجع Microsoft

- [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects): إدارة مجموعة عمليات وحدودها وإنهاؤها، انتقال العمليات التابعة افتراضيًا، وإمكان الهروب عند تفعيل breakaway؛ كما أن حدود الأمن يجب أن تطبق لكل عملية ولا يمنح Job وحده عزل ملفات/شبكة.
- [AppContainer isolation](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation): عزل ملفات النظام وبيانات الاعتماد والشبكة والعمليات، مع منح وصول تفصيلي وفق capabilities.
- [Launch an AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer): إنشاء AppContainer، token وSIDs وACL، واشتراط منح القدرات اللازمة صراحةً.
- [CreateRestrictedToken](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken): تعطيل SIDs كـdeny-only، حذف privileges، وإضافة restricting SIDs؛ لا يمثل وحده sandbox مكتملًا.
