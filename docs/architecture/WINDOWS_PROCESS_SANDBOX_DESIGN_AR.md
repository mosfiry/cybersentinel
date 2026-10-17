# تصميم Windows sandbox لعمليات المهمة

**الحالة:** التصميم سبق التعديلات البرمجية. شُغلت المجموعة الكاملة على Linux: `1973 passed, 25 skipped, 4 warnings` (exit 0). تخطت المجموعة الاختبارات التي تتطلب backend حيًا لأن probe الإنتاج أعاد `cgroup_v2_delegation_unavailable`، كما تخطى اختبار Job الأصلي لعدم وجود Windows. Windows process sandbox ما زال محجوبًا؛ لا يُدّعى قبول Windows أو Mission كاملة.
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
- scripts وعمليات القبول وعمليات worker هي أدوات تشغيل/اختبار وليست ToolSpecs متاحة للمهمة. صار harness يطلق التطبيق المثبت عبر `CreateProcessW(CREATE_SUSPENDED)`، يعينه إلى Job Object فريد قبل Resume، ويحفظ process handle ووقت الإنشاء ومسار image؛ إعادة التشغيل والإنهاء تستخدم Job المملوك وتنتظر صفر أعضاء. PowerShell لا يستخدم `taskkill` أو process sweep، ولا يحذف install/profile/state إلا بعد إثبات Job فارغ. هذا يثبت ملكية lifecycle للتطبيق فقط، ولا يثبت sandbox لأوامر Mission.
- أدوات القبول المساعدة، مثل إنشاء شهادة TLS وخادم MCP المحلي، تستخدم `scripts/acceptance_process_tree.py`: Job Object على Windows، وcgroup v2 عند إعداد delegated root صريح، وإلا process group مخصص على POSIX مع تحقق إنهاء المجموعة. أوامر الشهادة محدودة بمهلة؛ وفشل cleanup يجعل acceptance تفشل بدل ادعاء نجاح، ولا يُحفظ traceback خام في sidecar.

## 3. عقد sandbox المشترك

يفصل التصميم بين عقد محايد المنصة وبين backend لكل نظام:

- **طلب التنفيذ** محدود ومثبت: argv ثابت، مسار عمل داخل جذر Owner المصرح به، هوية Mission/request/tool-call، ExecutionContext وفنس التنفيذ، بيئة قليلة ومحددة، سياسة شبكة، حدود زمن/موارد، ومسارات artifacts المسموح بها.
- **واجهة backend** تتضمن فحص قدرات المنصة قبل dispatch، تهيئة العزل، تشغيلًا بإيصال بدء صادر من backend، مراقبة الحالة والإلغاء، ثم إغلاقًا يؤكد انتهاء كل العمليات التابعة. لا يقبل العقد تشغيلًا افتراضيًا بصلاحيات المضيف عند غياب backend.
- يحدد `ToolSpec.dispatch_boundary` حد الإلغاء لكل أثر: `workspace_process_start` لـ`run_project_tests`، و`scope_pinned_http_send` لطلبات MCP المقيدة، و`handler` للأدوات المحلية. تُسلسل كتابات الحالة المحلية مع marker الإلغاء حتى لا يُقبل marker بين كتابة الأثر وتسجيل نتيجته؛ وتبقى الأداة النشطة مسجلة حتى تنتهي فعليًا بعد timeout.
- **بيانات النتيجة** تفصل بين حالة بدء العملية والنتيجة النهائية؛ و`ProcessResult` يسجل outcome وreason code صريحين (`SUCCEEDED`, `COMMAND_FAILED`, `TIMED_OUT`, `CANCELLED`, `RESOURCE_LIMIT_EXCEEDED`) مع `process_started`, PID ووقت UTC لبدء العملية عندما تتوفر. لا يصنف إشارات الإيقاف الملتبسة مثل `SIGKILL` تلقائيًا كحد موارد؛ في Linux تُعرف إشارة حد الموارد فقط عندما تكون الإشارة نفسها صريحة مثل `SIGXCPU`/`SIGXFSZ`. لا تحفظ الأسرار أو environment أو command output الخام غير الضروري.
- **الأسباب المميزة القابلة للتدقيق:** رفض التفويض، `backend_unavailable`، `sandbox_setup_failed`، `resource_limit_signal`، `process_timeout`، `process_cancelled`، `command_nonzero_exit`، `process_exit_zero`. يظل `RESOURCE_BLOCKED` حالة Mission كما هي ولا يختزل هذه الأسباب إلى نجاح أو إلى سبب مشترك. الرفض أو فشل الإعداد قبل حد الإطلاق يسجل `dispatch_attempted=false` مع غياب إيصال البدء. بعد write-ahead، لا يثبت غياب marker أو نجاح تنظيف cgroup أن الأمر لم ينفذ: إذا عاد `Popen` ولم يصل إيصال بدء موثوق، يبقى الأثر ملتبسًا و`RECOVERY_REQUIRED`. يقتصر no-effect proof بعد write-ahead على فشل إنشاء launcher المؤكد قبل بدء child.
- لأداة process المعزولة فقط، يمر `TOOL_CALLED` بعد عودة primitive التشغيل بعملية فعلية، مع `process_started=true` ومعرف backend/PID. يثبت Registry الـeffect dispatch write-ahead بعد التفويض وتجهيز backend مباشرة قبل `Popen`؛ إذا فشل callback لا يُنشأ child. فشل التهيئة قبل callback يسجل no-effect/`RESOURCE_BLOCKED` ولا ينتج حدث بدء أو دليل نتيجة؛ أما غياب receipt بعد إنشاء launcher فيبقى ملتبسًا حتى لو انتهت الشجرة أو تعذر تسجيل marker، ولا يسمح بإعادة المحاولة التلقائية.
- إلغاء Owner النشط يُسجل في `mission_queue` منفصلًا عن نسخة Mission حتى لا يبطل worker fence، ويُكتب عند حد الإلغاء المحمي قبل الإشارة للأدوات النشطة. إذا كان handler محليًا يكتب حالة، يكتمل الأثر الجاري أولًا تحت الحد نفسه، ثم يثبت marker؛ وأي dispatch جديد بعده يُرفض. طلبات MCP المحددة النطاق تعيد فحص سياق التنفيذ داخل النقل تحت القفل مباشرة قبل كتابة الطلب على socket: إذا سبق marker الإرسال يُمنع الطلب، وإذا سبقه الإرسال فالأثر البعيد يبقى ملتبسًا؛ `notifications/cancelled` أفضل جهد وليست دليلًا على عكس أثر الخادم. يطبق Runtime الإلغاء تحت الـfence الحالي عند العودة من provider/tool وعند كل حفظ، فلا يُكمل native-model Mission بعد قبول marker؛ يبقى `RECOVERY_REQUIRED` كما هو عند أثر ملتبس، ويمنع marker إعادة claim/re-enqueue تلقائيًا.

### 3.1 بوابة MCP المشتركة ومقاطعة DNS

- لا يُحجز قفل الطلب المحلي أو قفل النظام أثناء `getaddrinfo`: ينفذ `PinnedSession` الحل في عامل daemon محدود السعة (أربعة أعمال DNS كحد أقصى)، ويراقب المستدعي deadline وOwner cancellation/pending marker. يعود الطلب بسرعة عند الإلغاء/المهلة، ولا يمكن لنتيجة resolver متأخرة إنشاء socket؛ يعاد فحص الإلغاء ثم تُراجع العناوين قبل استعمالها. استدعاء resolver الأصلي في النظام قد يظل عالقًا ولا يمكن قتله بأمان على كل منصة؛ لذلك تبقى خاناته محدودة، وإذا امتلأت تفشل طلبات DNS الجديدة مغلقة بلا إرسال.
- بعد DNS فقط، يمسك `MissionDispatchGate` قفل طلب محليًا وقفل ملف OS لكل Mission حتى إغلاق HTTP connection بالكامل، وقفل send مستقلًا حول كل socket write. يستخدم التنفيذ `fcntl.flock` على POSIX و`msvcrt.locking` على بايت واحد في Windows، ويضع ملفات hashed تحت مجلد بجانب قاعدة `MissionStore`. لا يستبدل هذا القفل CAS SQLite ولا يوفر ضمانًا موزعًا متعدد المضيفين؛ التشغيل يفترض filesystem محليًا مدعومًا بدلالات قفل متحققة، ولا يُدّعى دعم network/shared filesystems دون تحقق نشر صريح.
- ينشر Owner cancellation أولًا ملف `.intent` ذريًا بوصفه إشارة إيقاظ/إيقاف لا نقطة commit؛ يراه watcher ويغلق socket النشط، كما يرفض أي request/send جديد. كل socket write مع فحص الإرسال الأول وcallback تسجيل `DISPATCHED` يمسك per-Mission OS `send_guard`. لا يُنشأ marker `.cancel` النهائي المثبت على القرص إلا داخل القفل نفسه؛ لذلك يخرج أي write سبق دخوله المنطقة الحرجة قبل هذا marker، ولا يبدأ write تالٍ بعده. بعدها ينتظر Owner اكتمال قفل الطلب وإغلاق HTTP connection، ثم ينفذ CAS الدائم لإلغاء Mission. عند رفض CAS تُزال فقط markers التي أنشأتها تلك المحاولة تحت send_guard؛ وعند crash/غموض تبقى الإشارات fail-closed إلى reconciliation موثوق. الاستثناء الوحيد لإرسال بعد marker هو إشعار MCP cancellation بعد إعادة فحص Owner/Mission/Scope/Fence.
- التحقق الحالي لبوابة POSIX جرى على Linux فقط؛ لم تتوفر Windows أصلية لتأكيد سلوك `msvcrt.locking` أو AppContainer/Job lifecycle. لا يُعد هذا التصميم أو اختبارات المحاكاة دليل قبول Windows.

## 4. ملف Linux الذي يجب الحفاظ عليه

المسار في `Workspace._sandbox_popen` يفوض إلى `workspace/process_sandbox.py`؛ backend `bubblewrap+prlimit+cgroup-v2` يجمع rootless Bubblewrap/prlimit مع namespaces للشبكة وPID وغيرها، workspace للقراءة فقط، tmpfs محدودًا، وchild cgroup مفوضًا يثبت حد الذاكرة/عدد العمليات وينهي شجرة التشغيل. يُدخل trampoline موثوق التنفيذ داخل cgroup قبل exec وتُقرأ `memory.events.local` لتصنيف OOM. لا يُتاح backend إلا مع delegation حقيقي قابل للكتابة و`cgroup.kill` وcontrollers المطلوبة؛ وجود bwrap/prlimit أو `RLIMIT_AS` وحده غير كافٍ. لا يدعي التصميم الحماية من كل ثغرات النواة أو خلو workspace من أسرار أدخلها المستخدم.

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

سجل قبول آمن ومقيد الحقول يسجل: هوية GitHub Actions (repository/run/attempt/ref/commit/runner image) عند توفرها، إصدار التطبيق وبصمة SHA-256 للـexecutable المثبت والإصدار/commit المتوقع، معرف Mission/request/tool call عند توفرها، ترتيب الأحداث وsequence/timestamp وhash الحدث، `kind` و`reason_code` والبيانات الخام على شكل حقول آمنة منتقاة مع SHA-256 للحمولة الأصلية، backend/profile والسبب الدقيق للرفض أو فشل الإعداد، وإثبات بدء العملية (PID ووقت UTC) ونتيجة الأمر الفعلية، الحدود المطبقة، مراجع الأدلة وهاشاتها وسلسلتها، حالة Mission النهائية، ودورة الإغلاق وإعادة الفتح والاستعادة.

لا يتضمن السجل كلمات مرور Owner أو الرموز أو environment أو النص الحر للحدث/نتيجة الاختبار؛ يسجل الحقول الآمنة فقط وهاش البيانات الأصلية كي لا تضيع قابلية المطابقة دون تسريب الحمولة. كل سجل فشل يظل فشلًا؛ لا يصنع harness أحداثًا أو أدلة لإكمال السلسلة، ولا يستنتج نجاحًا من HTTP 200 أو اختفاء نافذة.

يشمل إسقاط الفشل المبكر قبل restart أيضًا timeline والأدلة وسلسلة التنفيذ كعدادات وهاشات وحقول منتقاة، بدل إرجاع حالة مختصرة فقط. ويحفظ تقرير E2E عند الاستثناء الحالة النهائية للـMission، وصحة hash-chain، و`kind`/`reason_code`/`detail_code` و`dispatch_attempted` وtool-call IDs عند توفرها؛ وتُحجب قيم `reason` والنصوص الحرة ومخرجات الأدوات. ويغطي ذلك أيضًا مسار AgentCore التوافقي الذي ينفذ الخطة دون native tool calls: يكتب سبب الحجب والـbackend وإثبات `dispatch_attempted=false` وغياب بدء العملية في سجل الفشل والحدث والـcheckpoint، مع حالة `not_dispatched`، ولا يمرر نص الخطأ الحر إلى الإسقاط الآمن.

## 7. آلية قبول التطبيق وإعادة Mission

يجب أن يكون launch الأصلي للتطبيق المثبت والإطلاق بعد restart عبر آلية واحدة موثقة تحتفظ بهوية العملية الحية وJob Object حتى نهاية دورة القبول. يُتحقق من executable path ووقت إنشاء العملية وPID ومقابلة process handle وعضوية Job؛ ويكون الإنهاء عبر handle/Job الذي أنشأه harness لا عبر إعادة حل PID من `taskkill`.

بعد الإنهاء، ينتظر harness Job الفارغ وزوال اتصال CDP، ثم يعيد تشغيل نفس executable المثبت ونفس profile المؤقت. نُفذ المسار في `scripts/windows_process_job.py` و`windows_desktop_acceptance.py`; إذا فشل تحقق identity/membership يفشل الاختبار ولا ينفذ قتلًا بديلًا. أُضيف اختبار Windows أصلي يشغل parent وchild فعليين، لكنه skipped على Linux الحالي. لذلك lifecycle code موجود، أما إثباته على Windows الأصلي واستعادة Mission end-to-end فما زالا غير مثبتين.

## 8. خطة الاختبارات ومعيار التمكين

اختبارات العقد المشتركة: نجاح backend موثق، backend غائب، فشل إعداد العزل قبل dispatch، رفض التفويض، مسار خارج workspace، منع قراءة ملف حساس/خارج workspace، منع الشبكة، timeout وcancellation، كل حد موارد، تنظيف الأبناء، failure/exit code حقيقي، وعدم إنشاء دليل تنفيذ دون بدء فعلي.

اختبارات Linux المستقلة تحافظ على Bubblewrap/prlimit، وتعلن عدم توفر تكامل العملية عندما يغيب cgroup الحقيقي بدل محاكاة availability. اختبارات Windows المستقلة يجب أن تكون على Windows أصلي وتشغل عمليات فعلية؛ mocks واختبارات Linux لا تثبت سلوك Windows. أضيف اختبار Job native للـparent/child، لكنه لم يعمل هنا. القبول الكامل لا يزال يتطلب تثبيت/Owner/استدلال محلي، Mission حقيقية، sandbox معتمدة، أدلة، restart واستعادة DB على Windows.

Windows backend `windows-appcontainer-job` في الشيفرة الحالية يعيد `backend_unavailable/windows_appcontainer_backend_unimplemented` حتى على Windows؛ لا يوجد AppContainer/Job Object/قيود ACL وحصة قرص منفذة. لا يُفعّل backend ولا يُمنح `PASS` إلا بعد اجتياز الاختبارات الأصلية كاملة على Windows. الاختبار الأصلي المستقبلي الذي يثبت backend غير المنفذ يثبت فقط الحجب fail-closed، لا قبول المهمة. تبقى المهمة `BLOCKED`/`PARTIALLY VERIFIED` وفق الأدلة؛ عند الرفض قبل حد الإطلاق يكون `dispatch_attempted=false`، أما فشل البدء الملتبس بعد write-ahead فيتطلب recovery ولا يوصف كأنه لم يُحاول.

## 9. مراجع Microsoft

- [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects): إدارة مجموعة عمليات وحدودها وإنهاؤها، انتقال العمليات التابعة افتراضيًا، وإمكان الهروب عند تفعيل breakaway؛ كما أن حدود الأمن يجب أن تطبق لكل عملية ولا يمنح Job وحده عزل ملفات/شبكة.
- [AppContainer isolation](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation): عزل ملفات النظام وبيانات الاعتماد والشبكة والعمليات، مع منح وصول تفصيلي وفق capabilities.
- [Launch an AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer): إنشاء AppContainer، token وSIDs وACL، واشتراط منح القدرات اللازمة صراحةً.
- [CreateRestrictedToken](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken): تعطيل SIDs كـdeny-only، حذف privileges، وإضافة restricting SIDs؛ لا يمثل وحده sandbox مكتملًا.


## 10. مراجعة تصميم منقحة قبل التنفيذ — 2026-10-16

**حالة هذه المراجعة:** هذا هو العقد المرجعي للتنفيذ الجاري، ويصحح الوصف التاريخي أعلاه: lock داخل العملية وحده لا ينسّق الإلغاء، و`RLIMIT_AS` لا يضع حدًا إجماليًا لشجرة العمليات.

**الحالة المحققة للمستودع قبل التصميم:** الفرع `fix/blocker-d-review-20261010` عند `9e95fbbac83ea7edd6b6613f8956e0fd6abc0699`، والأب `f915490c28e3a0cdbd65a2a0b214b99ab167225b`. نقطة البداية `34cca3b54f316b9989994e9327be1b91e306409b` سلف للفرع. تحقق GitHub المباشر أعاد الفرع نفسه، و`main` عند `8a3fd109c0e586db13ed48a7371ac9ad06465b74`، و`v5.1.0` عند الكائن `684b344c183da1dee8dfd229c93cef0fd29396a5` (مفكوكًا إلى `26739d9b01b3b1ff492854e7e21789be20b1be0e`)، وصفحة الإصدارات تعرض `v5.1.0` كأحدث إصدار ولا تعرض `v5.2.0`.

نقطتا الاستعادة المحليتان قبل التعديل:

- baseline: `safety/blocker-d-pre-remediation-20261016` عند `34cca3b…`، bundle SHA-256: `d8e4ea289c8ddaf2f0193fbac10ca4435f2d9f246941a5eef67268e0ae7ab338`.
- رأس ما قبل الإصلاح: `safety/blocker-d-pre-remediation-20261016-9e95fbb` عند `9e95fbb…`، bundle SHA-256: `5745e5815958ecea9e9d25bc0feac0418fb17c47219bdf4f78db0e16b63232e4`.

### 10.1 عقد تنفيذ موحد لكل منصة

يبقى العقد المشترك في `workspace/process_sandbox.py` محايدًا للمنصة، ولا تنتشر فروع `sys.platform` في أدوات المهمة. يتضمن طلب التنفيذ: argv مثبتًا ومتحققًا؛ cwd وجذر workspace مربوطين بحد Owner؛ mission/request/task/action/tool-call ومعرّفات fence؛ سياسة لا تسمح بالشبكة أو أسرار المضيف افتراضيًا؛ حدود الوقت والذاكرة الإجمالية وCPU وعدد العمليات والكتابة؛ ومرجع artifact محدودًا.

يجب أن يميز العقد بين `authorization_denied`، و`backend_unavailable`، و`sandbox_setup_failed`، و`RESOURCE_LIMIT_EXCEEDED`، و`TIMED_OUT`، و`CANCELLED`، و`COMMAND_FAILED`، و`SUCCEEDED`. لا يحوّل `RESOURCE_BLOCKED` أو فشل الإعداد إلى نجاح. نتيجة بدء العملية receipt مستقل صادر من backend بعد نجاح إنشاء العملية، يحتوي على PID موجب ووقت UTC وهوية عملية/تشغيل ومراجع المهمة والنداء والـbackend/profile؛ عدم وجود receipt يعني عدم وجود دليل على بدء العملية.

`DISPATCHED` في ledger هو حد write-ahead لمحاولة الأثر، وليس برهانًا على إنشاء OS process. لا ينشئ harness حدث `TOOL_CALLED` أو process evidence قبل تحقق التفويض والنطاق والإعداد وبدء العملية بالطريقة المعتمدة. إذا أثبتت واجهة النظام فشل الإنشاء قبل وجود child، يسجل no-effect؛ وإذا تعذر إثبات ذلك بعد write-ahead، تبقى الحالة `RECOVERY_REQUIRED`/ملتبسة ولا يسمح بإعادة المحاولة تلقائيًا.

### 10.2 Windows: لا تفعيل دون حاجز أمني كامل وإثبات أصلي

يبقى `WindowsAppContainerBackend` محجوبًا fail-closed حتى اكتمال backend حقيقي ونجاح اختبارات Windows أصلية. الاسم الحالي `windows-appcontainer-job` لا يثبت وجود Job أو AppContainer؛ التنفيذ الحالي يصرح `windows_appcontainer_backend_unimplemented` حتى على Windows. لا يُستبدل ذلك بـ`Popen` عادي أو تشغيل بصلاحيات المستخدم أو Job Object منفرد.

التنفيذ المقترح عند توفر Windows runner:

1. إنشاء AppContainer أو LPAC مخصص لكل profile أمني مع capabilities أقل ما يمكن. السياسة الافتراضية لا تمنح `internetClient` أو `privateNetworkClientServer` أو server capabilities. يجب أن تثبت اختبارات sockets حظر الشبكة الفعلية، لا مجرد حذف متغيرات البيئة.
2. منح SID الخاص بالعزل قراءة/تنفيذًا للـPython runtime ومدخل workspace مصرح/منقّى فقط. يكون إدخال workspace للقراءة فقط؛ والكتابة تذهب إلى temp/artifacts معزولين. لا تُكشف ملفات المستخدم أو بيانات الاعتماد أو DB التطبيق أو مفاتيحه. إذا لم يمكن فرض ACL الفعلية أو عزل الأسرار، يرفض backend التشغيل.
3. ينشأ Job Object لكل تشغيل قبل العملية، وتضبط حدود العملية/CPU والذاكرة/عدد الأبناء المتاحة، `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`، ومنع breakaway. يبدأ child معلقًا، ثم يربط بالـJob ويُتحقق من عضويته وهوية token والـACL والسياسات قبل Resume. فشل أي تحقق ينهي handle المعلّق المملوك لهذه المحاولة فقط ويغلقه.
4. Job Object لإدارة lifecycle وحدود العمليات؛ لا يوفر وحده عزل ملفات أو شبكة ولا حصة كتابة موثوقة على القرص. يتطلب حد الكتابة حاوية/قرصًا مؤقتًا محدودًا فعليًا أو يظل backend غير متاح. Restricted Token تقييم إضافي لتقليل privileges/SIDs فقط، وليس بديلًا عن AppContainer/ACL أو آلية افتراضية مكافئة.
5. الإلغاء ينهي Job المملوك لهذه المحاولة فقط، وينتظر إشارة خلوه ويتحقق من اختفاء كل أعضائه. غياب `AssignProcessToJobObject` أو capability أو ACL أو حد القرص أو تحقق الشبكة سبب رفض دقيق قبل بدء التنفيذ، بلا fallback.

للقبول المثبت، يقتضي Windows CI أصليًا اختبارات نجاح تنفيذ معزول، رفض مسار خارج workspace، منع ملف حساس وشبكة غير مصرح بها، موارد، timeout/cancel وتنظيف كل descendants. اختبارات Linux أو mocks أو `sys.platform` المحاكى لا تعد إثباتًا. وثائق Microsoft المرجعية: [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)، [AppContainer isolation](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation)، [Implementing an AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer)، و[CreateRestrictedToken](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken).

### 10.3 Linux: حد إجمالي مطلوب؛ لا اعتبار RLIMIT_AS حد شجرة

`bubblewrap+prlimit` الحالي يفرض `RLIMIT_AS` لكل عملية ولا يحد مجموع ذاكرة الأبناء أو الأعمال المتزامنة. لا يُعرض backend Linux على أنه متاح إلا مع cgroup v2 مفوضة ومهيأة ومملوكة للخدمة: controller `memory` مفعّل، حد إجمالي `memory.max` مثبت على subtree خاص بالخدمة، child cgroup لكل تشغيل، `memory.oom.group=1`، وحد `pids.max`، وآلية `cgroup.kill` موثوقة متاحة. يجب أن يدخل launcher موثوق إلى child cgroup **قبل** `exec` لـbubblewrap/الأمر غير الموثوق؛ لا يُنقل process بعد إطلاقه ولا يكشف cgroup filesystem داخل sandbox. تُقرأ `memory.events.local` لتصنيف OOM صريحًا كـ`RESOURCE_LIMIT_EXCEEDED` دون الخلط مع timeout أو cancel أو SIGKILL خارجي. تبقى حدود `prlimit` الحالية مكملة ولا تضعف.

الـsubtree الإجمالي يحد كل الأعمال المتزامنة التابعة لنفس service delegation، وليس عمليات تطبيق أخرى أو host كاملًا. لا تُنشأ أو تُنقل cgroups في hierarchy يملكها systemd/المضيف؛ إعداد `Delegate=` والـleaf/controller topology مسؤولية deployment مصرح به. عدم توافر التفويض/التحقق/الكتابة/`cgroup.kill` يؤدي إلى `backend_unavailable` أو `sandbox_setup_failed` مع صفر إطلاق. وثائق Linux الرسمية: [cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html) و[systemd delegation](https://systemd.io/CGROUP_DELEGATION/). الفحص الحالي أظهر أن runner لا يملك تفويضًا قابلًا للكتابة؛ لذلك لا يوجد تكامل cgroup حقيقي يمكن إثباته هنا.

### 10.4 مزامنة Owner cancellation وdispatch وterminal state

الـlocks والـevents داخل `tools.registry` إشارات محلية فقط ولا تصلح مصدر الحقيقة عبر worker processes. مصدر الحقيقة هو SQLite fence والحالة الدائمة:

- تتسابق كتابة marker الإلغاء وCAS انتقال الأثر `RESERVED → DISPATCHED` في transaction دائمة واحدة على DB queue/effect؛ يتحقق CAS من marker وlease epoch/worker generation/fence وOwner snapshot. إذا سبق الإلغاء، لا handler ولا process يبدأ، ويغلق الحجز `FAILED/no-effect` فقط بدليل عدم dispatch. إذا سبق dispatch، لا يدعي الإلغاء no-effect؛ يعرض التنفيذ in-flight/ambiguous ويمنع retry.
- يقتصر القفل المحلي على حدود CAS قصيرة. لا يبقى ممسوكًا حول handler طويل؛ بعد قبول marker تُرسل إشارة cancellation تعاونية ويظل أثر ما بعد dispatch غير محسوم إلى أن تثبت نتيجته.
- لا تستخدم `MissionQueue.enqueue(CANCELLED)` كعملية cancel. تُراجع حالة Mission والـqueue terminal داخل CAS؛ إن سبق الإكمال ترجع العملية `already_completed` بلا marker دائم أو تغيير terminal state. إذا اختلفت DBs، يلزم transaction بربط SQLite تحت rollback-journal أو بروتوكول دائم متكافئ؛ لا يعتمد على قفل Python.
- recovery يقرأ marker الدائم ويطابقه مع Mission progress/queue. لا تعاد المهمة إلى READY أو claimable مع بقاء marker، وتُرفض start/resume بعد restart بوضوح. لا تُمحى هوية Owner أو موافقة/Scope أو fence عند الاستعادة.

### 10.5 MCP: deadline يشمل انتظار executor وحد الإرسال

الـdeadline يبدأ قبل `submit` ويحسب وقت الانتظار في `_REMOTE_EXECUTOR`. عند timeout/cancel يُضبط token للمحاولة وتلغى Future إن كانت ما تزال queued. يتحقق worker نفسه من token والـdeadline وOwner/Mission/Scope/ExecutionFence عند حد socket send تحت dispatch guard؛ أي Future استيقظت متأخرة ترفض قبل إرسال bytes. إذا بدأ الإرسال فعلًا، النتيجة الخارجية ملتبسة ولا تحدث retry تلقائية. تنفيذ MCP الحالي يطبق Future cancellation وإعادة فحص scope عند حد الإرسال؛ واختبارات queued-timeout وcancel notification بعد انتهاء deadline تغطي هذا السلوك. `notifications/cancelled` محاولة منفصلة قصيرة، ويمكنها تجاوز deadline التنفيذ فقط، لا Owner authentication أو mission identity أو scope أو fence.

### 10.6 أدلة القبول والخصوصية

متحقق القبول يربط receipt `process_started` حقيقيًا بـMission/request/task/action/tool-call وdispatch/effect، ويفرض `process_started=true` وPID موجبًا ووقت بدء UTC والـbackend/profile المثبتين والمتطابقين بين سجل sandbox ونتيجة الأداة، مع `SUCCEEDED` وسبب خروج صفر وعدم وجود resource-limit reason. ثم يطابقه مع `ToolExecuted` وevent/chain. `ToolExecuted` وحده لا يثبت أن OS process بدأ. إسقاط الفشل يحفظ `kind`/`reason_code`/resource reason وmetadata البدء الآمنة وdigest للحمولة الخام دون كشف النص الحساس.

تُستبدل فحوص regex الشكلية للـIDs/الأكواد بـallowlists ثابتة أو كشف أسرار قبل الإسقاط. لا تمرر قيم token-shaped حتى لو بدت صياغتها كـID أو `reason_code`. لا تسجل نص exception الخام من API/PowerShell أو traceback غير مفلتر؛ تسجل فئة/`reason_code` ثابتًا وحقولًا آمنة وhash/length عند الحاجة. لا تلتقط كلمات مرور Owner أو tokens أو environment أو output غير ضروري. chain/hash يثبت الاتساق لا هوية مصدر خارجي؛ يجب وصفه كدليل قابل للمراجعة لا كتوقيع/attestation مستقل.

### 10.7 Lifecycle القبول وإعادة الاستعادة

الإطلاق الأول وإعادة الفتح في acceptance harness يستخدمان primitive واحدة تملكها عملية الاختبار: Job Object للـUI app process tree، يحتفظ بالـhandles حتى إغلاقها. يسجل launch receipt يشمل image path المثبت، PID، creation time، job identity/عضوية Job وCDP endpoint المربوط بالعملية. الإنهاء عبر Job/handle الذي أنشأه الاختبار فقط، ثم wait والتحقق من Job فارغ وprocess exited وCDP غير متاح. لا تستخدم اسم executable وحده، ولا snapshot واسع أو `taskkill` PID-only، ولا تقتل عمليات مستخدم أخرى. إذا لم يثبت launch identity، يفشل الاختبار بوضوح بلا إنهاء. الكود يطلق نفس executable/profile عند restart، ويترك runtime نفسها تستعيد Mission من checkpoint وسجلات DB؛ لا يصطنع harness أحداث إكمال أو replay لأثر غير آمن. هذا السلوك لم يُشغّل على Windows في هذه المهمة.

هذا الـJob في harness مسؤول عن دورة حياة **التطبيق المثبت** فقط، ولا يثبت أن كود الاختبارات داخل Windows sandbox. لا يُخلط الإثباتان. يجب حفظ Mission ID وسلسلة الأدلة، مقارنة سلامة DB/trajectory/hash-chain قبل وبعد restart، وتسجيل حالات الإغلاق وإعادة الفتح/resume ومحاولاتها ونتائجها.

### 10.8 جرد مسارات التشغيل وحدودها

تصل واجهات `Workspace.run_shell`, `run_process`, `develop`, `git_readonly`, `ProcessManager.start` وأداة `run_project_tests` إلى `_sandbox_popen` والـbackend المشترك؛ يظل هذا المسار الوحيد لتنفيذ أوامر Mission. `tools.browser`/Playwright مسار منفصل بحدود المتصفح وشبكة scope، وليس منفذ shell ولا بديلًا عن sandbox workspace. `agent/local_runtime/runtime.py` يبدأ executable ثابتًا من مجلد runtime للاستدلال المحلي على loopback مع مفتاح مؤقت ومهل startup/inference؛ و`agent/local_runtime/hardware.py` يشغّل استعلامات ثابتة مثل `nvidia-smi` وPowerShell بمهلة قصيرة، وهذه خدمات/استطلاعات موثوقة وليست ToolSpecs تعطي تنفيذًا اعتباطيًا. تبقى هذه المسارات محدودة بالـargv والثابت التنفيذي والبيئة والمهلة، ولا تسجل كدليل sandbox لاختبارات المشروع؛ فشل timeout لا يخفى كنجاح.

### 10.9 بوابة التنفيذ والاختبارات

الترتيب المنفذ: إغلاق سباقات CAS؛ عقد backend ونتائج الموارد/البدء؛ deadline MCP حتى socket send؛ evidence sanitizer/verifier؛ ثم lifecycle harness. المجموعة الكاملة اجتازت بـ`1973 passed, 25 skipped`، لكن الاختبارات التي تشترط تشغيل process sandbox الحقيقي skipped هنا بسبب `cgroup_v2_delegation_unavailable`، واختبار Windows Job الأصلي skipped على Linux. يلزم runner مفوض لإثبات cgroup، وWindows أصلي لإثبات Job والقبول. لا يحسب mock بديلًا.

لا تُفعّل Windows backend ولا تُخفض المتطلبات ولا تُنشئ tag/release. التقرير النهائي يصنف وفق الأدلة. ما لم تتوفر بيئة Windows ذات backend حقيقي واختبار Mission كامل، لا تكون النتيجة `PASS`.
