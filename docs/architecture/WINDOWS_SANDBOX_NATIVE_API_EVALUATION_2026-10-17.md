# تقييم واجهات Windows الأصلية لعزل عمليات المهام

**القرار:** لا تفعيل لـ`windows-appcontainer-job` ولا تغيير في التنفيذ. يبدأ هذا التقييم من الفرع `fix/blocker-d-review-20261010` عند SHA `a6204fb5de8e68da83e240cbc08032a418f0d8ae`. لا يثبت نجاح المهمة؛ تظل `PROCESS_SANDBOX_UNAVAILABLE` و`RESOURCE_BLOCKED` صحيحتين إلى أن تجتاز بوابات Windows الأصلية المذكورة أدناه.

## الخلاصة التقنية

لا توجد واجهة واحدة موثقة هنا تحقق كامل العقد. التركيب المستقر الممكن يجمع AppContainer أو LPAC، وقوائم ACL صريحة، وJob Object، ومراقبًا موثوقًا لمهلة الزمن الحقيقي، وآلية مستقلة لحصة القرص، وإيصال بدء دائمًا مربوطًا بـMission. كل طبقة تحتاج اختبارًا على Windows فعلي.

تقدم Microsoft أيضًا `Experimental_CreateProcessInSandbox` على Windows 11. توثيقه يصف AppContainer وقواعد ملفات وشبكة، لكنه يصرح بأن الواجهة تجريبية وقابلة للتغيير، ويتطلب تحميل `processmodel.dll` ديناميكيًا لأن الرأس العام غير متاح. المواصفة الموثقة تعرض `fs_read_only` و`fs_read_write` وcapabilities وسياسة proxy، ولا تعرض حقولًا لحدود CPU أو الذاكرة أو القرص أو الزمن. لذلك لا تصلح هذه الواجهة وحدها لإثبات متطلبات CyberSentinel، ولا يُعتمد عليها في backend إنتاجي قبل استقرارها واختبارها على Windows مدعوم. [1]

وتوجد قيود تكامل أخرى: يجب أن تكون `processAttributes` و`threadAttributes` فارغة، ويجب أن يكون `inheritHandles=false`. كما أن `ui_restrictions` تُنشئ Job لقيود واجهة المستخدم، ولا توثق إعداد حدود موارد Job التي يملكها المستدعي أو ربط Job مخصصة عند الإنشاء. لذلك لا تحقق الواجهة، كما هي موثقة، عقد تمرير artifact/start-marker handles أو Job المخصصة في التصميم الحالي من دون إعادة تصميم واختبارات Windows مستقلة. [1]

## الهوية والملفات والشبكة

المسار المستقر المرشح هو إنشاء هوية AppContainer مستقلة للتشغيل بواسطة `CreateAppContainerProfile` أو اشتقاق SID معروف، ثم إعداد `STARTUPINFOEX` مع `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` وإطلاق العملية عبر `CreateProcessW`. يتيح LPAC إضافة `PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT`. يجب ألا تمنح العملية capabilities لا يحتاجها الاختبار. AppContainer يعزل الموارد، لكن المسارات المسموحة تبقى قرار ACL؛ تغيير `cwd` أو تمرير مسار workspace لا يفرض حدًا أمنيًا وحده. `CreateRestrictedToken` قد يخفض صلاحيات إضافية، لكنه لا يحل محل AppContainer أو ACL أو عزل الشبكة. [2] [3] [4] [12]

على الملفات، يجب أن تحد ACL الفعلية الوصول إلى نسخة تشغيل مؤقتة من المشروع، مع فصل المدخلات للقراءة فقط عن مجلدات الكتابة المؤقتة والأدلة. يلزم اختبار المنع على ملفات خارج النطاق، وملفات تعريف المستخدم، وأسرار الاختبار، وقواعد بيانات التطبيق، مع مسارات traversal وreparse points. لا يجوز منح SID صلاحية على مجلد أوسع من المشروع ثم الاكتفاء بتقييد المسار في Python. وسيحتاج أي مسار لاستخدام هوية AppContainer متكررة إلى إثبات عدم تراكم ACLs أو الصلاحيات؛ مع الواجهة التجريبية، الهويات المتطابقة تشترك في ملف التعريف نفسه، ولذلك يجب أن يكون لكل تشغيل هوية فريدة. [1] [3]

توثيق AppContainer يصف الشبكة بأنها محجوبة ما لم تُمنح capabilities مناسبة؛ لا تُمنح `internetClient` أو `privateNetworkClientServer` في السياسة الحالية. يجب مع ذلك اختبار اتصالات IPv4 وIPv6 إلى loopback والشبكة الخاصة والإنترنت، وطلبات DNS والاتصالات الواردة. لا يكفي الاعتماد على Windows Firewall العام، لأن Windows يسمح بخروج الشبكة افتراضيًا في الإعداد المعتاد. [1] [3] [5]

## حدود الموارد وشجرة العمليات

Job Object مرشح لملكية شجرة العملية: تُنشأ Job مستقلة لكل محاولة، وتُضبط الحدود قبل السماح بالتنفيذ، ويُمنع breakaway، وتُحتفظ handles الأصلية، ويُنهي الإلغاء Job المقصودة وحدها. `PROC_THREAD_ATTRIBUTE_JOB_LIST` يمكنه ربط العملية بـJob عند الإنشاء في Windows 10 وما بعده. إذا استُخدم البديل `CREATE_SUSPENDED` ثم `AssignProcessToJobObject`، يجب التحقق من نجاح الإسناد والهوية والحدود قبل `ResumeThread`؛ فشل الإسناد يعني عدم استئناف العملية. يجب اختبار التعشيش داخل Job التي قد يفرضها CI، وأي حد أدنى للنظام المستهدف. [6] [7] [8]

تغطي Job Objects بعض الحدود الإجمالية، لا كلها:

- `ActiveProcessLimit` يحد عدد العمليات النشطة المرتبطة بالـJob.
- `JobMemoryLimit` يحد مجموع الذاكرة **المعتمدة/المحجوزة (committed virtual memory)** للعمليات في Job؛ تجاوز الحد يجعل طلبات الالتزام الجديدة تفشل. هذا ليس حدًا عامًا لحجم القرص ولا يصح وصفه بأنه حد RAM بسيط.
- `JOB_OBJECT_LIMIT_JOB_TIME` يحسب وقت CPU بنمط user-mode على مستوى Job؛ ليس مهلة زمن حقيقي. `JOBOBJECT_CPU_RATE_CONTROL_INFORMATION` يحد معدل CPU لكل فترة جدولة، ولا يساوي ميزانية CPU تراكمية. [13]
- المهلة الحائطية تحتاج مراقبًا موثوقًا خارج العملية يستخدم ساعة monotonic، ثم ينهي Job ويؤكد خلوها من الأعضاء.
- Job Object لا يقدم حصة كتابة للقرص. حصص NTFS التي توثقها Microsoft تُدار لكل مستخدم على مستوى حجم NTFS، لا لكل Job؛ يلزم إثبات ملاءمتها لهوية AppContainer على النظام المستهدف، أو استخدام مساحة تخزين منفصلة ذات حد يفرضه النظام. حد حجم artifact داخل التطبيق وحده غير كافٍ.

تستند هذه الحدود إلى بنى Job الرسمية، لا إلى تقدير من التطبيق. يجب أن تختبر المجموعة أبناءً متعددين يتجاوزون الحدود مجتمعين، لا عملية واحدة فقط. [6] [9] [10] [11]

## بدء العملية والدليل الدائم

عودة `CreateProcessW` توفر handles العملية والخيط ومعرف العملية، لكنها ليست وحدها إيصالًا دائمًا مربوطًا بـMission. عند الإطلاق يجب حفظ محاولة dispatch أولًا عبر Execution Fence القائم؛ ثم لا يسجل backend `process_started=true` إلا بعد إثبات عملية Windows فعلية، وهوية token/SID، ومسار executable، وعضوية Job وحدودها، ووقت الإنشاء. يُحفظ إيصال محدود الحقول ومربوط بمعرفات Mission/request/tool-call في السجل الدائم قبل قبول نتيجة الأداة. لا تسجل environment أو أسرار أو مخرجات خام. [14]

إذا وقع crash بعد إنشاء العملية أو استئنافها وقبل حفظ إيصال البدء، فلا يجوز تفسير غياب الإيصال على أنه دليل أن العملية لم تعمل. تظل المحاولة ملتبسة وتحتاج مصالحة، ولا تُعاد تلقائيًا. هذا يحافظ على سجل الأدلة وExecution Fence بدل اصطناع بدء أو نجاح.

## بوابات Windows المطلوبة قبل إتاحة backend

1. اختبار إيجابي أصلي يثبت AppContainer/LPAC الفعلية وSID والـcapabilities، وأن الأمر والأبناء داخل Job المحددة قبل بدء الكود غير الموثوق.
2. اختبارات ملفات إيجابية وسلبية للمدخلات والمخرجات المصرح بها، وللنطاق الخارجي وملفات المستخدم والأسرار وقواعد بيانات التطبيق، بما فيها reparse points وعمليات التنقل خارج المجلد.
3. اختبارات شبكة سلبية لـloopback وIPv4/IPv6 وDNS والشبكة المحلية والإنترنت والاستماع الوارد، من داخل العملية نفسها.
4. اختبارات إجمالية لمجموع الذاكرة المعتمدة، وعدد العمليات، وزمن CPU، والمهلة الحائطية، وامتلاء القرص عبر كتابة مباشرة من أكثر من عملية فرعية؛ يجب أن يطابق سبب الإيقاف الحد الذي فرضه النظام.
5. اختبارات إلغاء وانهيار للـOwner والـworker، و`KILL_ON_JOB_CLOSE`، ومحاولة breakaway، وفشل إنشاء/إعداد Job. تتحقق كل حالة من عدم بقاء أبناء ومن عدم قتل عمليات أخرى.
6. اختبار قبول Mission مثبتة بالكامل بعد تبديل النموذج وإعادة تشغيل التطبيق/المهمة: حفظ نفس Mission والأدلة والنتيجة، مطابقة Owner وScope Firewall، وعدم إعادة side effect ملتبس أو تسجيل dispatch/process-start بلا دليل أصلي.

الاختبارات المحاكية على Linux أو `sys.platform` المزيف أو تشغيل `Popen` عادي لا تثبت هذه البوابات. إذا تعذر أي اختبار أصلي، تبقى الإتاحة `false` وتظل حالة المهمة محجوبة.

## حالة المستودع عند التقييم

في المصدر الحالي، `WindowsAppContainerBackend.availability()` يعيد `backend_unavailable/windows_appcontainer_backend_unimplemented` حتى على Windows، و`spawn()` يرفض قبل أي `Popen`. هذا السلوك يُترك كما هو. خطة المشروع وقائمة المهام فيهما بنود غير مكتملة؛ لم تُعدّل أو تُستبدل في هذا التقييم.

## المراجع

[1]: https://learn.microsoft.com/en-us/windows/win32/secauthz/createprocessinsandbox "Create Process in Sandbox — experimental API"
[2]: https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer "Launch an AppContainer"
[3]: https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation "AppContainer isolation"
[4]: https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken "CreateRestrictedToken function"
[5]: https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules "Windows Firewall rules"
[6]: https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects "Job Objects"
[7]: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute "UpdateProcThreadAttribute function"
[8]: https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-assignprocesstojobobject "AssignProcessToJobObject function"
[9]: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information "JOBOBJECT_BASIC_LIMIT_INFORMATION structure"
[10]: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information "JOBOBJECT_EXTENDED_LIMIT_INFORMATION structure"
[11]: https://learn.microsoft.com/en-us/windows/win32/fileio/managing-disk-quotas "Managing Disk Quotas"
[12]: https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-createappcontainerprofile "CreateAppContainerProfile function"
[13]: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_cpu_rate_control_information "JOBOBJECT_CPU_RATE_CONTROL_INFORMATION structure"
[14]: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw "CreateProcessW function"
