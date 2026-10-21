# CyberSentinel: لماذا يتوقف LPAC وما يلزم لتشغيل Mission بأمان

## النتيجة الحالية: BLOCKED

فشل Windows الأصلي مؤكد، لكن **الكائن المفقود الذي أدى إلى الخطأ لم يُحدد بعد**. لا يصح تحويل الرقم 2 إلى ادعاء أن ملف EXE نفسه مفقود، أو إلى ادعاء أن CI لا يدعم LPAC. كذلك لا يكفي إصلاح launcher الاختباري لإغلاق D2: backend الإنتاجي لـWindows لا يزال غير منفذ أصلًا.

هذه نقطة عمل مستقلة من إصلاح D4 عند `77515ed87435b051faf0d16a04ee89246eeff1aa` على فرع `fix/blocker-d2-lpac-20261021`. لم يُفعّل backend ولم تُخفف الصلاحيات أو الاختبارات. لا تغيير لـmain أو v5.1.0 أو Skill Routing أو Cloudflare أو Workers Builds.

## Latest native evidence on the diagnostic commit

[Windows run 39579691012](https://github.com/mosfiry/cybersentinel/actions/runs/39579691012) tested `feeb6236c70520931bb9e92c022b517aef77dd58`. MSVC built the trusted probe successfully; all four LPAC tests still failed at CreateProcessW. Each failure reported Win32=2, advisory NTSTATUS=`0xC000000F`, an existing executable matching the broker's running module, and an existing cwd with metadata error codes zero. These are broker-side observations after failure, not proof of LPAC access or the identity of the missing internal object. The profile/namespace/dependency hypotheses remain unresolved, and no child token or confinement was verified. Separate Job and VHD jobs passed; their artifacts do not establish a combined sandbox.

The same revision's [Linux CI run](https://github.com/mosfiry/cybersentinel/actions/runs/39579691217) failed because an unchanged test read an empty PID file after checking only its existence. The publication-race mechanism was reproduced separately; that test and its helpers were not changed. Full outcomes, earlier failures, image-version differences and the acceptance matrix are preserved in [the checkpoint results](../../tasks/d2-lpac-20261021/results.md). Final local regression was 2330 passed, 53 skipped, 4 warnings; that does not override either CI failure.

## ما ثبت مباشرة

في [تشغيل Windows على أساس D4](https://github.com/mosfiry/cybersentinel/actions/runs/39248495206)، فشلت اختبارات LPAC الأصلية الأربعة عند `CreateProcessW`، مع نجاح 17 اختبارًا آخر في job نفسها. سجل الـprobe يقول `CreateProcessW LPAC (2)`؛ الرقم **2 هو Win32 GetLastError**، أما خروج launcher برقم **20** فهو كود فشل ثابت في الاختبار، وليس نتيجة تشغيل طفل. الفشل يسبق فتح token الطفل و`ResumeThread`؛ لذلك لا توجد في هذه المحاولة هوية طفل مثبتة أو أدلة رفض ملفات من داخله.

تعريف Microsoft للرمز 2 هو [ERROR_FILE_NOT_FOUND](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-): «النظام لا يجد الملف المحدد». يختلف عن PATH_NOT_FOUND=3 وACCESS_DENIED=5 وBAD_ENVIRONMENT=10. هذه أسماء لفئات الأخطاء، وليست برهانًا على أي كائن داخلي بعينه ولا تستبعد ترجمة Windows لفشل داخلي إلى هذا الرمز.

الـrunner الأصلي كان Windows build `10.0.26100`، image `win25-vs2026`، version `20261007.264.1`. في التشغيل نفسه نجحت 19 حالة Job/رفض آمن و6 حالات VHD. نجاح هاتين البدائيتين لا يثبت LPAC أو منع الشبكة أو عزل Mission.

في [desktop acceptance على D4](https://github.com/mosfiry/cybersentinel/actions/runs/39248495208)، انتهت Mission إلى `RESOURCE_BLOCKED` مع `PROCESS_SANDBOX_UNAVAILABLE`، وليس `GOAL_COMPLETED`. هذه نتيجة متسقة مع رفض backend الإنتاجي، ولا تثبت أن LPAC probe وحده هو كل سبب تعطيل Mission.

وفي [تجربة LowBox على D4](https://github.com/mosfiry/cybersentinel/actions/runs/39248495242)، كان workflow أخضر لكن artifact يقول `mission_acceptance=BLOCKED`، ومرحلة التنفيذ الفعلية `nt_create_lowbox_token` أعادت NTSTATUS `0xC0000022` وترجمته Win32=5، دون طفل متحقق أو resumed. هذا إخفاق مختلف عن CreateProcessW=2، وليس بديلًا مكافئًا أو نجاحًا للعزل.

## أين يحدث الفشل

`tests/native/appcontainer_acl_probe.c::launch_child` ينشئ قائمة attributes تحتوي SECURITY_CAPABILITIES وLPAC opt-out، مع SID التشغيل، وعدد capabilities يساوي صفرًا. يمرر التطبيق صراحة في `lpApplicationName`، ويقتبس سطر الأوامر، ويستخدم `STARTUPINFOEXW` و`EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW`، و`bInheritHandles=FALSE`.

إعداد attributes يطابق [نمط Microsoft لإطلاق LPAC](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer). لا يوجد في السجل فشل `UpdateProcThreadAttribute`. يُنشأ Job قبل العملية، لكن `AssignProcessToJobObject` يأتي بعد نجاح CreateProcessW، ولذلك لم تصل المحاولة الفاشلة إلى الإسناد أو التحقق من العضوية.

اختبار Python يبني probe بـMSVC `/MT /W4 /WX`، ثم ينسخه تحت `C:\cs-native-lpac-<random>\native-control`. root يمنح SID المحدد traversal فقط، وnative-control يمنحه القراءة والتنفيذ؛ workspace يملك DACL محمية ولا يمنح WRITE_DAC/WRITE_OWNER للـSID. لا توجد منحة ALL APPLICATION PACKAGES لتسهيل التشغيل. هذه إعدادات المصدر؛ لا تحل محل إثبات الوصول الفعلي من token الطفل.

البيئة المخصصة تحتوي SystemRoot وwindir وPATH نحو System32 وTEMP/TMP نحو workspace فقط. سياسة profileless مقصودة: `DeriveAppContainerSidFromAppContainerName` لا ينشئ profile، والاختبارات ترفض وجود مجلدات أو mapping/storage profile المعروفة قبل/بعد الإطلاق. دليل Microsoft المعتاد ينشئ profile؛ لذلك غياب تهيئة profile/namespace **فرضية تحتاج تجربة محددة**، وليس إصلاحًا مثبتًا. إضافة profile قد تضيف كتابة خارج الحصة المطلوبة، فلا يجوز إدخالها صامتًا.

## فصل الأسباب المحتملة

| الاحتمال | ما نعرفه | ما يفصل فيه |
|---|---|---|
| EXE أو cwd غير موجود | launcher نفسه يعمل من نسخة probe؛ المسارات مطلقة في Python، لكن السجل القديم لا يقيسها عند الفشل | قياس broker محدود لوجود image/cwd وتطابق module، ثم trace إذا بقي الفشل |
| خلل attributes أو SID | إعداد LPAC مقصود ومتوافق مع النمط، وتجاوز مراحل الإعداد دون فشل مسجل | مقارنة ABI وSID وattributes على Windows مع عدم تغيير السياسة |
| حقوق image/أسلافه أو موارد OS | ACL مقصودة للـSID، ولا يوجد دليل token طفل؛ Win32=2 لا يثبت رفض صلاحيات | Effective-access/ACL read-only وProcMon/ETW للكائن الذي فشل |
| profile أو object namespace غير مهيأ | التنفيذ profileless عمدًا، خلاف مسار التوثيق المعتاد | trace للكائن المفقود وتجربة معزولة مصرح بها؛ أي profile جديد يستلزم إثبات جميع الكتابات وحصتها |
| runtime/DLL/تهيئة البيئة | static CRT يقلل اعتماد CRT الخارجي ولا يلغي imports النظام؛ لم يصل الاختبار إلى child environment checks | فحص PE imports وloader trace؛ فصل فشل CreateProcess عن موت طفل بعد نجاحه |
| قيد CI | Windows APIs وبعض البدائيات تعمل؛ فشل LowBox مختلف | نفس SHA والسياسة على Windows VM مدعومة ثم مقارنة trace؛ لا دليل حالي على أن CI وحده السبب |

## التغيير المنفذ هنا وحدوده

أضيف تشخيص **عند الفشل فقط** إلى probe الموثوق: حفظ Win32 فور CreateProcessW، تسجيل وجود image/cwd من منظور broker وأخطاء metadata وتطابق image مع module الجاري، وطباعة رسالة النظام المحدودة بـ512 wchar. يُلتقط آخر NTSTATUS ديناميكيًا إن توفر، ويُوسم advisory صراحة؛ قد يكون قديمًا ولا يحدد الكائن أو يثبت سببية بمفرده. لا تسجيل paths أو SID أو argv أو environment values في التشخيص الجديد، ولا إنشاء profile أو capability أو إطلاق بديل أو استئناف طفل فاشل.

اختبارات source guards المحمولة تمنع فقدان الخطأ وتغيير الفشل إلى نجاح؛ **ليست اختبارات عزل Windows**. شُملت شريحة D2 في بوابة Windows الأصلية نفسها: expected tests الأربعة ورفض skip والمفقود والفشل وجمع artifacts المرتبطة بـSHA بقيت كما هي. لا تغيير لبوابة D4 أو verifier أو backend أو MissionRuntime أو ToolRegistry.

نتيجة التشغيل الجديد والاختبارات النهائية تُسجل في `tasks/d2-lpac-20261021/results.md`.

## التصميم المطلوب: backend حقيقي، لا تجاوز

### 1. عقد الإطلاق والفشل

يبقى `ProcessSandboxBackend.availability/spawn` مدخل Workspace الوحيد، و`WindowsAppContainerBackend` داخل `workspace/process_sandbox.py` هو موضع التكامل، لا `Popen` مباشر داخل tool أو Mission. تُراجع أولًا ملاءمة عقد `Popen[bytes]` وartifact_fd/start_marker_fd على Windows: Windows HANDLE ليس POSIX fd، ولا يجوز افتراض أن البروتوكول الحالي يعالج ذلك بلا adapter موثوق.

لا ترجع availability=true لمجرد إصدار Windows أو وجود API. يلزم probe ذاتي بسياسة الإنتاج، إثبات LPAC والـJob والتخزين والمنع والتنظيف، وبصمة implementation/runtime والسياسة. يبقى `windows_appcontainer_backend_unimplemented` حتى اكتمال ذلك. الفشل قبل الإنشاء يرفض دون marker أو ادعاء process_started؛ الغموض بعد write-ahead يُحفظ RECOVERY_REQUIRED بلا replay تلقائي.

### 2. الهوية وأقل الحقوق

SID عشوائي مستقل لكل run، مع LPAC opt-out وبدون network/registry/COM capabilities افتراضيًا، وبيئة allowlist بلا أسرار. أنشئ معلّقًا مع Job binding ذري عبر JOB_LIST حيث يدعم العقد، ثم تحقق من TokenIsAppContainer وTokenIsLessPrivilegedAppContainer وSID المطابق وLow Integrity وcapabilities الفعلية والصلاحيات الخطرة وهوية executable ووقت إنشائه وعضوية Job قبل السماح بالتشغيل. يُعاد التحقق من داخل trusted bootstrap؛ نجاح CreateProcess لا يكفي.

لا تضف صلاحيات administrator إلى الطفل. ما تحتاجه fixture مثل SeSecurityPrivilege لقراءة/ضبط mandatory labels ليس إذنًا للطفل ولا شرطًا مقبولًا لتشغيل كود مشروع بامتيازات broker. أي privileged helper يجب أن يكون صغيرًا ومثبت الهوية وله IPC موثق ومدخلات محدودة.

### 3. الملفات والقرص والـregistry والأجهزة

افصل project snapshot للقراءة فقط، وruntime موثوق للقراءة/التنفيذ فقط، وtemp/artifacts للكتابة ضمن حجم ثابت. استخدم NTFS محليًا وDACL محمية exact-SID، وbroker owner، دون منح واسعة أو WRITE_DAC/WRITE_OWNER. احتفظ بمقابض موثوقة وافحص final path/volume/file identity لمنع junction/reparse/hardlink/rename وTOCTOU، ولا تعوّل على cwd أو متغير TEMP.

VHD ثابت الحجم بدائية مرشحة وليست حلًا مكتملاً: يجب تركيب snapshot ومساحات temp/artifact وقياس حدودها بحيث تقع **كل الكتابات الممكنة** داخل حدود OS الإجمالية، بما فيها ملفات profile والـregistry المؤهلة والـruntime caches. لا يوجد Job disk quota. يجب تدقيق grants الموروثة من OS/ALL RESTRICTED APPLICATION PACKAGES والـnamed objects والأجهزة والـIPC، وتوثيق قراءات OS المسموحة صراحة. اختبارات sentinel وحدها لا تثبت حصر كل المسارات على النظام.

**بوابة قرار معماري:** إن لم يمكن تشغيل LPAC profileless مدعوم بالقيود الحالية، لا يُستخدم profile افتراضي قابل للكتابة خارج الحجم الثابت. يلزم إثبات طريقة مدعومة تحصر تخزينه دون تخفيف السياسة، أو اقتراح حد VM أقوى ومراجعته مستقلًا؛ لا اعتماد أي منهما تلقائيًا في هذه المهمة.

### 4. الشبكة

لا capabilities شبكة ولا loopback exemption أو firewall allow واسع. اختبر من الطفل وأبنائه IPv4/IPv6 وTCP/UDP وDNS وloopback/private/public والمنافذ الواردة. اختبر named-pipe/IPC أو broker قد يوفر network بالنيابة عنه. عند الحاجة إلى network tool مشروع، يبقى المسار typed عبر broker وToolRegistry وسياسة scope وOwner والفنس وDNS pinning القائمة، لا socket عام للطفل. لا منح internetClient لتجاوز فشل تشغيل image.

### 5. الشجرة والموارد والإلغاء

Job مستقل لكل run مع KILL_ON_JOB_CLOSE، بلا breakaway، وحدود aggregate memory/process count/CPU الفعلية وإثبات قراءتها. wall-clock deadline بساعة monotonic ومراقب موثوق؛ لا يساوي CPU time. handles غير موروثة افتراضيًا، وقائمة HANDLE_LIST ضيقة لقنوات محددة فقط عند الحاجة.

في خطأ الإنشاء/التحقق أو الإلغاء قبل Resume: لا تشغيل غير موثوق، أنهِ المملوك وانتظر reap. في timeout/cancel بعد التشغيل: أنهِ Job المملوك وتحقق من خلوه، ثم أغلق المقابض وافصل VHD واسحب ACL؛ فشل التنظيف ظاهر وقابل لإعادة المحاولة، وليس نجاحًا صامتًا. موت broker يجب أن يقتل الشجرة أيضًا. سحب ACL أو تحرير SID لا يلغي handles مفتوحة، لذلك يكون إنهاء الشجرة أولًا.

### 6. ربط Mission والأدلة والاستئناف

المسار يبقى `MissionRuntime → tools.registry.execute → Workspace → backend`. احفظ Owner/session/scope snapshot وExecution Fence وCAS الإلغاء وeffect ledger. `before_spawn` هو write-ahead وليس دليل بدء؛ receipt بعد تحقق OS والـbootstrap يربط mission/run/request/task/action/tool-call وPID/creation-time/backend/policy/image digest ووقت البدء والنتيجة والحصص. لا تقبل JSON يكتبه كود المشروع وحده كإثبات هوية العزل؛ مصدر الهوية broker وقناة موثقة.

المهمة المثبتة بعد restart تعيد فتح stores الحقيقية وتفحص receipt والسلسلة والتفويض الحالي، ولا تعيد أثرًا مجهولًا أو resurrect صلاحية قديمة. لا تعديل في D4 لقبول evidence ناقصة/قديمة، ولا إزالة شرط تطابق run identity وSHA وبصمة الملف التنفيذي ونافذة الوقت وMission الواحدة.

## الاختبارات اللازمة قبل التفعيل

1. **تحديد الخطأ:** نفس SHA على Windows CI وVM مناسبة، قياسات image/cwd وimports وACL/ancestors وprofile artifacts، ثم ProcMon/ETW restricted trace إذا لم يحدد التشخيص الكائن. لا تجربة profile أو capability واسعة ضمن إصلاح المنتج.
2. **إثبات الهوية:** LPAC/SID/IL/capabilities/privileges والـJob قبل Resume ومن trusted bootstrap، ثم إثبات الوراثة للأبناء. رفض أي mismatch وعدم ظهور marker.
3. **ملفات وموارد سلبية:** قراءة/كتابة أسرار broker والـDB وprofile وworkspace آخر ممنوعة برمز OS؛ رفض DACL/owner tamper وreparse/hardlink/rename/ADS/UNC/device/registry/IPC routes، وإثبات project/runtime read-only. low-label sentinels تفصل DACL عن MIC.
4. **شبكة:** محاولات حقيقية من الطفل والأحفاد لجميع المسارات أعلاه مع counters للـlisteners؛ لا يكفي غياب string output.
5. **حصص وتنظيف:** امتلاء القرص عبر أبناء متزامنين وكل writable roots؛ aggregate CPU/memory/pids، timeout، exit الجذر وبقاء أحفاد، تعطل broker، إلغاء متزامن مع الإطلاق/Resume، فشل allocation/attribute/job/identity/receipt/detach. جميعها bounded وتثبت خلو الشجرة أو تصنف تعذر التنظيف صراحة.
6. **Mission حقيقية:** النسخة المثبتة والنموذج المحلي عبر ToolRegistry الفعلي، تشغيل `run_project_tests` داخل العزل وصولًا إلى GOAL_COMPLETED، ثم إعادة تشغيل واستئناف مع Owner reauthorization وسلسلة أدلة صحيحة وعدم إعادة side effects. لا mocks للنموذج/العزل كبديل لهذا القبول.
7. **D4 والتراجع:** رفض missing/stale/mismatched evidence، ومجموعة pytest كاملة دون حذف أي إخفاق/skip، وقبول Windows UI الحقيقي. لا green للـworkflow أو أدوات Job منفصلة تغني عنها.

## ما يلزم للخطوة التالية

Windows VM أو جهاز مخول يدعم الاختبارات الأصلية وtrace، مع toolchain/runtime مثبتين وبيانات اختبار معزولة؛ ثم تحديد الكائن الذي يفشل في الفتح قبل قرار profile/namespace. لا توجد في الأجهزة المتاحة حاليًا بيئة Windows تفاعلية. لذلك التحقيق والتصميم قابلان للحفظ والمراجعة، لكن D2 وقبول Mission والاستئناف **غير مغلقين**.
