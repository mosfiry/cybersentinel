# D2 LPAC — متابعة B: تشخيص إطلاق محدود

## النطاق والنتيجة

هذه متابعة تشخيصية فقط لفرع `fix/blocker-d2-lpac-20261021` عند أساس `5a540ffa47a53803005c620511075b5a8873a2af`. عند فشل `CreateProcessW`، يلتقط الـprobe قيمة Win32 فورًا قبل أي تشخيص؛ ثم يطبع مؤشرات بلا مسارات: مطلقية image وcwd، وجود الملف/المجلد، نتيجة فتح image للقراءة من **الـbroker فقط** وحجمه إن أمكن، تطابقه مع module الجاري، قناع وجود أربعة DLLs نظامية متوقعة، PID/bitness للـbroker وlaunch flags. تبقى رسالة النظام محدودة الحجم، ويظل NTSTATUS موسومًا advisory.

فتح الـbroker للملف لا يثبت وصول LPAC إليه. قائمة DLLs الثابتة تفحص وجود `kernel32.dll` و`kernelbase.dll` و`ntdll.dll` و`advapi32.dll` في مجلد النظام؛ لا تثبت أن loader حل كل PE imports. لا تُسجل المسارات أو SID أو argv أو قيم البيئة. لا تُنشأ عملية بديلة ولا profile، ولا تُضاف capabilities أو ACL أو استثناءات شبكة؛ ولا تتغير سياسة الإطلاق أو backend الإنتاجي. خطأ 2 وNTSTATUS `0xC000000F` لا يحددان المورد المفقود، وهذه الإضافة لا تغلق D2.

## تحقق هذه المتابعة

اختبارات `tests/test_windows_lpac_diagnostics.py` هي source guards محمولة وليست اختبار عزل Windows. شُغّلت: `python -m pytest -q tests/test_windows_lpac_diagnostics.py` — `4 passed`، ومع اختبار workflow المرتبط `python -m pytest -q tests/test_windows_lpac_diagnostics.py tests/test_windows_appcontainer_ci_workflow.py` — `7 passed`. نجح MinGW في compile صارم للـobject والربط إلى PE x64 باستخدام `-municode` (مع تجاهل تحذير MSVC-specific `#pragma comment` فقط). هذا ليس بناء MSVC ولا تشغيلًا أصليًا. الأدلة الخام في `/workspace/d2-continuation-evidence/b-*`. حتى نقطة التحقق المحلية هذه، قبل الدفع إلى CI، لم يُشغّل probe على Windows ولم يُنفذ ProcMon/ETW؛ نتائج CI اللاحقة تخص SHA المدفوع ويجب فصلها عن هذا التحقق المحلي. صلاحية تحميل driver أو التتبع داخل hosted runner **غير مفحوصة**؛ لا توجد جلسة Windows تفاعلية مصرّح بها متاحة هنا. لا يُدّعى وجود native tracing.

## إعادة إنتاج trace عند توفر جلسة موثوقة ومصرح بها

1. استخدم Windows تفاعليًا مصرحًا، ونفّذ نفس SHA/الاختبار الأصلي عبر بوابة Windows المعتادة دون تغيير DACL أو profile أو capabilities أو الشبكة. ابدأ ProcMon capture قبل الاختبار، واحتفظ بملف PML الخام مع SHA ونسخة Windows ووقت المحاولة.
2. عند فشل `CreateProcessW`، خذ `broker_pid` من سطر `lpac_launch_diagnostic`. صفِّ أحداث ProcMon بعد الالتقاط إلى `Process ID is <broker_pid>`، وعمليات `Process Create`, `CreateFile`, `QueryOpen`, `Load Image`, وعمليات Registry مثل `RegOpenKey`, `RegQueryValue`, `RegCreateKey`, `RegSetValue`. احتفظ كذلك بالأحداث المحيطة زمنيًا لتسلسل الإطلاق، ثم صدّر العرض المصفّى CSV.
3. اربط أحداث `NAME NOT FOUND` بتسلسل العملية والطابع الزمني/المورد وبالفشل المرصود؛ لا تعتبر كل miss منفرد سببًا، إذ قد تكون نتيجة طبيعية للبحث عن DLL أو registry key في مسارات بديلة. يلزم حدث ذو صلة وقرائن متسقة قبل اقتراح سبب. افصل أحداث broker قبل إنشاء الطفل عن أي أحداث لاحقة، ولا تنسب وصولًا أو رفضًا إلى token طفل لم يُنشأ.
4. سجّل PML وCSV وSHA/runner والإعدادات كأدلة؛ لا تعدّل الصلاحيات في محاولة trace. إن لم تتوفر صلاحية التتبع، سجّل ذلك كقيد غير مختبر بدل استنتاج أن hosted runner يمنعها.
