# CyberSentinel Windows Desktop

## استخدام Installer

حزمة Windows x64 المثبتة من هذا الفرع تحتوي على Electron وPython backend المجمّع وruntime CPU لـ`llama.cpp`. على المستخدم تشغيل ملف `CyberSentinel-Setup-5.1.0.exe` واتباع معالج التثبيت، ثم إنشاء كلمة مرور Owner عند أول تشغيل. لا يحتاج الاستخدام المثبت إلى Python أو Node.js أو Docker أو WSL أو Termux أو Terminal أو إعداد `.env` أو تشغيل bridge يدويًا.

من **الإعدادات** اختر نموذجًا ملائمًا للجهاز، ثم نزّله وفعّله. يتطلب تنزيل النموذج اتصال إنترنت ومساحة قرص بحسب الحجم المعروض؛ بعد اكتمال التنزيل والتحقق من SHA-256 يمكن تشغيل الاستدلال المحلي دون الإنترنت. النماذج المتاحة في كتالوج هذا البناء: Qwen3 4B، Qwen3 8B، وDeepSeek-R1-Distill-Qwen 7B، جميعها GGUF Q4_K_M. التطبيق يعرض حدود الذاكرة والمساحة، ولا يسمح بالتفعيل إن كان الجهاز غير ملائم.

تظهر المشاريع في Workspace، ويمكن إنشاء مشروع مُدار أو استيراد مجلد باستخدام نافذة Windows الأصلية. تُحفظ قاعدة البيانات والحالة والنماذج تحت مجلد `userData` الخاص بالتطبيق؛ مسار المجلد المختار لا يُعرض للواجهة. تبقى المهام والأدلة وسجل التشغيل على الجهاز بين جلسات التطبيق.

## حالة النشر والتوقيع

هذا بناء تطويري لفرع `work/windows-native-local-llm` وإصدار Desktop المرشح `5.1.0` فوق Core `5.0.0`. يُرفع Installer كـGitHub Actions artifact مرتبط بالـworkflow وcommit SHA لمدة 90 يومًا، مع SHA-256 وmanifest. المستودع عام؛ تعامل مع الفرع وسجل التشغيل والـartifact على أنها مرئية/قابلة للتنزيل وفق أذونات GitHub للمستودع. لا ينشئ هذا المسار tag أو GitHub Release أو نشرًا في registry/خدمة إنتاجية. الـInstaller غير موقّع رقميًا؛ قد يعرض Windows SmartScreen تحذير ناشر غير معروف. تحقق من SHA-256 للملف الذي استلمته قبل التثبيت.

## بناء Installer من المصدر

يتطلب البناء على Windows x64: Python 3.12، Node.js 22، والاتصال لتنزيل اعتماديات build وruntime المثبّت. ينفذ workflow الموثق الاختبارات أولًا ثم:

```powershell
python -m pip install -r requirements.txt -r requirements-desktop-build.txt
python scripts/download_llama_runtime.py
python scripts/build_desktop_backend.py
cd desktop
npm ci --no-audit --no-fund
npm run icon
npm run dist
cd ..
python scripts/write_installer_manifest.py desktop/dist --version 5.1.0
```

الناتج: `desktop/dist/CyberSentinel-Setup-5.1.0.exe` وملف `.sha256` و`installer-manifest.json`. يفشل سكربت runtime إذا لم يطابق ملف llama.cpp الحجم والـSHA المثبتين؛ ويفحص build سكربت backend تشغيل `--desktop-self-test` والـweb assets. سجل المصدر والإصدارات والحجوم وSHA-256 للنماذج وruntime في [`docs/LOCAL_MODEL_ARTIFACTS.md`](../docs/LOCAL_MODEL_ARTIFACTS.md).

## تطوير التطبيق من المصدر

تشغيل Electron التطويري فقط يحتاج Python ومصدر المستودع واعتمادياته وNode.js:

```powershell
python -m pip install -r requirements.txt
cd desktop
npm ci
npm start
```

هذا المسار مخصص للمطورين. لا يغير متطلبات Installer النهائي. دعم حزم واجهة الاستخدام يقتصر على Windows x64؛ لا ندّعي حزم macOS/Linux. Workflow يبني على `windows-latest` ويختبر bundle دون نافذة تفاعلية، لذلك يلزم rehearsal يدوي على Windows للتحقق من تجربة SmartScreen والتثبيت الفعلية.

**حد واجهة Workspace على Windows:** واجهات المهام والمشاريع والتقارير مدعومة؛ file browser وGit viewer يستمران في الرفض الآمن إذا لم تتوفر آليات handle-relative/no-follow المطلوبة على المنصة.
