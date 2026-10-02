# M2 — Architecture Design Checkpoint

**الحالة: تصميم فقط.** هذه الوثيقة لا تنفّذ M2، ولا تثبت تشغيل supervisor أو قبولًا أو deployment. قاعدة هذا القرار هي المصدر في clone عند `579387ff58910c14d8ca277cfdd68535220be846` وسجل M0/M1. لم تُشغّل اختبارات وظيفية لهذا checkpoint.

## القرار وحدود المرحلة

يعتمد M2 **queue مع supervisor بوصفهما سلطة التنفيذ الإنتاجية الوحيدة للمهمات طويلة العمر**. لكن لا يُفعّل supervisor إنتاجيًا بالتوازي مع مسار التنفيذ المتزامن الحالي. إلى أن يكتمل M2.a–M2.c ويثبت مخزن fenced، يبقى `/api/chat` على سلوكه الحالي، ويظل cutover إلى supervisor مهمة M2.d صريحة. عند cutover، يتحول handler إلى واجهة متزامنة تنتظر نتيجة المهمة التي نفذها supervisor؛ لا ينفّذ handler المهمة بنفسه.

يجمع التنفيذ المستهدف حالة mission وqueue/claim وevidence وسجلات التحقق (proof records) وeffect-intents في **ملف SQLite سلطوي واحد** خلف repository واحد قابل للمعاملة، مثل `mission_runtime.sqlite3` (اسم الملف المقترح، وليس ملفًا موجودًا أو migration منفذة). يجب أن تقع كل كتابة worker حساسة داخل معاملة واحدة على الاتصال نفسه: تحقق claim الجارية، مقارنة revision، تحديث mission، وكتابة evidence/proof أو intent أو إقرار queue ذي الصلة. لا يُسمح بنمط «اقرأ lease من DB، ثم اكتب في DB أخرى» كأنه ذرّي.

هذا القرار متعمد لأن إعدادات `journal_mode` الفعلية لقواعد المصدر غير مثبتة. ينص [توثيق SQLite الرسمي لـATTACH](https://sqlite.org/lang_attach.html) على أن المعاملة عبر قواعد مرفقة لا تكون ذرية عبر الملفات إذا كان الملف الرئيسي `:memory:` أو إذا كان `journal_mode=WAL`؛ وتكرر [صفحة WAL الرسمية](https://www.sqlite.org/wal.html) أن الذرية متعددة الملفات لا تتحقق ككل في WAL. لذلك لا نعتمد على ATTACH أو على إعداد journal غير متحقق منه. يمكن إبقاء WAL خيار تشغيل لملف السلطة الواحد، لكنه ليس ضمانًا عابرًا لملفات متعددة.

## الوقائع المصدرية التي يقيدها القرار

- `MissionQueue` يملك `lease_id` و`generation` وsnapshot claim غير قابلة للتغيير، وعمليات queue الحالية تفحصها ضمن معاملات queue نفسها (`agent/mission_worker.py`). هذا fencing محلي للطابور فقط.
- `MissionStore` يخزن payload المهمة ويستخدم integrity hash وCAS على payload (`agent/mission.py`)، لكنه لا يشترك حاليًا في معاملة `MissionQueue`.
- `EvidenceChainStore` يستخدم قاعدة مستقلة ذات تسلسل وhash chain (`agent/evidence.py`)، بينما تتضمن mission أيضًا evidence وحقول `verification_state`/`verification_history`. نتيجة `VerificationReport` الحالية ليست سجل proof مستقلًا داخل معاملة mission.
- يمر `/api/chat` حاليًا عبر `AgentCore.run_owner_mission()` وينفذ `MissionRuntime` داخل الطلب (`api/chat.py`, `agent/agent_core.py`). توجد queue وscheduler وواجهات mission، لكن سجل M0 لا يثبت مستهلك supervisor إنتاجيًا. لذلك لا يعني وجود queue أن cutover قد حدث.
- تبقى مصادقة Owner وقرارات authorization ولقطات scope/policy حدودًا مستقلة؛ generation أو lease ليسا تفويضًا من Owner ولا يوسّعان scope.

## الثوابت المستهدفة

1. **سلطة تنفيذ واحدة:** بعد M2.d فقط، يستهلك supervisor queue وينفذ جميع mission slices؛ لا يوجد مسار inline موازٍ يشغّل المهمة نفسها.
2. **claim فريد متزايد:** هوية التنفيذ هي `(mission_id, worker_id, lease_id, generation, acquired_at, expires_at)`، مع generation متزايدة لا يعاد ضبطها عند release أو recovery أو migration. إعادة استخدام `worker_id` لا تعيد صلاحية claim قديم.
3. **فحص وكتابة ذرّيان محليًا:** كل كتابة worker دائمة مشروطة بالclaim الحالي الحي وبrevision المتوقعة، وتتحقق منهما وتكتب mission والـqueue/evidence/proof/intents التابعة في معاملة واحدة على قاعدة السلطة. claim قديم لا يغيّر أيًا من هذه الصفوف.
4. **عدم خلط الصلاحية:** فحص lease لا يحل محل إعادة التحقق من Owner authorization أو policy أو scope عند حدود التنفيذ الحساسة.
5. **دليل متسق:** observation وevidence التي يعتمد عليها التقدم أو الإكمال وverification/proof record المرتبط بها تحفظ مع انتقال mission في المعاملة نفسها؛ لا يظهر proof ناجح إذا فشل حفظ evidence أو mission.
6. **intent دائم قبل الإرسال:** كل أثر خارجي له مفتاح intent ثابت، مشتق من mission/action/plan version وهوية العملية المنطقية، ويُسجل قبل dispatch. لا يُنشأ مفتاح جديد لمجرد reclaim أو إعادة تشغيل العامل.
7. **المجهول ليس فشلًا قابلًا لإعادة المحاولة:** عند فقد النتيجة بعد بدء dispatch تصبح المهمة `RECOVERY_REQUIRED` والـintent `OWNER_RECONCILIATION_REQUIRED` (أو حالة UNKNOWN مكافئة). لا retry آليًا ولا استنتاج لعدم التنفيذ من timeout أو crash.
8. **لا exactly-once عام:** لا يضمن SQLite تنفيذ أثر خارج العملية مرة واحدة بالضبط. لا تتحقق هذه الخاصية إلا إذا كان الطرف الخارجي نفسه يوفّر idempotency/fencing أو receipt protocol موثقًا ومستخدمًا بصورة صحيحة.

## نموذج repository وحدود المعاملة

الاقتراح هو واجهة داخلية واحدة، مثل `MissionRepository`, تملك فتح الاتصال وبدء/إنهاء معاملات الكتابة. الحد الأدنى للكيانات المنطقية في ملف السلطة:

- `missions`: payload، revision/CAS version، request-id عند توفره، وexecution generation المرتبطة بآخر claim.
- `mission_queue`: حالة المهمة ومواعيدها وعدّاد المحاولات وحقول lease الحالية وgeneration المتزايدة. صف queue والـmission يستخدمان `mission_id` نفسه؛ لا ينشأ task execution authority موازٍ.
- `evidence_events`: صفوف evidence immutable ذات `evidence_id`, sequence، previous/current hash، provenance ومرجع mission/action/claim generation.
- `verification_proofs`: مخرجات verifier الحتمية (مثل validator/version، evidence digest، القرار، المعايير الناقصة ووقت الإنشاء)، مميزة عن Owner HMAC/authentication evidence. وجود hash لا يجعل سجلًا غير موقّع شهادة موثوقة.
- `effect_intents`: intent key ثابت فريد، payload digest، action/tool، حالة dispatch/outcome، attempt sequence، receipt/reference إن وجد، وآخر سبب reconciliation.
- `schedules` عند إبقاء scheduling ضمن authority: الاستحقاق وإنشاء queue item أو تحديثه عملية repository واحدة، لا ملف schedule منفصل ينجح تحديثه ويفشل enqueue بعده.

كل كتابة worker تستخدم معاملة قصيرة على الاتصال نفسه، وتتحقق من queue row الحالي: تطابق mission/worker/lease id/generation/acquired-at/expiry، أن الحالة قابلة للتنفيذ، وأن `expires_at > now` بعد أخذ قفل الكاتب. يلي ذلك CAS على revision وتغيير الصفوف التابعة. يعاد رفض الكتابة إن لم يتطابق claim أو revision. عملية claim نفسها تزيد generation داخل معاملة queue؛ وعملية تحديث mission لا تقرأ generation من مخزن آخر ثم تكتب لاحقًا. يجب أن تكون كل API كتابة worker متاحة عبر repository، لا عبر `MissionStore.save()` غير المحمي.

اللحظة المنطقية لقبول كتابة قاعدة البيانات هي التحقق والـconditional write تحت قفل الكاتب في المعاملة نفسها؛ لا يمكن لعامل B أن يستولي على الصف ويتداخل بين فحص A وكتابته في ذلك الملف. لكن هذا لا يجعل معاملة SQLite قفلًا موزعًا على خدمة خارجية ولا يوقف اتصالًا خارجيًا بدأ بالفعل.

## تدفق التنفيذ المقترح

1. **إنشاء/استئناف:** يتحقق API من Owner وauthorization/scope كالمعتاد، وينشئ أو يحمّل mission ويدرج/يجدّد queue item في معاملة repository. لا ينفذ request handler الأداة.
2. **Claim:** supervisor يطالب بأقدم mission مستحقة. تحديث حالة queue، تسجيل worker/lease، وزيادة generation يجري ذريًا. snapshot الناتجة immutable.
3. **تهيئة slice:** يحمل supervisor mission/revision ثم يطلب من repository حفظ checkpoint ومرحلة التنفيذ مع claim الحالية. كل تقدم لاحق للمهمة يحمل سياق claim نفسه.
4. **قبل أثر خارجي:** بعد authorization وscope revalidation، يحفظ transaction واحد checkpoint وintent ثابتًا بحالة `PREPARED`. قبل الاتصال مباشرة، يسجل `DISPATCHING` ومحاولة الإرسال في معاملة قصيرة fenced ثم يعمل commit. بعد ذلك فقط ينادي الأداة/المزوّد.
5. **نتيجة معروفة:** إذا وصل رد نهائي موثوق، يحفظ worker observation وevidence وسجل proof عند انطباقه، ويحدث intent والـmission والـqueue في معاملة واحدة fenced. عند اكتمال mission يكون terminal acknowledgement جزءًا من المعاملة نفسها.
6. **استمرار أو انتظار:** يحرر worker claim أو يترك queue بحالة قابلة للاستئناف وفق حالة المهمة، ويعود supervisor إلى queue. الحالات التي تحتاج Owner أو reconciliation لا تتحول إلى QUEUED تلقائيًا.

## التعافي والانهيار والـTOCTOU

- **قبل commit لأي معاملة DB:** rollback؛ لا تظهر كتابة mission/evidence/proof/intent/queue جزئية من تلك المعاملة.
- **بعد commit intent=`PREPARED` وقبل `DISPATCHING`:** يعرف النظام من البروتوكول أن call لم يبدأ، بشرط أن يكون كل مسار dispatch ملزمًا أولًا بانتقال `DISPATCHING` الدائم. يمكن للـsupervisor الجديد متابعة ما قبل dispatch بعد تحققه من claim والسياسة.
- **بعد commit `DISPATCHING` وقبل استلام/حفظ نتيجة:** النتيجة مبهمة، سواء وقع crash قبل إرسال البايتات أم أثناءها أم بعد نجاح الخدمة. عند restart تُصنف UNKNOWN/`OWNER_RECONCILIATION_REQUIRED`، وتنتقل mission إلى `RECOVERY_REQUIRED`، ولا تعاد المحاولة تلقائيًا.
- **بعد رد خارجي وقبل commit النتيجة:** قد يكون الأثر وقع، لكن DB لا تعرف ذلك؛ تطبق قاعدة UNKNOWN نفسها. receipt موثوق أو تأكيد Owner/reconciler مطلوب قبل السماح بمتابعة محددة.
- **نتيجة حتمية بأنها لم تُرسل:** لا تُقبل إلا إذا كان adapter قادرًا على إثبات عدم بدء call. عندئذ فقط يمكن إعادة تسليح intent بقرار صريح ومع سجل المحاولة؛ timeout أو إلغاء Future أو موت العامل ليس إثباتًا.
- **انتهاء claim قرب dispatch:** يبقى سباق TOCTOU بين آخر check محلي وبين وصول call إلى الطرف الآخر: قد تنتهي lease أو يحصل reclaim بعد commit `DISPATCHING` وقبل أن يستقبل المزود الطلب. فحص DB «ثم call» ليس atomic مع خدمة خارجية. يرفض repository كتابات العامل القديم اللاحقة، لكن SQLite لا يستطيع إلغاء أثر بدأ أو منع أثر وصل إلى الخارج بالفعل. يلزم fencing/idempotency يطبقه الطرف الخارجي نفسه أو reconciliation؛ وإلا النتيجة UNKNOWN. لا ندّعي exactly-once.
- **عامل قديم عاد بعد reclaim:** لا يكتب mission أو evidence أو proof أو intent أو acknowledgement؛ أي receipt وصل منه يمر إلى reconciler/عامل claim حالي للتحقق منه وتسجيله fenced.

## استراتيجية نقل البيانات القديمة

تكون التهيئة **مهاجرة additive/idempotent فقط**: قراءة ملفات المصدر القائمة قراءة فقط، إضافة schema/جداول/أعمدة في ملف السلطة الجديد، نسخ الصفوف بمفاتيح ثابتة مع سجل import/hash، وحفظ ملفات المصدر وصفوفها كما هي. لا `DELETE`, لا `REPLACE`, ولا overwrite لصف canonical قائم. الصف المطابق الموجود مسبقًا يعد مستوردًا؛ اختلاف المحتوى تحت المفتاح نفسه يسجل conflict قابلًا للمراجعة ولا يُحل بتخمين أو باستبدال أحد الصفين. تعاد migration بأمان بعد interruption، وتبقى legacy stores قابلة للرجوع إليها حتى قرار تقاعد منفصل.

المواضع المثبتة في المصدر/جرد M0 هي mission في `missions.sqlite3`، queue في `mission_queue.sqlite3`، scheduler في `mission_scheduler.sqlite3`، سجل task المتوافق في `tasks.sqlite3`، و`EvidenceChainStore` في `evidence_chain.db`. يُنقل فقط ما يمكن ربط schema ومفاتيحه من المصدر: mission وqueue/evidence أولًا، والسجلات المجدولة إذا أُبقي scheduling؛ أما `tasks.sqlite3` فيبقى compatibility projection لا سلطة تنفيذ. لا يُدمج أو يُحوّل صف قديم إلى authorization/claim صالح بلا دليل تاريخي. هذه الوثيقة لا تنفذ migration ولا تفترض تطابقًا دلاليًا غير مثبت؛ يفحص M2 التنفيذ الفعلي للصفوف والحالات قبل import، ويحتفظ بأي conflict في المصدر ويوقف ذلك الصف دون إسقاط باقي البيانات.

## توافق API وخطة cutover

حتى cutover M2.d لا تغيير في `/api/chat` أو إنشاء supervisor عامل في الإنتاج. عند M2.d:

- يبقى endpoint `POST /api/chat` متزامنًا ويحتفظ بشكل الرد الحالي (`conversation_id`, `answer`, `mission_id`, `status`, `activity`, `mission`) ومصادقة Owner. يرسل إلى repository ويطلب queue start/resume ثم ينتظر نتيجة **المهمة نفسها** التي ينفذها supervisor؛ لا يشغّل MissionRuntime من handler.
- كل بدء واستئناف طويل العمر يمر من queue authority بعد cutover. يجب أن تمنع اختبارات القبول وجود مسار chat inline ثانٍ، وأن تثبت أن retry لطلب يحمل `request_id` ثابتًا يعيد ربطه بالمهمة نفسها حيث تدعم قاعدة السلطة ذلك.
- إذا تجاوز التنفيذ مهلة العميل أو reverse proxy، فقد ينقطع الاتصال أو يعود خطأ نقل بينما تستمر المهمة الدائمة لدى supervisor. انقطاع HTTP **لا يعني** إلغاء mission ولا يجيز إعادة تنفيذ أثر. الرد المتزامن قد يتأخر بطول المهمة، وقد يواجه حدود وقت العميل.
- واجهة async (202/operation id/status أو streaming مستقل، وتحديث الواجهة) قرار ومرحلة منفصلة إذا تقررت. لا تُضاف هنا، ولا تُعالج بإبقاء executor ثاني داخل HTTP.

## مهام التنفيذ التالية

### M2.a — atomic fenced mission write + انحدار stale A/B حتمي

- **العمل:** إنشاء repository في ملف سلطة واحد، وربط current queue claim + generation + mission revision في عملية كتابة واحدة؛ رفض claim A بعد أن يأخذ B generation التالية. لا تُشغّل أدوات خارجية في الاختبار.
- **ملفات متوقعة:** `agent/mission_repository.py` (جديد)، `agent/mission.py` و`agent/mission_worker.py` حسب فصل المسؤوليات، `tests/test_mission_store_fencing.py` (جديد). لا تعدّل واجهة API هنا.
- **قبول واختبار:** ساعة ثابتة/Barrier أو تبديل claim حتمي، A ثم reclaim إلى B بنفس `worker_id` إن لزم، محاولة A تفشل بلا أي تغيير في payload/revision أو صف B، وكتابة B تنجح؛ اختبارات rollback عند خطأ transaction. الأمر: `python -m pytest tests/test_mission_store_fencing.py tests/test_mission_queue_fencing.py -q`.
- **Checkpoint:** commit ذري على الفرع نفسه، parent مسجل، وتحديث `MANUS_MISSION_STATE.md` إلى M2.a فقط بعد نجاح القبول؛ لا ادعاء cutover.

### M2.b — evidence/proof ضمن معاملة fenced نفسها

- **العمل:** نقل إضافة evidence ونتيجة verifier/proof المرتبطة إلى repository؛ حفظ mission checkpoint والأدلة وسلسلة hashes والـproof atomically تحت claim/revision ذاتها، دون إنشاء سجل proof كاذب أو فقدان evidence قديمة.
- **ملفات متوقعة:** `agent/mission_repository.py`, `agent/evidence.py`, `agent/verification.py`, `agent/mission_runtime.py`, واختبارات `tests/test_mission_evidence_atomicity.py` و`tests/test_verification_proof_persistence.py`.
- **قبول واختبار:** حقن فشل بين كتابة evidence وproof يثبت rollback الكامل؛ stale claim لا يضيف evidence ولا proof؛ إعادة الفتح تتحقق من hash chain وevidence digest/verifier version. الأوامر: `python -m pytest tests/test_mission_evidence_atomicity.py tests/test_verification_proof_persistence.py -q`.
- **Checkpoint:** commit مستقل بعد M2.a، مع سجل migration الإضافية إن بدأ تنفيذها، وبقاء ملفات legacy الأصلية.

### M2.c — intent/outcome للآثار مع unknown صريح

- **العمل:** إضافة `PREPARED`/`DISPATCHING`/نتيجة حتمية/UNKNOWN أو الحالات المناظرة، intent key ثابتًا، receipt metadata، واستعادة crash إلى `RECOVERY_REQUIRED` و`OWNER_RECONCILIATION_REQUIRED` دون retry آلي.
- **ملفات متوقعة:** `agent/mission_repository.py`, `agent/mission_runtime.py`, adapter dispatch المناسب بعد التحقق من مساره في المصدر، واختبارات `tests/test_effect_intent_recovery.py` و`tests/test_external_effect_unknown.py`.
- **قبول واختبار:** crash محاكى قبل وبعد `DISPATCHING` يميز ما قبل الإرسال عن المجهول؛ لا يتكرر fake external call بعد outcome مبهم/restart؛ stale worker لا يكتب نتيجة؛ reconciliation صريح موثق هو وحده ما يسمح بالمتابعة. الأمر: `python -m pytest tests/test_effect_intent_recovery.py tests/test_external_effect_unknown.py -q`.
- **Checkpoint:** commit مستقل يثبت state machine والاختبارات المحلية فقط؛ لا اختبار مزود حي ولا ادعاء exactly-once.

### M2.d — queue supervisor وcompatibility cutover بعد إثبات fenced store

- **بوابة البدء:** لا يبدأ إلا بعد قبول M2.a–M2.c واختبارات crash/stale; لا تفعيل supervisor مزدوج أثناء التطوير أو rollout.
- **العمل:** supervisor مدعوم بعملية تشغيل مُدارة يستهلك queue من repository السلطوي؛ تحويل mission start/resume وكل مسار طويل العمر إلى queue؛ تحويل `/api/chat` إلى blocking facade تنتظر المهمة نفسها، مع الحفاظ على response/auth contract. لا async UI في هذه المرحلة.
- **ملفات متوقعة:** `agent/mission_worker.py` أو وحدة supervisor منفصلة، `bridge.py`, `api/chat.py`, `api/missions.py`, واختبارات `tests/test_mission_supervisor.py` و`tests/test_chat_sync_supervisor_compat.py`. لا تغييرات في `web/` أو Desktop/Electron/Windows.
- **قبول واختبار:** عاملان متنافسان يملكان claim واحدًا؛ restart يعيد queue دون إعادة dispatch لمجهول؛ chat ينتظر terminal/recovery state ويعيد الشكل السابق؛ اختبار يثبت أن handler لا يستدعي inline executor، ولا توجد سلطة تنفيذ ثانية؛ بدء حديث يمر من queue. الأمر: `python -m pytest tests/test_mission_supervisor.py tests/test_chat_sync_supervisor_compat.py tests/test_mission_queue_fencing.py -q`.
- **Checkpoint:** commit مستقل بعد قبول الاختبارات، ثم cutover موثق ومنفصل وفق تشغيل مخطط؛ لا PR/merge أو deployment ضمن هذا التصميم.

### ارتباط M3–M15

ينتهي M2 عند قبول M2.d. M2.c يوفّر سجل intent وunknown/reconciliation كقاعدة لأي تحسين لاحق، وM2.d يوفّر نقطة الدخول الوحيدة التي تستطيع المراحل اللاحقة البناء عليها. **M3–M15 مراحل لاحقة منفصلة وليست جزءًا من M2**: لا تُنقل مهامها أو واجهاتها أو عملياتها إلى هذه المرحلة ولا يُدّعى إنجازها هنا. يبدأ أي عمل فيها من checkpoint M2 المقبول، ويظل تعريف كل phase واختباره في خطته/قرارها المستقل؛ واجهة HTTP غير المتزامنة وقرار تحديث UI، إن طُلبا، يحتاجان مرحلة مستقلة ولا يبرران تنفيذًا ثانيًا.

## مخاطر وحقائق غير مثبتة

- لم يُتحقق من `PRAGMA journal_mode` للقواعد الحالية أو من عملية deployment/عدد supervisors؛ لهذا لا نعتمد على معاملتي ATTACH متعددة الملفات.
- لا تثبت ملفات المصدر وحدها أن كل adapter يستطيع معرفة «لم يُرسل» أو يدعم idempotency key أو receipt موثوقًا. هذه قدرة لكل أداة/مزود وتحتاج إثباتًا منفصلًا.
- `EvidenceChainStore` الحالي منفصل عن mission payload؛ mapping الكامل، ترتيب history، وأي تعارض legacy تحتاج فحص schema/صفوف في تنفيذ migration الفعلي. لا تتضمن هذه الوثيقة قراءة قواعد أو نقل بيانات.
- وقت HTTP الوسيط ومهلات client غير مثبتة؛ بعد cutover قد تطول الاستجابة أكثر من حدودها بينما يستمر العمل. لا يوجد هنا قرار async UI.
- SQLite single-file مع WAL يظل قاعدة ملف محلية؛ لا يُفترض استخدام ملف WAL مشترك على filesystem شبكي أو عبر مضيفين مختلفين. أي مطلب توزيع متعدد المضيفين يحتاج repository transaction يدعمه backend آخر، لا ادعاء ضمان من هذا القرار.
- لا يوجد في هذا checkpoint قبول/نشر/تشغيل حي أو تغييرات كود؛ المخطط والاختبارات المذكورة أهداف مستقبلية.
