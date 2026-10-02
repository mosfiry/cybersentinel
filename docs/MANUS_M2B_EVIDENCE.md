# أدلة M2.b — evidence ضمن معاملة claim-fenced

## الحالة والنطاق

نُفذت M2.b على الفرع `manus/durable-runtime-fencing` انطلاقًا من `8724cd16b63f28f41260952e6119f18dcbbb072f`. قبل التعديل كانت الشجرة نظيفة، وكان `HEAD` و`git ls-remote origin refs/heads/manus/durable-runtime-fencing` متطابقين مع هذا الـSHA. parent المقصود للـcheckpoint هو SHA الأساس نفسه؛ لا يتضمن هذا الملف SHA ذاتيًا.

النطاق المقبول هنا محدود إلى **evidence المملوكة للمهمة** التي يصل بها `MissionStore.save(..., claim=...)` عبر claim صالح. تحفظ نسخة append-only ذات hash chain من كل evidence جديدة مع mission payload وrevision في ملف SQLite نفسه، بعد التحقق من claim الحالي/expiry والـrevision داخل `BEGIN IMMEDIATE` نفسها. هذا ليس supervisor cutover، ولا يحمي أي runtime لا يمرر claim.

## خريطة writers الفعلية والضمان

| الموضع | writer الفعلي | ما يثبته M2.b وما لا يثبته |
|---|---|---|
| `agent/mission_runtime.py:169,216,233,363,423,541` | مسارات runtime تضيف observations/evidence إلى `mission.evidence`؛ وعند متابعة المسار تحفظها عبر `self.store.save(mission)`. | عندما يكون runtime مربوطًا بـ`MissionStore.with_claim()` من `MissionWorker`، يحفظ `MissionStore.save` mission evidence والـledger في معاملة authority واحدة. حفظ مسار inline بلا claim لا يُعتبر fenced بموجب M2.b. |
| `agent/mission.py:159-228` | `MissionStore` يملك mission payload/revision؛ يتحقق من claim عبر `MissionQueue._require_current_claim` على الاتصال نفسه. | التغيير ينشئ جدول `mission_evidence_events` additive/idempotent في ملف MissionStore. يضيف فقط evidence الجديدة append-only، ويضمّن worker/lease/generation/acquired/expiry في الحدث المحسوب hash له. claim قديم يُرفض قبل إضافة أي حدث. |
| `agent/evidence.py:66-137` | `MissionEvidenceChain` يهيئ الجدول، يضيف الأحداث على اتصال المعاملة القائمة، ويعيد فتح السلسلة/يتحقق من hashes. | الأحداث المرتبطة بالـmission تُخزن في ملف السلطة نفسه؛ لا `ATTACH` ولا `lease_status()` منفصل يتبعه store آخر. فشل تحديث mission بعد إدخال الحدث يتراجع بالـrollback عن كليهما. |
| `agent/mission_runtime.py:320,469` | النتيجة الفعلية لـ`GoalVerification` توضع في `mission.verification_state` ثم تُحفظ مع mission JSON. | نتيجة التحقق المحفوظة تبقى جزءًا من تحديث mission نفسه. لا يضيف هذا التغيير جدول proof مستقلًا. |
| `agent/verification.py:33-57` | `VerificationEngine.verify()` ينشئ `VerificationReport` في الذاكرة. | لا توجد callsite تخزن `VerificationReport` كـproof دائم في مسار mission؛ لم نخترع proof writer أو جدول `verification_proofs`. لا تُسمى `verification_state` شهادة مستقلة. |

## Workspace وlegacy EvidenceChainStore — استثناء غير fenced

وجد فحص call graph قبل التغيير الكاتب التالي: `agent/agent_core.py:222-224` ينشئ `EvidenceChainStore(DB_PATH.with_name("evidence_chain.db"))` ويمرره إلى `tools.registry.execute()`؛ وعند تشغيل `run_project_tests` يربطه `tools/registry.py:332` بـ`Workspace`. يسجل `workspace/environment.py:109-115` كل عملية عبر `Workspace._record()` ثم `append_workspace_event()` في قاعدة legacy المنفصلة. لذلك كان هذا الكاتب يسبق حفظ mission ولا يشارك authority transaction أو claim.

**سلوك هذا المسار بقي كما هو في M2.b** بناءً على مراجعة الحفاظ على audit القائم. يظل سجل Workspace في `evidence_chain.db` legacy **غير fenced/unverified**، بما في ذلك عند تهيئة AgentCore؛ لم ننقله أو نحذفه أو نعد بذرية بينه وبين mission. اختبار التكامل يثبت أن AgentCore ما زال يمرر EvidenceChainStore وأن الحدث يحتفظ بـmission/request/tool/operation/hash-chain metadata. لا تُقرأ أو تُهاجر قاعدة legacy في runtime أثناء هذا التغيير؛ لا يُدّعى أن أحداث Workspace الموجودة أو الجديدة صارت ضمن ضمان M2.b.

أما evidence المملوكة للمهمة التي يعتمدها runtime للتقدم/التحقق فتُحفظ في authority ledger وmission payload ذريًا **فقط عندما يكون هناك claim صالح**. `/api/chat` وAgentCore inline يظلان بلا claim؛ لم نغير عقدهما أو نمررهما عبر fencing زائف، ولا يُحسب هذا المسار ضمن قبول M2.b. يجوز إبقاء المسارين منفصلين حتى M2.d.

## الترحيل وحفظ البيانات

- يضاف `mission_evidence_events` بواسطة `CREATE TABLE IF NOT EXISTS` إلى قاعدة `MissionStore` فقط؛ لا تعديل أو حذف لصفوف mission القائمة، ولا backfill أو overwrite لـevidence القديمة. الأحداث الجديدة لا تبدأ إلا عندما يضيف worker ذو claim evidence جديدة.
- سجلات evidence المضمنة سابقًا في mission payload تبقى كما هي، ولا يعاد تفسيرها كـclaim أو تُمنح generation بأثر رجعي.
- لم تُقرأ أو تُهاجر قاعدة `evidence_chain.db` legacy، وبقيت `EvidenceChainStore` الحالية وسلوك `append_workspace_event` كما هما.
- استُخدمت قواعد `tmp_path` في الاختبارات. قواعد clone الثلاث ignored الموثقة في M2.a بقيت دون تغيير:

| الملف | الحجم | SHA-256 |
|---|---:|---|
| `knowledge.sqlite3` | 20,480 bytes | `93e78ed6bd85bbb8eb4c9cf5e92105739e220bdf87f92d5e75bba7b1c124bd7b` |
| `memory.sqlite3` | 28,672 bytes | `a617102b1153d4cf220d8cbeae0c804f5b830856cbcf7d48251e13a86f01f227` |
| `tasks.sqlite3` | 24,576 bytes | `69bbc1fba28b48a97d02c6ced0cb7e0e2952ec5b0d5eb6ffb95cfb1a4759f3d8` |

لم يظهر ملف قاعدة بيانات جديد في clone؛ جرد الملفات الذي أُعيد بعد الاختبارات استثنى `web/` و`.git/`.

## اختبارات ونتائج

### Test-first

على الأساس `8724cd16...` قبل تعديل التنفيذ، فشل جمع الاختبارات الجديدة بالسبب المتوقع: `ImportError` لغياب `MissionEvidenceChain` في `agent.evidence`. بعد التنفيذ اجتازت اختبارات M2.b ضمن المجموعة المركزة أدناه.

### قبول M2.b

- `python -m pytest tests/test_mission_evidence_atomicity.py tests/test_verification_proof_persistence.py -q`: 6 اختبارات M2.b؛ تشمل stale A بعد reclaim B بلا evidence/chain/revision mutation، قبول كتابة B وverification state، runtime slice حقيقي عبر claim-bound MissionStore، rollback بعد إدخال evidence وقبل تحديث mission، reopen والتحقق من hash chain، وترحيل schema قديم additive/idempotent مع بقاء legacy chain التجريبي مطابقًا.
- `python -m pytest tests/test_mission_evidence_atomicity.py tests/test_verification_proof_persistence.py tests/test_mission_store_fencing.py tests/test_mission_queue_fencing.py tests/test_governed_execution.py tests/test_deterministic_goal_verification.py tests/test_agent_core_state.py tests/test_crash_restart_resume.py tests/test_phase6k7b_mission_runtime.py -q`: **64 passed**. أزيل `CYBERSENTINEL_LIVE_PROVIDER_KEY` و`CYBERSENTINEL_LIVE_ROUTER_FACTORY` من عملية pytest.
- `python -m pytest tests/test_agent_adaptive_loop.py -q`: **24 passed** مع متغيرات live-provider نفسها غير مضبوطة داخل العملية.
- `python -m compileall -q agent workspace tools api bridge.py tests/test_mission_evidence_atomicity.py tests/test_verification_proof_persistence.py`: ناجح؛ تعمد الفحص عدم دخول `web/`.
- `git diff --check`: ناجح.
- لم تُشغّل full suite: suite/compileall الشامل قد يقرأ أو يكتب داخل `web/` أو يتعامل مع قواعد SQLite المحمية في clone، وكلاهما خارج النطاق في هذا checkpoint. لا يُسجل ذلك كنجاح full suite.

### حالات الاختبار

| الملف | ما يغطيه |
|---|---|
| `tests/test_mission_evidence_atomicity.py` | stale A/B على SQLite مؤقت؛ claim صالح يضيف evidence ويحدث chain head؛ اختبار integration عبر `MissionRuntime.run_slice`؛ trigger يحقن فشلًا بعد insert للـevidence وقبل update للـmission ويثبت rollback كاملًا؛ migration تحفظ mission payload والـlegacy chain التجريبي وتُعاد idempotently. |
| `tests/test_verification_proof_persistence.py` | حفظ `GoalVerification` state مع evidence تحت claim صالح وreopen؛ عدم إنشاء proof table؛ اختبار AgentCore/Workspace يحفظ سلوك legacy events وmetadata، مع عدم ادعاء fencing لها. |

## الملفات المتغيرة وحدود القبول

- `agent/evidence.py`: إضافة authority-local `MissionEvidenceChain`؛ لم يتغير writer `EvidenceChainStore` legacy.
- `agent/mission.py`: ربط new evidence append-only بالـclaim/revision/transaction الموجودة، مع rollback مشترك.
- `tests/test_mission_evidence_atomicity.py`: regressions deterministic جديدة.
- `tests/test_verification_proof_persistence.py`: حفظ actual `verification_state` واختبار legacy Workspace writer.
- `docs/MANUS_M2B_EVIDENCE.md`, `docs/MANUS_MISSION_STATE.md`: حدود checkpoint ونتائجه.
- لم يتغير `agent/verification.py`, `agent/mission_runtime.py`, `workspace/environment.py`, `tools/registry.py`, `web/`, API shape، Owner auth/scope/policy، أو قواعد المستخدم خارج clone.

**Nonclaims:** لا fencing لأحداث legacy Workspace chain، ولا ضمان للمسار inline بلا claim، ولا proof store أو `VerificationReport` دائم، ولا حماية عامة للآثار الخارجية من crash/unknown، ولا M2.c intent/outcome، ولا M2.d supervisor/API cutover، ولا deployment أو exactly-once.
