# جرد M0: مسار المهمة والـlease وfencing

هذا الجرد يوثّق `main` فقط، ولا ينفّذ M1 أو يغيّر كودًا. جُمعت حالة GitHub الحية في 2026-10-02 نحو 13:54 (+02): `HEAD` الرمزي يشير إلى `refs/heads/main`، و`main` عند `8a3fd109c0e586db13ed48a7371ac9ad06465b74`. أنشأت clone جديدًا ونظيفًا في `/workspace/cybersentinel-m0-20261002-1329` من ذلك الـSHA ثم أنشأت محليًا `manus/durable-runtime-fencing` منه؛ أبوه `be24ae326c710145d192f13e167ef02bf2f51792`. لم أستخدم شجرة العمل السابقة.

## نقاط GitHub الحية

أثبت `git ls-remote --symref` و`git ls-remote --heads` الحالة التالية. جلبت بيانات commit الوصفية للفروع الأربعة المسمّاة عبر GitHub API فقط؛ لم أعمل checkout لها ولم أقرأ محتوى أي ملف منها.

| المرجع | SHA | الأب | بيانات commit الوصفية |
|---|---|---|---|
| `HEAD` → `main` | `8a3fd109c0e586db13ed48a7371ac9ad06465b74` | `be24ae326c710145d192f13e167ef02bf2f51792` | `ci status report (ci-skip-marker)`؛ 2026-09-27T23:09:24Z |
| `vibe/principal-engineering` | `165706dba48c6224b0cb45bfcb5944839297096f` | `46a1cc51a68447250a7bc8a2a8d8d8f11c76d727` | `vibe: phase V3 mission lifecycle audit (state machine + invariants verified)`؛ 2026-10-02T02:21:31Z |
| `work/desktop-client` | `08a87cf3db7d489c7773fc497c16a45fecd92dff` | `6f24fe69bf640e08b32e31e7f9e20aed2c5da9b3` | توثيق معمارية desktop والعقد والتدقيق؛ 2026-10-01T10:44:46Z |
| `engineering/agile-runtime-lease-fencing` | `3b7b29653769dd7c80616161f8ce6fe18fd58ab9` | `2469aa9b0f5d9ffffd0eb3b7b02aa33fe51db237` | `test: fence stale worker after safe retry lease transfer`؛ 2026-10-02T04:59:55Z |
| `manus/durable-runtime-fencing` قبل الإنشاء | غير موجود على remote | — | غير موجود محليًا قبل إنشاء الفرع؛ أُنشئ بعد ذلك من `origin/main` أعلاه |

في لقطة `ls-remote` نفسها كان هناك **57 فرعًا حيًا**. الأسماء وSHA الكاملة:

| الفرع | SHA |
|---|---|
| `desktop/windows-exe` | `5dc5e1cb80f96972e241024335a86899a99baab0` |
| `diagnostics/phase1-tail` | `fa4594090061a4ad0eaf0994b3c34fe9200eaba2` |
| `docs/authority-constitution` | `f2a29d3fc48825402b96a02ea5c68de6e8ea7d87` |
| `docs/owner-project-handoff-ar` | `5f095144ab93c4b48f44b737f69ac2f3513dd402` |
| `engineering/agile-foundation` | `cb1aca63682035f8555e7e0b752b1747f133b534` |
| `engineering/agile-runtime` | `71536e2175ed14def01aac48e909999bcf991fb1` |
| `engineering/agile-runtime-crash-reconcile` | `dcc982c8c8bec0847249ebc1eb963db9691bd4bb` |
| `engineering/agile-runtime-lease-fencing` | `3b7b29653769dd7c80616161f8ce6fe18fd58ab9` |
| `engineering/agile-runtime-owner-reconcile` | `266e931364a2326d7a5fc5ffb2e96d50e5dfc480` |
| `engineering/agile-runtime-reconcile-execution` | `34ee19c256205c33275ecdb2c144d12d0390be75` |
| `engineering/agile-runtime-reconcile-input-contract` | `9b73b707c68f0b004f3ce565582e5fc7c2c1a0bc` |
| `engineering/agile-runtime-reconcile-not-executed` | `65d6f5a6c3638fe71c01417e2fa49afa9928e33f` |
| `engineering/agile-runtime-restart-recovery` | `1e1ae3cdbb6c9a565163959363e60e8d4902a775` |
| `engineering/agile-runtime-safe-retry-restart` | `2469aa9b0f5d9ffffd0eb3b7b02aa33fe51db237` |
| `engineering/final-completion` | `092245b51278cfc12593bfca4a898edf11b3ac17` |
| `engineering/mission-orchestration` | `c1fae6e4fbb5c29e3a87b703ccff3c287a29a61f` |
| `engineering/mission-orchestration-live-integration` | `b9a920403d3dd8b60efc55d1589fdcaafd6fddaa` |
| `feature/agent-context-engine` | `1735c411b21200dfb3c153b0430c990a35f6fd9c` |
| `feature/agent-runtime-2.0` | `d86c66d5972819ce358c88411d88c8f65dab8320` |
| `feature/autonomous-cyber-agent-foundation` | `547d58754ed16525d75fc38aa35fc01ef1932bbd` |
| `feature/canonical-snapshot-gate-and-transition-matrix` | `1f46e01ca64d2c1e446fcf70ea315bc91b15ba72` |
| `feature/cybersentinel-ide-ui` | `4d4ef174bdbab786a26416b387b48c1663aac1ff` |
| `feature/github-only-poc` | `75f6d07094a955a914120457320d28f2ef93cab8` |
| `feature/kali-tool-ecosystem` | `7b4c214ac32205cc43de3fc86cd739cb4ee12226` |
| `feature/live-worker-capability-contract` | `8960d7077666c0f1ef3733512582e66683425a1f` |
| `feature/native-tool-calling` | `20e56ca6d5566930cf41f6528a3445cc44dc8d9c` |
| `feature/owner-auth-multi-model` | `5669e82a63210673d06b648838f9a27c0e035262` |
| `feature/owner-derived-snapshot-allowlist` | `f25cd56e9570935a5bf67d374dc53e9d0031a36f` |
| `feature/proof-carrying-execution-boundary` | `513cfd62f78921787ad5852b154e42362ebfa16a` |
| `feature/search-external-integrations` | `30cfe2b37cd866d43cef59cb70839d608e1278a2` |
| `feature/v4.3-agent-hardening` | `90b14179d1274d3c9615678fedc207ba8453d1cc` |
| `feature/v4.4-tool-registry-context` | `c7e6181ad867c2e413c61896d18fba9b18ea88de` |
| `feature/v4.5-plan-evidence-integrity` | `29baf264c5e057240f3673d5cdea35709aab40cc` |
| `feature/v4.6-lifecycle-reliability` | `4346cec3562c97bfc4a130d248a17ef894040cb4` |
| `feature/v4.7-owner-red-team-reasoning` | `3522557c4ad15e092936b037095f5903d0025aa7` |
| `feature/v4.8-owner-authority-reasoning` | `52371b99b67c849dee5cf70df0581b72cd20e182` |
| `feature/v4.9-learning-loop` | `4a7a506280a3037215576bf6c181d3cbafb6698d` |
| `fix/evidence-boundary` | `2931bad3f2f2e15dacfd77c118c1fee6e4e286ca` |
| `import/owner-policy-agent-v4.2` | `b58a648fac0cb9145e713932ac62cb575e1cdd76` |
| `integration/agent-workspace-pr17` | `09ec8879eb6ba42cbd2f7437830afc49f10e2487` |
| `integration/cybersentinel-final-completion` | `47683c22079eb17e79f43d21147a8fba98c4e127` |
| `main` | `8a3fd109c0e586db13ed48a7371ac9ad06465b74` |
| `quality/ci-regression-2026-09-25` | `3d8f06c84a11c745d475a4e72ed286a545d45ec8` |
| `reliability/long-handler-heartbeat` | `c5660b4553a9dc8e92225d63f6dd51d1567385fb` |
| `security/b3-four-layer-intent` | `126266992ce38023b4f48e0036b8a37a62b6cbc9` |
| `security/characterization-baseline` | `74036800913b7431d9afb5c904a0df8cce779918` |
| `security/core-authority-hardening` | `55b154b5dd5a67ec354f6eb9353cd2194c8e6b50` |
| `security/owner-auth-closure` | `480622a7484206b6dc150ad144aad0db88f22c01` |
| `security/owner-password-auth-migration` | `eb1d868f69765e0532e751cb862405244a91759c` |
| `security/r1-closure-b2-b1` | `54fc32166bb2151d894d3d3e7440f1503062ca45` |
| `security/r1-intent-characterization` | `459acd9d1d2cacddb9158ff1fad96dc67632a98f` |
| `security/r1-intent-engine` | `78368c796ee4edea8604999db9fa5bcf850eb8b8` |
| `security/truthfulness-overhaul` | `2a013f8fac76358f36eea6a6e2e3ab0acc754bfe` |
| `vibe/principal-engineering` | `165706dba48c6224b0cb45bfcb5944839297096f` |
| `work/agent-workspace-ui` | `12c903d920721fef7525441ddea1a139517bb159` |
| `work/arabic-auth-ci-docs-20260929` | `71ce3c9550ad258a9cb01f03a7dc5e337f08ce93` |
| `work/desktop-client` | `08a87cf3db7d489c7773fc497c16a45fecd92dff` |

لم أفتح أي فرع من هذه الفروع ولا ملفات Desktop/Electron/Windows أو أصول `web/`. على main عُدّت أسماء الأصول المتعقبة فقط لتثبيت حد الاستثناء: `web/app.js`, `web/index.html`, `web/style.css`.

## مسار التنفيذ الموجود على main

في `agent/mission_worker.py:51-70` الطابور SQLite مستقل، ويحوي `lease_owner` و`lease_expires_at` فقط. `claim_next()` يبدأ `BEGIN IMMEDIATE` ويحجز صفًا مستحقًا في `:79-89`. الكتابة النهائية تتحقق من `worker_id` وحالة الصف في `:91-103`، وheartbeat يحدّث الانتهاء بشرط `mission_id + state + lease_owner` في `:105-112`. لا يوجد generation/fencing متزايد يميز claim بعينه. هوية worker الافتراضية هي `worker` والمهلة الافتراضية 120 ثانية (`agent/mission_worker.py:36,139-148`)؛ لذلك إذا أعادت عمليتان استخدام الهوية نفسها بعد انتهاء lease فقد ينجح تحديث worker قديم على lease جديد. هذا استنتاج من شروط التحديث، وليس اختبارًا شُغّل في M0.

`recover_expired()` و`recover_after_restart()` يزيلان المالك والمهلة ويعيدان حالات إلى `QUEUED` من دون قراءة mission checkpoint (`agent/mission_worker.py:114-125`). والـworker يحوّل `RECOVERY_REQUIRED` إلى `WAITING_FOR_TOOL` (`:156-189`)، لكن claim لا يقبل `WAITING_FOR_TOOL` (`:84`)، كما أن `MissionService.resume_mission()` يرفض `RECOVERY_REQUIRED` إلى أن تتم المصالحة (`api/missions.py:34-41`). لذلك لا تكفي استعادة queue وحدها لاستعادة mission ذات أثر غير محسوم.

الأهم تشغيليًا أن `MissionWorker.run_once()` و`MissionScheduler.dispatch_due()` وُجدا تعريفًا واختُبرا، لكن البحث عبر Python المتعقب لم يجد مستهلكًا إنتاجيًا لهما: ظهرت الاستدعاءات في الاختبارات فقط. الـAPI ينشئ الطابور والجدولة (`bridge.py:82-87`)، و`start_mission()` يضيف إلى الطابور فقط، و`schedule_mission()` يسجل موعدًا فقط (`api/missions.py:19-24,67-70`). لا يظهر supervisor/tick في الخادم يقوم بتفريغ الطابور.

المسار الذي ينفذ فعليًا مختلف: `/api/chat` يستدعي `chat()` (`bridge.py:332-345`)، و`api/chat.py:90-108` يستدعي `AgentCore.run_owner_mission()` مباشرة؛ ثم يشغّل `MissionRuntime.run_model_loop()` أو `run_to_completion()` داخل الطلب نفسه (`agent/agent_core.py:296-330`). أما `/api/tasks` فهو compatibility adapter: ينفذ `core.run_owner_mission()` قبل إنشاء سجل Task في SQLite آخر (`agent/mission_task_adapter.py:30-38,40-52`; `agent/task_manager.py:14-25`). `AgentTaskRuntime` موجود، لكنه لا يظهر كمستهلك API الإنتاجي في هذا المسار.

هناك lifecycle أقدم في `core/lifecycle.py`: `begin()` يفرض claim فريدًا حسب `request_id`، والطلب المكتمل يعيد النتيجة، واختبارات ذلك في `tests/test_v46_lifecycle.py:13-18,44-52`. لكن `api/chat.py:13,95-108` يستخدم `RUNTIME` من `core.engine` ثم يدخل AgentCore؛ مسح call sites لم يجد استدعاءً إنتاجيًا لـ`core.engine._handle_once()` أو `core.engine.handle()`. مع ذلك، استيراد `core.engine` يستدعي `recover_incomplete()` عند تحميل الوحدة (`core/engine.py:22-28`). كذلك لا يضمن مسار MissionStore idempotency حسب `request_id`: المفتاح الأساسي هو `mission_id` (`agent/mission.py:158-189`)، و`run_owner_mission()` ينشئ mission جديدة ويحفظها من دون lookup سابق حسب الطلب (`agent/agent_core.py:229-295`).

## حدود التخزين والتعافي والآثار الجانبية

الحالة موزعة على قواعد منفصلة: mission في `missions.sqlite3`، queue في `mission_queue.sqlite3`، scheduler في `mission_scheduler.sqlite3` (`bridge.py:82-87`)، وسجل task في `tasks.sqlite3` (`agent/task_manager.py:14-16`)، و`EvidenceChainStore` في `evidence_chain.db` (`agent/agent_core.py:216-224`). لا توجد معاملة ذرية واحدة تشمل هذه القواعد، والجدولة تسجل schedule ثم تضيف إلى queue كعمليتين منفصلتين (`agent/mission_worker.py:227-243`). كما أن `mark_missed()` يحوّل السجل إلى `SLEEPING` ولا يستخدم `retry_limit` لتقرير إعادة المحاولة (`:245-251`).

في MissionRuntime العادي يُحفظ checkpoint بحالة `in_flight` قبل استدعاء executor (`agent/mission_runtime.py:503-512`). وعند عودة نتيجة عادية، حتى إن كانت `success=False`، يُحفظ checkpoint `completed` ثم تطبق سياسة failure/retry (`:514-525,564-593`). في المقابل، مسار الأدوات الأصلي/المتوازي يترك checkpoint in-flight ويحوّل الاستثناء إلى `RECOVERY_REQUIRED` (`:335-375,398-440`). والمصالحة الصريحة لا تستنتج ما حدث من الانهيار؛ بل تتلقى `executed` وreceipt اختياريًا من المستدعي (`:193-239`). اختبارات الانهيار وإعادة التشغيل ومنع إعادة الأثر موجودة في `tests/test_phase6k7b_mission_runtime.py:41-87` و`tests/test_failure_recovery_replan.py:109-197` و`tests/test_tool_continuity.py:164-207`.

وجدت حافة مهمة في المسار الافتراضي لـAgentCore: `_executor()` يمسك كل استثناء من `execute_tool()` ويعيد قاموس فشل عادي (`agent/agent_core.py:216-227`)؛ عندها يستطيع `run_slice()` تسجيل checkpoint مكتمل بدل ترك الحالة للمصالحة (`agent/mission_runtime.py:514-525`). كما أن `tools/registry.py:336-343` يستدعي `future.cancel()` عند timeout، لكنه لا ينتظر انتهاء handler؛ إلغاء Future لا يثبت أن العمل الذي بدأ قد توقف. **النتيجة:** timeout أو استثناء بعد dispatch قد يبدو فشلًا حتميًا في المسار المباشر مع أن أثرًا جانبيًا ربما اكتمل. هذه فجوة تصميمية محتملة تستحق اختبار قبول في M1؛ لم أغيّرها هنا.

مهمات MissionRuntime تحمل authorization/policy/scope snapshot منفصلًا عن lease. `MissionAuthorizationSnapshot` يربط owner وmission وtarget والأدوات والحدود الزمنية والشبكة ومساحة العمل ويحسب hash (`security/mission_authorization.py:27-64,89-118`)، وOwner evidence والتحقق HMAC جزء مستقل (`security/owner_policy.py:67-99`). كما أن `AuthorizationDecision` و`Scope Snapshot` يتحقق منهما قبل dispatch (`tools/registry.py:276-315`؛ وتغطي الحالات السلبية `tests/test_security_integrity_adversarial.py:25-65` و`tests/test_governed_execution.py:95-181`). يجب أن يبقى fencing إضافةً لهذه القيود، لا بديلًا عنها ولا سببًا لتوسيع الصلاحيات.

`MissionStore` يكتشف الكتابة القديمة بمقارنة integrity hash وتحديث CAS على payload القديم (`agent/mission.py:129-144,167-183`)، لكنه SHA-256 غير موقّع، وليس إثبات هوية أو ختمًا سريًا. `EvidenceChainStore` مستقل، يضيف `sequence/previous_hash/current_hash` ويعيد التحقق من السلسلة (`agent/evidence.py:36-58,61-95`). تغطيته موجودة: `tests/test_governed_execution.py:53-73` يتحقق من أثر workspace وسلسلة الأدلة، و`:271-301` يتحقق من بقاء المهمة والـqueue والأدلة بعد إعادة فتح قواعدها. الحد المتبقي هو عدم وجود transaction موزعة تربط كتابة الأثر الخارجي، وسجل الأدلة، وmission checkpoint معًا.

## التحقق والتقارير والاختبارات

المهمة تحفظ `completion_criteria`, `evidence`, `verification_state` و`verification_history` (`agent/mission.py:56-80,129-155`). الإكمال الحاسم يفحص الأدلة المطلوبة عبر verifier في `agent/mission_runtime.py:465-476`. توجد أيضًا `VerificationEngine` و`VerificationReport` عامة (`agent/verification.py:17-57`)، لكن واجهة MissionService تعرض status/timeline/evidence/artifacts/logs فقط (`api/missions.py:51-65`)، ولم يظهر مولّد تقرير/موافقة خاص بالمهمة في فحص الرموز المتعقبة. `verification_history` موجودة في النموذج والتسلسل، ولم يظهر كاتب لها في البحث.

جرد البحث شمل **476 من 479 مسارًا متعقبًا** (كلها عدا أصول `web/` الثلاثة التي لم تُفتح)، بما فيها diagnostics؛ بحث `git grep` الموحد عن lease/heartbeat/generation/fencing/claim/recovery/mission/runtime/task/auth/request_id/idempotency/side-effect/evidence/verification/finding/report/approval/schedule/worker وجد 3,096 سطر تطابق في 235 مسارًا. هذا عدّ لمواضع الكلمات لا لعدد العيوب. لم يظهر ملف توجيه tracked مثل `AGENTS.md` أو ما يعادله؛ convention الاختبار في `README.md:5-20` و`docs/TESTING.md:1-5,18-24`، ومكتشف pytest مضبوط على `tests/` (`pytest.ini:1-4`).

أوامر المشروع المعتادة هي `python -m compileall -q .` و`python -m pytest -q`؛ يهيئ CI الأساسي Python 3.13 ويشغّل compileall وpytest و`git diff --check` وفحص الأسرار (`.github/workflows/tests.yml:12-60`). لم أشغّل أي test أو compile أو workflow ضمن M0.

رصدت اختلافين في قواعد التشغيل المتعقبة: workflow التشخيص يشغّل compileall وpytest مع `set +e` ويسجل الخطأ دون تحويله إلى exit فاشل (`.github/workflows/pytest-diagnostics.yml:92-115`)، لذلك قد تكون حالة job ناجحة رغم فشل الاختبارات؛ كما أن workflow الأساسي يكتب `diag.txt` عند فشل التثبيت فقط، وقد يعرض ملف الحالة `SUCCESS` إذا فشل compile/pytest قبل إنشاء `diag.txt` (`.github/workflows/tests.yml:24-49,62-72`)، مع بقاء step الفاشل ظاهرًا في حالة job. كلا workflowين يملكان `contents: write` وينشران diagnostics عبر push (`tests.yml:73-85`; `pytest-diagnostics.yml:139-164`). ووجدت mismatch في POC اليدوي: workflow يمرر `OWNER_TOKEN` (`.github/workflows/github-only-poc.yml:59-84`) لكن السكربت لا يقرأ إلا `OWNER_SESSION_TOKEN` أو `--owner-session-token` (`scripts/run_real_provider_mission.py:50-61`)، لذا قد يُستدعى runner مع credentials ويظل محجوبًا.

## خلاصة M0 وما ينبغي أن يبدأ به M1

M0 مكتمل كجرد وتوثيق فقط: لا تعديل كود، لا checkout للفروع المحمية، لا تعديل Vibe/Desktop/Electron/Windows، ولا تشغيل اختبارات أو قبول حي. الخلاصة التشغيلية هي أن queue والـlease موجودان لكن لا يظهر مستهلك production لها، بينما الإدخال الفعلي يشغّل MissionRuntime تزامنيًا؛ لذلك إضافة token إلى queue وحدها لا تثبت التنفيذ الحي ولا تمنع كتابة worker قديم.

الخطوة الدقيقة المقترحة لـM1 هي أولًا تثبيت مسار التنفيذ المعتمد (إما توصيل supervisor فعلي بالـqueue أو اعتماد المسار المتزامن الحالي)، ثم تصميم token fencing متزايد ومخزن ذريًا مع كل claim/reclaim، وإلزام heartbeat وكل كتابة حالة نهائية بشرط `mission_id + lease_generation` لا اسم worker وحده. يجب أن يبدأ الاختبار بحالة ABA لعمليتين لهما `worker_id` نفسه بعد انتهاء lease، ثم worker قديم يكتمل بعد reclaim، وانهيار/timeout بعد بدء أثر خارجي مع مصالحة محمية قبل إعادة المحاولة. هذه توصية مسجلة وليست بدءًا لـM1، ويجب إبقاء authorization/scope/Owner evidence دون تخفيف.
