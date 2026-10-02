# M2.d.cutover — blocker evidence

**الحالة: BLOCKED قبل تعديل الكود؛ لم يحدث cutover أو deployment.** Baseline المحلي والبعيد عند بداية العمل كانا متطابقين على `manus/durable-runtime-fencing` عند `3789aab54caa71fd77930126f8d45b73918a1ecc`، والـworking tree نظيف. هذه المذكرة مصدرية فقط؛ لم تُفتح أو تُعدل أو تُبصم قواعد SQLite أو بيانات المستخدم.

## نتيجة فحص مسارات التنفيذ

`bridge.py` يوجّه `POST /api/chat` (السطر 332 وما بعده) إلى `api.chat.chat()` ثم ينتظر النتيجة في request thread. `api/chat.py` (السطر 90 وما بعده) يستدعي `AgentCore.run_owner_mission()` أو `resume_mission()` مباشرة. `AgentCore.run_owner_mission()` يبني الخطة ويحفظ Mission ثم يختار native `MissionRuntime.run_model_loop()` أو `run_to_completion()` (`agent/agent_core.py:229-330`). `MissionTaskAdapter` يفعل الشيء نفسه inline لمساري إنشاء واستئناف task (`agent/mission_task_adapter.py:30-52`).

المسارات الإضافية تشمل `/api/command` و`/api/chat/stream` اللذين ينتهيان في `chat()`، و`/api/tasks/{id}/stream` الذي ينتهي في `resume_task()`. بالمقابل، `/api/missions/{id}/start|resume` يستخدم `MissionService` وqueue، لكن `bridge.py:85` ينشئ store في `missions.sqlite3` وqueue في `mission_queue.sqlite3` منفصلين؛ `MissionWorker.run_once()` يرفض runtime ما لم يكن المساران إلى ملف SQLite واحد (`agent/mission_worker.py:413-418`). `bridge.main()` لا يشغّل `MissionSupervisor` أصلًا (`bridge.py:416-422`). لذلك لا يوجد cutover جزئي يمكن تفعيله بأمان: المسارات متباينة والـsupervisor غير موصول بدورة حياة الخادم.

## سبب التوقف: Owner authorization لا ينتقل حاليًا إلى عامل دائم بأمان

1. `security/owner_password.py:122-139` ينشئ `session_id` عشوائيًا بواسطة `secrets.token_urlsafe(32)` ويعيده كمعرف الجلسة الذي تستخدمه الواجهات. `bridge.py` يمرر هذا المعرف إلى `chat()` (`bridge.py:338`، و`api/chat.py:90-108`).
2. `security/owner_policy.py:67-111` يضمّن `session_id` داخل `OwnerAuthenticationEvidence.to_dict()`، و`security/authorization_context.py:69-84` يضمّن الإثبات ومعرف الجلسة في `AuthorizationContext.to_dict()`. `AgentCore` ينشئ هذا السياق ثم يحفظ الـMission (`agent/agent_core.py:191-194, 277-296`). يتضمن `Mission.to_dict()` سياق التفويض (`agent/mission.py:136-141`) وتحفظه `MissionStore` كحمولة JSON (`agent/mission.py:235-252`). إذن ربط worker بنفس الحمولة سيكرر bearer token الخام في تخزين المهمة. مسار `/api/tasks` لديه مسار تخزين إضافي: `api/chat.py:45-53` يمرر Owner session إلى `MissionTaskAdapter`، و`TaskManager` يكتب `owner_session_id` و`execution_state` في `tasks.sqlite3` (`agent/task_manager.py:14-22, 76-87`).
3. توقيع `OwnerAuthenticationEvidence` مبني على `_EVIDENCE_SECRET = secrets.token_bytes(32)` عند تحميل العملية (`security/owner_policy.py:18-21, 84-99, 245-253`). لا يمكن لعملية جديدة التحقق من الإثبات السابق باستخدام المفتاح نفسه. ويؤكد `AgentCore.resume_mission()` أن استئناف Mission يطلب مصادقة Owner جديدة، ويجدد policy/auth context قبل التشغيل (`agent/agent_core.py:332-374`). لا يوجد حاليًا handoff durable خالٍ من token يشرح كيف يستعيد supervisor صلاحية تشغيل task بعد restart؛ وضع مفتاح دائم جديد أو تجاوز إعادة المصادقة سيغير حد الثقة بلا تصميم معتمد.
4. شرط عدم إرسال token إلى النموذج لا يمكن إثباته بالتسلسل الحالي: في fallback compaction يضمّن `ContextAssembler` `mission.authorization_context` و`mission.scope_snapshot` ضمن provider messages (`agent/model_intelligence/context.py:106-132`). كما أن `ProgramAuthorization.to_dict()` يتضمن `owner_session_id`، و`scope_store.save_snapshot()` يحفظه في JSON (`security/scope.py:97-128`, `security/scope_store.py:45-53`).

إزالة `session_id` من الحقول المخزنة وحدها لا تكفي: سيُفقد إثبات Owner الذي يتطلبه `AuthorizationContext.from_dict()`، كما أن إثباتات العملية السابقة غير قابلة للتحقق بعد restart. يلزم اختيار handoff صريح يحفظ Owner policy وscope/workspace دون token خام أو توسيع صلاحية، مع سلوك واضح للمهام التي تبقى queued بعد انتهاء العملية.

## حدود السلوك القائم التي لم تُخترع لها semantics جديدة

- `request_id` ليس idempotency key في المصدر: `api/chat.py` ينشئه أو يقبله، لكن `MissionStore` يحمل المفتاح على `mission_id` فقط، والـqueue keyed على `mission_id`، ولا يظهر lookup أو قيد uniqueness على `request_id` (`agent/mission.py:71-92, 235-252`; `agent/mission_worker.py` queue schema/`enqueue`). لذلك لم أعدّل retry/replay semantics.
- `AgentCore` يختار `run_model_loop()` لمزود native tool calling، بينما `MissionWorker.run_once()` يستدعي `run_to_completion()` (`agent/agent_core.py:303-311`; `agent/mission_worker.py:436-442`). يجب أن يحافظ cutover على هذا الاختيار، لا أن يغيّر الاستجابات ضمنيًا.

## الإجراء في هذا checkpoint

لم أعدل كودًا، ولم أنشئ أو أشغّل supervisor، ولم أشغّل اختبارات أو compileall حتى لا يستدعي اختبار API وحدة `TaskManager` التي تهيئ `tasks.sqlite3` عند import أو `scope_store` الذي يهيئ مخزن scope تلقائيًا. لم أستخدم مزودًا حيًا أو هدفًا خارجيًا. لا PR أو merge أو deployment.

القرار المطلوب قبل الكود: تحديد ما إذا كانت المهام بعد restart ستنتظر إعادة مصادقة Owner صريحة عبر API قبل إعادة enqueue، أو سيُعتمد تصميم capability durable آمن منفصل. إلى أن يُحسم ذلك، يبقى تنفيذ API الحالي دون تغيير، ولا تُفعّل سلطة supervisor.
