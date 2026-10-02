# خطة M2.d.cutover — توصيل supervisor دون سلطة تنفيذ مزدوجة

**الحالة: BLOCKED قبل تعديل الكود.** هذا المستند يسجل قراءة المصدر الحالي على الفرع `manus/durable-runtime-fencing` عند baseline `3789aab54caa71fd77930126f8d45b73918a1ecc`. تطابق `HEAD` المحلي والبعيد، وكان working tree نظيفًا. لم أقرأ فروعًا أخرى أو أفتح قواعد SQLite.

## النطاق والعقد

المطلوب هو جعل `MissionQueue` و`MissionSupervisor` مسار التنفيذ الوحيد للمهام طويلة العمر، مع إبقاء `POST /api/chat` متزامنًا وبشكل استجابة ومصادقة Owner نفسيهما. يجب أن ينتظر handler المهمة التي شغّلها supervisor، وألا يلغيها أو يعيد إرسالها عند انقطاع العميل. لا async/202، ولا UI أو stream جديد، ولا تغيير في Desktop أو `web/`، ولا deployment.

## Call graph الحالي من المصدر

```text
POST /api/chat                         POST /api/command
  bridge.Handler.do_POST                  bridge.Handler.do_POST
    _owner_session()                        _owner_session()
    api.chat.chat(...)                      api.chat.chat(...)
      _owner_session()                        _owner_session()
      ensure_conversation/add user msg         ensure_conversation/add user msg
      AgentCore.run_owner_mission(...)         AgentCore.run_owner_mission(...)
        _auth → _plan                          _auth → _plan
        MissionRuntime.create                  MissionRuntime.create
        MissionStore.save                      MissionStore.save
        MissionRuntime.run_model_loop          MissionRuntime.run_model_loop
          أو run_to_completion                   أو run_to_completion
        _executor → authorize_tool → Registry/Workspace/external handler

POST /api/chat/stream → api.chat.stream → chat(...) على request thread
POST /api/tasks → MissionTaskAdapter.create_task → AgentCore.run_owner_mission(run=True)
POST /api/tasks/{id}/resume → MissionTaskAdapter.resume_task → AgentCore.resume_mission()
GET /api/tasks/{id}/stream → task_stream → resume_task(run=True)
POST /api/missions/{id}/start|resume → MissionService → MissionQueue.enqueue()
```

`bridge.main()` ينشئ `ThreadingHTTPServer` ويستدعي `serve_forever()` فقط؛ لا يوجد startup/shutdown hook ينشئ أو يشغل `MissionSupervisor`. أما `_mission_service()` في `bridge.py` فينشئ `MissionStore` على `missions.sqlite3` و`MissionQueue` على `mission_queue.sqlite3` منفصل. يرفض `MissionWorker.run_once()` runtime إذا لم يتطابق ملفا السلطة؛ لذلك هذا المسار لا يصلح كما هو لسلطة fenced واحدة. مسارات `/api/chat` و`/api/tasks`، على العكس، تنفذ `MissionRuntime` تزامنيًا داخل request thread اليوم.

## Blocker يمنع cutover آمنًا الآن

`owner_password._create_session()` ينشئ `session_id` عشوائيًا عبر `token_urlsafe(32)` ويعيده كمرجع bearer الذي تقبله API. يمرر `bridge.py` هذا المعرف إلى `api.chat.chat()` ثم `AgentCore`; ينشئ `OwnerAuthenticationEvidence` و`AuthorizationContext` وفيهما `session_id`. `AuthorizationContext.to_dict()` و`OwnerAuthenticationEvidence.to_dict()` يضمّنان المعرف، و`Mission.to_dict()` يضمّن `authorization_context`، و`MissionStore.save()` يحفظ الحمولة JSON في SQLite. مسار task التوافقي يحفظ أيضًا `owner_session_id` و`mission.to_dict()` في `TaskManager`.

في الوقت نفسه، مفتاح HMAC لإثبات Owner (`owner_policy._EVIDENCE_SECRET`) عشوائي للعملية (`secrets.token_bytes(32)`). لا يمكن لـworker بعد process restart إعادة التحقق من الإثبات المحفوظ؛ ومسار `AgentCore.resume_mission()` الحالي يشترط مصادقة Owner جديدة ويصدر سياقًا جديدًا. بالتالي لا يمكن توصيل العامل الدائم بمجرد نقل الكائن المخزن: الإبقاء على الحقول الحالية يكرر bearer token الخام في مخزن mission/task، وإزالتها دون تصميم handoff جديد يفقد إثبات التفويض، بينما اختراع مفتاح دائم أو تمديد صلاحية إثبات Owner يغير حد الثقة/السياسة. لن أفعّل supervisor جزئيًا أو أخفّض هذا الشرط ضمن تخمين.

هناك أيضًا أثر منفصل يجب أن يبقى ظاهرًا: `ContextAssembler` قد يضمّن `authorization_context` الكامل في provider payload في مسار compaction الاحتياطي؛ لا يمكن إثبات شرط عدم وصول token للنموذج ما دام التسلسل الخام قائمًا. كما لا توجد دلالة replay على `request_id`: الـmission keyed على `mission_id`، والـqueue keyed على `mission_id`؛ لا يوجد lookup أو unique constraint للمهمة حسب `request_id`. لم أضف semantics جديدة لهذه الحالة.

## الخطوات بعد حسم سياسة التفويض

1. تعريف handoff بلا bearer token خام: إما إعادة مصادقة Owner صريحة قبل استئناف أي مهمة بعد process restart، أو capability durable معتمدة لا توسع scope ولا تتطلب حفظ token خام. يجب تحديد الحالات المحفوظة والانتقال المتوقع عند انتهاء الإثبات.
2. تحويل authority إلى SQLite file واحد، وبناء lifecycle object صريح يبدأ supervisor مرة واحدة في `bridge.main()` ويتوقف graceful عند shutdown؛ لا تشغيل عند import أو في الاختبارات.
3. توصيل create/start/resume لكل route طويل العمر إلى queue؛ جعل `/api/chat` blocking facade ينتظر terminal أو `RECOVERY_REQUIRED`، دون تشغيل runtime inline، مع الحفاظ على payload/auth/Owner checks وscope/workspace كما هي.
4. مطابقة worker runtime مع نمط `AgentCore` الحالي، بما فيه native `run_model_loop` مقابل `run_to_completion`، وإعادة تحقق authorization قبل أي dispatch. لا retry تلقائي بعد `DISPATCHING` غير المحسوم.
5. إضافة اختبارات SQLite حقيقية في `tmp_path` لـHTTP-like submission/response، منافسة supervisor، stop/restart مع auth revalidation، disconnect/timeout بلا duplicate enqueue، unknown outcome، Owner/auth/scope negative paths، وRegistry handler محلي فعلي. تشغيل الاختبارات والـcompileall فقط مع مسارات temp؛ تجنب full suite أو أي import يفتح قواعد المستخدم قبل عزل مساراتها.
6. بعد قبول الكود والاختبارات فقط: كتابة أدلة M2.d، تحديث الحالة، commit مرحلي، والتحقق من fast-forward ثم push عادي دون force. لا PR/merge/deploy.

## حدود هذا checkpoint

لم يُنفذ كود cutover، ولم يُشغّل supervisor أو اختبارات/compileall أو مزود حي، ولم تُفتح أو تُعدل أو تُبصم أي قاعدة SQLite. الوثيقة المصاحبة `docs/MANUS_M2D_CUTOVER_EVIDENCE.md` تسجل المراجع المصدرية والقرار. الخطوة التالية هي تحديد سياسة إعادة التفويض/القدرة الآمنة؛ حتى ذلك الحين يبقى `/api/chat` على التنفيذ inline الحالي ولا يبدأ supervisor إنتاجيًا.
