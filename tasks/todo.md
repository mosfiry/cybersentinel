# M2.d.cutover — TODO

الحالة: متوقف قبل تعديل الكود بسبب handoff التفويض، وليس تنفيذًا جزئيًا.

- [ ] حسم Owner لسياسة استعادة التفويض بعد process restart: إعادة مصادقة صريحة قبل إعادة enqueue، أم تصميم capability durable منفصل لا يخزن bearer token خامًا ولا يوسع الصلاحيات.
- [ ] تصميم واختبار serialization token-free لـOwner evidence وMission/Task/Scope، مع المحافظة على scope/workspace كاملين، ومنع بيانات الاعتماد من provider payload.
- [ ] ربط `MissionStore` و`MissionQueue` بملف authority واحد وإنشاء supervisor lifecycle واحد في `bridge.main()`.
- [ ] نقل start/resume في `/api/chat` و`/api/command` وtask APIs إلى supervisor؛ إبقاء `/api/chat` متزامنًا بنفس response/auth contract ومنع inline runtime.
- [ ] مطابقة worker لمسار `run_model_loop` أو `run_to_completion` القائم، مع fencing وheartbeat وunknown-outcome fail-closed.
- [ ] اختبار API، queue، supervisor، stop/restart وإعادة المصادقة، disconnect/replay حيث يدعمه المصدر، وlocal Registry handler باستخدام قواعد temp فقط.
- [ ] بعد نجاح الاختبارات فقط: تحديث أدلة M2.d والحالة، commit ثم push عادي fast-forward فقط.

لا يبدأ أي بند تنفيذي قبل حسم أول بند؛ لا supervisor جزئي، لا migration، لا PR/merge/deploy.
