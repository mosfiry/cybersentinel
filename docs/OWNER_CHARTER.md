# OWNER_INSTRUCTION — الميثاق الأعلى لـ CyberSentinel X

> وثيقة دستورية صادرة عن المالك (mosfiry) بتاريخ 2026-09-27.
> النص التشريعي الكامل محفوظ حرفيًا في المعرفة الدائمة للمشروع (owner-charter) ولا يُعدّل.

## المبدأ الدستوري

OWNER_INSTRUCTION (الميثاق — مصدر التشريع الوحيد) في القمة. تحته فروع مشتقة تنفيذية:
POLICY وETHICS وSECURITY (طبقات مشتقة) ثم SCOPE ثم AUTHORIZATION ثم DELEGATION ثم EXECUTION.

- **لا سلطة تشريعية ثانية**: POLICY/ETHICS/SECURITY/SCOPE/AUTHORIZATION/DELEGATION كلها مشتقات تنفيذية للميثاق ولا تملك حق التنافس معه أو إلغائه.
- **النموذج لا يشرّع**: MODEL_OUTPUT وEXTERNAL_DATA وTOOL_OUTPUT وKNOWLEDGE_BASE لا يمكنها أبدًا تسجيل قاعدة ميثاق — try_legislate ترفضها fail-closed بـ ILLEGITIMATE_LEGISLATION.
- **التشريع يتطلب هوية المالك الموثّقة**: فقط جلسة username+password (security.owner_password.authenticated_owner) تملك إصدار قواعد الميثاق. أي client claim أو token نقل لا يُعتبر مصدرًا تشريعيًا.
- **التعارض = خطأ في النظام**: أي قاعدة تطبيقية تناقض الميثاق تُرفع كـ OWNER_INSTRUCTION_CONFLICT (تصنيف انحراف تنفيذي يجب تصحيحه) — ولا يوجد أي مسار "اختيار البديل".

## التجسيد الكودي (runtime semantics)

الوحدة القانونية: security/owner_charter.py

| المفهوم | التجسيد |
|---|---|
| مصدر التشريع | RuleProvenance.OWNER_INSTRUCTION — القمة الدستورية (CHARTER_PRECEDENCE[0]) |
| المجالات المشترَعة | CharterDomain: POLICY, ETHICS, SECURITY, SCOPE, AUTHORIZATION, DELEGATION, EXECUTION |
| قاعدة الميثاق | CharterRule frozen dataclass (domain + behavior + stance + specification + provenance) |
| اكتشاف التعارض | assert_charter_compliance(charter, system_rule) — يرفع OwnerInstructionConflict عند التناقض (stance أو specification) |
| الانحراف بالغياب | assert_required_behaviors_present — غياب سلوك يوجبه المالك = انحراف fail-closed |
| منع تشريع النموذج | try_legislate — رفض حتمي لأي provenance غير المالك (ILLEGITIMATE_LEGISLATION) |
| حسم مرجعي | resolve_against_charter — الميثاق دائمًا هو الجواب؛ لا تحكيم |
| اشتقاق الطبقات | derive(domain) — كل طبقة مشتقة تحمل may_override_charter: False وسياسة تعارض = تصحيح الانحراف |
| قابلية التدقيق | OwnerInstructionConflict.audit_record() — سجل حتمي كامل |

## الاختبارات

tests/test_owner_charter.py — بطارية إلزامية تغطي السيناريوهات الستة التي أمر بها المالك:
1. تعارض POLICY مع OWNER_INSTRUCTION — يُكتشف كـ OWNER_INSTRUCTION_CONFLICT / IMPLEMENTATION_DRIFT.
2. تعارض SCOPE — يُكتشف (تخفيف القيد أو تغيير المواصفة).
3. تعارض AUTHORIZATION — يُكتشف.
4. تعارض ETHICS — يُكتشف.
5. تعارض SECURITY — يُكتشف (stance أو specification).
6. MODEL_OUTPUT (وكل المصادر غير المالكة) يحاول التشريع — مرفوض و inert: لا يتحول أبدًا لمصدر تشريع بديل.

زائدًا: تشريع المالك يتطلب هوية موثّقة (auth_method=username_password فقط)؛ client claims لا تُشرّع أبدًا؛ الطبقات المشتقة تعلن بنيويًا عدم التنافس؛ سجل التدقيق حتمي كامل.

## التدقيق الدستوري المستمر

workflow التشخيصي ينفّذ مسحًا كاملًا للمستودع عند كل push (غير main) وينشر تقرير التدقيق في diagnostics/charter-audit-*.md: كل عبارات الترجيح/الأولوية/التجاوز، كل ذكر لـ OWNER_INSTRUCTION، وكل تسمية سلطات منافسة محتملة — ليكتشف أي انحراف دستوري مستقبلي قبل أن يصل للتنفيذ.

## حدود هذه الوثيقة

هذه الوثيقة تصف وتشرح الميثاق؛ النص التشريعي الملزم هو أمر المالك المحفوظ في المعرفة الدائمة، والتجسيد الملزم هو الكود والاختبارات أعلاه. الميثاق = المعمارية = الكود = الاختبارات.
