# OWNER Charter Full-Repository Audit — Closure 2026-09-27

Mandate §12 (بحث المستودع بالكامل عن أي سلطة تشريعية منافسة): تم تنفيذ مسح كامل
على جميع ملفات المستودع (371 ملفًا) عبر خطوة التدقيق الدستوري في CI
(workflow: pytest-diagnostics.yml, commit 60641eb89996, report:
diagnostics/charter-audit-70b618f193e8.part000/001.md).

## What was scanned

- عبارات الترجيح والأولوية والتجاوز (precedence/priority/override/supersede) في كل الملفات.
- كل ذكر لـ OWNER_INSTRUCTION / owner_instruction.
- تسميات السلطات المنافسة المحتملة (MODEL_POLICY / SAFETY_POLICY / ETHICS_POLICY / TOOL_POLICY).
- مواقع تعريف قواعد الأخلاق/الأمان/السياسة.
- كل ذكر لـ MODEL_OUTPUT كسلطة.

## Findings

1. **لا توجد سلطة تشريعية منافسة داخل المستودع.** كل مواقع الترجيح المتوافقة مع
   الميثاق تضع OWNER_INSTRUCTION في القمة:
   `security/authority.py`: OWNER_INSTRUCTION (800) > SYSTEM_PLATFORM (700) >
   OWNER_POLICY > DETERMINISTIC_ENFORCEMENT > AUTHORIZATION_SCOPE > TOOL_RUNTIME >
   MODEL_OUTPUT (200) > EXTERNAL_DATA. لا يوجد أي ملف يعطي Model/Safety/Ethics/
   Policy/Scope/Authorization/Tool/Knowledge/External Data سلطة إلغاء أو إعادة
   تعريف OWNER_INSTRUCTION.

2. **المصادر غير الموثوقة مجردة من مفاتيح السلطة بشكل ملازم** (fail-closed):
   `agent/model_intelligence/validation.py` (FORBIDDEN_AUTHORITY_KEYS),
   `cyber/intel_ingest.py`, `cyber/malware.py`, `cyber/mission_adapter.py`,
   `agent/observation_intelligence.py` — أي نص خارجي أو مخرج موديل يحاول ادعاء
   authorization/scope/owner_instruction يُجرد ولا يُعامل أبدًا كسلطة.

3. **تم اكتشاف انحراف واحد (IMPLEMENTATION_DRIFT) وإصلاحه**: اختبار
   `test_compliant_system_rule_passes` في `tests/test_owner_charter.py` كان يحتوي
   على "استثناء التشديد" (tightening exception) — الافتراض بأن قاعدة نظام تستطيع
   تحريم ما أذن به المالك صراحة. هذا يمنح النظام سلطة مستقلة لتقييد إذن المالك،
   وهو ما يناقض الميثاق (المالك وحده يحدد المسموح والممنوع؛ أي اختلاف A≠B هو
   OWNER_INSTRUCTION_CONFLICT بلا استثناء). أصلحه commit `3725c7b5fc13`:
   الاختبار الآن يؤكد أن charter=allowed مقابل rule=forbidden يُرفع كـ
   OWNER_INSTRUCTION_CONFLICT (تصنيف drift)، ويؤكد classification في سجل التدقيق.

4. **الانحراف من النوع الثاني المطلوب في الميثاق (missing required behavior)**
   مغطى بـ `assert_required_behaviors_present` في `security/owner_charter.py`
   (غياب المطلوب = drift، fail-closed)، مع اختبارات في `tests/test_owner_charter.py`.

5. **كشف الانحراف المستقبلي مؤتمت**: خطوة المسح الدستوري تعمل عند كل push
   (غير main) وتنشر تقرير التدقيق في diagnostics/charter-audit-*.md — أي صياغة
   مستقبلية تمنح سلطة تنافس OWNER_INSTRUCTION ستظهر في التقرير قبل أن تصل للتنفيذ.

## Evidence chain

- Charter module: `security/owner_charter.py` (blob ea7a21e4) — commit 70b618f193e8.
- Adversarial battery (6 mandated scenarios + extras): `tests/test_owner_charter.py`
  (blob 6d86bc9d after the tightening-exception fix).
- Audit report: `diagnostics/charter-audit-70b618f193e8.part000/001.md` (commit 60641eb89996).
- CI result for the corrected battery: `diagnostics/ci-3725c7b5fc13.md` = SUCCESS
  marker (38 bytes) — commit da264df8b89c: full suite green
  (test_owner_charter.py + test_owner_password_auth.py + 691 tests).
- Drift fix: commit 3725c7b5fc13.

الخلاصة: الميثاق = المعمارية = الكود = الاختبارات — OWNER_INSTRUCTION هي مصدر
التشريع الوحيد، وكل التعارضات تُصنَّف OWNER_INSTRUCTION_CONFLICT / IMPLEMENTATION_DRIFT
وتُصحَّح، ولا يوجد أي مسار تحكيم بديل.
