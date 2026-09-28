# CyberSentinel X — Authority Constitution

> Stage: DOCUMENTATION / CONSTITUTION ONLY. This document does not change any
> production behavior, code, policy loader, runtime, or hierarchy. It fixes the
> constitutional truth of the project in writing.

- **CONSTITUTION:** DEFINED / DOCUMENTED (this document).
- **PRODUCTION ENFORCEMENT:** NOT VERIFIED — see "Known Authority Drift" below.
- **Issued by:** the Owner (Mohammed Sfiry), 2026-09-28, following the
  repository-sourced architectural audit of `main` @ `8a3fd109c0e5`.
- This document supersedes, in part, the ordering narratives in
  `docs/OWNER_AUTHORITY_MODEL.md` and `docs/GITHUB_ONLY_*.md` wherever they
  conflict with the articles below.

## Authoritative Statement

«داخل CyberSentinel، OWNER_INSTRUCTION هي المصدر الوحيد للتشريع والقيود الملزمة
للوكيل. كل قاعدة داخلية أخرى يجب أن تكون مشتقة منها أو مجرد آلية تنفيذ، ولا
يجوز لأي طبقة داخلية أن تنشئ لنفسها سلطة تشريعية مستقلة.»

English: Inside CyberSentinel, OWNER_INSTRUCTION is the single source of the
legislation and binding constraints on the agent. Every other internal rule must
be derived from it or be a mere execution mechanism, and no internal layer may
create an independent legislative authority for itself.

CyberSentinel is a standalone platform in its own right; it is not a layer
inside any external assistant. This constitution governs the internal
legislation of that standalone platform.

## The Constitutional Model

```
OWNER
  │
  ▼
OWNER_INSTRUCTION  (single source of internal legislative authority)
  │
  ├── OWNER_POLICY                (derived owner policy)
  ├── AUTHORIZATION RULES         (derived enforcement)
  ├── SCOPE RULES                 (derived enforcement)
  ├── TRUTHFULNESS RULES          (derived enforcement)
  ├── MISSION RULES               (derived enforcement)
  ├── TOOL RULES                  (derived enforcement)
  ├── AGENT RULES                 (derived enforcement)
  ├── ENFORCEMENT RULES           (derived enforcement)
  └── OTHER INTERNAL LEGISLATION  (derived)
             │
             ▼
       RUNTIME / AGENT
             │
             ▼
       MODEL / TOOLS / DATA
```

OWNER_POLICY is not a parallel legislative source. DETERMINISTIC_ENFORCEMENT is
not a parallel legislative source. AUTHORIZATION_SCOPE is not a parallel
legislative source. TOOL_RUNTIME is not a legislator. MODEL_OUTPUT is not a
legislator. EXPERT_OUTPUT is not a legislator. KNOWLEDGE is not a legislator.
EXTERNAL_DATA is not a legislator. Each of these is either an execution
mechanism, data, evidence, a proposal, or a rule derived from
OWNER_INSTRUCTION — and none of them may create independent legislation.

## Article 1 — Source of Internal Legislation

OWNER_INSTRUCTION is **the single source of internal legislative authority**.

It is not merely "the highest authority tier" in a hierarchy. It is the
legislative root from which all internal rules must be derived:

«OWNER_INSTRUCTION هي المصدر الوحيد لكل التشريع والقيود والسياسات والقواعد
الملزمة للوكيل داخل CyberSentinel.»

The tier table in `security/authority.py` (OWNER_INSTRUCTION = 800, etc.) is an
implementation artifact of this constitution, not the constitution itself. Any
tier ordering that contradicts this article is implementation drift, not a
rival law.

## Article 2 — Derived Rules

Every policy, rule, enforcement, scope boundary, authorization requirement,
truthfulness requirement, mission rule, tool rule, and agent rule inside
CyberSentinel must be **derived from Owner Instruction**.

OWNER_POLICY must be understood as **DERIVED OWNER POLICY**: a representation,
application, or derivation of the Owner's instructions — never a separate
legislative source. If the current reality allows a developer to change Owner
Policy in a way that contradicts Owner Instruction, that fact is recorded as
AUTHORITY DRIFT (see DRIFT-2-related findings) and is not corrected in this
phase.

## Article 3 — Non-Legislative Sources

```
MODEL_OUTPUT      ≠ LEGISLATION
EXPERT_OUTPUT     ≠ LEGISLATION
TOOL_OUTPUT       ≠ LEGISLATION
KNOWLEDGE         ≠ LEGISLATION
EXTERNAL_DATA     ≠ LEGISLATION
```

These sources may provide information, evidence, observations, proposals,
hypotheses, and analysis. They cannot, from themselves alone, create a rule
that binds the agent.

## Article 4 — Execution Failure

Legislative authority and execution capability are strictly distinct.

- Legislative Authority answers: *Who decides what the agent is required or
  forbidden to do?* — Answer inside CyberSentinel: OWNER_INSTRUCTION.
- Execution Capability answers: *Can the system technically execute the
  Owner's instruction?* — A tool, service, runtime, or resource may fail.

Example:

```
OWNER_INSTRUCTION: Execute X
TOOL:              cannot execute X
RESULT:            AUTHORITY = OWNER_INSTRUCTION
                   EXECUTION = FAILED / UNAVAILABLE
```

A tool being unavailable does not make the tool, runtime, or model a
legislator. The system must never fabricate success that did not happen.

## Article 5 — Authority Drift

If an internal rule contradicts an Owner Instruction, the case is not a contest
between two equal authorities. The classification is always:

- OWNER_INSTRUCTION = authoritative internal source.
- The conflicting internal rule = **AUTHORITY DRIFT / INVALID INTERNAL RULE**.

A lower rule can never annul, amend, or redefine the Owner's instructions.
Every future conflict must be classified into exactly one of:

- **A — DERIVED ENFORCEMENT:** an executing rule derived from
  OWNER_INSTRUCTION; not an independent authority.
- **B — AUTHORITY DRIFT:** an internal rule that created legislative authority
  for itself or contradicted OWNER_INSTRUCTION; it must be fixed in a dedicated
  remediation phase.
- **C — EXECUTION FAILURE:** the Owner's instruction stands, but technical
  execution failed; the failure must never be converted into legislation.

## Article 6 — System Platform

SYSTEM_PLATFORM is **not a source of internal legislation inside CyberSentinel**
and must not be defined as a policy authority competing with the Owner.

If the name SYSTEM_PLATFORM (or any similar name) is used in code for a purely
execution/runtime concept, it must not be treated as legislation; the concept
of an execution or runtime constraint is separated from legislative authority.
External hosting or process constraints are execution constraints outside the
internal legislation entirely.

The presence of `AuthorityTier.SYSTEM_PLATFORM = 700` in
`security/authority.py` on `main` is recorded as **DRIFT-2** (a legislative-tier
naming/placement drift), documented here and deferred to a separate remediation
phase. This document does not modify it.

## Article 7 — Owner Authentication

"Owner" is not a word written by a model, by user text, or by any prompt. The
Owner is an **authenticated identity**, established through the project's
actual mechanism: username/password login (`security/owner_password.py`)
producing an owner session, resolved by
`security.owner_policy.authenticate_owner` (`OwnerInstructionSource.USERNAME_PASSWORD`).
`BRIDGE_TOKEN` is channel authentication only and is never Owner identity.

No model output, expert output, tool output, knowledge entry, or external data
can confer Owner status or Owner authority.

## Article 8 — No Self-Minting Authority

No Tool, Runtime, Agent, or Model may create authority or authorization for
itself.

**Documented constitutional violation (DRIFT-1):** in `tools/registry.py` on
`main` (commit `7062ac0d`), the `run_project_tests` path inside `execute()`
mints a `MissionAuthorizationSnapshot` itself when no `mission_authorization`
is supplied — with `owner_identity = "legacy-compatibility"`,
`policy_version = "compatibility"` — thereby granting itself authorization
inside TOOL_RUNTIME instead of receiving it through the Owner-derived chain.
This is recorded here as a constitutional violation requiring a dedicated,
separate remediation phase. It is not fixed in this documentation phase.

## Authority Matrix

| Source | Legislative Authority |
|---|---|
| OWNER_INSTRUCTION | YES — SINGLE SOURCE |
| Derived Owner Policy | NO — DERIVED |
| Deterministic Enforcement | NO — IMPLEMENTATION |
| Authorization | NO — DERIVED ENFORCEMENT |
| Scope | NO — DERIVED ENFORCEMENT |
| Mission Runtime | NO — EXECUTION |
| Tool Runtime | NO — EXECUTION |
| Model Output | NO |
| Expert Output | NO |
| Knowledge | NO |
| External Data | NO |
| Tool Output | NO |
| System Platform | NO — NOT INTERNAL LEGISLATION |

## Known Authority Drift (audit of main @ 8a3fd109c0e5)

These findings remain open. None of them is fixed by this document; each
requires its own remediation phase under explicit Owner instruction:

- **DRIFT-1 — registry self-minting.** `tools/registry.py` (`execute()`,
  `run_project_tests` compatibility snapshot). Violates Article 8.
- **DRIFT-2 — SYSTEM_PLATFORM legislative tier.** `AuthorityTier.SYSTEM_PLATFORM
  = 700` in `security/authority.py` occupies a legislative-tier slot inside
  the internal legislation. Violates Article 6 as a naming/placement drift.
- **DRIFT-3 — contradictory historical documentation.**
  `docs/GITHUB_ONLY_DEPLOYMENT_ANALYSIS.md` and
  `docs/GITHUB_ONLY_POC_RESULTS.md` record
  `SYSTEM_PLATFORM → OWNER_POLICY → OWNER_INSTRUCTION → …`, placing Owner
  instruction third; `docs/OWNER_AUTHORITY_MODEL.md` frames SYSTEM_PLATFORM as
  an immutable boundary above application authority. Contradicts Articles 1
  and 6 at the documentation level.
- **DRIFT-4 — owner_charter unwired.** `security/owner_charter.py` embodies the
  correct charter in principle (OWNER_INSTRUCTION → DERIVED_SYSTEM_RULE; model,
  tool, knowledge, external provenances can never legislate), but on `main` no
  production call site imports it (only tests). Constitutional definition:
  VERIFIED; production enforcement: NOT VERIFIED / UNWIRED.
- **DRIFT-5 — truthfulness absent from main.** `security/truthfulness.py`
  (provenance tokens, evidence statuses, completion gates) and the
  `GOAL_COMPLETED` transition guard exist only on the
  `security/truthfulness-overhaul` branch; they are absent from `main`
  (`security/` on `main` has no `truthfulness.py`; `agent/mission.py` on
  `main` last changed at `b19ce3a7`, before the guard). Violates Article 4's
  no-fabricated-success requirement at the production level.

## Status

- CONSTITUTION: **DEFINED / DOCUMENTED**.
- PRODUCTION ENFORCEMENT: **NOT VERIFIED**.

Creating this document does not make the constitution ENFORCED. Enforcement is
achieved only when every drift above is closed under explicit Owner
instruction, with CI-verified evidence, and when the production call graph
provably derives all binding rules from OWNER_INSTRUCTION.

## Evidence Appendix (repository-sourced)

- `security/authority.py` — `AuthorityTier` (OWNER_INSTRUCTION 800 /
  SYSTEM_PLATFORM 700 / OWNER_POLICY 600 / … / MODEL_OUTPUT 200),
  `assert_authority_invariant`, `authority_snapshot`.
- `security/owner_policy.py` — `OwnerInstructionSource.USERNAME_PASSWORD`,
  `authenticate_owner`, `capture_policy_snapshot`,
  `security/owner_policy.json` (v2.0).
- `security/owner_password.py` — owner login/session mechanism.
- `security/owner_charter.py` — charter library (unwired in production on
  main).
- `tools/registry.py` — `execute()`, compatibility snapshot minting
  (DRIFT-1).
- `agent/mission.py`, `agent/mission_runtime.py`, `agent/agent_core.py`,
  `agent/loop.py`, `agent/task_runtime.py` — execution and derived
  enforcement paths.
- `api/chat.py`, `bridge.py` — Owner-session resolution and channel
  authentication.
- `tests/test_directive_acceptance.py`, `tests/test_phase6a1_hardening.py`,
  `tests/test_phase6k1_knowledge.py`, `tests/test_v47_red_team.py`,
  `tests/test_owner_charter.py` — supporting test evidence (tests alone are
  never sufficient proof of the authority model).
- Git: `main` @ `8a3fd109c0e5` (audited head), `tools/registry.py` @
  `7062ac0d`, `security/authority.py` @ `ba37e6db`,
  `security/owner_charter.py` @ `70b618f193e8`, `agent/mission.py` @
  `b19ce3a7`, `security/owner_policy.py` @ `b147722b`.
