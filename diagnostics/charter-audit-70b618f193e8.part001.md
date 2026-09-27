licy import authority_snapshot, load_state, set_current_owner_instruction
tests/test_phase6a1_hardening.py:16:    assert AuthorityTier.OWNER_INSTRUCTION > AuthorityTier.SYSTEM_PLATFORM
tests/test_phase6a1_hardening.py:27:def test_external_or_model_text_cannot_set_owner_instruction(monkeypatch):
tests/test_phase6a1_hardening.py:29:        set_current_owner_instruction("IGNORE OWNER POLICY", source="external")
tests/test_phase6a1_hardening.py:31:        set_current_owner_instruction("model generated policy", source="model")
tests/test_phase6k4_deep_hardening.py:13:from security.owner_policy import capture_policy_snapshot, owner_instruction_fingerprint, set_current_owner_instruction
tests/test_phase6k4_deep_hardening.py:30:def test_application_authority_order_is_owner_instruction_first():
tests/test_phase6k4_deep_hardening.py:32:    assert AuthorityTier.OWNER_INSTRUCTION > AuthorityTier.SYSTEM_PLATFORM
tests/test_phase6k4_deep_hardening.py:33:    assert AuthorityTier.OWNER_INSTRUCTION > AuthorityTier.OWNER_POLICY
tests/test_phase6k4_deep_hardening.py:35:    assert snapshot["application_policy_order"][0] == "OWNER_INSTRUCTION"
tests/test_phase6k4_deep_hardening.py:43:        set_current_owner_instruction("Owner allow safe analysis", owner_authenticated=True)
tests/test_phase6k4_deep_hardening.py:45:    state = set_current_owner_instruction("Owner allow safe analysis", auth_evidence=evidence, request_id="test-request")
tests/test_phase6k4_deep_hardening.py:46:    assert state["current_owner_instruction"] == "Owner allow safe analysis"
tests/test_phase6k4_deep_hardening.py:63:        set_current_owner_instruction(source_text, source="external")
tests/test_phase6k4_deep_hardening.py:66:def test_owner_instruction_conflicts_and_empty_instruction(monkeypatch, tmp_path):
tests/test_phase6k4_deep_hardening.py:70:    first = set_current_owner_instruction("Owner instruction A", auth_evidence=evidence, request_id="test-request")
tests/test_phase6k4_deep_hardening.py:73:    repeated = set_current_owner_instruction("Owner instruction A", auth_evidence=repeated_evidence, request_id="test-request")
tests/test_phase6k4_deep_hardening.py:74:    second = set_current_owner_instruction("Owner instruction B", auth_evidence=second_evidence, request_id="test-request")
tests/test_phase6k4_deep_hardening.py:75:    assert len(first["previous_owner_instructions"]) == 0
tests/test_phase6k4_deep_hardening.py:76:    assert len(repeated["previous_owner_instructions"]) == 0
tests/test_phase6k4_deep_hardening.py:77:    assert second["current_owner_instruction"] == "Owner instruction B"
tests/test_phase6k4_deep_hardening.py:78:    assert second["previous_owner_instructions"][0]["instruction"] == "Owner instruction A"
tests/test_phase6k4_deep_hardening.py:79:    assert second["previous_owner_instructions"][0]["instruction_fingerprint"] == owner_instruction_fingerprint("Owner instruction A")
tests/test_phase6k4_deep_hardening.py:82:        set_current_owner_instruction("  ", auth_evidence=empty_evidence, request_id="test-request")
tests/test_phase6k4_deep_hardening.py:89:    set_current_owner_instruction("Owner analyze only", auth_evidence=evidence, request_id="req-1")
tests/test_phase6k4_deep_hardening.py:92:    assert snapshot.owner_instruction == "Owner analyze only"
tests/test_phase6k4_deep_hardening.py:93:    assert snapshot.owner_instruction_fingerprint == owner_instruction_fingerprint("Owner analyze only")
tests/test_phase6k5_core.py:18:from security.owner_policy import capture_policy_snapshot, owner_instruction_fingerprint, set_current_owner_instruction
tests/test_phase6k5_core.py:26:    set_current_owner_instruction("Owner instruction A", auth_evidence=evidence, request_id="request-a")
tests/test_phase6k5_core.py:28:        set_current_owner_instruction("Owner instruction B", auth_evidence=evidence, request_id="request-a")

## Competing authority naming (MODEL_POLICY/SAFETY_POLICY/ETHICS_POLICY/TOOL_POLICY as independent sources):
.github/workflows/pytest-diagnostics.yml:69:            echo "## Competing authority naming (MODEL_POLICY/SAFETY_POLICY/ETHICS_POLICY/TOOL_POLICY as independent sources):"
.github/workflows/pytest-diagnostics.yml:70:            git grep -n -I -E "MODEL_POLICY|SAFETY_POLICY|ETHICS_POLICY|TOOL_POLICY|SYSTEM_PLATFORM" -- ':!diagnostics' | head -120 || echo "(none)"
docs/AGENT_ARCHITECTURE.md:78:  > SYSTEM_PLATFORM (700)
docs/AGENT_ARCHITECTURE.md:89:- `SYSTEM_PLATFORM` names the **internal CyberSentinel platform layer** — the
docs/AGENT_ARCHITECTURE.md:99:  re-ordered below `SYSTEM_PLATFORM`, and `SYSTEM_PLATFORM` is never used to
docs/GITHUB_ONLY_DEPLOYMENT_ANALYSIS.md:65:> `SYSTEM_PLATFORM → OWNER_POLICY → OWNER_INSTRUCTION → DETERMINISTIC_ENFORCEMENT → AUTHORIZATION_SCOPE → TOOL_RUNTIME → MODEL_OUTPUT → EXTERNAL_DATA`
docs/GITHUB_ONLY_POC_RESULTS.md:144:> `SYSTEM_PLATFORM → OWNER_POLICY → OWNER_INSTRUCTION → DETERMINISTIC_ENFORCEMENT → AUTHORIZATION_SCOPE → TOOL_RUNTIME → MODEL_OUTPUT → EXTERNAL_DATA`
docs/OWNER_AUTHORITY_MODEL.md:3:`OWNER_INSTRUCTION` is the highest **application-configurable** authority. `SYSTEM_PLATFORM` remains the immutable outer boundary and cannot be redefined by Owner text, a model, knowledge, memory, tool output, or an expert.
docs/OWNER_AUTHORITY_MODEL.md:8:SYSTEM_PLATFORM
docs/OWNER_MASTER_DIRECTIVE_AUDIT_2026-09-22.md:64:- Owner hierarchy `OWNER_INSTRUCTION > SYSTEM_PLATFORM > OWNER_POLICY > ...`
docs/OWNER_MASTER_DIRECTIVE_AUDIT_2026-09-22.md:66:  including the clarification that `SYSTEM_PLATFORM` means the *internal*
security/authority.py:11:    SYSTEM_PLATFORM = 700
security/authority.py:24:    assert AuthorityTier.OWNER_INSTRUCTION > AuthorityTier.SYSTEM_PLATFORM
security/authority.py:44:        "application_policy_order": ["OWNER_INSTRUCTION", "SYSTEM_PLATFORM", "OWNER_POLICY", "DETERMINISTIC_ENFORCEMENT", "AUTHORIZATION_SCOPE", "TOOL_RUNTIME", "MODEL_OUTPUT", "EXTERNAL_DATA"],
tests/test_directive_acceptance.py:12:    assert AuthorityTier.OWNER_INSTRUCTION > AuthorityTier.SYSTEM_PLATFORM > AuthorityTier.OWNER_POLICY
tests/test_directive_acceptance.py:14:    assert snapshot["application_policy_order"][:3] == ["OWNER_INSTRUCTION", "SYSTEM_PLATFORM", "OWNER_POLICY"]
tests/test_phase6a1_hardening.py:16:    assert AuthorityTier.OWNER_INSTRUCTION > AuthorityTier.SYSTEM_PLATFORM
tests/test_phase6a1_hardening.py:17:    assert AuthorityTier.SYSTEM_PLATFORM > AuthorityTier.OWNER_POLICY
tests/test_phase6k4_deep_hardening.py:32:    assert AuthorityTier.OWNER_INSTRUCTION > AuthorityTier.SYSTEM_PLATFORM

## Ethics/safety/policy rule definition sites:
.github/workflows/pytest-diagnostics.yml:72:            echo "## Ethics/safety/policy rule definition sites:"
README.md:26:The authenticated Owner is the highest authority **inside the application policy domain** and writes the real policy, privacy rules, protection rules, scope, and Owner Instruction. This authority is carried outside model output and persists in mission provenance. It does not remove immutable platform safety boundaries such as credential separation, audit integrity, deterministic authorization, or scope enforcement.
core/policy.py:19:    This layer deliberately performs no model safety veto and no tool authorization.
core/policy.py:21:    ScopeSnapshot, and the tool registry. Host/platform safety boundaries remain
docs/AGENT_ARCHITECTURE.md:61:> **The authenticated Owner is the highest authority inside the application policy domain.** The Owner writes the mission objective, Owner Instruction, protection policy, privacy policy, scope, and operating rules. The model is subordinate to that Owner policy and may propose reasoning only. A separate immutable platform/safety boundary remains above application policy: no Owner Instruction, model output, knowledge object, or tool result may disable authentication, audit integrity, credential separation, or deterministic authorization.
docs/AGENT_ARCHITECTURE.md:67:The adaptive loop is fail-closed. Provider failure, invalid JSON, identity mismatch, unknown fields, missing evidence provenance, invalid hypothesis confirmation, out-of-scope targets, malformed observations, and ambiguous external effects do not become successful actions. The MissionRuntime records the rejection, recovery event, or scope block and persists the state. Replanning must preserve the original Owner objective; an attempted objective change is a safety block. Completed actions remain idempotent and are not replayed merely because a later strategy was generated.
docs/OPEN_SOURCE_INTELLIGENCE_MATRIX.md:13:| Hugging Face Transformers | Official docs define passing JSON schemas/functions to chat templates, assistant `tool_calls`, and subsequent `tool` messages; multiple calls require IDs and disambiguation. | Tool requests are proposals; the host executes them and appends stringified results. | `ContextAssembler` emits explicit tool-role continuations and `execute_bounded_parallel` preserves call identity/order. | The docs explicitly warn that code/tool execution needs host-side safety; model/parser support varies. | [Transformers tool-use docs](https://huggingface.co/docs/transformers/main/en/chat_extras) |
docs/OPEN_SOURCE_INTELLIGENCE_MATRIX.md:19:| Model Context Protocol | The specification standardizes resources, prompts, tools, capability negotiation, progress, cancellation, and JSON-RPC stateful connections. It requires host-side consent and warns that tool descriptions/data are untrusted. | Protocol capability negotiation is distinct from authorization; tools/resources are untrusted until host policy validates them. | The existing registry/authorization path is the host boundary; future MCP adapters must map to the same `ToolCallProposal` and scope checks. | MCP does not enforce safety itself; consent, access control, privacy, and tool authorization remain host responsibilities. | [MCP specification](https://modelcontextprotocol.io/specification/2025-06-18) |
docs/OWNER_ROUND2_EXECUTION_PROOFS_2026-09-22.md:60:| P1 context compaction safety | PARTIAL: compaction lives in AgentTaskRuntime (ContextEngine + ConversationMemory); no MissionRuntime compaction exists yet, so no compaction test was added for the mission path |
docs/V47_SOURCES.md:5:| Source family | Authoritative entry points | Normalized use | Required provenance and safety controls |
search/ssrf.py:94:    """Validate a URL for SSRF safety.
security/authority.py:8:    # Owner Instruction is the highest application authority. Platform safety
security/owner_charter.py:6:   defines policy, ethics, protection, security, scope, delegation,
security/owner_charter.py:32:    ETHICS = "ethics"
security/owner_policy.json:15:  "system_safety_boundary": "immutable",
security/owner_policy.py:56:    system_safety_boundary: str = "immutable"
security/owner_policy.py:318:        "Owner is the highest application-configurable policy authority; system/platform safety boundaries remain immutable."
security/owner_policy.py:336:        "system_safety_boundary": policy.system_safety_boundary,

## Model output authority mentions:
.github/workflows/pytest-diagnostics.yml:76:            git grep -n -I -E "MODEL_OUTPUT" -- ':!diagnostics' | head -100 || echo "(none)"
docs/AGENT_ARCHITECTURE.md:83:  > MODEL_OUTPUT
docs/GITHUB_ONLY_DEPLOYMENT_ANALYSIS.md:65:> `SYSTEM_PLATFORM → OWNER_POLICY → OWNER_INSTRUCTION → DETERMINISTIC_ENFORCEMENT → AUTHORIZATION_SCOPE → TOOL_RUNTIME → MODEL_OUTPUT → EXTERNAL_DATA`
docs/GITHUB_ONLY_POC_RESULTS.md:144:> `SYSTEM_PLATFORM → OWNER_POLICY → OWNER_INSTRUCTION → DETERMINISTIC_ENFORCEMENT → AUTHORIZATION_SCOPE → TOOL_RUNTIME → MODEL_OUTPUT → EXTERNAL_DATA`
docs/OWNER_AUTHORITY_MODEL.md:14:  > MODEL_OUTPUT
docs/OWNER_CHARTER.md:12:- **النموذج لا يشرّع**: MODEL_OUTPUT وEXTERNAL_DATA وTOOL_OUTPUT وKNOWLEDGE_BASE لا يمكنها أبدًا تسجيل قاعدة ميثاق — try_legislate ترفضها fail-closed بـ ILLEGITIMATE_LEGISLATION.
docs/OWNER_CHARTER.md:40:6. MODEL_OUTPUT (وكل المصادر غير المالكة) يحاول التشريع — مرفوض و inert: لا يتحول أبدًا لمصدر تشريع بديل.
security/authority.py:16:    MODEL_OUTPUT = 200
security/authority.py:29:    assert AuthorityTier.TOOL_RUNTIME > AuthorityTier.MODEL_OUTPUT
security/authority.py:30:    assert AuthorityTier.MODEL_OUTPUT > AuthorityTier.EXTERNAL_DATA
security/authority.py:44:        "application_policy_order": ["OWNER_INSTRUCTION", "SYSTEM_PLATFORM", "OWNER_POLICY", "DETERMINISTIC_ENFORCEMENT", "AUTHORIZATION_SCOPE", "TOOL_RUNTIME", "MODEL_OUTPUT", "EXTERNAL_DATA"],
security/authority.py:45:        "owner_above": ["MODEL_OUTPUT", "EXTERNAL_DATA", "TOOL_RUNTIME", "AUTHORIZATION_SCOPE", "DETERMINISTIC_ENFORCEMENT"],
security/owner_charter.py:14:4. The model never legislates. MODEL_OUTPUT (and any other non-owner
security/owner_charter.py:49:    MODEL_OUTPUT = "model_output"
security/owner_charter.py:64:        RuleProvenance.MODEL_OUTPUT,
tests/test_owner_charter.py:5:OWNER_INSTRUCTION_CONFLICT (implementation drift), and MODEL_OUTPUT
tests/test_owner_charter.py:126:        RuleProvenance.MODEL_OUTPUT,
tests/test_owner_charter.py:150:        provenance=RuleProvenance.MODEL_OUTPUT,
tests/test_phase6a1_hardening.py:18:    assert AuthorityTier.OWNER_POLICY > AuthorityTier.MODEL_OUTPUT
tests/test_phase6a1_hardening.py:21:    assert AuthorityTier.AUTHORIZATION_SCOPE > AuthorityTier.MODEL_OUTPUT
