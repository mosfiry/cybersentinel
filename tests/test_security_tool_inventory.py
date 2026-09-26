"""Stage A (Security Tooling Expansion): typed security tool inventory tests.

Layer 1 (Tool Definition) battery for security/tool_inventory.py. These
tests prove that the definition catalog is authority-free, deterministic,
fail-closed, and that catalog membership is NOT runtime registration:

- INV-TOOL-1: descriptive data only; the module has no authorize/execute
  surface and imports nothing from the authorization/proof/owner/runtime
  layers (dependency direction enforced by AST below).
- INV-TOOL-2: definition is not registration; tools.registry.KNOWN_TOOLS is
  unchanged by this catalog and offensive definitions gain no runtime path.
- INV-TOOL-3: risk -> authorization class is a fixed owner-curated table
  enforced at construction time.
- INV-TOOL-4: offensive risk classes are lab-only and cannot claim external
  targets.
- INV-TOOL-5: evidence support is mandatory.
- INV-TOOL-6: dangerous capabilities require dry-run support.
- INV-TOOL-7: canonical uniqueness across categories (Bettercap, Trivy,
  kube tools are single entries).
- INV-TOOL-8: forged/unknown/duplicate/authority-shaped/malformed inputs
  fail closed, every time.
"""

from __future__ import annotations

import ast
import dataclasses
from pathlib import Path

import pytest

import security.tool_inventory as tool_inventory
from security.tool_inventory import (
    DEFAULT_SECURITY_TOOL_INVENTORY,
    RISK_AUTHORIZATION_CLASS,
    SecurityToolDefinition,
    SecurityToolInventory,
    ToolAccessLevel,
    ToolAuthorizationClass,
    ToolAvailability,
    ToolCapability,
    ToolCategory,
    ToolInventoryError,
    ToolRiskClass,
)

import tools.registry


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "security" / "tool_inventory.py"


def _minimal_definition(**overrides) -> SecurityToolDefinition:
    """Build the least-privileged valid definition; overrides break invariants."""
    values: dict = {
        "tool_id": "unit.tool",
        "canonical_name": "Unit Tool",
        "category": ToolCategory.SECURITY_RESOURCES,
        "description": "Unit-test definition.",
        "capabilities": (ToolCapability.DATA_TRANSFORMATION,),
        "risk_class": ToolRiskClass.INFORMATIONAL,
        "authorization_class": ToolAuthorizationClass.PUBLIC_INFORMATION,
        "availability": ToolAvailability.PLANNED,
        "process_execution": ToolAccessLevel.NONE,
        "required_runtime": "builtin",
        "network_required": False,
        "external_target_capability": False,
    }
    values.update(overrides)
    return SecurityToolDefinition(**values)


# ---------------------------------------------------------------------------
# INV-TOOL-3: deterministic classification
# ---------------------------------------------------------------------------


def test_stage_a_risk_authorization_mapping_table_is_total_and_fixed():
    assert set(RISK_AUTHORIZATION_CLASS) == set(ToolRiskClass)
    assert RISK_AUTHORIZATION_CLASS[ToolRiskClass.INFORMATIONAL] is ToolAuthorizationClass.PUBLIC_INFORMATION
    assert RISK_AUTHORIZATION_CLASS[ToolRiskClass.PASSIVE_RECON] is ToolAuthorizationClass.OWNER_APPROVED_PASSIVE
    assert RISK_AUTHORIZATION_CLASS[ToolRiskClass.AUTHORIZED_SCANNING] is ToolAuthorizationClass.AUTHORIZED_SCOPE_REQUIRED
    assert RISK_AUTHORIZATION_CLASS[ToolRiskClass.LAB_SECURITY_TESTING] is ToolAuthorizationClass.LAB_AUTHORIZED_TARGET_REQUIRED
    assert RISK_AUTHORIZATION_CLASS[ToolRiskClass.PRIVILEGED_SECURITY] is ToolAuthorizationClass.PRIVILEGED_OWNER_APPROVAL
    assert RISK_AUTHORIZATION_CLASS[ToolRiskClass.HIGH_RISK] is ToolAuthorizationClass.LAB_AUTHORIZED_TARGET_REQUIRED
    assert RISK_AUTHORIZATION_CLASS[ToolRiskClass.LOCAL_ANALYSIS] is ToolAuthorizationClass.LOCAL_DATA_ONLY


@pytest.mark.parametrize("risk,expected", sorted(
    ((risk, auth) for risk, auth in RISK_AUTHORIZATION_CLASS.items()),
    key=lambda pair: pair[0].value,
))
def test_stage_a_authorization_class_must_match_risk_class(risk, expected):
    # A supplied class that disagrees with the risk class fails closed.
    wrong = next(auth for auth in ToolAuthorizationClass if auth is not expected)
    with pytest.raises(ToolInventoryError):
        _minimal_definition(risk_class=risk, authorization_class=wrong)
    # The matching class is accepted and stored.
    definition = _minimal_definition(risk_class=risk, authorization_class=expected)
    assert definition.authorization_class is expected


# ---------------------------------------------------------------------------
# INV-TOOL-4: lab-only default for offensive risk classes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("risk", sorted(tool_inventory.OFFENSIVE_RISK_CLASSES, key=lambda r: r.value))
def test_stage_a_offensive_risk_class_requires_lab_only(risk):
    # Supply the matching authorization class so ONLY the lab-only rule can
    # be the rejection reason.
    with pytest.raises(ToolInventoryError):
        _minimal_definition(
            risk_class=risk,
            authorization_class=RISK_AUTHORIZATION_CLASS[risk],
            lab_only=False,
        )


@pytest.mark.parametrize("risk", sorted(
    set(ToolRiskClass) - tool_inventory.OFFENSIVE_RISK_CLASSES, key=lambda r: r.value,
))
def test_stage_a_non_offensive_risk_classes_are_not_lab_only_by_default(risk):
    definition = _minimal_definition(risk_class=risk)
    assert definition.lab_only is False


def test_stage_a_lab_only_tool_cannot_claim_external_target():
    with pytest.raises(ToolInventoryError):
        _minimal_definition(lab_only=True, external_target_capability=True)


# ---------------------------------------------------------------------------
# INV-TOOL-5 / INV-TOOL-6: evidence-first and dry-run-first
# ---------------------------------------------------------------------------


def test_stage_a_evidence_support_is_mandatory():
    with pytest.raises(ToolInventoryError):
        _minimal_definition(evidence_support=False)


def test_stage_a_destructive_capability_requires_dry_run():
    with pytest.raises(ToolInventoryError):
        _minimal_definition(destructive_capability=True, dry_run_support=False)


def test_stage_a_external_target_requires_dry_run():
    with pytest.raises(ToolInventoryError):
        _minimal_definition(external_target_capability=True, dry_run_support=False)


def test_stage_a_process_execution_requires_dry_run():
    with pytest.raises(ToolInventoryError):
        _minimal_definition(process_execution=ToolAccessLevel.EXECUTE, dry_run_support=False)


# ---------------------------------------------------------------------------
# INV-TOOL-8: fail-closed validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_id", ["", " ", "UPPER", "-lead", ".lead", "has space", "has*star", "tool\nid", "nötool", None])
def test_stage_a_invalid_tool_ids_rejected(bad_id):
    with pytest.raises(ToolInventoryError):
        _minimal_definition(tool_id=bad_id)


@pytest.mark.parametrize("bad_version", ["", "v1", "1..2", "1.2.3.4.5", "latest", "1-0", None])
def test_stage_a_invalid_versions_rejected(bad_version):
    with pytest.raises(ToolInventoryError):
        _minimal_definition(version=bad_version)


def test_stage_a_invalid_adapter_version_rejected():
    with pytest.raises(ToolInventoryError):
        _minimal_definition(adapter_version="Not A Version!")


def test_stage_a_non_owner_provenance_rejected():
    with pytest.raises(ToolInventoryError):
        _minimal_definition(provenance="MODEL_SUGGESTED")
    with pytest.raises(ToolInventoryError):
        _minimal_definition(provenance="")


def test_stage_a_empty_capabilities_rejected():
    with pytest.raises(ToolInventoryError):
        _minimal_definition(capabilities=())


def test_stage_a_duplicate_capabilities_rejected():
    with pytest.raises(ToolInventoryError):
        _minimal_definition(capabilities=(ToolCapability.OSINT, ToolCapability.OSINT))


def test_stage_a_forged_capability_string_rejected():
    with pytest.raises(ToolInventoryError):
        _minimal_definition(capabilities=("TOTAL_CONTROL",))


def test_stage_a_missing_description_rejected():
    with pytest.raises(ToolInventoryError):
        _minimal_definition(description="   ")


def test_stage_a_authority_shaped_schema_keys_rejected():
    with pytest.raises(ToolInventoryError):
        _minimal_definition(input_schema={"type": "object", "properties": {"owner_token": {"type": "string"}}})
    with pytest.raises(ToolInventoryError):
        _minimal_definition(output_schema={"type": "object", "properties": {"authorization": {"type": "string"}}})
    with pytest.raises(ToolInventoryError):
        _minimal_definition(input_schema={"type": "object", "allowed_tools": []})


def test_stage_a_schema_requires_type_key():
    with pytest.raises(ToolInventoryError):
        _minimal_definition(input_schema={"properties": {}})


def test_stage_a_invalid_category_and_risk_strings_rejected():
    with pytest.raises(ToolInventoryError):
        _minimal_definition(category="ROOT")
    with pytest.raises(ToolInventoryError):
        _minimal_definition(risk_class="ZERO_RISK", authorization_class=ToolAuthorizationClass.PUBLIC_INFORMATION)


def test_stage_a_definition_is_frozen():
    definition = _minimal_definition()
    with pytest.raises((AttributeError, TypeError)):
        definition.tool_id = "other.tool"  # type: ignore[misc]
    with pytest.raises((AttributeError, TypeError)):
        definition.risk_class = ToolRiskClass.INFORMATIONAL  # type: ignore[misc]


def test_stage_a_replace_cannot_reclassify_registered_entry():
    """dataclasses.replace builds a NEW object; the frozen entry in the catalog
    is untouched, and re-registering the clone fails closed."""
    catalog = SecurityToolInventory([_minimal_definition()])
    original = catalog.get_required("unit.tool")
    clone = dataclasses.replace(
        original,
        tool_id="unit.tool.forged",
        risk_class=ToolRiskClass.LAB_SECURITY_TESTING,
        authorization_class=ToolAuthorizationClass.LAB_AUTHORIZED_TARGET_REQUIRED,
        lab_only=True,
    )
    assert clone.tool_id == "unit.tool.forged"
    assert catalog.get_required("unit.tool").risk_class is ToolRiskClass.INFORMATIONAL
    with pytest.raises(ToolInventoryError):
        catalog.register(clone)  # duplicate canonical name


# ---------------------------------------------------------------------------
# Catalog semantics
# ---------------------------------------------------------------------------


def test_stage_a_duplicate_tool_id_rejected():
    catalog = SecurityToolInventory([_minimal_definition()])
    with pytest.raises(ToolInventoryError):
        catalog.register(_minimal_definition(category=ToolCategory.REPORTING, canonical_name="Other Name"))


def test_stage_a_duplicate_canonical_name_rejected_case_insensitive():
    catalog = SecurityToolInventory([_minimal_definition()])
    with pytest.raises(ToolInventoryError):
        catalog.register(_minimal_definition(tool_id="other.tool", canonical_name="uNiT tOoL"))


def test_stage_a_unknown_tool_fails_closed():
    catalog = SecurityToolInventory([_minimal_definition()])
    assert catalog.get("does.not.exist") is None
    assert catalog.get("") is None
    with pytest.raises(ToolInventoryError):
        catalog.get_required("does.not.exist")


def test_stage_a_canonical_name_lookup_is_case_insensitive():
    catalog = SecurityToolInventory([_minimal_definition()])
    assert catalog.by_canonical_name("unit tool") is not None
    assert catalog.by_canonical_name("UNIT TOOL") is not None
    assert catalog.by_canonical_name("Unit Tool ") is not None  # trimmed
    assert catalog.by_canonical_name("nothing") is None


def test_stage_a_untyped_registration_rejected():
    catalog = SecurityToolInventory()
    with pytest.raises(ToolInventoryError):
        catalog.register({"tool_id": "not.a.definition"})  # type: ignore[arg-type]


def test_stage_a_register_returns_the_definition_and_indexes_capabilities():
    definition = _minimal_definition(
        capabilities=(ToolCapability.DATA_TRANSFORMATION, ToolCapability.REPORT_EXPORT),
    )
    catalog = SecurityToolInventory()
    assert catalog.register(definition) is definition
    assert catalog.providers_for(ToolCapability.REPORT_EXPORT) == (definition,)


def test_stage_a_providers_for_unknown_capability_string_fails_closed():
    catalog = SecurityToolInventory([_minimal_definition()])
    with pytest.raises(ToolInventoryError):
        catalog.providers_for("OMNISCIENCE")


def test_stage_a_tools_in_category_and_risk_class_filters():
    catalog = SecurityToolInventory([_minimal_definition()])
    assert catalog.tools_in_category(ToolCategory.SECURITY_RESOURCES) == (catalog.get_required("unit.tool"),)
    assert catalog.tools_in_category("SECURITY_RESOURCES") == (catalog.get_required("unit.tool"),)
    assert catalog.tools_in_category(ToolCategory.OSINT) == ()
    assert catalog.tools_with_risk_class(ToolRiskClass.INFORMATIONAL) == (catalog.get_required("unit.tool"),)
    assert catalog.tools_with_risk_class("INFORMATIONAL") == (catalog.get_required("unit.tool"),)
    assert catalog.tools_with_risk_class(ToolRiskClass.HIGH_RISK) == ()


def test_stage_a_to_dict_is_complete():
    payload = _minimal_definition().to_dict()
    expected_keys = {
        "tool_id", "canonical_name", "category", "description", "capabilities",
        "risk_class", "required_runtime", "platform", "availability",
        "authorization_class", "input_schema", "output_schema", "network_required",
        "filesystem_access", "process_execution", "privileged_execution",
        "destructive_capability", "external_target_capability", "lab_only",
        "dry_run_support", "evidence_support", "provenance", "version",
        "adapter_version",
    }
    assert set(payload) == expected_keys
    assert payload["category"] == "SECURITY_RESOURCES"
    assert payload["capabilities"] == ["DATA_TRANSFORMATION"]
    assert payload["provenance"] == "OWNER_CURATED"


# ---------------------------------------------------------------------------
# Seed catalog (owner-curated reference list)
# ---------------------------------------------------------------------------


def test_stage_a_seed_catalog_covers_all_categories():
    categories = {
        ToolCategory(row["category"]) for row in DEFAULT_SECURITY_TOOL_INVENTORY.snapshot()
    }
    assert categories == set(ToolCategory)


def test_stage_a_seed_catalog_size_and_canonical_uniqueness():
    assert len(DEFAULT_SECURITY_TOOL_INVENTORY) >= 80
    ids = list(DEFAULT_SECURITY_TOOL_INVENTORY.tool_ids())
    assert len(ids) == len(set(ids))
    names = [row["canonical_name"] for row in DEFAULT_SECURITY_TOOL_INVENTORY.snapshot()]
    assert len(names) == len({name.casefold() for name in names})


def test_stage_a_pinned_classifications():
    nmap = DEFAULT_SECURITY_TOOL_INVENTORY.get_required("nmap")
    assert nmap.risk_class is ToolRiskClass.AUTHORIZED_SCANNING
    assert nmap.authorization_class is ToolAuthorizationClass.AUTHORIZED_SCOPE_REQUIRED
    assert ToolCapability.PORT_SCANNING in nmap.capabilities

    metasploit = DEFAULT_SECURITY_TOOL_INVENTORY.get_required("metasploit")
    assert metasploit.risk_class is ToolRiskClass.LAB_SECURITY_TESTING
    assert metasploit.lab_only is True
    assert metasploit.external_target_capability is False

    hydra = DEFAULT_SECURITY_TOOL_INVENTORY.get_required("hydra")
    assert hydra.risk_class is ToolRiskClass.HIGH_RISK
    assert hydra.lab_only is True

    whois = DEFAULT_SECURITY_TOOL_INVENTORY.get_required("whois")
    assert whois.risk_class is ToolRiskClass.INFORMATIONAL
    assert whois.authorization_class is ToolAuthorizationClass.PUBLIC_INFORMATION


def test_stage_a_all_offensive_seed_tools_are_lab_only_and_internal():
    offensive = [
        definition
        for risk in tool_inventory.OFFENSIVE_RISK_CLASSES
        for definition in DEFAULT_SECURITY_TOOL_INVENTORY.tools_with_risk_class(risk)
    ]
    assert offensive, "seed catalog must contain offensive definitions to prove containment"
    for definition in offensive:
        assert definition.lab_only is True, definition.tool_id
        assert definition.external_target_capability is False, definition.tool_id


def test_stage_a_every_seed_definition_is_consistent():
    for tool_id in DEFAULT_SECURITY_TOOL_INVENTORY.tool_ids():
        definition = DEFAULT_SECURITY_TOOL_INVENTORY.get_required(tool_id)
        assert definition.authorization_class is RISK_AUTHORIZATION_CLASS[definition.risk_class]
        assert definition.evidence_support is True
        assert definition.provenance == "OWNER_CURATED"
        assert definition.capabilities


def test_stage_a_port_scanning_providers_are_nmap_masscan_rustscan():
    providers = DEFAULT_SECURITY_TOOL_INVENTORY.providers_for(ToolCapability.PORT_SCANNING)
    assert [p.tool_id for p in providers][:3] == ["nmap", "masscan", "rustscan"]


def test_stage_a_bettercap_is_one_canonical_multi_capability_definition():
    bettercap = DEFAULT_SECURITY_TOOL_INVENTORY.get_required("bettercap")
    assert DEFAULT_SECURITY_TOOL_INVENTORY.by_canonical_name("Bettercap") is bettercap
    assert bettercap.category is ToolCategory.WIRELESS_SECURITY
    assert ToolCapability.MITM_INTERCEPTION in bettercap.capabilities
    assert ToolCapability.PACKET_CAPTURE in bettercap.capabilities
    # No duplicate Bettercap entry under Network Analysis or anywhere else.
    duplicates = [
        row for row in DEFAULT_SECURITY_TOOL_INVENTORY.snapshot()
        if row["canonical_name"].casefold() == "bettercap"
    ]
    assert len(duplicates) == 1


def test_stage_a_trivy_and_kube_tools_are_canonical_single_entries():
    trivy = DEFAULT_SECURITY_TOOL_INVENTORY.get_required("trivy")
    assert ToolCapability.CONTAINER_AUDIT in trivy.capabilities
    assert trivy.category is ToolCategory.CLOUD_SECURITY
    assert DEFAULT_SECURITY_TOOL_INVENTORY.by_canonical_name("kube-hunter") is DEFAULT_SECURITY_TOOL_INVENTORY.get_required("kube_hunter")
    assert DEFAULT_SECURITY_TOOL_INVENTORY.by_canonical_name("kube-bench") is DEFAULT_SECURITY_TOOL_INVENTORY.get_required("kube_bench")


def test_stage_a_lab_definitions_carry_lab_environment_capability():
    labs = DEFAULT_SECURITY_TOOL_INVENTORY.tools_in_category(ToolCategory.PRACTICE_LABS)
    assert len(labs) >= 6
    for definition in labs:
        assert ToolCapability.LAB_ENVIRONMENT in definition.capabilities
        assert definition.risk_class in tool_inventory.OFFENSIVE_RISK_CLASSES
        assert definition.lab_only is True


def test_stage_a_default_inventory_rebuild_is_deterministic():
    rebuilt = tool_inventory._build_default_inventory()
    assert rebuilt.snapshot() == DEFAULT_SECURITY_TOOL_INVENTORY.snapshot()
    assert rebuilt.tool_ids() == DEFAULT_SECURITY_TOOL_INVENTORY.tool_ids()


# ---------------------------------------------------------------------------
# INV-TOOL-1 / INV-TOOL-2: authority freedom and definition != registration
# ---------------------------------------------------------------------------


FORBIDDEN_IMPORT_ROOTS = ("tools", "agent")
FORBIDDEN_SECURITY_MODULES = (
    "security.authorization",
    "security.mission_authorization",
    "security.execution_proof",
    "security.owner_policy",
    "security.owner_budget",
    "security.owner_instruction",
    "security.execution_boundary",
    "security.execution_plan",
)


def test_stage_a_module_imports_no_authority_or_execution_layers():
    source = MODULE_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                assert root not in FORBIDDEN_IMPORT_ROOTS, f"forbidden import: {alias.name}"
                if alias.name.startswith("security."):
                    assert alias.name in ("security.tool_inventory",), f"forbidden import: {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            root = module.split(".")[0] if module else ""
            assert root not in FORBIDDEN_IMPORT_ROOTS, f"forbidden import: {module}"
            if module.startswith("security."):
                assert module not in FORBIDDEN_SECURITY_MODULES, f"forbidden import: {module}"
                assert module in ("security.tool_inventory",), f"forbidden import: {module}"


def test_stage_a_module_defines_no_authority_or_execution_functions():
    source = MODULE_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    banned_prefixes = ("execute", "authorize", "authorise", "run_", "invoke", "grant", "approve", "register_handler", "allow")
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            folded = node.name.casefold()
            assert not any(folded.startswith(prefix) for prefix in banned_prefixes), (
                f"layer-1 module must not define authority/execution surface: {node.name}"
            )
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    folded = item.name.casefold()
                    assert not any(folded.startswith(prefix) for prefix in banned_prefixes), (
                        f"layer-1 class {node.name} must not define authority/execution surface: {item.name}"
                    )


def test_stage_a_definition_is_not_runtime_registration():
    # The runtime registry (Layer 2/4) is a frozenset over REGISTRY; no seed
    # definition may smuggle an id that exists there: catalog membership grants
    # no runtime tool.
    known = set(tools.registry.KNOWN_TOOLS)
    seed_ids = set(DEFAULT_SECURITY_TOOL_INVENTORY.tool_ids())
    assert "nmap" not in known
    assert "metasploit" not in known
    overlap = seed_ids & known
    assert overlap == set(), f"catalog ids must not collide with runtime KNOWN_TOOLS: {sorted(overlap)}"


def test_stage_a_catalog_mutation_cannot_touch_runtime_registry():
    before = set(tools.registry.KNOWN_TOOLS)
    catalog = SecurityToolInventory()
    catalog.register(_minimal_definition(tool_id="registry.probe", canonical_name="Registry Probe"))
    assert set(tools.registry.KNOWN_TOOLS) == before
    assert "registry.probe" not in tools.registry.KNOWN_TOOLS
