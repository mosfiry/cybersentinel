from __future__ import annotations

"""Stage A (Security Tooling Expansion): typed security tool DEFINITION catalog.

This module implements Layer 1 (Tool Definition) of the security tooling
expansion. It is a PURE, authority-free, deterministic catalog of security
tool definitions (what a tool IS), deliberately separated from:

- Layer 2 (Tool Adapter): how CyberSentinel invokes a tool
  (tools/registry.py ToolSpec handlers; none of them live here),
- Layer 3 (Authorization): whether a request may use a tool
  (security/authorization.py, Owner Policy, MissionAuthorizationSnapshot),
- Layer 4 (Execution): whether one specific invocation may run
  (ExecutionPlan -> gate -> proof -> tools.registry.execute -> handler).

Invariants (INV-TOOL-1..8):

- INV-TOOL-1 (descriptive data only): a SecurityToolDefinition is data,
  never authority. No field grants, widens, or repairs any permission, and
  this module deliberately defines NO authorize/execute surface at all.
  External tool output remains UNTRUSTED DATA everywhere: it can never
  change Owner Policy, authorization, scope, or this catalog.
- INV-TOOL-2 (definition is not registration): catalog membership never
  registers an executable runtime tool. tools/registry.py is untouched by
  this module; an entry here grants no execution path whatsoever.
- INV-TOOL-3 (deterministic classification): risk_class and
  authorization_class are owner-curated code constants; the mapping between
  them is enforced at definition time and can never be decided by model
  output at runtime.
- INV-TOOL-4 (lab-only default): offensive risk classes (LAB_SECURITY_TESTING,
  PRIVILEGED_SECURITY, HIGH_RISK) are always defined lab_only=True and
  external_target_capability=False; a definition that claims otherwise fails
  closed at construction.
- INV-TOOL-5 (evidence-first): every definition must declare
  evidence_support=True.
- INV-TOOL-6 (dry-run-first): destructive capability, external-target
  capability, or process execution requires dry_run_support=True.
- INV-TOOL-7 (canonical uniqueness): one canonical definition per tool
  across categories. Multi-category roles are expressed through
  capabilities, never through duplicate definitions (e.g. Bettercap is one
  definition; MITM and capture roles are capabilities).
- INV-TOOL-8 (fail closed): unknown tools, forged identities, wildcard
  identifiers, duplicate registrations, authority-shaped schema keys, and
  non-owner provenance are rejected deterministically.

This module imports nothing from security.authorization*,
security.mission_authorization, security.execution_proof,
security.owner_*, tools.registry, or agent.*. The dependency direction is
enforced by tests/test_security_tool_inventory.py.
"""

from dataclasses import dataclass, field
from enum import Enum
import re
from typing import Any, Iterable


__all__ = [
    "DEFAULT_SECURITY_TOOL_INVENTORY",
    "SecurityToolDefinition",
    "SecurityToolInventory",
    "ToolAccessLevel",
    "ToolAuthorizationClass",
    "ToolAvailability",
    "ToolCapability",
    "ToolCategory",
    "ToolInventoryError",
    "ToolRiskClass",
]


class ToolInventoryError(ValueError):
    """Raised when a security tool definition or catalog operation fails closed."""


class ToolCategory(str, Enum):
    RECONNAISSANCE = "RECONNAISSANCE"
    SCANNING_ENUMERATION = "SCANNING_ENUMERATION"
    WEB_APPLICATION_TESTING = "WEB_APPLICATION_TESTING"
    EXPLOITATION = "EXPLOITATION"
    CREDENTIAL_ATTACKS = "CREDENTIAL_ATTACKS"
    WIRELESS_SECURITY = "WIRELESS_SECURITY"
    NETWORK_ANALYSIS = "NETWORK_ANALYSIS"
    ACTIVE_DIRECTORY = "ACTIVE_DIRECTORY"
    CLOUD_SECURITY = "CLOUD_SECURITY"
    REVERSE_ENGINEERING = "REVERSE_ENGINEERING"
    OSINT = "OSINT"
    CONTAINERS_DEVSECOPS = "CONTAINERS_DEVSECOPS"
    REPORTING = "REPORTING"
    PRACTICE_LABS = "PRACTICE_LABS"
    SECURITY_RESOURCES = "SECURITY_RESOURCES"


class ToolRiskClass(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    PASSIVE_RECON = "PASSIVE_RECON"
    AUTHORIZED_SCANNING = "AUTHORIZED_SCANNING"
    LAB_SECURITY_TESTING = "LAB_SECURITY_TESTING"
    PRIVILEGED_SECURITY = "PRIVILEGED_SECURITY"
    HIGH_RISK = "HIGH_RISK"
    LOCAL_ANALYSIS = "LOCAL_ANALYSIS"


class ToolCapability(str, Enum):
    DNS_LOOKUP = "DNS_LOOKUP"
    WHOIS_LOOKUP = "WHOIS_LOOKUP"
    PASSIVE_RECON = "PASSIVE_RECON"
    SUBDOMAIN_ENUMERATION = "SUBDOMAIN_ENUMERATION"
    PORT_SCANNING = "PORT_SCANNING"
    SERVICE_ENUMERATION = "SERVICE_ENUMERATION"
    WEB_ENUMERATION = "WEB_ENUMERATION"
    HTTP_ANALYSIS = "HTTP_ANALYSIS"
    PACKET_CAPTURE = "PACKET_CAPTURE"
    PACKET_ANALYSIS = "PACKET_ANALYSIS"
    OSINT = "OSINT"
    CLOUD_AUDIT = "CLOUD_AUDIT"
    CONTAINER_AUDIT = "CONTAINER_AUDIT"
    CODE_ANALYSIS = "CODE_ANALYSIS"
    BINARY_ANALYSIS = "BINARY_ANALYSIS"
    REPORT_GENERATION = "REPORT_GENERATION"
    REPORT_EXPORT = "REPORT_EXPORT"
    LAB_EXPLOITATION = "LAB_EXPLOITATION"
    CREDENTIAL_AUDIT = "CREDENTIAL_AUDIT"
    DATA_TRANSFORMATION = "DATA_TRANSFORMATION"
    EXPLOIT_RESEARCH = "EXPLOIT_RESEARCH"
    WORDLIST_GENERATION = "WORDLIST_GENERATION"
    WIRELESS_MONITORING = "WIRELESS_MONITORING"
    MITM_INTERCEPTION = "MITM_INTERCEPTION"
    AD_ENUMERATION = "AD_ENUMERATION"
    VULNERABILITY_SCANNING = "VULNERABILITY_SCANNING"
    LAB_ENVIRONMENT = "LAB_ENVIRONMENT"


class ToolAvailability(str, Enum):
    BUILTIN = "BUILTIN"
    EXTERNAL = "EXTERNAL"
    PLANNED = "PLANNED"


class ToolAuthorizationClass(str, Enum):
    PUBLIC_INFORMATION = "PUBLIC_INFORMATION"
    OWNER_APPROVED_PASSIVE = "OWNER_APPROVED_PASSIVE"
    AUTHORIZED_SCOPE_REQUIRED = "AUTHORIZED_SCOPE_REQUIRED"
    LAB_AUTHORIZED_TARGET_REQUIRED = "LAB_AUTHORIZED_TARGET_REQUIRED"
    PRIVILEGED_OWNER_APPROVAL = "PRIVILEGED_OWNER_APPROVAL"
    LOCAL_DATA_ONLY = "LOCAL_DATA_ONLY"


class ToolAccessLevel(str, Enum):
    NONE = "NONE"
    READ = "READ"
    WRITE = "WRITE"
    EXECUTE = "EXECUTE"


# Deterministic risk -> authorization class mapping (INV-TOOL-3). This table
# is owner-curated code; it is never consulted from, or influenced by,
# model output or external tool output.
RISK_AUTHORIZATION_CLASS: dict[ToolRiskClass, ToolAuthorizationClass] = {
    ToolRiskClass.INFORMATIONAL: ToolAuthorizationClass.PUBLIC_INFORMATION,
    ToolRiskClass.PASSIVE_RECON: ToolAuthorizationClass.OWNER_APPROVED_PASSIVE,
    ToolRiskClass.AUTHORIZED_SCANNING: ToolAuthorizationClass.AUTHORIZED_SCOPE_REQUIRED,
    ToolRiskClass.LAB_SECURITY_TESTING: ToolAuthorizationClass.LAB_AUTHORIZED_TARGET_REQUIRED,
    ToolRiskClass.PRIVILEGED_SECURITY: ToolAuthorizationClass.PRIVILEGED_OWNER_APPROVAL,
    ToolRiskClass.HIGH_RISK: ToolAuthorizationClass.LAB_AUTHORIZED_TARGET_REQUIRED,
    ToolRiskClass.LOCAL_ANALYSIS: ToolAuthorizationClass.LOCAL_DATA_ONLY,
}

OFFENSIVE_RISK_CLASSES = frozenset({
    ToolRiskClass.LAB_SECURITY_TESTING,
    ToolRiskClass.PRIVILEGED_SECURITY,
    ToolRiskClass.HIGH_RISK,
})

TOOL_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
VERSION_PATTERN = re.compile(r"^\d+(\.\d+){0,3}$")
ADAPTER_VERSION_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]*$")

PROVENANCE_OWNER_CURATED = "OWNER_CURATED"

AUTHORITY_KEY_TOKENS = (
    "authorization", "authorisation", "owner", "credential", "execution_proof",
    "proof", "capability", "permission", "grant", "budget", "approval",
    "allowed_tools", "scope_expansion", "token", "secret", "password",
)


def _is_authority_key(name: Any) -> bool:
    folded = str(name).casefold()
    return any(token in folded for token in AUTHORITY_KEY_TOKENS)


def _coerce_enum(value: Any, enum_cls: type, label: str) -> Any:
    if isinstance(value, enum_cls):
        return value
    if isinstance(value, str):
        try:
            return enum_cls(value.strip())
        except ValueError:
            raise ToolInventoryError("invalid " + label + ": " + str(value)) from None
    raise ToolInventoryError(label + " must be a " + enum_cls.__name__ + " or its string value")


def _validate_schema(schema: Any, label: str) -> dict[str, Any]:
    if not isinstance(schema, dict):
        raise ToolInventoryError(label + " must be a dict schema")
    if "type" not in schema:
        raise ToolInventoryError(label + " requires a 'type' key")
    for key in schema:
        if _is_authority_key(key):
            raise ToolInventoryError("authority-shaped " + label + " key rejected: " + str(key))
    properties = schema.get("properties")
    if properties is not None:
        if not isinstance(properties, dict):
            raise ToolInventoryError(label + " properties must be a dict")
        for key in properties:
            if _is_authority_key(key):
                raise ToolInventoryError("authority-shaped " + label + " property rejected: " + str(key))
    return dict(schema)


@dataclass(frozen=True)
class SecurityToolDefinition:
    """One canonical, immutable, authority-free security tool definition."""

    tool_id: str
    canonical_name: str
    category: ToolCategory
    description: str
    capabilities: tuple[ToolCapability, ...]
    risk_class: ToolRiskClass
    required_runtime: str = "external-binary"
    platform: str = "linux"
    availability: ToolAvailability = ToolAvailability.EXTERNAL
    authorization_class: ToolAuthorizationClass = ToolAuthorizationClass.PUBLIC_INFORMATION
    input_schema: dict[str, Any] = field(default_factory=lambda: {"type": "object", "properties": {}})
    output_schema: dict[str, Any] = field(default_factory=lambda: {"type": "object", "properties": {}})
    network_required: bool = False
    filesystem_access: ToolAccessLevel = ToolAccessLevel.NONE
    process_execution: ToolAccessLevel = ToolAccessLevel.NONE
    privileged_execution: bool = False
    destructive_capability: bool = False
    external_target_capability: bool = False
    lab_only: bool = False
    dry_run_support: bool = True
    evidence_support: bool = True
    provenance: str = PROVENANCE_OWNER_CURATED
    version: str = "1.0.0"
    adapter_version: str = "unbuilt"

    def __post_init__(self) -> None:
        tool_id = str(self.tool_id or "").strip()
        if not tool_id or not TOOL_ID_PATTERN.match(tool_id):
            raise ToolInventoryError("invalid tool_id: " + str(self.tool_id))
        object.__setattr__(self, "tool_id", tool_id)
        canonical_name = str(self.canonical_name or "").strip()
        if not canonical_name:
            raise ToolInventoryError("tool " + tool_id + " requires a canonical name")
        object.__setattr__(self, "canonical_name", canonical_name)
        description = str(self.description or "").strip()
        if not description:
            raise ToolInventoryError("tool " + tool_id + " requires a description")
        object.__setattr__(self, "description", description)
        for name in ("required_runtime", "platform"):
            if not str(getattr(self, name) or "").strip():
                raise ToolInventoryError("tool " + tool_id + " requires " + name)
        object.__setattr__(self, "category", _coerce_enum(self.category, ToolCategory, "tool " + tool_id + " category"))
        risk = _coerce_enum(self.risk_class, ToolRiskClass, "tool " + tool_id + " risk class")
        object.__setattr__(self, "risk_class", risk)
        object.__setattr__(self, "availability", _coerce_enum(self.availability, ToolAvailability, "tool " + tool_id + " availability"))
        object.__setattr__(self, "filesystem_access", _coerce_enum(self.filesystem_access, ToolAccessLevel, "tool " + tool_id + " filesystem access"))
        object.__setattr__(self, "process_execution", _coerce_enum(self.process_execution, ToolAccessLevel, "tool " + tool_id + " process execution"))

        # INV-TOOL-3: the authorization class is derived deterministically
        # from the risk class; nothing (and no one) can decouple them.
        expected_auth = RISK_AUTHORIZATION_CLASS[risk]
        supplied_auth = _coerce_enum(self.authorization_class, ToolAuthorizationClass, "tool " + tool_id + " authorization class")
        if supplied_auth is not expected_auth:
            raise ToolInventoryError(
                "tool " + tool_id + " authorization class must be the deterministic mapping of its risk class: "
                + risk.value + " -> " + expected_auth.value
            )
        object.__setattr__(self, "authorization_class", expected_auth)

        if not self.capabilities:
            raise ToolInventoryError("tool " + tool_id + " requires at least one capability")
        capabilities: list[ToolCapability] = []
        for item in self.capabilities:
            capability = _coerce_enum(item, ToolCapability, "tool " + tool_id + " capability")
            if capability in capabilities:
                raise ToolInventoryError("duplicate capability for tool " + tool_id + ": " + capability.value)
            capabilities.append(capability)
        object.__setattr__(self, "capabilities", tuple(capabilities))

        # INV-TOOL-4: lab-only default for offensive risk classes.
        if risk in OFFENSIVE_RISK_CLASSES and not self.lab_only:
            raise ToolInventoryError(
                "tool " + tool_id + " has risk class " + risk.value + " and must be defined lab_only=True"
            )
        if self.lab_only and self.external_target_capability:
            raise ToolInventoryError(
                "lab-only tool " + tool_id + " cannot claim external_target_capability"
            )

        # INV-TOOL-6: dry-run-first for dangerous capabilities.
        dangerous = self.destructive_capability or self.external_target_capability or self.process_execution is ToolAccessLevel.EXECUTE
        if dangerous and not self.dry_run_support:
            raise ToolInventoryError("tool " + tool_id + " requires dry_run_support=True")

        # INV-TOOL-5: evidence-first.
        if not self.evidence_support:
            raise ToolInventoryError("tool " + tool_id + " must declare evidence_support=True")

        object.__setattr__(self, "input_schema", _validate_schema(self.input_schema, "tool " + tool_id + " input_schema"))
        object.__setattr__(self, "output_schema", _validate_schema(self.output_schema, "tool " + tool_id + " output_schema"))

        if not VERSION_PATTERN.match(str(self.version or "")):
            raise ToolInventoryError("tool " + tool_id + " has an invalid version: " + str(self.version))
        if not ADAPTER_VERSION_PATTERN.match(str(self.adapter_version or "")):
            raise ToolInventoryError("tool " + tool_id + " has an invalid adapter_version: " + str(self.adapter_version))
        if str(self.provenance or "") != PROVENANCE_OWNER_CURATED:
            raise ToolInventoryError(
                "tool " + tool_id + " provenance must be " + PROVENANCE_OWNER_CURATED + " (model output can never mint definitions)"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "canonical_name": self.canonical_name,
            "category": self.category.value,
            "description": self.description,
            "capabilities": [capability.value for capability in self.capabilities],
            "risk_class": self.risk_class.value,
            "required_runtime": self.required_runtime,
            "platform": self.platform,
            "availability": self.availability.value,
            "authorization_class": self.authorization_class.value,
            "input_schema": dict(self.input_schema),
            "output_schema": dict(self.output_schema),
            "network_required": self.network_required,
            "filesystem_access": self.filesystem_access.value,
            "process_execution": self.process_execution.value,
            "privileged_execution": self.privileged_execution,
            "destructive_capability": self.destructive_capability,
            "external_target_capability": self.external_target_capability,
            "lab_only": self.lab_only,
            "dry_run_support": self.dry_run_support,
            "evidence_support": self.evidence_support,
            "provenance": self.provenance,
            "version": self.version,
            "adapter_version": self.adapter_version,
        }


class SecurityToolInventory:
    """Deterministic catalog of canonical security tool definitions.

    The catalog is Layer 1 ONLY (INV-TOOL-1, INV-TOOL-2): it stores and
    indexes definitions. It has no handlers, no execution, no authorization,
    and no runtime side effects of any kind.
    """

    def __init__(self, definitions: Iterable[SecurityToolDefinition] = ()) -> None:
        self._order: list[SecurityToolDefinition] = []
        self._by_id: dict[str, SecurityToolDefinition] = {}
        self._by_canonical: dict[str, SecurityToolDefinition] = {}
        self._by_capability: dict[ToolCapability, list[SecurityToolDefinition]] = {}
        for definition in definitions:
            self.register(definition)

    def register(self, definition: SecurityToolDefinition) -> SecurityToolDefinition:
        if not isinstance(definition, SecurityToolDefinition):
            raise ToolInventoryError("catalog entries must be typed SecurityToolDefinition objects")
        # INV-TOOL-7: canonical uniqueness across categories.
        if definition.tool_id in self._by_id:
            raise ToolInventoryError("duplicate tool_id in catalog: " + definition.tool_id)
        folded = definition.canonical_name.casefold()
        if folded in self._by_canonical:
            raise ToolInventoryError("duplicate canonical tool in catalog: " + definition.canonical_name)
        self._order.append(definition)
        self._by_id[definition.tool_id] = definition
        self._by_canonical[folded] = definition
        for capability in definition.capabilities:
            self._by_capability.setdefault(capability, []).append(definition)
        return definition

    def get(self, tool_id: str) -> SecurityToolDefinition | None:
        return self._by_id.get(str(tool_id or "").strip())

    def get_required(self, tool_id: str) -> SecurityToolDefinition:
        definition = self.get(tool_id)
        if definition is None:
            raise ToolInventoryError("unknown security tool: " + str(tool_id))
        return definition

    def by_canonical_name(self, name: str) -> SecurityToolDefinition | None:
        return self._by_canonical.get(str(name or "").strip().casefold())

    def providers_for(self, capability: ToolCapability | str) -> tuple[SecurityToolDefinition, ...]:
        capability = _coerce_enum(capability, ToolCapability, "capability")
        return tuple(self._by_capability.get(capability, ()))

    def tools_in_category(self, category: ToolCategory | str) -> tuple[SecurityToolDefinition, ...]:
        category = _coerce_enum(category, ToolCategory, "category")
        return tuple(definition for definition in self._order if definition.category is category)

    def tools_with_risk_class(self, risk_class: ToolRiskClass | str) -> tuple[SecurityToolDefinition, ...]:
        risk_class = _coerce_enum(risk_class, ToolRiskClass, "risk class")
        return tuple(definition for definition in self._order if definition.risk_class is risk_class)

    def tool_ids(self) -> tuple[str, ...]:
        return tuple(definition.tool_id for definition in self._order)

    def snapshot(self) -> list[dict[str, Any]]:
        return [definition.to_dict() for definition in self._order]

    def __len__(self) -> int:
        return len(self._order)


def _definition(tool_id: str, canonical_name: str, category: ToolCategory, capabilities: tuple[ToolCapability, ...], risk_class: ToolRiskClass, description: str, **overrides: Any) -> SecurityToolDefinition:
    """Build one seed definition with deterministic defaults."""
    defaults: dict[str, Any] = {
        "required_runtime": "external-binary",
        "platform": "linux",
        "availability": ToolAvailability.EXTERNAL,
        "authorization_class": RISK_AUTHORIZATION_CLASS[risk_class],
        "network_required": risk_class in (ToolRiskClass.PASSIVE_RECON, ToolRiskClass.AUTHORIZED_SCANNING, ToolRiskClass.HIGH_RISK),
        "process_execution": ToolAccessLevel.EXECUTE,
        "lab_only": risk_class in OFFENSIVE_RISK_CLASSES,
        "external_target_capability": risk_class in (ToolRiskClass.PASSIVE_RECON, ToolRiskClass.AUTHORIZED_SCANNING),
    }
    defaults.update(overrides)
    return SecurityToolDefinition(
        tool_id=tool_id,
        canonical_name=canonical_name,
        category=category,
        description=description,
        capabilities=capabilities,
        risk_class=risk_class,
        **defaults,
    )


# ---------------------------------------------------------------------------
# Owner-curated seed catalog (Stage A). Every row is a canonical definition
# (INV-TOOL-7). Defining an offensive tool here is KNOWLEDGE ONLY: no
# adapter, no handler, no runtime registration, and no authority exist for
# any of these tools in this module (INV-TOOL-1, INV-TOOL-2).
# ---------------------------------------------------------------------------


def _seed_rows() -> list[tuple[ToolCategory, str, str, tuple[ToolCapability, ...], ToolRiskClass, str, dict[str, Any]]]:
    rows: list[tuple[ToolCategory, str, str, tuple[ToolCapability, ...], ToolRiskClass, str, dict[str, Any]]] = []

    def add(category: ToolCategory, tool_id: str, canonical: str, caps: tuple[ToolCapability, ...], risk: ToolRiskClass, description: str, **overrides: Any) -> None:
        rows.append((category, tool_id, canonical, caps, risk, description, overrides))

    # --- Reconnaissance ---
    add(ToolCategory.RECONNAISSANCE, "shodan", "Shodan", (ToolCapability.PASSIVE_RECON, ToolCapability.OSINT), ToolRiskClass.PASSIVE_RECON, "Internet-connected device search engine used for passive exposure discovery.")
    add(ToolCategory.RECONNAISSANCE, "theharvester", "theHarvester", (ToolCapability.PASSIVE_RECON, ToolCapability.OSINT, ToolCapability.SUBDOMAIN_ENUMERATION), ToolRiskClass.PASSIVE_RECON, "Passive email, subdomain, and host aggregation from public sources.")
    add(ToolCategory.RECONNAISSANCE, "maltego", "Maltego", (ToolCapability.PASSIVE_RECON, ToolCapability.OSINT), ToolRiskClass.PASSIVE_RECON, "Relationship and entity graphing for passive infrastructure intelligence.")
    add(ToolCategory.RECONNAISSANCE, "amass", "Amass", (ToolCapability.PASSIVE_RECON, ToolCapability.SUBDOMAIN_ENUMERATION, ToolCapability.DNS_LOOKUP), ToolRiskClass.PASSIVE_RECON, "Attack-surface mapping and subdomain enumeration with passive collection.")
    add(ToolCategory.RECONNAISSANCE, "subfinder", "Subfinder", (ToolCapability.SUBDOMAIN_ENUMERATION, ToolCapability.DNS_LOOKUP), ToolRiskClass.PASSIVE_RECON, "Passive subdomain discovery using online data sources.")
    add(ToolCategory.RECONNAISSANCE, "whois", "WHOIS", (ToolCapability.WHOIS_LOOKUP, ToolCapability.DNS_LOOKUP), ToolRiskClass.INFORMATIONAL, "Public registration record lookup for domains and addresses.", network_required=True, external_target_capability=True)

    # --- Scanning & Enumeration ---
    add(ToolCategory.SCANNING_ENUMERATION, "nmap", "Nmap", (ToolCapability.PORT_SCANNING, ToolCapability.SERVICE_ENUMERATION, ToolCapability.VULNERABILITY_SCANNING), ToolRiskClass.AUTHORIZED_SCANNING, "Network port scanning and service detection for explicitly authorized scope.")
    add(ToolCategory.SCANNING_ENUMERATION, "masscan", "Masscan", (ToolCapability.PORT_SCANNING,), ToolRiskClass.AUTHORIZED_SCANNING, "High-rate TCP port scanning restricted to authorized scope.")
    add(ToolCategory.SCANNING_ENUMERATION, "rustscan", "RustScan", (ToolCapability.PORT_SCANNING,), ToolRiskClass.AUTHORIZED_SCANNING, "Fast port scanning that delegates service detection to authorized workflows.")
    add(ToolCategory.SCANNING_ENUMERATION, "enum4linux", "enum4linux", (ToolCapability.SERVICE_ENUMERATION,), ToolRiskClass.AUTHORIZED_SCANNING, "SMB and NetBIOS enumeration against authorized targets.")
    add(ToolCategory.SCANNING_ENUMERATION, "snmpwalk", "SNMPwalk", (ToolCapability.SERVICE_ENUMERATION,), ToolRiskClass.AUTHORIZED_SCANNING, "SNMP tree walking against authorized community strings and hosts.")
    add(ToolCategory.SCANNING_ENUMERATION, "netcat", "Netcat", (ToolCapability.SERVICE_ENUMERATION, ToolCapability.PACKET_ANALYSIS), ToolRiskClass.AUTHORIZED_SCANNING, "Raw TCP/UDP connectivity probing and banner collection for authorized targets.")

    # --- Web Application Testing ---
    add(ToolCategory.WEB_APPLICATION_TESTING, "burpsuite", "Burp Suite", (ToolCapability.HTTP_ANALYSIS, ToolCapability.WEB_ENUMERATION, ToolCapability.VULNERABILITY_SCANNING), ToolRiskClass.AUTHORIZED_SCANNING, "HTTP interception and web application scanning inside authorized scope.")
    add(ToolCategory.WEB_APPLICATION_TESTING, "owasp_zap", "OWASP ZAP", (ToolCapability.HTTP_ANALYSIS, ToolCapability.WEB_ENUMERATION, ToolCapability.VULNERABILITY_SCANNING), ToolRiskClass.AUTHORIZED_SCANNING, "Open-source web application scanner and proxy for authorized targets.")
    add(ToolCategory.WEB_APPLICATION_TESTING, "nikto", "Nikto", (ToolCapability.WEB_ENUMERATION, ToolCapability.VULNERABILITY_SCANNING), ToolRiskClass.AUTHORIZED_SCANNING, "Web server misconfiguration and known-vulnerability scanning.")
    add(ToolCategory.WEB_APPLICATION_TESTING, "gobuster", "Gobuster", (ToolCapability.WEB_ENUMERATION,), ToolRiskClass.AUTHORIZED_SCANNING, "Directory and file brute-forcing against authorized web roots.")
    add(ToolCategory.WEB_APPLICATION_TESTING, "ffuf", "ffuf", (ToolCapability.WEB_ENUMERATION,), ToolRiskClass.AUTHORIZED_SCANNING, "Fast web fuzzer for content discovery inside authorized scope.")
    add(ToolCategory.WEB_APPLICATION_TESTING, "dirsearch", "Dirsearch", (ToolCapability.WEB_ENUMERATION,), ToolRiskClass.AUTHORIZED_SCANNING, "Web path enumeration for authorized web applications.")

    # --- Exploitation (knowledge/lab-only definitions; no executable path exists) ---
    add(ToolCategory.EXPLOITATION, "metasploit", "Metasploit", (ToolCapability.LAB_EXPLOITATION, ToolCapability.VULNERABILITY_SCANNING), ToolRiskClass.LAB_SECURITY_TESTING, "Exploitation framework for authorized lab targets only.", destructive_capability=True)
    add(ToolCategory.EXPLOITATION, "searchsploit", "Searchsploit", (ToolCapability.EXPLOIT_RESEARCH,), ToolRiskClass.INFORMATIONAL, "Offline Exploit-DB search for research; lookup is not execution.", network_required=False, external_target_capability=False)
    add(ToolCategory.EXPLOITATION, "beef", "BeEF", (ToolCapability.LAB_EXPLOITATION,), ToolRiskClass.LAB_SECURITY_TESTING, "Browser exploitation framework restricted to lab environments.", destructive_capability=True)
    add(ToolCategory.EXPLOITATION, "sqlmap", "SQLmap", (ToolCapability.LAB_EXPLOITATION, ToolCapability.WEB_ENUMERATION), ToolRiskClass.LAB_SECURITY_TESTING, "SQL injection testing tool for lab targets only.", destructive_capability=True)
    add(ToolCategory.EXPLOITATION, "commix", "Commix", (ToolCapability.LAB_EXPLOITATION,), ToolRiskClass.LAB_SECURITY_TESTING, "Command injection testing tool for lab targets only.", destructive_capability=True)
    add(ToolCategory.EXPLOITATION, "routersploit", "RouterSploit", (ToolCapability.LAB_EXPLOITATION,), ToolRiskClass.LAB_SECURITY_TESTING, "Router exploitation framework for lab devices only.", destructive_capability=True)

    # --- Credential Attacks ---
    add(ToolCategory.CREDENTIAL_ATTACKS, "hashcat", "Hashcat", (ToolCapability.CREDENTIAL_AUDIT,), ToolRiskClass.LAB_SECURITY_TESTING, "Offline hash auditing against owner-provided capture files.", network_required=False)
    add(ToolCategory.CREDENTIAL_ATTACKS, "john", "John the Ripper", (ToolCapability.CREDENTIAL_AUDIT,), ToolRiskClass.LAB_SECURITY_TESTING, "Offline password auditing against owner-provided capture files.", network_required=False)
    add(ToolCategory.CREDENTIAL_ATTACKS, "hydra", "Hydra", (ToolCapability.CREDENTIAL_AUDIT,), ToolRiskClass.HIGH_RISK, "Online credential attack tool restricted to lab targets.")
    add(ToolCategory.CREDENTIAL_ATTACKS, "medusa", "Medusa", (ToolCapability.CREDENTIAL_AUDIT,), ToolRiskClass.HIGH_RISK, "Parallel online login auditing restricted to lab targets.")
    add(ToolCategory.CREDENTIAL_ATTACKS, "cewl", "CeWL", (ToolCapability.WORDLIST_GENERATION, ToolCapability.OSINT), ToolRiskClass.PASSIVE_RECON, "Custom wordlist generation by crawling public site content.")
    add(ToolCategory.CREDENTIAL_ATTACKS, "crunch", "Crunch", (ToolCapability.WORDLIST_GENERATION, ToolCapability.DATA_TRANSFORMATION), ToolRiskClass.INFORMATIONAL, "Offline wordlist generator; no external interaction.", network_required=False, external_target_capability=False)

    # --- Wireless Security ---
    add(ToolCategory.WIRELESS_SECURITY, "aircrack_ng", "Aircrack-ng", (ToolCapability.CREDENTIAL_AUDIT, ToolCapability.LAB_EXPLOITATION), ToolRiskClass.LAB_SECURITY_TESTING, "WiFi capture analysis and audit suite for authorized lab wireless ranges.")
    add(ToolCategory.WIRELESS_SECURITY, "kismet", "Kismet", (ToolCapability.WIRELESS_MONITORING, ToolCapability.PACKET_CAPTURE), ToolRiskClass.PRIVILEGED_SECURITY, "Passive wireless monitoring and intrusion detection.", privileged_execution=True, external_target_capability=False)
    add(ToolCategory.WIRELESS_SECURITY, "wifite", "Wifite", (ToolCapability.LAB_EXPLOITATION, ToolCapability.CREDENTIAL_AUDIT), ToolRiskClass.HIGH_RISK, "Automated wireless auditing for lab wireless ranges only.", privileged_execution=True, destructive_capability=True)
    add(ToolCategory.WIRELESS_SECURITY, "bettercap", "Bettercap", (ToolCapability.MITM_INTERCEPTION, ToolCapability.PACKET_CAPTURE, ToolCapability.WIRELESS_MONITORING), ToolRiskClass.HIGH_RISK, "Network interception and monitoring Swiss army knife for lab ranges only.", destructive_capability=True)
    add(ToolCategory.WIRELESS_SECURITY, "reaver", "Reaver", (ToolCapability.LAB_EXPLOITATION,), ToolRiskClass.HIGH_RISK, "WPS attack tool for lab devices only.", privileged_execution=True, destructive_capability=True)
    add(ToolCategory.WIRELESS_SECURITY, "hcxdumptool", "hcxdumptool", (ToolCapability.PACKET_CAPTURE, ToolCapability.CREDENTIAL_AUDIT), ToolRiskClass.HIGH_RISK, "WiFi packet capture for handshake collection in lab ranges.", privileged_execution=True)

    # --- Network Analysis ---
    add(ToolCategory.NETWORK_ANALYSIS, "wireshark", "Wireshark", (ToolCapability.PACKET_CAPTURE, ToolCapability.PACKET_ANALYSIS), ToolRiskClass.AUTHORIZED_SCANNING, "Graphical packet capture and protocol analysis for authorized captures.")
    add(ToolCategory.NETWORK_ANALYSIS, "tcpdump", "tcpdump", (ToolCapability.PACKET_CAPTURE, ToolCapability.PACKET_ANALYSIS), ToolRiskClass.PRIVILEGED_SECURITY, "Command-line packet capture requiring elevated privileges.", privileged_execution=True, external_target_capability=False)
    add(ToolCategory.NETWORK_ANALYSIS, "ettercap", "Ettercap", (ToolCapability.MITM_INTERCEPTION, ToolCapability.PACKET_CAPTURE), ToolRiskClass.HIGH_RISK, "Man-in-the-middle interception tool for lab networks only.", destructive_capability=True)
    add(ToolCategory.NETWORK_ANALYSIS, "tshark", "TShark", (ToolCapability.PACKET_CAPTURE, ToolCapability.PACKET_ANALYSIS), ToolRiskClass.AUTHORIZED_SCANNING, "Command-line packet analysis for authorized captures.")
    add(ToolCategory.NETWORK_ANALYSIS, "scapy", "Scapy", (ToolCapability.PACKET_ANALYSIS, ToolCapability.PACKET_CAPTURE), ToolRiskClass.HIGH_RISK, "Packet crafting and analysis library for lab network use only.")

    # --- Active Directory (lab-only definitions) ---
    add(ToolCategory.ACTIVE_DIRECTORY, "bloodhound", "BloodHound", (ToolCapability.AD_ENUMERATION,), ToolRiskClass.LAB_SECURITY_TESTING, "Active Directory path analysis for authorized lab domains.")
    add(ToolCategory.ACTIVE_DIRECTORY, "netexec", "NetExec", (ToolCapability.AD_ENUMERATION, ToolCapability.SERVICE_ENUMERATION), ToolRiskClass.LAB_SECURITY_TESTING, "Network service and AD auditing for lab domains only.")
    add(ToolCategory.ACTIVE_DIRECTORY, "impacket", "Impacket", (ToolCapability.AD_ENUMERATION, ToolCapability.LAB_EXPLOITATION), ToolRiskClass.LAB_SECURITY_TESTING, "Protocol toolkit for AD testing in lab domains only.")
    add(ToolCategory.ACTIVE_DIRECTORY, "certipy", "Certipy", (ToolCapability.AD_ENUMERATION, ToolCapability.LAB_EXPLOITATION), ToolRiskClass.LAB_SECURITY_TESTING, "AD certificate service testing for lab domains only.")
    add(ToolCategory.ACTIVE_DIRECTORY, "rubeus", "Rubeus", (ToolCapability.AD_ENUMERATION, ToolCapability.CREDENTIAL_AUDIT), ToolRiskClass.LAB_SECURITY_TESTING, "Kerberos interaction testing for lab domains only.")
    add(ToolCategory.ACTIVE_DIRECTORY, "mimikatz", "Mimikatz", (ToolCapability.CREDENTIAL_AUDIT, ToolCapability.LAB_EXPLOITATION), ToolRiskClass.HIGH_RISK, "Windows credential extraction tool; lab environments only.", destructive_capability=True)

    # --- Cloud Security ---
    add(ToolCategory.CLOUD_SECURITY, "scoutsuite", "ScoutSuite", (ToolCapability.CLOUD_AUDIT,), ToolRiskClass.AUTHORIZED_SCANNING, "Multi-cloud configuration audit for owner-owned accounts.")
    add(ToolCategory.CLOUD_SECURITY, "prowler", "Prowler", (ToolCapability.CLOUD_AUDIT,), ToolRiskClass.AUTHORIZED_SCANNING, "Cloud security posture assessment for owner-owned accounts.")
    add(ToolCategory.CLOUD_SECURITY, "pacu", "Pacu", (ToolCapability.CLOUD_AUDIT, ToolCapability.LAB_EXPLOITATION), ToolRiskClass.LAB_SECURITY_TESTING, "AWS exploitation testing framework for lab accounts only.")
    add(ToolCategory.CLOUD_SECURITY, "trivy", "Trivy", (ToolCapability.CONTAINER_AUDIT, ToolCapability.CODE_ANALYSIS), ToolRiskClass.AUTHORIZED_SCANNING, "Local container image and dependency vulnerability scanning.", network_required=False, external_target_capability=False)
    add(ToolCategory.CLOUD_SECURITY, "kube_hunter", "kube-hunter", (ToolCapability.CLOUD_AUDIT, ToolCapability.CONTAINER_AUDIT), ToolRiskClass.AUTHORIZED_SCANNING, "Kubernetes cluster probing for owner-owned clusters.")
    add(ToolCategory.CLOUD_SECURITY, "kube_bench", "kube-bench", (ToolCapability.CONTAINER_AUDIT, ToolCapability.CLOUD_AUDIT), ToolRiskClass.AUTHORIZED_SCANNING, "CIS Kubernetes benchmark checks for owner-owned clusters.", network_required=False, external_target_capability=False)

    # --- Reverse Engineering (offline local analysis) ---
    add(ToolCategory.REVERSE_ENGINEERING, "ghidra", "Ghidra", (ToolCapability.BINARY_ANALYSIS, ToolCapability.CODE_ANALYSIS), ToolRiskClass.LOCAL_ANALYSIS, "Offline disassembly and decompilation of local binaries.", network_required=False, external_target_capability=False)
    add(ToolCategory.REVERSE_ENGINEERING, "ida_free", "IDA Free", (ToolCapability.BINARY_ANALYSIS, ToolCapability.CODE_ANALYSIS), ToolRiskClass.LOCAL_ANALYSIS, "Offline disassembler for local binaries.", network_required=False, external_target_capability=False)
    add(ToolCategory.REVERSE_ENGINEERING, "x64dbg", "x64dbg", (ToolCapability.BINARY_ANALYSIS,), ToolRiskClass.LOCAL_ANALYSIS, "Offline Windows user-mode debugger for local binaries.", network_required=False, external_target_capability=False)
    add(ToolCategory.REVERSE_ENGINEERING, "radare2", "Radare2", (ToolCapability.BINARY_ANALYSIS, ToolCapability.CODE_ANALYSIS), ToolRiskClass.LOCAL_ANALYSIS, "Offline command-line reverse engineering framework.", network_required=False, external_target_capability=False)
    add(ToolCategory.REVERSE_ENGINEERING, "cutter", "Cutter", (ToolCapability.BINARY_ANALYSIS, ToolCapability.CODE_ANALYSIS), ToolRiskClass.LOCAL_ANALYSIS, "Graphical reverse engineering front-end for local binaries.", network_required=False, external_target_capability=False)
    add(ToolCategory.REVERSE_ENGINEERING, "binary_ninja", "Binary Ninja", (ToolCapability.BINARY_ANALYSIS, ToolCapability.CODE_ANALYSIS), ToolRiskClass.LOCAL_ANALYSIS, "Offline binary analysis platform for local binaries.", network_required=False, external_target_capability=False)

    # --- OSINT ---
    add(ToolCategory.OSINT, "spiderfoot", "SpiderFoot", (ToolCapability.OSINT, ToolCapability.PASSIVE_RECON), ToolRiskClass.PASSIVE_RECON, "Automated open-source intelligence collection.")
    add(ToolCategory.OSINT, "sherlock", "Sherlock", (ToolCapability.OSINT,), ToolRiskClass.PASSIVE_RECON, "Username enumeration across public platforms.")
    add(ToolCategory.OSINT, "recon_ng", "Recon-ng", (ToolCapability.OSINT, ToolCapability.PASSIVE_RECON), ToolRiskClass.PASSIVE_RECON, "Web reconnaissance framework using public sources.")
    add(ToolCategory.OSINT, "phoneinfoga", "PhoneInfoga", (ToolCapability.OSINT,), ToolRiskClass.PASSIVE_RECON, "Phone number footprinting from public sources.")
    add(ToolCategory.OSINT, "ghunt", "GHunt", (ToolCapability.OSINT,), ToolRiskClass.PASSIVE_RECON, "Public Google account footprinting from open sources.")
    add(ToolCategory.OSINT, "holehe", "Holehe", (ToolCapability.OSINT,), ToolRiskClass.PASSIVE_RECON, "Email registration checks across public services.")

    # --- Containers & DevSecOps ---
    add(ToolCategory.CONTAINERS_DEVSECOPS, "dockle", "Dockle", (ToolCapability.CONTAINER_AUDIT,), ToolRiskClass.AUTHORIZED_SCANNING, "Local container image linting and best-practice checks.", network_required=False, external_target_capability=False)
    add(ToolCategory.CONTAINERS_DEVSECOPS, "docker_bench", "Docker Bench", (ToolCapability.CONTAINER_AUDIT,), ToolRiskClass.AUTHORIZED_SCANNING, "CIS Docker benchmark checks on the local host.", network_required=False, external_target_capability=False)
    add(ToolCategory.CONTAINERS_DEVSECOPS, "checkov", "Checkov", (ToolCapability.CONTAINER_AUDIT, ToolCapability.CODE_ANALYSIS), ToolRiskClass.AUTHORIZED_SCANNING, "Infrastructure-as-code static analysis for local repositories.", network_required=False, external_target_capability=False)

    # --- Reporting ---
    add(ToolCategory.REPORTING, "dradis", "Dradis", (ToolCapability.REPORT_GENERATION,), ToolRiskClass.INFORMATIONAL, "Collaborative reporting platform for assessment evidence.", network_required=False, external_target_capability=False)
    add(ToolCategory.REPORTING, "ghostwriter", "Ghostwriter", (ToolCapability.REPORT_GENERATION,), ToolRiskClass.INFORMATIONAL, "Reporting platform for engagement findings.", network_required=False, external_target_capability=False)
    add(ToolCategory.REPORTING, "serpico", "Serpico", (ToolCapability.REPORT_GENERATION,), ToolRiskClass.INFORMATIONAL, "Simple report generation application.", network_required=False, external_target_capability=False)
    add(ToolCategory.REPORTING, "cherrytree", "CherryTree", (ToolCapability.REPORT_GENERATION,), ToolRiskClass.LOCAL_ANALYSIS, "Local hierarchical note-taking for findings.", network_required=False, external_target_capability=False)
    add(ToolCategory.REPORTING, "obsidian", "Obsidian", (ToolCapability.REPORT_GENERATION, ToolCapability.DATA_TRANSFORMATION), ToolRiskClass.LOCAL_ANALYSIS, "Local markdown knowledge base for findings.", network_required=False, external_target_capability=False)
    add(ToolCategory.REPORTING, "markdown", "Markdown", (ToolCapability.REPORT_GENERATION, ToolCapability.REPORT_EXPORT, ToolCapability.DATA_TRANSFORMATION), ToolRiskClass.INFORMATIONAL, "Plain-text reporting format for evidence bundles.", availability=ToolAvailability.PLANNED, network_required=False, external_target_capability=False, process_execution=ToolAccessLevel.NONE, required_runtime="builtin")

    # --- Practice Labs (LAB_TARGET environments; names are never authority) ---
    add(ToolCategory.PRACTICE_LABS, "kali_linux", "Kali Linux", (ToolCapability.LAB_ENVIRONMENT,), ToolRiskClass.LAB_SECURITY_TESTING, "Security testing lab distribution for local lab use.", network_required=False)
    add(ToolCategory.PRACTICE_LABS, "parrot_os", "Parrot OS", (ToolCapability.LAB_ENVIRONMENT,), ToolRiskClass.LAB_SECURITY_TESTING, "Security testing lab distribution for local lab use.", network_required=False)
    add(ToolCategory.PRACTICE_LABS, "hack_the_box", "Hack The Box", (ToolCapability.LAB_ENVIRONMENT,), ToolRiskClass.LAB_SECURITY_TESTING, "Authorized lab target platform; requires explicit LAB_TARGET authorization.")
    add(ToolCategory.PRACTICE_LABS, "tryhackme", "TryHackMe", (ToolCapability.LAB_ENVIRONMENT,), ToolRiskClass.LAB_SECURITY_TESTING, "Authorized lab training platform; requires explicit LAB_TARGET authorization.")
    add(ToolCategory.PRACTICE_LABS, "portswigger_academy", "PortSwigger Academy", (ToolCapability.LAB_ENVIRONMENT,), ToolRiskClass.LAB_SECURITY_TESTING, "Authorized web security labs; requires explicit LAB_TARGET authorization.")
    add(ToolCategory.PRACTICE_LABS, "vulnhub", "VulnHub", (ToolCapability.LAB_ENVIRONMENT,), ToolRiskClass.LAB_SECURITY_TESTING, "Authorized offline lab images; requires explicit LAB_TARGET authorization.")

    # --- Security Resources (knowledge; ingestion never grants execution) ---
    add(ToolCategory.SECURITY_RESOURCES, "cyberchef", "CyberChef", (ToolCapability.DATA_TRANSFORMATION, ToolCapability.CODE_ANALYSIS), ToolRiskClass.LOCAL_ANALYSIS, "Local data transformation and decoding workbench.", network_required=False, external_target_capability=False)
    add(ToolCategory.SECURITY_RESOURCES, "exploitdb", "Exploit-DB", (ToolCapability.EXPLOIT_RESEARCH,), ToolRiskClass.INFORMATIONAL, "Offline exploit archive for research; lookup is not execution.", network_required=False, external_target_capability=False)
    add(ToolCategory.SECURITY_RESOURCES, "seclists", "SecLists", (ToolCapability.WORDLIST_GENERATION,), ToolRiskClass.INFORMATIONAL, "Offline wordlist and credential-list repository.", network_required=False, external_target_capability=False)
    add(ToolCategory.SECURITY_RESOURCES, "gtfobins", "GTFOBins", (ToolCapability.EXPLOIT_RESEARCH,), ToolRiskClass.INFORMATIONAL, "Offline Unix binary misuse reference; knowledge only.", network_required=False, external_target_capability=False)
    add(ToolCategory.SECURITY_RESOURCES, "lolbas", "LOLBAS", (ToolCapability.EXPLOIT_RESEARCH,), ToolRiskClass.INFORMATIONAL, "Offline Windows living-off-the-land binary reference; knowledge only.", network_required=False, external_target_capability=False)
    add(ToolCategory.SECURITY_RESOURCES, "virustotal", "VirusTotal", (ToolCapability.OSINT, ToolCapability.PASSIVE_RECON), ToolRiskClass.PASSIVE_RECON, "Public file and indicator reputation lookups.")

    return rows


def _build_default_inventory() -> SecurityToolInventory:
    inventory = SecurityToolInventory()
    for category, tool_id, canonical, caps, risk, description, overrides in _seed_rows():
        inventory.register(_definition(tool_id, canonical, category, caps, risk, description, **overrides))
    return inventory


DEFAULT_SECURITY_TOOL_INVENTORY = _build_default_inventory()
