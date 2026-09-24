from __future__ import annotations

"""Kali Linux tool ecosystem integration for CyberSentinel.

ARCHITECTURAL INVARIANT (unchanged, non-negotiable):

    OWNER_INSTRUCTION
        > SYSTEM_PLATFORM
        > OWNER_POLICY
        > DETERMINISTIC_ENFORCEMENT
        > AUTHORIZATION_SCOPE
        > TOOL_RUNTIME
        > MODEL_OUTPUT
        > EXTERNAL_DATA

FULL TECHNICAL CAPABILITY != FULL AUTHORITY.

CyberSentinel may *own* the technical capability to invoke Kali tools
when the runtime provides them, but no capability, tool registry, model
router, tool output, or external data may ever *authorize* execution.
Only the Owner (via an Owner-approved MissionAuthorizationSnapshot) can,
and only the deterministic governance gate converts capability into
execution.

The only path from an LLM proposal to execution is:

    model proposes tool
        -> capability discovery check
        -> authorization snapshot check
        -> scope firewall check
        -> deterministic policy check
        -> authorized execution
        -> observation
        -> evidence
        -> verification

There is no direct "LLM -> tool call -> execution" path and no
EXECUTE_ANYWAY state.
"""

from kali.taxonomy import KaliToolCategory, KALI_CATEGORIES
from kali.registry import KaliToolSpec, KaliToolRegistry, build_default_registry
from kali.discovery import CapabilityStatus, ToolCapability, KaliCapabilityProbe, RuntimeDescriptor
from kali.runtime import KaliRuntimeAdapter, LocalKaliRuntime, SimulatedKaliRuntime, ToolExecutionResult, ToolTimeout
from kali.governance import (
    ExecutionDecision,
    KaliExecutionGate,
    AUTHORIZATION_BLOCKED,
    CAPABILITY_BLOCKED,
    NEEDS_OWNER_APPROVAL,
    AUTHORIZED,
)
from kali.evidence import (
    ProvenanceLayer,
    PROVENANCE_HIERARCHY,
    KaliExecutionEvidence,
    evidence_from_execution,
)

__all__ = [
    "KaliToolCategory",
    "KALI_CATEGORIES",
    "KaliToolSpec",
    "KaliToolRegistry",
    "build_default_registry",
    "CapabilityStatus",
    "ToolCapability",
    "KaliCapabilityProbe",
    "RuntimeDescriptor",
    "KaliRuntimeAdapter",
    "LocalKaliRuntime",
    "SimulatedKaliRuntime",
    "ToolExecutionResult",
    "ToolTimeout",
    "ExecutionDecision",
    "KaliExecutionGate",
    "AUTHORIZATION_BLOCKED",
    "CAPABILITY_BLOCKED",
    "NEEDS_OWNER_APPROVAL",
    "AUTHORIZED",
    "ProvenanceLayer",
    "PROVENANCE_HIERARCHY",
    "KaliExecutionEvidence",
    "evidence_from_execution",
]
