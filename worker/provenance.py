from __future__ import annotations

from enum import Enum


class ProvenanceLayer(str, Enum):
    """The fixed authority hierarchy. Nothing in this package may change it,
    and no data may be promoted up this hierarchy by any worker, model
    output, evidence, capability, or finding."""

    OWNER_INSTRUCTION = "OWNER_INSTRUCTION"
    SYSTEM_PLATFORM = "SYSTEM_PLATFORM"
    OWNER_POLICY = "OWNER_POLICY"
    DETERMINISTIC_ENFORCEMENT = "DETERMINISTIC_ENFORCEMENT"
    AUTHORIZATION_SCOPE = "AUTHORIZATION_SCOPE"
    TOOL_RUNTIME = "TOOL_RUNTIME"
    MODEL_OUTPUT = "MODEL_OUTPUT"
    EXTERNAL_DATA = "EXTERNAL_DATA"


# Fixed order: higher index = lower authority.
PROVENANCE_HIERARCHY: tuple[ProvenanceLayer, ...] = (
    ProvenanceLayer.OWNER_INSTRUCTION,
    ProvenanceLayer.SYSTEM_PLATFORM,
    ProvenanceLayer.OWNER_POLICY,
    ProvenanceLayer.DETERMINISTIC_ENFORCEMENT,
    ProvenanceLayer.AUTHORIZATION_SCOPE,
    ProvenanceLayer.TOOL_RUNTIME,
    ProvenanceLayer.MODEL_OUTPUT,
    ProvenanceLayer.EXTERNAL_DATA,
)

_RANK = {layer: index for index, layer in enumerate(PROVENANCE_HIERARCHY)}

# Layers that may NEVER be claimed by non-owner sources regardless of
# direction: these are authority layers, and nothing a worker produces
# (capability, evidence, model output, external data) can grant them.
AUTHORITY_LAYERS: frozenset[ProvenanceLayer] = frozenset({
    ProvenanceLayer.OWNER_INSTRUCTION,
    ProvenanceLayer.OWNER_POLICY,
    ProvenanceLayer.AUTHORIZATION_SCOPE,
})

# Provenance of anything produced by the worker package:
WORKER_PROVENANCE_LAYERS: frozenset[ProvenanceLayer] = frozenset({
    ProvenanceLayer.EXTERNAL_DATA,
    ProvenanceLayer.MODEL_OUTPUT,
    ProvenanceLayer.TOOL_RUNTIME,
})


def promotion_allowed(source: ProvenanceLayer, claimed: ProvenanceLayer) -> bool:
    """Authority boundary check.

    A worker-derived source layer may NEVER claim an authority layer, even
    though authority layers sit above it in the hierarchy. Capability,
    evidence and findings are facts about the world, not grants of power.
    """
    if source in WORKER_PROVENANCE_LAYERS and claimed in AUTHORITY_LAYERS:
        return False
    return _RANK[claimed] >= _RANK[source] is False or _RANK[source] <= _RANK[claimed]
