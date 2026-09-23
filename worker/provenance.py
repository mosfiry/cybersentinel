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


# Fixed order: lower index = higher authority.
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

# Layers that may NEVER be claimed by non-owner sources: authority layers.
# Nothing a worker produces (capability, evidence, model output, external
# data) can grant them.
AUTHORITY_LAYERS: frozenset[ProvenanceLayer] = frozenset({
    ProvenanceLayer.OWNER_INSTRUCTION,
    ProvenanceLayer.OWNER_POLICY,
    ProvenanceLayer.AUTHORIZATION_SCOPE,
})

# The only provenance layers worker-produced data may ever claim.
WORKER_PROVENANCE_LAYERS: frozenset[ProvenanceLayer] = frozenset({
    ProvenanceLayer.TOOL_RUNTIME,
    ProvenanceLayer.MODEL_OUTPUT,
    ProvenanceLayer.EXTERNAL_DATA,
})


def promotion_allowed(source: ProvenanceLayer, claimed: ProvenanceLayer) -> bool:
    """Authority boundary check: may data of provenance `source` be
    recorded as provenance `claimed`?

    Rules (deterministic, no exceptions):
      * Worker-derived data (TOOL_RUNTIME / MODEL_OUTPUT / EXTERNAL_DATA)
        may only ever be recorded as one of those same worker layers — it
        can never claim an authority layer (OWNER_INSTRUCTION, OWNER_POLICY,
        AUTHORIZATION_SCOPE) or any system layer above it. Capability,
        evidence and findings are facts about the world, not grants of power.
      * For non-worker sources, only a same-or-lower authority claim is
        allowed (rank(claimed) >= rank(source)); upward promotion is denied.
    """
    if source in WORKER_PROVENANCE_LAYERS:
        return claimed in WORKER_PROVENANCE_LAYERS
    return _RANK[claimed] >= _RANK[source]
